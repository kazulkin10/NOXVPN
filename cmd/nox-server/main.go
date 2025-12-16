package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"

	"nox-core/internal/server"
	ipam "nox-core/internal/server"
	noxcrypto "nox-core/pkg/crypto"
	"nox-core/pkg/frame"
	"nox-core/pkg/tun"
)

const (
	streamData  uint32 = 100
	defaultCIDR        = "10.8.0.0/24"
	leaseTTL           = 10 * time.Minute
)

const (
	defaultHandshakeRPS   = 20
	defaultHandshakeBurst = 40
	defaultMaxClients     = 256
)

func main() {
	addr := getenv("NOX_LISTEN", ":9000")
	cidr := getenv("NOX_SUBNET", defaultCIDR)
	handshakeRPS := getenvInt("NOX_HANDSHAKE_RPS", defaultHandshakeRPS)
	handshakeBurst := getenvInt("NOX_HANDSHAKE_BURST", defaultHandshakeBurst)
	maxClients := getenvInt("NOX_MAX_CLIENTS", defaultMaxClients)

	k, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}

	ciph, err := noxcrypto.NewCipherFromKey(k)
	if err != nil {
		log.Fatalf("cipher init: %v", err)
	}

	cleanupTUN("nox0")
	t, err := tun.Create("nox0")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TUN nox0 created")
	if err := configureServerTUN("nox0", cidr); err != nil {
		log.Fatalf("tun setup failed: %v", err)
	}

	allocator, err := ipam.NewIPAlloc(cidr)
	if err != nil {
		log.Fatalf("ip alloc: %v", err)
	}
	if total, used := allocator.Stats(); true {
		log.Printf("ipam: subnet %s total=%d used=%d\n", cidr, total, used)
	}

	limiter := server.NewTokenBucket(handshakeRPS, handshakeBurst)

	go func() {
		tk := time.NewTicker(5 * time.Minute)
		defer tk.Stop()
		for range tk.C {
			if killed := allocator.ReapIdle(leaseTTL); killed > 0 {
				log.Printf("ipam: reaped %d idle lease(s)\n", killed)
			}
		}
	}()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("NOX server listening on", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handle(conn, t, ciph, allocator, limiter, maxClients)
	}
}

func sessionIDForClient(clientID string) [8]byte {
	sum := sha256.Sum256([]byte(clientID))
	var out [8]byte
	copy(out[:], sum[:])
	return out
}

func handle(conn net.Conn, t *tun.Tun, ciph *noxcrypto.Cipher, allocator *ipam.IPAlloc, limiter *server.TokenBucket, maxClients int) {
	defer conn.Close()

	ra := conn.RemoteAddr().String()
	if limiter != nil && !limiter.Allow() {
		log.Println("handshake rate-limited from", ra)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fr, err := frame.Read(conn)
	if err != nil {
		log.Println("hello read:", err)
		return
	}
	if fr.Type != frame.TypeControl || len(fr.Payload) < 9 || fr.Payload[0] != frame.CtrlHello {
		log.Println("hello invalid from", ra)
		return
	}
	var sessionID [8]byte
	copy(sessionID[:], fr.Payload[1:9])
	sessionKey := hex.EncodeToString(sessionID[:])
	clientID := strings.Split(ra, ":")[0]
	log.Printf("client %s session %s connected", clientID, sessionKey)

	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	lease, isNew, err := allocator.Acquire(sessionKey)
	if err != nil {
		total, used := allocator.Stats()
		log.Printf("ipam: %v (used=%d/%d)\n", err, used, total)
		return
	}
	leaseHeld := true
	defer func() {
		if leaseHeld {
			allocator.Release(sessionKey)
		}
	}()

	if maxClients > 0 {
		if _, used := allocator.Stats(); used > maxClients {
			log.Printf("reject: max clients %d reached\n", maxClients)
			allocator.Release(sessionKey)
			leaseHeld = false
			return
		}
	}
	leaseCIDR := fmt.Sprintf("%s/%d", lease.IP.String(), lease.MaskBits)
	if isNew {
		log.Printf("ipam: lease %s for %s (new)\n", leaseCIDR, sessionKey)
	} else {
		log.Printf("ipam: lease %s for %s (reused)\n", leaseCIDR, sessionKey)
	}

	assignPayload := []byte{frame.CtrlAssignIP}
	assignPayload = append(assignPayload, []byte(leaseCIDR)...)

	if err := frame.Encode(conn, &frame.Frame{
		Type:     frame.TypeControl,
		StreamID: 0,
		Flags:    0,
		Payload:  assignPayload,
	}); err != nil {
		log.Println("assign send:", err)
		allocator.Release(sessionKey)
		leaseHeld = false
		return
	}

	kaDone := make(chan struct{})
	var kaOnce sync.Once
	closeKA := func() { kaOnce.Do(func() { close(kaDone) }) }
	defer closeKA()

	go func() {
		tk := time.NewTicker(20 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_ = frame.Encode(conn, &frame.Frame{
					Type:     frame.TypeControl,
					StreamID: 0,
					Flags:    0,
					Payload:  []byte{frame.CtrlHeartbeat},
				})
				allocator.Touch(sessionKey)
			case <-kaDone:
				return
			}
		}
	}()

	go func() {
		for {
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			fr, err := frame.Read(conn)
			if err != nil {
				log.Println("read frame:", err)
				closeKA()
				return
			}

			if fr.Type == frame.TypeControl {
				if len(fr.Payload) > 0 {
					switch fr.Payload[0] {
					case frame.CtrlReleaseIP:
						allocator.Release(sessionKey)
					case frame.CtrlHeartbeat:
						allocator.Touch(sessionKey)
					}
				}
				continue
			}

			pt, err := ciph.Open(fr.Payload)
			if err != nil {
				log.Println("decrypt:", err)
				closeKA()
				return
			}

			allocator.Touch(sessionKey)

			if fr.StreamID == streamData {
				if _, err := t.WritePacket(pt); err != nil {
					log.Println("tun write:", err)
					closeKA()
					return
				}
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-kaDone:
			return
		default:
		}

		_ = t.SetReadDeadline(time.Now().Add(time.Second))
		n, err := t.ReadPacket(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Println("tun read:", err)
			return
		}
		enc := ciph.Seal(buf[:n])

		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := frame.Encode(conn, &frame.Frame{
			Type:     frame.TypeData,
			StreamID: streamData,
			Flags:    0,
			Payload:  enc,
		}); err != nil {
			log.Println("conn write:", err)
			return
		}
	}
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func loadKey() ([]byte, error) {
	keyHex := strings.TrimSpace(os.Getenv("NOX_KEY_HEX"))
	if keyHex == "" {
		if path := strings.TrimSpace(os.Getenv("NOX_KEY_FILE")); path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read NOX_KEY_FILE: %w", err)
			}
			keyHex = strings.TrimSpace(string(raw))
		}
	}
	if keyHex == "" {
		return nil, fmt.Errorf("NOX_KEY_HEX required (or set NOX_KEY_FILE)")
	}
	k, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode NOX_KEY_HEX: %w", err)
	}
	if len(k) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("NOX_KEY_HEX must be %d bytes", chacha20poly1305.KeySize)
	}
	return k, nil
}

func configureServerTUN(name, cidr string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("lookup link %s: %w", name, err)
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	_, bits := ipnet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("only IPv4 cidr supported")
	}
	base := ipnet.IP.To4()
	if base == nil {
		return fmt.Errorf("bad base ip")
	}
	gw := make(net.IP, len(base))
	copy(gw, base)
	gw[3]++
	gwNet := &net.IPNet{IP: gw, Mask: ipnet.Mask}

	addr := &netlink.Addr{IPNet: gwNet}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("addr replace %s: %w", gwNet.String(), err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up: %w", err)
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route replace %s: %w", ipnet.String(), err)
	}
	log.Printf("tun %s up addr=%s route=%s\n", name, gwNet.String(), ipnet.String())
	return nil
}

func cleanupTUN(name string) {
	_ = exec.Command("ip", "link", "del", name).Run()
	_ = exec.Command("ip", "tuntap", "del", "dev", name, "mode", "tun").Run()
}
