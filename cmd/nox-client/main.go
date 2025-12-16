package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	noxcrypto "nox-core/pkg/crypto"
	"nox-core/pkg/frame"
	"nox-core/pkg/tun"
)

const (
	streamData uint32 = 100
)

var sessionID [8]byte

func main() {
	server := getenv("NOX_SERVER", "208.123.185.235:9000")
	staticCIDR := getenv("NOX_CLIENT_CIDR", "10.8.0.2/24")
	tunName := getenv("NOX_TUN", "nox1")

	loadSessionID()

	keyHex := strings.TrimSpace(os.Getenv("NOX_KEY_HEX"))
	if keyHex == "" {
		log.Fatal("NOX_KEY_HEX required")
	}
	k, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatalf("decode NOX_KEY_HEX: %v", err)
	}
	if len(k) != chacha20poly1305.KeySize {
		log.Fatalf("NOX_KEY_HEX must be %d bytes", chacha20poly1305.KeySize)
	}

	ciph, err := noxcrypto.NewCipherFromKey(k)
	if err != nil {
		log.Fatalf("cipher init: %v", err)
	}

	for {
		if err := runOnce(server, staticCIDR, tunName, ciph); err != nil {
			log.Println("run:", err)
		}
		time.Sleep(2 * time.Second)
	}
}

func runOnce(server, staticCIDR, tunName string, ciph *noxcrypto.Cipher) error {
	conn, err := net.DialTimeout("tcp", server, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("connected to server")

	t, err := tun.Create(tunName)
	if err != nil {
		return err
	}
	log.Println("client TUN", tunName, "created")
	defer func() {
		_ = t.Close()
		// best-effort удалить интерфейс, чтобы избежать TUNSETIFF busy при следующем запуске
		_ = exec.Command("ip", "link", "del", tunName).Run()
	}()

	assigned := staticCIDR

	// отправляем HELLO с SessionID
	helloPayload := append([]byte{frame.CtrlHello}, sessionID[:]...)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := frame.Encode(conn, &frame.Frame{
		Type:     frame.TypeControl,
		StreamID: 0,
		Flags:    0,
		Payload:  helloPayload,
	}); err != nil {
		return err
	}

	// ждём control AssignIP
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	fr, err := frame.Read(conn)
	if err == nil && fr.Type == frame.TypeControl && len(fr.Payload) > 1 && fr.Payload[0] == frame.CtrlAssignIP {
		assigned = strings.TrimSpace(string(fr.Payload[1:]))
		log.Println("Assigned:", assigned)
	} else {
		log.Println("No assign from server, using static:", assigned)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// применяем IP + route
	exec.Command("sh", "-c", "ip addr replace "+assigned+" dev "+tunName).Run()
	exec.Command("sh", "-c", "ip link set "+tunName+" up").Run()
	exec.Command("sh", "-c", "ip route replace 10.8.0.0/24 dev "+tunName).Run()

	// keepalive sender + сигнал остановки обоих направлений
	// keepalive sender
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
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_ = frame.Encode(conn, &frame.Frame{
					Type:     frame.TypeControl,
					StreamID: 0,
					Flags:    0,
					Payload:  []byte{frame.CtrlHeartbeat},
				})
			case <-kaDone:
				return
			}
		}
	}()

	// conn -> tun
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
				continue
			}
			pt, err := ciph.Open(fr.Payload)
			if err != nil {
				log.Println("decrypt:", err)
				closeKA()
				return
				continue
			}
			if fr.StreamID == streamData {
				if _, err := t.WritePacket(pt); err != nil {
					log.Println("tun write:", err)
					closeKA()
					return
				}
			}
		}
	}()

	// tun -> conn
	buf := make([]byte, 65535)
	for {
		select {
		case <-kaDone:
			return nil
		default:
		}

		_ = t.SetReadDeadline(time.Now().Add(time.Second))
		n, err := t.ReadPacket(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
		n, err := t.ReadPacket(buf)
		if err != nil {
			closeKA()
			return err
		}
		enc := ciph.Seal(buf[:n])
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := frame.Encode(conn, &frame.Frame{
			Type:     frame.TypeData,
			StreamID: streamData,
			Flags:    0,
			Payload:  enc,
		}); err != nil {
			closeKA()
			return err
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

func loadSessionID() {
	if v := strings.TrimSpace(os.Getenv("NOX_SESSION_ID")); len(v) == 16 {
		if b, err := hex.DecodeString(v); err == nil {
			copy(sessionID[:], b)
			return
		}
	}
	if _, err := rand.Read(sessionID[:]); err != nil {
		log.Fatalf("session id gen: %v", err)
	}
n
}
