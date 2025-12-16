package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	ipam "nox-core/internal/server"
	noxcrypto "nox-core/pkg/crypto"
	"nox-core/pkg/frame"
	"nox-core/pkg/tun"
)

const (
	streamData  uint32 = 100
	defaultCIDR        = "10.8.0.0/24"

)

func main() {
	addr := getenv("NOX_LISTEN", ":9000")
	cidr := getenv("NOX_SUBNET", defaultCIDR)

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

	t, err := tun.Create("nox0")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TUN nox0 created")

	allocator, err := ipam.NewIPAlloc(cidr)
	if err != nil {
		log.Fatalf("ip alloc: %v", err)
	}

	go func() {
		tk := time.NewTicker(5 * time.Minute)
		defer tk.Stop()
		for range tk.C {

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
		go handle(conn, t, ciph, allocator)
	}
}

func sessionIDForClient(clientID string) [8]byte {
	sum := sha256.Sum256([]byte(clientID))
	var out [8]byte
	copy(out[:], sum[:])
	return out
}

func handle(conn net.Conn, t *tun.Tun, ciph *noxcrypto.Cipher, allocator *ipam.IPAlloc) {
	defer conn.Close()

	ra := conn.RemoteAddr().String()
	clientID := strings.Split(ra, ":")[0]

	log.Println("client connected from", ra)

	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))



	assignPayload := []byte{frame.CtrlAssignIP}
	assignPayload = append(assignPayload, []byte(leaseCIDR)...)

	if err := frame.Encode(conn, &frame.Frame{
		Type:     frame.TypeControl,
		StreamID: 0,
		Flags:    0,
		Payload:  assignPayload,
	}); err != nil {
		log.Println("assign send:", err)

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
n
					}
				}
				continue
			}

			pt, err := ciph.Open(fr.Payload)
			if err != nil {
				log.Println("decrypt:", err)
				continue
			}



			if fr.StreamID == streamData {
				if _, err := t.WritePacket(pt); err != nil {
					log.Println("tun write:", err)
					continue
				}
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := t.ReadPacket(buf)
		if err != nil {
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
