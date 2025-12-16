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
