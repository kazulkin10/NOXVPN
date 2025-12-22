package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"

	"nox-core/v2/client"
	"nox-core/v2/transport"
)

func main() {
	keyHex := os.Getenv("NOX_KEY_HEX")
	serverAddr := os.Getenv("NOX_SERVER")
	if keyHex == "" || serverAddr == "" {
		log.Fatal("NOX_KEY_HEX and NOX_SERVER required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Fatalf("invalid NOX_KEY_HEX")
	}
	var sessionID [8]byte
	if sid := os.Getenv("NOX_SESSION_ID"); sid != "" {
		b, err := hex.DecodeString(sid)
		if err == nil && len(b) == 8 {
			copy(sessionID[:], b)
		}
	} else {
		rand.Read(sessionID[:])
	}
	opts := client.Options{Key: key, Session: sessionID, Server: serverAddr, MTU: 1400, TunName: envOr("NOX_TUN", "nox1")}
	c, err := client.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connecting to %s with session %x", serverAddr, sessionID)
	if err := c.Run(transport.TCPDialer{}); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
