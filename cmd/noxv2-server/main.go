package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"

	"nox-core/v2/server"
	"nox-core/v2/transport"
)

func main() {
	listen := envOr("NOX_LISTEN", ":9000")
	subnetStr := envOr("NOX_SUBNET", "10.8.0.0/24")
	keyHex := os.Getenv("NOX_KEY_HEX")
	if keyHex == "" {
		log.Fatal("NOX_KEY_HEX required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Fatalf("invalid NOX_KEY_HEX")
	}
	oneshotMTU := flag.Int("mtu", 1400, "server MTU")
	flag.Parse()

	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		log.Fatalf("parse subnet: %v", err)
	}

	srv, err := server.New(server.Options{Key: key, Subnet: subnet, MTU: *oneshotMTU})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := transport.ListenTCP(listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("NOX v2 server listening on %s", listen)
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
