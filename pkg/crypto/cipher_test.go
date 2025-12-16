package crypto

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewCipherFromKeyLength(t *testing.T) {
	if _, err := NewCipherFromKey(make([]byte, chacha20poly1305.KeySize-1)); err == nil {
		t.Fatal("expected error for short key")
	}

	key := make([]byte, chacha20poly1305.KeySize)
	c, err := NewCipherFromKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := []byte("hello")
	sealed := c.Seal(msg)
	opened, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(opened) != string(msg) {
		t.Fatalf("round trip mismatch: %q vs %q", opened, msg)
	}
}
