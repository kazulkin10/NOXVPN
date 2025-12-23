package tun

import (
	"testing"
	"time"
)

func TestFakePairRoundTrip(t *testing.T) {
	a, b := NewFakePair()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	if _, err := a.WritePacket(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 8)
	if n, err := b.ReadPacket(buf); err != nil {
		t.Fatalf("read: %v", err)
	} else if n != len(payload) {
		t.Fatalf("len mismatch: %d", n)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestFakeDeadline(t *testing.T) {
	a, _ := NewFakePair()
	defer a.Close()
	if err := a.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := a.ReadPacket(buf); err == nil {
		t.Fatalf("expected timeout")
	}
}
