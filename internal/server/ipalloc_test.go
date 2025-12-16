package server

import (
	"testing"
	"time"
)

func TestIPAllocAcquireReuseAndRelease(t *testing.T) {
	alloc, err := NewIPAlloc("10.8.0.0/29") // 6 usable hosts (2..5)
	if err != nil {
		t.Fatalf("new ipalloc: %v", err)
	}

	lease1, fresh, err := alloc.Acquire("sess-a")
	if err != nil || !fresh {
		t.Fatalf("first acquire failed: fresh=%v err=%v", fresh, err)
	}

	// Reuse should return same IP and not count as fresh
	lease2, fresh, err := alloc.Acquire("sess-a")
	if err != nil || fresh {
		t.Fatalf("reuse acquire failed: fresh=%v err=%v", fresh, err)
	}
	if lease1.IP.String() != lease2.IP.String() {
		t.Fatalf("expected same IP on reuse: %s vs %s", lease1.IP, lease2.IP)
	}

	// A different session should get another IP
	lease3, fresh, err := alloc.Acquire("sess-b")
	if err != nil || !fresh {
		t.Fatalf("second session acquire failed: fresh=%v err=%v", fresh, err)
	}
	if lease3.IP.Equal(lease1.IP) {
		t.Fatalf("expected different IP for different session")
	}

	// Release frees the IP for reuse
	alloc.Release("sess-a")
	lease4, fresh, err := alloc.Acquire("sess-c")
	if err != nil || !fresh {
		t.Fatalf("acquire after release failed: fresh=%v err=%v", fresh, err)
	}
	if lease4.IP.String() != lease1.IP.String() {
		t.Fatalf("expected reused freed IP %s, got %s", lease1.IP, lease4.IP)
	}
}

func TestIPAllocReapIdle(t *testing.T) {
	alloc, err := NewIPAlloc("10.8.0.0/29")
	if err != nil {
		t.Fatalf("new ipalloc: %v", err)
	}

	if _, _, err := alloc.Acquire("sess-idle"); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// make it old
	alloc.mu.Lock()
	if l, ok := alloc.bySession["sess-idle"]; ok {
		l.LastSeen = time.Now().Add(-15 * time.Minute)
	}
	alloc.mu.Unlock()

	killed := alloc.ReapIdle(10 * time.Minute)
	if killed != 1 {
		t.Fatalf("expected 1 reap, got %d", killed)
	}
}

func TestIPAllocExhaustion(t *testing.T) {
	alloc, err := NewIPAlloc("10.8.0.0/30") // usable .2 only (one host)
	if err != nil {
		t.Fatalf("new ipalloc: %v", err)
	}

	if _, _, err := alloc.Acquire("sess-a"); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, _, err := alloc.Acquire("sess-b"); err == nil {
		t.Fatalf("expected exhaustion error")
	}
}
