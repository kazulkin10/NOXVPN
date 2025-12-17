package server

import (
	"testing"
	"time"
)

func TestTokenBucketAllowAndRefill(t *testing.T) {
	tb := NewTokenBucket(5, 2) // 5/sec, burst=2

	if !tb.Allow() || !tb.Allow() {
		t.Fatalf("expected burst tokens available")
	}
	if tb.Allow() { // burst exhausted
		t.Fatalf("expected limiter to block")
	}

	time.Sleep(300 * time.Millisecond) // ~1.5 tokens at 5/sec
	if !tb.Allow() {
		t.Fatalf("expected token after refill")
	}
}
