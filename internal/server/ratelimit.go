package server

import "time"

// TokenBucket is a simple token bucket limiter (non-thread-safe: use per accept goroutine).
// It is intentionally small to avoid extra deps.
type TokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func NewTokenBucket(ratePerSec, burst int) *TokenBucket {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	if burst <= 0 {
		burst = ratePerSec
	}
	now := time.Now()
	return &TokenBucket{
		rate:   float64(ratePerSec),
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now,
	}
}

// Allow reports whether a token is available. It also refills tokens over time.
func (t *TokenBucket) Allow() bool {
	now := time.Now()
	dt := now.Sub(t.last).Seconds()
	t.last = now
	t.tokens += dt * t.rate
	if t.tokens > t.burst {
		t.tokens = t.burst
	}
	if t.tokens < 1 {
		return false
	}
	t.tokens -= 1
	return true
}
