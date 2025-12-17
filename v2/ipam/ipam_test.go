package ipam

import (
	"net"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return n
}

func TestAllocateReleaseReuse(t *testing.T) {
	m, err := New(mustCIDR(t, "10.8.0.0/30"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var sid [8]byte
	sid[0] = 1
	l1, err := m.Allocate(sid)
	if err != nil {
		t.Fatal(err)
	}
	m.Release(sid)
	l2, err := m.Allocate(sid)
	if err != nil {
		t.Fatal(err)
	}
	if !l1.IP.Equal(l2.IP) {
		t.Fatalf("expected sticky IP reuse, got %v vs %v", l1.IP, l2.IP)
	}
}

func TestExhaustionAndSweep(t *testing.T) {
	m, err := New(mustCIDR(t, "10.8.0.0/30"), time.Millisecond*10)
	if err != nil {
		t.Fatal(err)
	}
	var s1, s2 [8]byte
	s1[0] = 1
	s2[0] = 2
	if _, err := m.Allocate(s1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Allocate(s2); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Allocate([8]byte{3}); err == nil {
		t.Fatalf("expected exhaustion")
	}
	time.Sleep(time.Millisecond * 15)
	m.Sweep()
	if _, err := m.Allocate([8]byte{3}); err != nil {
		t.Fatalf("expected reuse after sweep: %v", err)
	}
}
