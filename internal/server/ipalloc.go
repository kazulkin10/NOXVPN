package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Lease describes one client assignment.
type Lease struct {
	IP       net.IP
	MaskBits int
	Session  string
	LastSeen time.Time
}

// IPAlloc manages IP leases with session stickiness and GC.
type IPAlloc struct {
	mu        sync.Mutex
	base      net.IP
	maskBits  int
	firstHost int
	lastHost  int
	nextHost  int
	bySession map[string]*Lease
	byIP      map[string]string
}

func NewIPAlloc(cidr string) (*IPAlloc, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 for now")
	}
	base := ipnet.IP.To4()
	if base == nil {
		return nil, errors.New("bad base ip")
	}

	hosts := 1 << (32 - ones)
	if hosts < 4 {
		return nil, errors.New("subnet too small")
	}

	// reserve .0 (network) и .1 (шлюз); оставляем broadcast нетронутым.
	firstHost := 2
	lastHost := hosts - 2
	if lastHost < firstHost {
		return nil, fmt.Errorf("subnet too small for leases: %d hosts", hosts)
	}

	return &IPAlloc{
		base:      base,
		maskBits:  ones,
		firstHost: firstHost,
		lastHost:  lastHost,
		nextHost:  firstHost,
		bySession: make(map[string]*Lease),
		byIP:      make(map[string]string),
	}, nil
}

func (a *IPAlloc) ipForHost(h int) net.IP {
	ip := make(net.IP, 4)
	copy(ip, a.base)
	ip[3] = byte(h)
	return ip
}

// Acquire returns an IP for the session. If the session already had a lease,
// it is reused. The bool indicates whether the lease is newly issued.
func (a *IPAlloc) Acquire(session string) (Lease, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if l, ok := a.bySession[session]; ok {
		l.LastSeen = time.Now()
		return *l, false, nil
	}

	// try linear scan from nextHost, then wrap around to firstHost
	now := time.Now()
	for pass := 0; pass < 2; pass++ {
		start := a.firstHost
		end := a.lastHost
		if pass == 0 {
			start = a.nextHost
		} else {
			end = a.nextHost - 1
		}
		for h := start; h <= end; h++ {
			ip := a.ipForHost(h)
			key := ip.String()
			if _, used := a.byIP[key]; used {
				continue
			}
			lease := &Lease{IP: ip, MaskBits: a.maskBits, Session: session, LastSeen: now}
			a.bySession[session] = lease
			a.byIP[key] = session
			a.nextHost = h + 1
			if a.nextHost > a.lastHost {
				a.nextHost = a.firstHost
			}
			return *lease, true, nil
		}
	}

	return Lease{}, false, errors.New("no free ip")
}

// Touch marks the session as active; returns false if session not found.
func (a *IPAlloc) Touch(session string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.bySession[session]; ok {
		l.LastSeen = time.Now()
		return true
	}
	return false
}

// Release frees the lease for the session.
func (a *IPAlloc) Release(session string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, ok := a.bySession[session]
	if !ok {
		return
	}
	host := int(l.IP[3])
	delete(a.bySession, session)
	delete(a.byIP, l.IP.String())
	if host >= a.firstHost && host <= a.lastHost && host < a.nextHost {
		a.nextHost = host
	}
}

// ReapIdle releases sessions idle longer than ttl and returns number removed.
func (a *IPAlloc) ReapIdle(ttl time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	killed := 0
	for sess, l := range a.bySession {
		if now.Sub(l.LastSeen) > ttl {
			delete(a.bySession, sess)
			delete(a.byIP, l.IP.String())
			killed++
		}
	}
	return killed
}

// Stats returns counts useful for logging.
func (a *IPAlloc) Stats() (total int, used int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	total = (a.lastHost - a.firstHost) + 1
	used = len(a.bySession)
	return total, used
}
