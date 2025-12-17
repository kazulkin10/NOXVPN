package ipam

import (
	"errors"
	"net"
	"sync"
	"time"
)

type Lease struct {
	IP       net.IP
	Session  [8]byte
	Acquired time.Time
	Expires  time.Time
}

type Manager struct {
	mu     sync.Mutex
	subnet *net.IPNet
	nextIP net.IP
	ttl    time.Duration
	leases map[string]Lease
}

func New(subnet *net.IPNet, ttl time.Duration) (*Manager, error) {
	if subnet == nil || subnet.IP.To4() == nil {
		return nil, errors.New("ipv4 subnet required")
	}
	first := firstHost(subnet)
	return &Manager{subnet: subnet, nextIP: first, ttl: ttl, leases: make(map[string]Lease)}, nil
}

func firstHost(n *net.IPNet) net.IP {
	base := ipToUint32(n.IP)
	return uint32ToIP(base + 1)
}

// Allocate sticky IP for session.
func (m *Manager) Allocate(session [8]byte) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(session[:])
	if l, ok := m.leases[key]; ok {
		l.Expires = time.Now().Add(m.ttl)
		m.leases[key] = l
		return l, nil
	}

	now := time.Now()
	for k, l := range m.leases {
		if l.Expires.Before(now) {
			delete(m.leases, k)
		}
	}

	total := hostCount(m.subnet)
	usable := total - 2
	if usable <= 0 {
		return Lease{}, errors.New("no available addresses")
	}
	base := ipToUint32(m.subnet.IP)
	start := ipToUint32(m.nextIP)
	for i := 0; i < usable; i++ {
		offset := (int(start-base-1) + i) % usable
		cand := uint32ToIP(base + uint32(offset+1))
		if m.isUsable(cand) && !m.inUse(cand) {
			lease := Lease{IP: append(net.IP(nil), cand...), Session: session, Acquired: time.Now(), Expires: time.Now().Add(m.ttl)}
			m.leases[key] = lease
			m.nextIP = uint32ToIP(base + uint32((offset+1)%usable+1))
			return lease, nil
		}
	}
	return Lease{}, errors.New("no available addresses")
}

func (m *Manager) inUse(ip net.IP) bool {
	for _, l := range m.leases {
		if l.IP.Equal(ip) && l.Expires.After(time.Now()) {
			return true
		}
	}
	return false
}

func next(ip net.IP) net.IP { // kept for compatibility
	return uint32ToIP(ipToUint32(ip) + 1)
}

// Release frees a lease if it belongs to the session.
func (m *Manager) Release(session [8]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.leases[string(session[:])]; ok {
		l.Expires = time.Now().Add(-time.Second)
		m.leases[string(session[:])] = l
	}
}

// Sweep removes expired leases.
func (m *Manager) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, l := range m.leases {
		if l.Expires.Before(now) {
			delete(m.leases, k)
		}
	}
}

func (m *Manager) Stats() (active int, free int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active = len(m.leases)
	total := hostCount(m.subnet) - 2
	if total < 0 {
		total = 0
	}
	free = total - active
	if free < 0 {
		free = 0
	}
	return
}

func hostCount(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	return 1 << (bits - ones)
}

func (m *Manager) isUsable(ip net.IP) bool {
	if ip.Equal(m.subnet.IP) {
		return false
	}
	last := lastAddr(m.subnet)
	if ip.Equal(last) {
		return false
	}
	return m.subnet.Contains(ip)
}

func lastAddr(n *net.IPNet) net.IP {
	base := ipToUint32(n.IP)
	size := uint32(hostCount(n))
	return uint32ToIP(base + size - 1)
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
