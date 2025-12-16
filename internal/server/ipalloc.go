package server

import (
"errors"
"net"
"sync"
"time"
)

type Lease struct {
IP       net.IP
LastSeen time.Time
}

type IPAlloc struct {
mu        sync.Mutex
base      net.IP
maskBits  int
nextHost  int
maxHost   int
bySession map[[8]byte]Lease
byIP      map[string][8]byte
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

// reserved: .0 network, .1 server, .255 broadcast (roughly), start from .2
return &IPAlloc{
base:      base,
maskBits: ones,
nextHost: 2,
maxHost:  hosts - 2,
bySession: make(map[[8]byte]Lease),
byIP:      make(map[string][8]byte),
}, nil
}

func (a *IPAlloc) ipForHost(h int) net.IP {
ip := make(net.IP, 4)
copy(ip, a.base)
ip[3] = byte(h)
return ip
}

func (a *IPAlloc) Acquire(session [8]byte) (net.IP, int, bool) {
a.mu.Lock()
defer a.mu.Unlock()

if l, ok := a.bySession[session]; ok {
l.LastSeen = time.Now()
a.bySession[session] = l
return l.IP, a.maskBits, false
}

for h := a.nextHost; h <= a.maxHost; h++ {
ip := a.ipForHost(h)
key := ip.String()
if _, used := a.byIP[key]; used {
continue
}
a.bySession[session] = Lease{IP: ip, LastSeen: time.Now()}
a.byIP[key] = session
a.nextHost = h + 1
return ip, a.maskBits, true
}

// simple wrap-around scan
for h := 2; h < a.nextHost; h++ {
ip := a.ipForHost(h)
key := ip.String()
if _, used := a.byIP[key]; used {
continue
}
a.bySession[session] = Lease{IP: ip, LastSeen: time.Now()}
a.byIP[key] = session
return ip, a.maskBits, true
}

return nil, 0, false
}

func (a *IPAlloc) Touch(session [8]byte) {
a.mu.Lock()
defer a.mu.Unlock()
if l, ok := a.bySession[session]; ok {
l.LastSeen = time.Now()
a.bySession[session] = l
}
}

func (a *IPAlloc) Release(session [8]byte) {
a.mu.Lock()
defer a.mu.Unlock()
l, ok := a.bySession[session]
if !ok {
return
}
delete(a.bySession, session)
delete(a.byIP, l.IP.String())
}

func (a *IPAlloc) ReapIdle(ttl time.Duration) (killed int) {
a.mu.Lock()
defer a.mu.Unlock()
now := time.Now()
for sess, l := range a.bySession {
if now.Sub(l.LastSeen) > ttl {
delete(a.bySession, sess)
delete(a.byIP, l.IP.String())
killed++
}
}
return
}
