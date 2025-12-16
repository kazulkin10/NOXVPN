package main

import (
"errors"
"io"
"log"
"net"
"sync"
"time"

"nox-core/internal/server"
"nox-core/pkg/control"
"nox-core/pkg/crypto"
"nox-core/pkg/frame"
"nox-core/pkg/tun"
)

type TokenBucket struct {
rateBytesPerSec float64
burstBytes      float64
mu              sync.Mutex
tokens          float64
last            time.Time
}

func NewTokenBucket(rateBytesPerSec, burstBytes int64) *TokenBucket {
now := time.Now()
return &TokenBucket{
rateBytesPerSec: float64(rateBytesPerSec),
burstBytes:      float64(burstBytes),
tokens:          float64(burstBytes),
last:            now,
}
}

func (t *TokenBucket) addTokens() {
now := time.Now()
dt := now.Sub(t.last).Seconds()
t.last = now
t.tokens += dt * t.rateBytesPerSec
if t.tokens > t.burstBytes {
t.tokens = t.burstBytes
}
}

func (t *TokenBucket) Wait(n int) {
need := float64(n)
for {
t.mu.Lock()
t.addTokens()
if t.tokens >= need {
t.tokens -= need
t.mu.Unlock()
return
}
deficit := need - t.tokens
rate := t.rateBytesPerSec
t.mu.Unlock()

if rate <= 0 {
time.Sleep(50 * time.Millisecond)
continue
}
sleepSec := deficit / rate
if sleepSec < 0.01 {
sleepSec = 0.01
}
time.Sleep(time.Duration(sleepSec * float64(time.Second)))
}
}

func main() {
t, err := tun.Create("nox0")
if err != nil {
log.Fatal("tun create:", err)
}
log.Println("TUN nox0 created")

alloc, err := server.NewIPAlloc("10.8.0.0/24")
if err != nil {
log.Fatal("ipalloc:", err)
}

// reap idle leases (safety net)
go func() {
for {
time.Sleep(30 * time.Second)
alloc.ReapIdle(90 * time.Second)
}
}()

ln, err := net.Listen("tcp", ":9000")
if err != nil {
log.Fatal(err)
}
log.Println("NOX server listening on :9000")

for {
conn, err := ln.Accept()
if err != nil {
log.Println("accept:", err)
continue
}
log.Println("client connected from", conn.RemoteAddr())
go handleConn(conn, t, alloc)
}
}

func handleConn(conn net.Conn, t *tun.Tun, alloc *server.IPAlloc) {
defer conn.Close()

ciph, err := crypto.NewCipher()
if err != nil {
log.Println("cipher init:", err)
return
}

limiter := NewTokenBucket(10*1024*1024/8, 20*1024*1024/8)

// session state
var (
sess       [8]byte
sessOK     bool
lastBeat   = time.Now()
beatMu     sync.Mutex
closeOnce  sync.Once
closeCh    = make(chan struct{})
)

// killer for hung clients (no heartbeat)
go func() {
tick := time.NewTicker(10 * time.Second)
defer tick.Stop()
for {
select {
case <-tick.C:
beatMu.Lock()
idle := time.Since(lastBeat)
beatMu.Unlock()
if idle > 45*time.Second {
closeOnce.Do(func() { close(closeCh) })
_ = conn.Close()
return
}
case <-closeCh:
return
}
}
}()

// TUN -> client (stream 100)
go func() {
pktBuf := make([]byte, 65535)
for {
select {
case <-closeCh:
return
default:
}
n, err := t.ReadPacket(pktBuf)
if err != nil {
log.Println("tun read:", err)
closeOnce.Do(func() { close(closeCh) })
_ = conn.Close()
return
}

enc, err := ciph.EncryptFrame(pktBuf[:n])
if err != nil {
log.Println("enc tun:", err)
closeOnce.Do(func() { close(closeCh) })
_ = conn.Close()
return
}

fr := frame.NewEncryptedFrame(frame.FrameData, 100, enc)
data, _ := frame.EncodeFrame(fr)

limiter.Wait(len(data))
if _, err := conn.Write(data); err != nil {
log.Println("write tun frame:", err)
closeOnce.Do(func() { close(closeCh) })
return
}
}
}()

defer func() {
if sessOK {
alloc.Release(sess)
}
closeOnce.Do(func() { close(closeCh) })
}()

for {
fr, err := frame.ReadFrame(conn)
if err != nil {
if errors.Is(err, io.EOF) {
log.Println("client closed")
return
}
log.Println("read frame:", err)
return
}

// ping/pong at frame layer (optional)
if fr.Type == frame.FramePing {
pong := &frame.Frame{Type: frame.FramePong, Flags: 0, StreamID: fr.StreamID, Payload: nil}
raw, _ := frame.EncodeFrame(pong)
limiter.Wait(len(raw))
_, _ = conn.Write(raw)
continue
}
if fr.Type == frame.FrameClose {
log.Println("got close")
return
}
if fr.Type != frame.FrameData {
continue
}

pt, err := ciph.DecryptFrame(fr.Payload)
if err != nil {
log.Println("decrypt:", err)
return
}

// control channel = stream 0
if fr.StreamID == 0 {
op, rest, ok := control.Decode(pt)
if !ok {
continue
}

switch op {
case control.OpHello:
s, ok := control.DecodeSession(rest)
if !ok {
continue
}
sess = s
sessOK = true
alloc.Touch(sess)

ip, mask, _ := alloc.Acquire(sess)
msg, _ := control.EncodeAssignIP(ip, mask)
enc, _ := ciph.EncryptFrame(msg)

resp := frame.NewEncryptedFrame(frame.FrameData, 0, enc)
raw, _ := frame.EncodeFrame(resp)
limiter.Wait(len(raw))
_, _ = conn.Write(raw)

beatMu.Lock()
lastBeat = time.Now()
beatMu.Unlock()

case control.OpBeat:
if sessOK {
alloc.Touch(sess)
}
beatMu.Lock()
lastBeat = time.Now()
beatMu.Unlock()
}
continue
}

// stream 100 = IP packets to server TUN
if fr.StreamID == 100 {
if _, err := t.WritePacket(pt); err != nil {
log.Println("tun write:", err)
}
continue
}
}
}
