package tun

import (
	"errors"
	"sync"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Fake is an in-memory TUN device pair used for testing packet flow
// without touching real kernel devices.
type Fake struct {
	peer     *Fake
	mu       sync.Mutex
	inbox    chan []byte
	deadline time.Time
	closed   bool
}

// NewFakePair returns two connected Fake devices.
func NewFakePair() (*Fake, *Fake) {
	a := &Fake{inbox: make(chan []byte, 8)}
	b := &Fake{inbox: make(chan []byte, 8)}
	a.peer = b
	b.peer = a
	return a, b
}

func (f *Fake) WritePacket(pkt []byte) (int, error) {
	f.mu.Lock()
	closed := f.closed
	peer := f.peer
	f.mu.Unlock()
	if closed {
		return 0, errors.New("fake tun closed")
	}
	if peer == nil {
		return 0, errors.New("fake tun not paired")
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case peer.inbox <- cp:
		return len(pkt), nil
	default:
		return 0, errors.New("fake tun peer backlog full")
	}
}

func (f *Fake) ReadPacket(buf []byte) (int, error) {
	f.mu.Lock()
	deadline := f.deadline
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, errors.New("fake tun closed")
	}

	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timeout = time.After(time.Until(deadline))
	}

	select {
	case pkt, ok := <-f.inbox:
		if !ok {
			return 0, errors.New("fake tun closed")
		}
		if len(pkt) > len(buf) {
			pkt = pkt[:len(buf)]
		}
		return copy(buf, pkt), nil
	case <-timeout:
		return 0, timeoutError{}
	}
}

func (f *Fake) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	close(f.inbox)
	f.mu.Unlock()
	return nil
}

func (f *Fake) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

var _ interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
	Close() error
	SetReadDeadline(time.Time) error
} = (*Fake)(nil)
