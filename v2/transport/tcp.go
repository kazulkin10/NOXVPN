package transport

import (
	"net"
	"time"
)

// TCPDialer dials TCP endpoints with timeouts.
type TCPDialer struct {
	Timeout time.Duration
}

func (d TCPDialer) Dial(addr string) (net.Conn, error) {
	if d.Timeout == 0 {
		d.Timeout = 10 * time.Second
	}
	return net.DialTimeout("tcp", addr, d.Timeout)
}

// TCPListener wraps net.Listener.
type TCPListener struct {
	net.Listener
}

func ListenTCP(addr string) (*TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &TCPListener{Listener: ln}, nil
}
