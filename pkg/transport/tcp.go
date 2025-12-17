package transport

import "net"

// Dial wraps net.Dial to keep a dedicated transport entrypoint.
// This placeholder exists to keep the package usable without pulling in
// additional dependencies.
func Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}
