//go:build !linux

package tun

import (
	"errors"
	"net"
)

type Config struct {
	Name string
	CIDR *net.IPNet
	MTU  int
}

type Device struct{}

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Ensure(cfg Config) (*Device, error) {
	return nil, errors.New("tun only supported on linux")
}
