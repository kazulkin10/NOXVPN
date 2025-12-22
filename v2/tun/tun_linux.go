//go:build linux

package tun

import (
	"fmt"
	"net"

	coretun "nox-core/pkg/tun"

	"github.com/vishvananda/netlink"
)

// Config is a TUN configuration.
type Config struct {
	Name string
	CIDR *net.IPNet
	MTU  int
}

// Device wraps the opened TUN and netlink link.
type Device struct {
	Tun  *coretun.Tun
	Link netlink.Link
}

// Manager configures TUN interfaces via netlink.
type Manager struct{}

func NewManager() *Manager { return &Manager{} }

// Ensure recreates the TUN interface, assigns address/route, and returns an opened device.
func (m *Manager) Ensure(cfg Config) (*Device, error) {
	if cfg.CIDR == nil || cfg.CIDR.IP.To4() == nil {
		return nil, fmt.Errorf("cidr required")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}

	if existing, err := netlink.LinkByName(cfg.Name); err == nil {
		_ = netlink.LinkDel(existing)
	}

	tunDev, err := coretun.Create(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("link by name: %w", err)
	}

	if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("set mtu: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("link up: %w", err)
	}
	addr := &netlink.Addr{IPNet: cfg.CIDR}
	if err := netlink.AddrReplace(link, addr); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("addr add: %w", err)
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK, Dst: cfg.CIDR}
	if err := netlink.RouteReplace(route); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("route add: %w", err)
	}

	return &Device{Tun: tunDev, Link: link}, nil
}
