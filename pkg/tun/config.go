package tun

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

const (
	// DefaultMTU is the MTU applied to NOX TUN devices when not otherwise specified.
	DefaultMTU = 1420
)

// Config describes how to configure a TUN device via netlink.
// Address is required; Route defaults to Address if omitted.
type Config struct {
	Name    string
	Address *net.IPNet
	Route   *net.IPNet
	MTU     int
}

// netlinkAPI allows configuring links; extracted for tests.
type netlinkAPI interface {
	LinkByName(string) (netlink.Link, error)
	LinkSetMTU(netlink.Link, int) error
	AddrReplace(netlink.Link, *netlink.Addr) error
	RouteReplace(*netlink.Route) error
	LinkSetUp(netlink.Link) error
}

type defaultNetlink struct{}

func (defaultNetlink) LinkByName(name string) (netlink.Link, error) { return netlink.LinkByName(name) }
func (defaultNetlink) LinkSetMTU(l netlink.Link, mtu int) error     { return netlink.LinkSetMTU(l, mtu) }
func (defaultNetlink) AddrReplace(l netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrReplace(l, addr)
}
func (defaultNetlink) RouteReplace(r *netlink.Route) error { return netlink.RouteReplace(r) }
func (defaultNetlink) LinkSetUp(l netlink.Link) error      { return netlink.LinkSetUp(l) }

// Configure applies the provided TUN configuration using netlink.
// It validates the inputs and configures MTU, address, route and link state.
func Configure(cfg Config) error {
	return configure(defaultNetlink{}, cfg)
}

func configure(nl netlinkAPI, cfg Config) error {
	if cfg.Name == "" {
		return fmt.Errorf("tun name is required")
	}
	if cfg.Address == nil {
		return fmt.Errorf("address is required")
	}
	addrIP := cfg.Address.IP.To4()
	if addrIP == nil {
		return fmt.Errorf("address must be IPv4")
	}
	mask := cfg.Address.Mask
	if mask == nil {
		return fmt.Errorf("address mask is required")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}

	link, err := nl.LinkByName(cfg.Name)
	if err != nil {
		return fmt.Errorf("lookup link %s: %w", cfg.Name, err)
	}

	if cfg.MTU > 0 {
		if err := nl.LinkSetMTU(link, cfg.MTU); err != nil {
			return fmt.Errorf("set mtu %d: %w", cfg.MTU, err)
		}
	}

	ipnet := &net.IPNet{IP: addrIP, Mask: mask}
	if err := nl.AddrReplace(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		return fmt.Errorf("addr replace %s: %w", ipnet.String(), err)
	}

	routeNet := cfg.Route
	if routeNet == nil {
		routeNet = ipnet
	}
	if err := nl.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: routeNet}); err != nil {
		return fmt.Errorf("route replace %s: %w", routeNet.String(), err)
	}

	if err := nl.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up: %w", err)
	}
	return nil
}

// MustParseCIDR parses a CIDR string and panics if it is invalid.
// It is intended for initialization helpers where invalid input is a programming error.
func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipnet
}
