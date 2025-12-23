package tun

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "fake" }

type fakeNetlink struct {
	link   *fakeLink
	setMTU int
	addr   *netlink.Addr
	route  *netlink.Route
	up     bool
}

func (f *fakeNetlink) LinkByName(name string) (netlink.Link, error) {
	return f.link, nil
}
func (f *fakeNetlink) LinkSetMTU(l netlink.Link, mtu int) error {
	f.setMTU = mtu
	return nil
}
func (f *fakeNetlink) AddrReplace(l netlink.Link, addr *netlink.Addr) error {
	f.addr = addr
	return nil
}
func (f *fakeNetlink) RouteReplace(r *netlink.Route) error {
	f.route = r
	return nil
}
func (f *fakeNetlink) LinkSetUp(l netlink.Link) error {
	f.up = true
	return nil
}

func TestConfigureUsesDefaultsAndRouteFallback(t *testing.T) {
	ipnet := MustParseCIDR("10.8.0.1/24")
	link := &fakeLink{attrs: netlink.LinkAttrs{Index: 10}}
	nl := &fakeNetlink{link: link}

	if err := configure(nl, Config{Name: "nox0", Address: ipnet}); err != nil {
		t.Fatalf("configure error: %v", err)
	}

	if nl.setMTU != DefaultMTU {
		t.Fatalf("expected default mtu %d, got %d", DefaultMTU, nl.setMTU)
	}
	if nl.addr == nil || nl.addr.IPNet.String() != ipnet.String() {
		t.Fatalf("addr not applied: %+v", nl.addr)
	}
	if nl.route == nil || nl.route.Dst.String() != ipnet.String() {
		t.Fatalf("route fallback mismatch: %+v", nl.route)
	}
	if !nl.up {
		t.Fatalf("link not set up")
	}
}

func TestConfigureAllowsCustomRouteAndMTU(t *testing.T) {
	ipnet := MustParseCIDR("10.8.0.2/24")
	route := MustParseCIDR("10.8.0.0/24")
	link := &fakeLink{attrs: netlink.LinkAttrs{Index: 11}}
	nl := &fakeNetlink{link: link}

	cfg := Config{Name: "nox1", Address: ipnet, Route: route, MTU: 1300}
	if err := configure(nl, cfg); err != nil {
		t.Fatalf("configure error: %v", err)
	}
	if nl.setMTU != 1300 {
		t.Fatalf("custom mtu not applied: %d", nl.setMTU)
	}
	if nl.route == nil || nl.route.Dst.String() != route.String() {
		t.Fatalf("custom route mismatch: %+v", nl.route)
	}
}

func TestConfigureRejectsIPv6(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("2001:db8::1/64")
	err := configure(&fakeNetlink{link: &fakeLink{attrs: netlink.LinkAttrs{Index: 1}}}, Config{Name: "nox", Address: ipnet})
	if err == nil {
		t.Fatalf("expected ipv6 to be rejected")
	}
}
