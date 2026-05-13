package router

import (
	"net"
	"testing"

	"github.com/ngthdong/vpn/internal/peer"
)

func TestLongestPrefixMatch(t *testing.T) {
	r := &Router{}

	_, net1, _ := net.ParseCIDR("10.0.0.0/8")
	_, net2, _ := net.ParseCIDR("10.0.1.0/24")
	_, net3, _ := net.ParseCIDR("0.0.0.0/0") // default route

	peerA := &peer.Peer{}
	peerB := &peer.Peer{}
	peerC := &peer.Peer{}

	r.Add(net1, peerA, 10)
	r.Add(net2, peerB, 10)
	r.Add(net3, peerC, 100) // default route, lowest priority

	cases := []struct {
		ip   string
		want *peer.Peer
	}{
		{"10.0.1.5", peerB},    // matches /24 over /8
		{"10.0.2.5", peerA},    // matches /8, not /24
		{"10.0.1.0", peerB},    // network address, still /24
		{"192.168.1.1", peerC}, // default route
		{"10.0.0.1", peerA},    // /8 match
	}

	for _, tc := range cases {
		got, ok := r.Lookup(net.ParseIP(tc.ip))
		if !ok {
			t.Fatalf("no route for %s", tc.ip)
		}
		if got != tc.want {
			t.Fatalf("ip %s: got wrong peer", tc.ip)
		}
	}
}

func TestMetricTieBreak(t *testing.T) {
	r := &Router{}
	_, network, _ := net.ParseCIDR("10.0.0.0/24")
	peerLow := &peer.Peer{}
	peerHigh := &peer.Peer{}

	r.Add(network, peerHigh, 100)
	r.Add(network, peerLow, 10) // lower metric = preferred

	got, _ := r.Lookup(net.ParseIP("10.0.0.5"))
	if got != peerLow {
		t.Fatal("metric tie-break failed")
	}
}

func TestNoRoute(t *testing.T) {
	r := &Router{}
	_, ok := r.Lookup(net.ParseIP("192.168.1.1"))
	if ok {
		t.Fatal("expected no route")
	}
}
