package router

import (
	"net"
	"sort"
	"sync"

	"github.com/ngthdong/vpn/internal/peer"
)

type Route struct {
	Network *net.IPNet // e.g. 10.0.0.0/24
	Peer    *peer.Peer // nil = local delivery
	Metric  int        // lower = preferred
}

type Router struct {
	mu     sync.RWMutex
	routes []Route // sorted by prefix length, descending (longest match first)
}

func (r *Router) Add(network *net.IPNet, p *peer.Peer, metric int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = append(r.routes, Route{Network: network, Peer: p, Metric: metric})
	sort.Slice(r.routes, func(i, j int) bool {
		// Longest prefix first; tie-break by metric
		li, _ := r.routes[i].Network.Mask.Size()
		lj, _ := r.routes[j].Network.Mask.Size()
		if li != lj {
			return li > lj
		}
		return r.routes[i].Metric < r.routes[j].Metric
	})
}

func (r *Router) Remove(network *net.IPNet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := network.String()
	filtered := r.routes[:0]
	for _, route := range r.routes {
		if route.Network.String() != key {
			filtered = append(filtered, route)
		}
	}
	r.routes = filtered
}

func (r *Router) Lookup(ip net.IP) (*peer.Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, route := range r.routes { 
		if route.Network.Contains(ip) {
			return route.Peer, true
		}
	}
	return nil, false
}

func (r *Router) Routes() []Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot := make([]Route, len(r.routes))
	copy(snapshot, r.routes)
	return snapshot
}
