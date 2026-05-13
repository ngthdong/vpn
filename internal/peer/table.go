package peer

import (
	"net"
	"sync"
)

type PeerTable struct {
	mu     sync.RWMutex
	byAddr map[string]*Peer // key: addr.String()
	byID   map[PeerID]*Peer // key: peer public key id
}

func NewPeerTable() *PeerTable {
	return &PeerTable{
		byAddr: make(map[string]*Peer),
		byID:   make(map[PeerID]*Peer),
	}
}

func (t *PeerTable) Add(p *Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byAddr[p.Addr.String()] = p
}

func (t *PeerTable) RegisterID(id PeerID, p *Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byID[id] = p
}

func (t *PeerTable) LookupAddr(addr net.Addr) (*Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.byAddr[addr.String()]
	return p, ok
}

func (t *PeerTable) LookupID(id PeerID) (*Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.byID[id]
	return p, ok
}

func (t *PeerTable) Evict(p *Peer) {
	t.mu.Lock()
	delete(t.byAddr, p.Addr.String())
	delete(t.byID, p.ID)
	t.mu.Unlock()

	p.Close()
}

func (t *PeerTable) All() []*Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	peers := make([]*Peer, 0, len(t.byAddr))
	for _, p := range t.byAddr {
		peers = append(peers, p)
	}
	return peers
}
