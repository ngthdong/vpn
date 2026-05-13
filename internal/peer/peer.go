package peer

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/session"
)

type State int

const (
	StateHandshaking State = iota
	StateEstablished
	StateClosed
)

type Peer struct {
	mu        sync.RWMutex
	ID        PeerID   // derived from remote public key
	Addr      net.Addr // remote UDP address
	state     State
	session   *session.Session
	Handshake *handshake.Handshake
	lastSeen  time.Time
	cancel    context.CancelFunc
	Done      chan struct{} // closed when peer goroutine exits
}

type PeerID [constant.KeySize]byte

func NewPeer(addr net.Addr, cancel context.CancelFunc) *Peer {
	return &Peer{
		Addr:     addr,
		state:    StateHandshaking,
		lastSeen: time.Now(),
		cancel:   cancel,
		Done:     make(chan struct{}),
	}
}

func (p *Peer) Touch() {
	p.mu.Lock()
	p.lastSeen = time.Now()
	p.mu.Unlock()
}

func (p *Peer) LastSeen() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastSeen
}

func (p *Peer) SetSession(s *session.Session, id PeerID) {
	p.mu.Lock()
	p.session = s
	p.ID = id
	p.state = StateEstablished
	p.mu.Unlock()
}

func (p *Peer) Session() (*session.Session, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.state != StateEstablished {
		return nil, false
	}
	return p.session, true
}

func (p *Peer) Close() {
	p.mu.Lock()
	p.state = StateClosed
	p.mu.Unlock()
	p.cancel()
	<-p.Done
}

func (id PeerID) String() string {
	return hex.EncodeToString(id[:8])
}
