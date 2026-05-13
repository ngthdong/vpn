package peer

import (
	"context"
	"log"
	"time"

	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
)

const (
	keepaliveInterval = 5 * time.Second
	idleTimeout       = 30 * time.Second
)

type Manager struct {
	table *PeerTable
	udp   *transport.UDPTransport
}

func NewManager(table *PeerTable, udp *transport.UDPTransport) *Manager {
	return &Manager{
		table: table,
		udp:   udp,
	}
}

func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.shutdownAll()
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *Manager) tick() {
	now := time.Now()
	for _, p := range m.table.All() {
		if now.Sub(p.LastSeen()) > idleTimeout {
			log.Printf("peer %s idle for %v, evicting", p.Addr, now.Sub(p.LastSeen()))
			m.table.Evict(p)
			continue
		}

		if sess, ok := p.Session(); ok {
			m.sendKeepalive(p, sess)
		}
	}
}

func (m *Manager) sendKeepalive(p *Peer, sess *session.Session) {
	aad := crypto.BuildAAD(proto.TypeKeepAlive, 0)
	pkt, err := sess.Encrypt(nil, aad)
	if err != nil {
		log.Printf("keepalive encrypt failed for %s: %v", p.Addr, err)
		return
	}

	pkt.Type = proto.TypeKeepAlive
	if err := m.udp.WritePacket(pkt, p.Addr); err != nil {
		log.Printf("keepalive send failed for %s: %v", p.Addr, err)
	}
}

func (m *Manager) shutdownAll() {
	for _, p := range m.table.All() {
		m.table.Evict(p)
	}
}
