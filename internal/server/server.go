package server

import (
	"context"
	"log"
	"net"

	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/router"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
)

type PacketHandler interface {
	HandlePacket(proto.Packet, net.Addr)
}

type Server struct {
	UDP       *transport.UDPTransport
	Table     *peer.PeerTable
	Manager   *peer.Manager
	Forwarder PacketHandler
	Router    *router.Router
}

func (s *Server) Run(ctx context.Context) error {
	go s.Manager.Run(ctx)

	for {
		pkt, addr, err := s.UDP.ReadPacket()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}

			log.Printf("udp read failed: %v", err)
			continue
		}

		switch pkt.Type {
		case proto.TypeHandshakeInit:
			s.handleHandshakeInit(ctx, pkt, addr)

		case proto.TypeKeepAlive:
			s.handleKeepalive(addr)

		case proto.TypeClose:
			s.handleClose(addr)

		case proto.TypeData:
			s.Forwarder.HandlePacket(pkt, addr)
		}
	}
}

func (s *Server) handleHandshakeInit(
	ctx context.Context,
	pkt proto.Packet,
	addr net.Addr,
) {
	if existing, ok := s.Table.LookupAddr(addr); ok {
		log.Printf(
			"re-handshake from %s, evicting existing peer",
			addr,
		)
		s.Table.Evict(existing)
	}

	_, cancel := context.WithCancel(ctx)

	p := peer.NewPeer(addr, cancel)
	s.Table.Add(p)

	hs, err := handshake.New()
	if err != nil {
		cancel()
		return
	}

	p.Handshake = hs

	respPkt, err := hs.HandleInit(pkt)
	if err != nil {
		log.Printf(
			"handshake init failed from %s: %v",
			addr,
			err,
		)

		s.Table.Evict(p)
		return
	}

	keys := hs.SessionKeys

	sess, err := session.NewSession(keys)
	if err != nil {
		s.Table.Evict(p)
		return
	}

	var id peer.PeerID
	copy(id[:], pkt.Payload)

	p.SetSession(sess, id)

	s.Table.RegisterID(id, p)

	_, network, err := net.ParseCIDR("10.0.0.2/32")
	if err != nil {
		log.Printf("parse cidr failed: %v", err)
		s.Table.Evict(p)
		return
	}

	s.Router.Add(network, p, 1)

	log.Println("send reply")
	if err := s.UDP.WritePacket(respPkt, addr); err != nil {
		log.Printf(
			"handshake resp failed to %s: %v",
			addr,
			err,
		)

		s.Table.Evict(p)
		return
	}

	log.Printf(
		"session established with peer=%s addr=%s",
		p.ID.String(),
		addr,
	)
}

func (s *Server) handleKeepalive(addr net.Addr) {
	p, ok := s.Table.LookupAddr(addr)
	if !ok {
		log.Printf("keepalive from unknown peer %s, dropping", addr)
		return
	}

	p.Touch()
}

func (s *Server) handleClose(addr net.Addr) {
	p, ok := s.Table.LookupAddr(addr)
	if !ok {
		log.Printf("close from unknown peer %s", addr)
		return
	}

	log.Printf("peer %s disconnected", addr)

	s.Table.Evict(p)
}
