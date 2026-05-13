package server

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
)

type Server struct {
	UDP     *transport.UDPTransport
	TUN     *tun.Device
	Table   *peer.PeerTable
	Manager *peer.Manager
}

func (s *Server) Run(ctx context.Context) error {
	go s.Manager.Run(ctx)

	for {
		pkt, addr, err := s.UDP.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("udp read error: %v", err)
			continue
		}

		switch pkt.Type {
		case proto.TypeHandshakeInit:
			s.handleHandshakeInit(ctx, pkt, addr)
		case proto.TypeData:
			s.handleData(pkt, addr)
		case proto.TypeKeepAlive:
			s.handleKeepalive(addr)
		case proto.TypeClose:
			s.handleClose(addr)
		default:
			log.Printf("unknown packet type 0x%02x from %s, dropping", pkt.Type, addr)
		}
	}
}

func (s *Server) handleHandshakeInit(ctx context.Context, pkt proto.Packet, addr net.Addr) {
	// One peer per address. If one already exists, evict it first
	if existing, ok := s.Table.LookupAddr(addr); ok {
		log.Printf("re-handshake from %s, evicting existing peer", addr)
		s.Table.Evict(existing)
	}

	peerCtx, cancel := context.WithCancel(ctx)
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
		log.Printf("handshake init failed from %s: %v", addr, err)
		s.Table.Evict(p)
		return
	}

	// Derive session and register peer by ID
	keys := hs.SessionKeys
	sess, err := session.NewSession(keys)
	if err != nil {
		s.Table.Evict(p)
		return
	}

	id := peer.PeerID(pkt.Payload)
	p.SetSession(sess, id)
	s.Table.RegisterID(id, p)

	// Send response
	if err := s.UDP.WritePacket(respPkt, addr); err != nil {
		log.Printf("handshake resp failed to %s: %v", addr, err)
		s.Table.Evict(p)
		return
	}

	go s.runPeerForwarder(peerCtx, p)
}

func (s *Server) handleData(pkt proto.Packet, addr net.Addr) {
	p, ok := s.Table.LookupAddr(addr)
	if !ok {
		log.Printf("data from unknown peer %s, dropping", addr)
		return
	}
	p.Touch()

	sess, ok := p.Session()
	if !ok {
		log.Printf("data from peer %s with no session, dropping", addr)
		return
	}

	plaintextLen := len(pkt.Payload) - constant.NonceSize - constant.TagSize

	aad := crypto.BuildAAD(proto.TypeData, uint16(plaintextLen))
	plaintext, err := sess.Decrypt(pkt, aad)
	if err != nil {
		log.Printf("decrypt failed from %s: %v", addr, err)
		return
	}

	if _, err := s.TUN.Write(plaintext); err != nil {
		log.Printf("tun write failed: %v", err)
	}
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

func (s *Server) runPeerForwarder(ctx context.Context, p *peer.Peer) {
	defer close(p.Done)

	buf := make([]byte, s.TUN.MTU()+4)
	for {
		s.TUN.FD.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := s.TUN.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			log.Printf("tun read error in peer forwarder: %v", err)
			return
		}

		sess, ok := p.Session()
		if !ok {
			return
		}

		aad := crypto.BuildAAD(proto.TypeData, uint16(n))
		encPkt, err := sess.Encrypt(buf[:n], aad)
		if err != nil {
			log.Printf("encrypt failed for peer %s: %v", p.Addr, err)
			continue
		}

		if err := s.UDP.WritePacket(encPkt, p.Addr); err != nil {
			log.Printf("udp write failed to %s: %v", p.Addr, err)
		}
	}
}
