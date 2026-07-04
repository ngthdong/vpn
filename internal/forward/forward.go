package forward

import (
	"context"
	"log"
	"net"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/event"
	"github.com/ngthdong/vpn/internal/nat"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/router"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
	"golang.org/x/sync/errgroup"
)

type IncomingPacket struct {
	Packet proto.Packet
	Addr net.Addr
}

type Forwarder struct {
	tun   *tun.Device
	udp   *transport.UDPTransport
	table *peer.PeerTable
	router *router.Router
	nat    *nat.Table
	bus    *event.Bus
	tunnelAddr net.IP
	mtu        int
	incoming chan IncomingPacket
}

// New creates a new Forwarder that bridges TUN device and UDP transport with encryption.
func NewForwarder(
	tunDevice *tun.Device,
	udp *transport.UDPTransport,
	table *peer.PeerTable,
	router *router.Router,
	natTable *nat.Table,
	bus *event.Bus,
	tunnelAddr net.IP,
) *Forwarder {
	return &Forwarder{
		tun:        tunDevice,
		udp:        udp,
		table:      table,
		router:     router,
		nat:        natTable,
		bus:        bus,
		tunnelAddr: tunnelAddr,
		mtu:        tunDevice.MTU(),
		incoming: make(chan IncomingPacket, 4096),
	}
}

func (f *Forwarder) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { return f.tunToTunnel(ctx) })
	eg.Go(func() error { return f.tunnelToTUN(ctx) })

	return eg.Wait()
}

func (f *Forwarder) tunToTunnel(ctx context.Context) error {
	bufCh := make(chan []byte)
	errCh := make(chan error, 1)

	// Dedicated blocking TUN reader goroutine
	go func() {
		buf := make([]byte, f.mtu+4)

		for {
			n, err := f.tun.Read(buf)
			log.Printf("TUN read: %d bytes", n) 
			if err != nil {
				errCh <- err
				return
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			bufCh <- pkt
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errCh:
			return err

		case pkt := <-bufCh:
			hdr, err := tun.ParseIPHeader(pkt)
			log.Printf("TUN read: %d bytes", hdr) 
			if err != nil {
				log.Printf("bad IP header, dropping: %v", err)
				continue
			}

			// Route lookup
			p, ok := f.router.Lookup(hdr.DstIP)
			if !ok {
				if hdr.DstIP.IsMulticast() || hdr.DstIP.IsLinkLocalMulticast() {
					continue
				}
			}

			// Optional SNAT
			if f.nat != nil {
				pkt, err = f.nat.SNAT(pkt, f.tunnelAddr)
				if err != nil {
					log.Printf("SNAT failed: %v", err)
					continue
				}
			}

			sess, ok := p.Session()
			if !ok {
				log.Printf("peer has no session, dropping")
				continue
			}

			aad := crypto.BuildAAD(
				proto.TypeData,
				uint16(len(pkt)),
			)

			encPkt, err := sess.Encrypt(pkt, aad)
			if err != nil {
				log.Printf("encrypt failed: %v", err)
				continue
			}

			if err := f.udp.WritePacket(encPkt, p.Addr); err != nil {
				log.Printf("udp write failed: %v", err)
				continue
			}

			if f.bus != nil {
				f.bus.Publish(event.Event{
					Type:   event.EventPacketForwarded,
					PeerID: p.ID.String(),
					Bytes:  len(pkt),
				})
			}
		}
	}
}

func (f *Forwarder) tunnelToTUN(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case incoming := <-f.incoming:
			encPkt := incoming.Packet
			addr := incoming.Addr

			p, ok := f.table.LookupAddr(addr)
			if !ok {
				log.Printf("packet from unknown peer %s, dropping", addr)
				continue
			}

			p.Touch()

			sess, ok := p.Session()
			if !ok {
				log.Printf("peer %s has no active session", addr)
				continue
			}

			plaintextLen := len(encPkt.Payload) -
				constant.NonceSize -
				constant.TagSize

			aad := crypto.BuildAAD(
				encPkt.Type,
				uint16(plaintextLen),
			)

			plaintext, err := sess.Decrypt(encPkt, aad)
			if err != nil {
				if f.bus != nil {
					f.bus.Publish(event.Event{
						Type:   event.EventDecryptFailure,
						PeerID: p.ID.String(),
					})
				}

				log.Printf("decrypt failed from %s: %v", addr, err)
				continue
			}

			if f.nat != nil {
				plaintext, err = f.nat.DNAT(plaintext)
				if err != nil {
					log.Printf("DNAT failed: %v", err)
					continue
				}
			}
			
			if _, err := f.tun.Write(plaintext); err != nil {
				log.Printf("tun write failed: %v", err)
				continue
			}

			if f.bus != nil {
				f.bus.Publish(event.Event{
					Type:   event.EventPacketForwarded,
					PeerID: p.ID.String(),
					Bytes:  len(plaintext),
				})
			}
		}
	}
}

func (f *Forwarder) HandlePacket(
	pkt proto.Packet,
	addr net.Addr,
) {
	select {
	case f.incoming <- IncomingPacket{
		Packet: pkt,
		Addr: addr,
	}:
	default:
		log.Printf("forwarder queue full, dropping packet")
	}
}	