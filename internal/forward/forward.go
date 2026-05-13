package forward

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
	"golang.org/x/sync/errgroup"
)

type Forwarder struct {
	tun     *tun.Device
	session *session.Session
	udp     *transport.UDPTransport
	peer    net.Addr
	mtu     int
}

// New creates a new Forwarder that bridges TUN device and UDP transport with encryption.
func NewForwarder(
	tunDevice *tun.Device, 
	session *session.Session, 
	udp *transport.UDPTransport, 
	peer net.Addr,
) *Forwarder {
	return &Forwarder{
		tun:     tunDevice,
		session: session,
		udp:     udp,
		peer:    peer,
		mtu:     tunDevice.MTU(),
	}
}

func (f *Forwarder) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { return f.tunToTunnel(ctx) })
	eg.Go(func() error { return f.tunnelToTUN(ctx) })

	return eg.Wait()
}

func (f *Forwarder) tunToTunnel(ctx context.Context) error {
	buf := make([]byte, f.mtu + 4)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		// Set read deadline to allow context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		// TUN reads are blocking, check context frequently enough
		n, err := f.tun.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		pkt := buf[:n]
		hdr, err := tun.ParseIPHeader(pkt)
		if err != nil {
			log.Printf("bad IP header, dropping: %v", err)
			continue
		}
		log.Printf("tun -> tunnel: %s -> %s proto=%d len=%d",
			hdr.SrcIP, hdr.DstIP, hdr.Proto, n)

		// The raw IP packet becomes the plaintext payload
		aad := crypto.BuildAAD(proto.TypeData, uint16(n))
		encrypted, err := f.session.Encrypt(pkt, aad)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		if err := f.udp.WritePacket(encrypted, f.peer); err != nil {
			return fmt.Errorf("udp write: %w", err)
		}
	}
}

func (f *Forwarder) tunnelToTUN(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		encPkt, _, err := f.udp.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("udp read: %w", err)
		}

		// Reconstruct the plaintext length for AAD:
		// Payload = nonce (12 bytes) + ciphertext (which includes 16-byte Poly1305 tag)
		// plaintext_len = payload_len - nonce_size - tag_size
		plaintextLen := len(encPkt.Payload) - constant.NonceSize - constant.TagSize
		aad := crypto.BuildAAD(encPkt.Type, uint16(plaintextLen))

		switch encPkt.Type {
		case proto.TypeKeepAlive: 
			_, err := f.session.Decrypt(encPkt, aad)
			if err != nil {
				log.Printf("keepalive decrypt failed: %v", err)
			}
			continue
		
		case proto.TypeData:
			plaintext, err := f.session.Decrypt(encPkt, aad)
			if err != nil {
				log.Printf("decrypt failed, dropping: %v", err)
				continue
			}

			hdr, err := tun.ParseIPHeader(plaintext)
			if err != nil {
				log.Printf("bad decrypted IP header, dropping: %v", err)
				continue
			}

			log.Printf("tunnel -> tun: %s -> %s proto=%d len=%d",
				hdr.SrcIP, hdr.DstIP, hdr.Proto, len(plaintext))

			if _, err := f.tun.Write(plaintext); err != nil {
				return fmt.Errorf("tun write: %w", err)
			}
		}
	}
}
