package transport

import (
	"fmt"
	"net"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/proto"
)

type UDPTransport struct {
	conn   net.PacketConn
	buffer [constant.MTU]byte // MTU-sized buffer
}

func NewUDPTransport(conn net.PacketConn) *UDPTransport {
	return &UDPTransport{
		conn: conn,
	}
}

// ReadPacket reads and decodes a proto.Packet from the UDP connection
func (t *UDPTransport) ReadPacket() (proto.Packet, net.Addr, error) {
	n, addr, err := t.conn.ReadFrom(t.buffer[:])
	if err != nil {
		return proto.Packet{}, nil, err
	}

	pkt, err := proto.Decode(t.buffer[:n])
	if err != nil {
		return proto.Packet{}, addr, fmt.Errorf("decode failed: %w", err)
	}

	return pkt, addr, nil
}

// WritePacket encodes and writes a proto.Packet to the UDP connection
func (t *UDPTransport) WritePacket(pkt proto.Packet, addr net.Addr) error {
	encoded, err := proto.Encode(pkt)
	if err != nil {
		return fmt.Errorf("encode failed: %w", err)
	}

	_, err = t.conn.WriteTo(encoded, addr)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	return nil
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

func (t *UDPTransport) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}
