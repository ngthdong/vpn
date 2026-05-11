package tun

import (
	"errors"
	"fmt"
	"net"

	"github.com/ngthdong/vpn/internal/constant"
)

type IPVersion uint8

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

type IPHeader struct {
	Version IPVersion
	SrcIP   net.IP
	DstIP   net.IP
	Proto   uint8 // TCP=6, UDP=17, ICMP=1
}

// String returns a representation of the IP header for debugging.
func (h IPHeader) String() string {
	return fmt.Sprintf("IPHeader{v%d %s -> %s proto=%d}", h.Version, h.SrcIP, h.DstIP, h.Proto)
}

func ParseIPHeader(pkt []byte) (IPHeader, error) {
	if len(pkt) < constant.IP4HeaderSize {
		return IPHeader{}, errors.New("packet too short for IP header")
	}

	version := IPVersion(pkt[0] >> 4)
	switch version {
	case 4:
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl {
			return IPHeader{}, errors.New("packet shorter than IHL")
		}
		return IPHeader{
			Version: IPv4,
			Proto:   pkt[9],
			SrcIP:   net.IP(append([]byte{}, pkt[12:16]...)),
			DstIP:   net.IP(append([]byte{}, pkt[16:20]...)),
		}, nil
	case 6:
		if len(pkt) < constant.IP6HeaderSize {
			return IPHeader{}, errors.New("packet too short for IPv6 header")
		}
		return IPHeader{
			Version: IPv6,
			Proto:   pkt[6],
			SrcIP:   net.IP(append([]byte{}, pkt[8:24]...)),
			DstIP:   net.IP(append([]byte{}, pkt[24:40]...)),
		}, nil
	default:
		return IPHeader{}, fmt.Errorf("unknown IP version: %d", version)
	}
}
