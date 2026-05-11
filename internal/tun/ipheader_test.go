package tun

import (
	"net"
	"testing"
)

func TestParseIPHeader(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		wantErr bool
		check   func(t *testing.T, h IPHeader)
	}{
		{
			name: "valid IPv4 packet",
			// IPv4 header: version=4, ihl=5, dscp=0, ecn=0, total_length=60, id=1234, flags=0, frag_offset=0
			// ttl=64, protocol=ICMP(1), checksum=0, src=192.0.2.1, dst=192.0.2.2
			packet: []byte{
				0x45, 0x00, 0x00, 0x3c, // version=4, ihl=5, dscp, ecn, total_len=60
				0x04, 0xd2, 0x00, 0x00, // id=1234, flags, frag_offset
				0x40, 0x01, 0x00, 0x00, // ttl=64, protocol=ICMP(1), checksum
				0xc0, 0x00, 0x02, 0x01, // src=192.0.2.1
				0xc0, 0x00, 0x02, 0x02, // dst=192.0.2.2
				// payload (20 bytes of zeros to reach 60 total)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantErr: false,
			check: func(t *testing.T, h IPHeader) {
				if h.Version != IPv4 {
					t.Errorf("expected IPv4, got %d", h.Version)
				}
				if h.Proto != 1 {
					t.Errorf("expected proto=1 (ICMP), got %d", h.Proto)
				}
				expected_src := net.IP{192, 0, 2, 1}
				expected_dst := net.IP{192, 0, 2, 2}
				if !h.SrcIP.Equal(expected_src) {
					t.Errorf("expected src=%s, got %s", expected_src, h.SrcIP)
				}
				if !h.DstIP.Equal(expected_dst) {
					t.Errorf("expected dst=%s, got %s", expected_dst, h.DstIP)
				}
			},
		},
		{
			name:    "packet too short (< 20 bytes)",
			packet:  []byte{0x45, 0x00, 0x00, 0x10},
			wantErr: true,
		},
		{
			name:    "invalid version (7)",
			packet:  append([]byte{0x70}, make([]byte, 19)...),
			wantErr: true,
		},
		{
			name:    "malformed IHL - packet shorter than IHL claims",
			packet:  append([]byte{0x4f}, make([]byte, 19)...),
			wantErr: true,
		},
		{
			name: "valid IPv4 with IHL=6 (24 bytes header)",
			packet: []byte{
				0x46, 0x00, 0x00, 0x40, // version=4, ihl=6, total_len=64
				0x00, 0x00, 0x00, 0x00, // id, flags, frag_offset
				0x40, 0x06, 0x00, 0x00, // ttl=64, protocol=TCP(6), checksum
				0x0a, 0x00, 0x00, 0x01, // src=10.0.0.1
				0x0a, 0x00, 0x00, 0x02, // dst=10.0.0.2
				// extra 4 bytes of header (IHL=6)
				0x00, 0x00, 0x00, 0x00,
				// payload (24 bytes to reach total_len=64)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantErr: false,
			check: func(t *testing.T, h IPHeader) {
				if h.Version != IPv4 {
					t.Errorf("expected IPv4, got %d", h.Version)
				}
				if h.Proto != 6 {
					t.Errorf("expected proto=6 (TCP), got %d", h.Proto)
				}
			},
		},
		{
			name: "valid IPv6 packet",
			packet: append(
				[]byte{
					0x60, 0x00, 0x00, 0x00, // version=6, traffic_class, flow_label
					0x00, 0x14, 0x3a, 0x40, // payload_len=20, next_header=ICMP(58), hop_limit=64
					// src address (16 bytes)
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					// dst address (16 bytes)
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
					// payload (20 bytes)
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
				},
				[]byte{}...,
			),
			wantErr: false,
			check: func(t *testing.T, h IPHeader) {
				if h.Version != IPv6 {
					t.Errorf("expected IPv6, got %d", h.Version)
				}
				if h.Proto != 58 {
					t.Errorf("expected proto=58 (ICMPv6), got %d", h.Proto)
				}
			},
		},
		{
			name:    "IPv6 packet too short",
			packet:  append([]byte{0x60}, make([]byte, 30)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := ParseIPHeader(tt.packet)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, hdr)
			}
		})
	}
}

// TestIPHeaderString verifies the String() method output.
func TestIPHeaderString(t *testing.T) {
	h := IPHeader{
		Version: IPv4,
		SrcIP:   net.IP{192, 168, 1, 1},
		DstIP:   net.IP{192, 168, 1, 2},
		Proto:   6,
	}
	s := h.String()
	if len(s) == 0 {
		t.Errorf("String() returned empty string")
	}
	// Verify expected components are present
	if !contains(s, "v4") && !contains(s, "v6") {
		t.Errorf("String() missing version info: %s", s)
	}
	if !contains(s, "proto") {
		t.Errorf("String() missing protocol info: %s", s)
	}
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
