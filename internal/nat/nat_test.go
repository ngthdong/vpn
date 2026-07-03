package nat

import "testing"

func TestIPChecksumRoundtrip(t *testing.T) {
	// Real IPv4 ICMP packet captured from tcpdump (checksum known good)
	pkt := []byte{
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0xf4, 0x7e, // checksum at [10:12] = 0xf47e
		0x0a, 0x00, 0x00, 0x02, // src: 10.0.0.2
		0x0a, 0x00, 0x00, 0x01, // dst: 10.0.0.1
	}
	// Corrupt checksum, recompute, verify it matches
	pkt[10] = 0xFF
	pkt[11] = 0xFF
	recomputeIPChecksum(pkt)
	if !verifyChecksum(pkt) {
		t.Fatal("invalid checksum")
	}
}

func verifyChecksum(pkt []byte) bool {
    ihl := int(pkt[0]&0x0F) * 4

    var sum uint32
    for i := 0; i < ihl; i += 2 {
        sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
    }

    for sum>>16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }

    return uint16(sum) == 0xffff
}