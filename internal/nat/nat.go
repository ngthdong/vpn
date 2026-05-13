package nat

import (
	"net"
	"sync"
	"time"

	"github.com/ngthdong/vpn/internal/tun"
)

type Entry struct {
	OriginalSrc   net.IP
	TranslatedSrc net.IP
	Proto         uint8
	CreatedAt     time.Time
}

type Table struct {
	mu      sync.RWMutex
	entries map[string]*Entry // key: originalSrc.String()
	ttl     time.Duration
}

func NewTable(ttl time.Duration) *Table {
	return &Table{
		entries: make(map[string]*Entry),
		ttl:     ttl,
	}
}

// SNAT rewrites the source IP of an outgoing packet.
// Returns the rewritten packet and records the translation.
func (t *Table) SNAT(pkt []byte, newSrc net.IP) ([]byte, error) {
	hdr, err := tun.ParseIPHeader(pkt)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(pkt))
	copy(out, pkt)

	// Rewrite source IP at bytes [12:16]
	copy(out[12:16], newSrc.To4())

	// Record translation for DNAT on the return path
	t.mu.Lock()
	t.entries[hdr.SrcIP.String()] = &Entry{
		OriginalSrc:   hdr.SrcIP,
		TranslatedSrc: newSrc,
		CreatedAt:     time.Now(),
	}
	t.mu.Unlock()

	// Recompute IP header checksum
	recomputeIPChecksum(out)
	return out, nil
}

// DNAT rewrites the destination IP of an incoming packet back to original.
func (t *Table) DNAT(pkt []byte) ([]byte, error) {
	hdr, err := tun.ParseIPHeader(pkt)
	if err != nil {
		return nil, err
	}

	t.mu.RLock()
	entry, ok := t.entries[hdr.DstIP.String()]
	t.mu.RUnlock()

	if !ok {
		return pkt, nil // no translation needed
	}

	out := make([]byte, len(pkt))
	copy(out, pkt)
	copy(out[16:20], entry.OriginalSrc.To4())
	recomputeIPChecksum(out)
	return out, nil
}

// Evict removes stale entries. Call from a ticker goroutine.
func (t *Table) Evict() {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-t.ttl)
	for k, e := range t.entries {
		if e.CreatedAt.Before(cutoff) {
			delete(t.entries, k)
		}
	}
}

func recomputeIPChecksum(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	pkt[10] = 0
	pkt[11] = 0

	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += (uint32(pkt[i]) << 8) | uint32(pkt[i+1])
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	pkt[10] = byte(checksum >> 8)
	pkt[11] = byte(checksum)
}
