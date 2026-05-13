package peer

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPeerEvictionNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	table := NewPeerTable()
	peers := make([]*Peer, 10)

	for i := range peers {
		ctx, cancel := context.WithCancel(context.Background())

		addr := &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, byte(i+1)),
			Port: 10000 + i,
		}

		p := NewPeer(addr, cancel)
		table.Add(p)
		peers[i] = p

		// Simulate a running forwarder goroutine
		go func(p *Peer, ctx context.Context) {
			defer close(p.Done)
			<-ctx.Done()
		}(p, ctx)
	}

	// Evict all peers
	for _, p := range peers {
		table.Evict(p)
	}

	// Give goroutines time to exit
	time.Sleep(50 * time.Millisecond)

	after := runtime.NumGoroutine()
	if after > baseline+2 { // +2 for test infrastructure
		t.Fatalf("goroutine leak: started with %d, now %d", baseline, after)
	}
}

func TestPeerTableConcurrentAccess(t *testing.T) {
	table := NewPeerTable()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)

		addr := &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, byte(i+1)),
			Port: 20000 + i,
		}

		go func(addr net.Addr) {
			defer wg.Done()

			ctx, cancel := context.WithCancel(context.Background())

			p := NewPeer(addr, cancel)

			go func() {
				defer close(p.Done)
				<-ctx.Done()
			}()

			table.Add(p)
		}(addr)

		go func(addr net.Addr) {
			defer wg.Done()
			table.LookupAddr(addr)
		}(addr)
	}

	wg.Wait()

	for _, p := range table.All() {
		table.Evict(p)
	}
}