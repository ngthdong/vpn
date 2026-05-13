package event

import "sync"

type EventType uint8

const (
	EventPacketForwarded EventType = iota
	EventSessionEstablished
	EventSessionEvicted
	EventDecryptFailure
	EventRouteAdded
	EventRouteRemoved
)

type Event struct {
	Type    EventType
	PeerID  string
	Bytes   int
	Details string
}

type Bus struct {
	mu          sync.RWMutex
	subscribers []chan Event
	bufSize     int
}

func NewBus(bufSize int) *Bus {
	return &Bus{bufSize: bufSize}
}

func (b *Bus) Subscribe() <-chan Event {
	ch := make(chan Event, b.bufSize)
	b.mu.Lock()
	b.subscribers = append(b.subscribers, ch)
	b.mu.Unlock()
	return ch
}

func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subscribers {
		select {
		case ch <- e:
		default:
			// subscriber is slow — drop the event, never block the hot path
		}
	}
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = nil
}
