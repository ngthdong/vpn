package event

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	packetsForwarded = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "vpn_packets_forwarded_total"},
		[]string{"peer"},
	)
	bytesForwarded = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "vpn_bytes_forwarded_total"},
		[]string{"peer"},
	)
	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "vpn_active_sessions"},
	)
	decryptFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "vpn_decrypt_failures_total"},
		[]string{"peer"},
	)
)

func init() {
	prometheus.MustRegister(packetsForwarded, bytesForwarded,
		activeSessions, decryptFailures)
}

func RunMetricsSubscriber(ctx context.Context, ch <-chan Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			switch e.Type {
			case EventPacketForwarded:
				packetsForwarded.WithLabelValues(e.PeerID).Inc()
				bytesForwarded.WithLabelValues(e.PeerID).Add(float64(e.Bytes))
			case EventSessionEstablished:
				activeSessions.Inc()
			case EventSessionEvicted:
				activeSessions.Dec()
			case EventDecryptFailure:
				decryptFailures.WithLabelValues(e.PeerID).Inc()
			}
		}
	}
}
