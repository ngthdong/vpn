package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	config "github.com/ngthdong/vpn/internal/configs"
	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/event"
	"github.com/ngthdong/vpn/internal/forward"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/router"
	"github.com/ngthdong/vpn/internal/server"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	// Event bus
	bus := event.NewBus(256)
	defer bus.Close()

	// Metrics subscriber
	metricsCh := bus.Subscribe()
	go event.RunMetricsSubscriber(ctx, metricsCh)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
			}
		}
	}()

	// Router
	rt := &router.Router{}

	// Prometheus endpoint
	http.Handle("/metrics", promhttp.Handler())

	go func() {
		log.Println("Prometheus metrics listening on :9090")

		if err := http.ListenAndServe(":9090", nil); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

	// Load configuration
	cfg, err := config.LoadServer("configs/server.yaml")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", cfg.Server.Listen)
	if err != nil {
		log.Fatalf("failed to listen udp: %v", err)
	}
	defer conn.Close()

	log.Println("UDP server listening on :9000")

	udpTransport := transport.NewUDPTransport(conn)

	// TUN device
	tunDev, err := tun.Open(
		cfg.TUN.Name,
		cfg.TUN.Address,
		constant.MaxPacketSize,
	)
	if err != nil {
		log.Fatalf("failed to open tun: %v", err)
	}
	defer tunDev.Close()

	log.Printf(
		"TUN device %s opened, MTU=%d",
		tunDev.Name(),
		tunDev.MTU(),
	)

	// Peer table + manager
	table := peer.NewPeerTable()

	manager := peer.NewManager(
		table,
		udpTransport,
	)

	// Data plane
	fwd := forward.NewForwarder(
		tunDev,
		udpTransport,
		table,
		rt,
		bus,
		net.ParseIP("10.0.0.1"), // server tunnel IP
	)

	// Control plane
	srv := &server.Server{
		UDP:       udpTransport,
		Table:     table,
		Manager:   manager,
		Forwarder: fwd,
		Router:    rt,
	}

	// Run subsystems
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return srv.Run(ctx)
	})

	eg.Go(func() error {
		return fwd.Run(ctx)
	})

	// Wait for shutdown
	if err := eg.Wait(); err != nil &&
		err != context.Canceled {
		log.Printf("shutdown with error: %v", err)
	}

	log.Println("server shutdown complete")
}
