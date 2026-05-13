package main

import (
	"context"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/server"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	conn, err := net.ListenPacket("udp", ":9000")
	if err != nil {
		log.Fatalf("failed to listen udp: %v", err)
	}
	defer conn.Close()

	log.Println("UDP server listening on :9000")

	tunDev, err := tun.Open("tun0", constant.MaxPacketSize)
	if err != nil {
		log.Fatalf("failed to open tun: %v", err)
	}
	defer tunDev.Close()

	log.Printf("TUN device %s opened, MTU=%d",
		tunDev.Name(),
		tunDev.MTU(),
	)

	table := peer.NewPeerTable()
	udpTransport := transport.NewUDPTransport(conn)

	srv := &server.Server{
		UDP:     udpTransport,
		TUN:     tunDev,
		Table:   table,
		Manager: peer.NewManager(table, udpTransport),
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server exited with error: %v", err)
	}

	log.Println("server shutdown complete")
}
