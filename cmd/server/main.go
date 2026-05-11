package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/forward"
	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
)

func handleRequest(
	ctx context.Context,
	conn net.PacketConn,
	buffer []byte,
	n int,
	remoteAddr net.Addr,
	tunDev *tun.Device,
	sessions map[string]*session.Session,
	mu *sync.Mutex,
	udpTransport *transport.UDPTransport,
) {
	pkt, err := proto.Decode(buffer[:n])
	if err != nil {
		log.Printf("Decode error: %v", err)
		return
	}

	fmt.Printf("\nReceived packet from %s: type=0x%02x, payload_len=%d\n", 
			remoteAddr, pkt.Type, len(pkt.Payload))

	switch pkt.Type {
	case proto.TypeHandshakeInit:
		log.Println("Handling handshake init")

		hs, err := handshake.New()
		if err != nil {
			log.Printf("Failed to create handshake: %v", err)
			return
		}

		respPkt, err := hs.HandleInit(pkt)
		if err != nil {
			log.Printf("HandleInit error: %v", err)
			return
		}

		encoded, err := proto.Encode(respPkt)
		if err != nil {
			log.Printf("Encode error: %v", err)
			return
		}

		_, err = conn.WriteTo(encoded, remoteAddr)
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}

		if !hs.Done() {
			log.Printf("Handshake not complete after HandleInit")
			return
		}

		fmt.Printf("handshake complete, key fingerprint: %x\n", hs.SessionKeys.RecvKey[:8])
		log.Println("Handshake complete")

		sess, err := session.NewSession(hs.SessionKeys)
		if err != nil {
			log.Printf("Failed to create session: %v", err)
			return
		}

		mu.Lock()
		sessions[remoteAddr.String()] = sess
		mu.Unlock()

		log.Printf("Session created for %s", remoteAddr)
		log.Println("=== Starting packet forwarding ===")

		fwd := forward.NewForwarder(tunDev, sess, udpTransport, remoteAddr)

		log.Println("Forwarder taking ownership of UDP socket")

		if err := fwd.Run(ctx); err != nil && err != context.Canceled {
			log.Printf("Forwarder error for %s: %v", remoteAddr, err)
		}

	case proto.TypeData:
		log.Printf("Unexpected TypeData from %s (should be handled by forwarder)", remoteAddr)

	default:
		log.Printf("Unexpected packet type: 0x%02x", pkt.Type)
	}
}

func main() {
	conn, err := net.ListenPacket("udp", ":9000")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Println("UDP server listening on :9000")

	tunDev, err := tun.Open("tun0", constant.MaxPacketSize)
	if err != nil {
		log.Fatalf("Failed to open TUN device: %v", err)
	}
	defer tunDev.Close()

	log.Printf("TUN device %s opened, MTU %d", tunDev.Name(), tunDev.MTU())

	udpTransport := transport.NewUDPTransport(conn)
	defer udpTransport.Close()

	sessions := make(map[string]*session.Session)
	mu := sync.Mutex{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nShutting down gracefully...")
		cancel()
	}()

	log.Println("Waiting for client handshake")

	buffer := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			log.Println("Server shut down")
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		handleRequest(ctx, conn, buffer, n, remoteAddr, tunDev, sessions, &mu, udpTransport)
	}
}