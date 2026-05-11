package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/forward"
	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
)

func handleHandshake(conn net.PacketConn, serverAddr *net.UDPAddr, hs *handshake.Handshake) (*session.Session, error) {
	buffer := make([]byte, constant.MTU)

	// Generate InitPacket
	initPkt, err := hs.InitPacket()
	if err != nil {
		return nil, err
	}

	encoded, err := proto.Encode(initPkt)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Sending HandshakeInit packet\n")

	_, err = conn.WriteTo(encoded, serverAddr)
	if err != nil {
		return nil, err
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, fmt.Errorf("handshake timeout")
		}
		return nil, err
	}

	respPkt, err := proto.Decode(buffer[:n])
	if err != nil {
		return nil, err
	}

	if respPkt.Type != proto.TypeHandshakeResp {
		return nil, fmt.Errorf("invalid handshake response")
	}

	err = hs.HandleResp(respPkt)
	if err != nil {
		return nil, err
	}

	if !hs.Done() {
		return nil, fmt.Errorf("handshake not complete")
	}

	sess, err := session.NewSession(hs.SessionKeys)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func runForwarder(
	ctx context.Context,
	tunDev *tun.Device,
	sess *session.Session,
	udpTransport *transport.UDPTransport,
	serverAddr net.Addr,
) error {
	fwd := forward.NewForwarder(tunDev, sess, udpTransport, serverAddr)
	return fwd.Run(ctx)
}

func main() {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	serverAddr, _ := net.ResolveUDPAddr("udp", "localhost:9000")

	hs, err := handshake.New()
	if err != nil {
		log.Fatalf("handshake init failed: %v", err)
	}

	sess, err := handleHandshake(conn, serverAddr, hs)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}

	log.Println("Handshake successful")

	tunDev, err := tun.Open("tun1", constant.MaxPacketSize)
	if err != nil {
		log.Fatalf("tun open failed: %v", err)
	}
	defer tunDev.Close()

	udpTransport := transport.NewUDPTransport(conn)
	defer udpTransport.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	if err := runForwarder(ctx, tunDev, sess, udpTransport, serverAddr); err != nil && err != context.Canceled {
		log.Fatalf("forwarder error: %v", err)
	}
}
