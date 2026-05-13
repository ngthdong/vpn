package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/event"
	"github.com/ngthdong/vpn/internal/forward"
	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/nat"
	"github.com/ngthdong/vpn/internal/peer"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/router"
	"github.com/ngthdong/vpn/internal/session"
	"github.com/ngthdong/vpn/internal/transport"
	"github.com/ngthdong/vpn/internal/tun"
)

func handleHandshake(
	conn net.PacketConn,
	serverAddr *net.UDPAddr,
	hs *handshake.Handshake,
) (*session.Session, error) {
	buffer := make([]byte, constant.MTU)

	initPkt, err := hs.InitPacket()
	if err != nil {
		return nil, err
	}

	encoded, err := proto.Encode(initPkt)
	if err != nil {
		return nil, err
	}

	log.Println("sending handshake init")

	if _, err := conn.WriteTo(encoded, serverAddr); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
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

	if err := hs.HandleResp(respPkt); err != nil {
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

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	// Independent subsystems
	bus := event.NewBus(256)
	rt := &router.Router{}
	natTable := nat.NewTable(5 * time.Minute)
	table := peer.NewPeerTable()

	// UDP transport
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to listen udp: %v", err)
	}
	defer conn.Close()

	serverAddr, err := net.ResolveUDPAddr(
		"udp",
		"127.0.0.1:9000",
	)
	if err != nil {
		log.Fatalf("resolve udp addr failed: %v", err)
	}

	udp := transport.NewUDPTransport(conn)

	// Handshake
	hs, err := handshake.New()
	if err != nil {
		log.Fatalf("handshake init failed: %v", err)
	}

	sess, err := handleHandshake(conn, serverAddr, hs)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}

	log.Println("handshake successful")

	// TUN device
	tunDev, err := tun.Open("tun1", constant.MaxPacketSize)
	if err != nil {
		log.Fatalf("tun open failed: %v", err)
	}
	defer tunDev.Close()

	log.Printf(
		"TUN device %s opened, MTU=%d",
		tunDev.Name(),
		tunDev.MTU(),
	)

	// Create peer representing server
	serverPeer := peer.NewPeer(serverAddr, func() {})
	serverPeer.SetSession(
		sess,
		peer.PeerID{},
	)

	table.Add(serverPeer)

	// Add default route through server
	_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")
	rt.Add(defaultRoute, serverPeer, 100)

	// Data plane
	fwd := forward.NewForwarder(
		tunDev,
		udp,
		table,
		rt,
		natTable,
		bus,
		net.ParseIP("10.0.0.2"), 
	)

	go func() {
		if err := fwd.Run(ctx); err != nil &&
			err != context.Canceled {
			log.Printf("forwarder error: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()

	log.Println("client shutdown")
}