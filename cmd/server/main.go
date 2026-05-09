package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/ngthdong/vpn/internal/proto"
)

func main() {
	// Listen on UDP port 9000
	conn, err := net.ListenPacket("udp", ":9000")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Println("UDP server listening on :9000")

	// Fixed 1500-byte buffer (MTU size)
	buffer := make([]byte, 1500)

	for {
		// Read from the connection
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		// Decode the proto.Packet
		pkt, err := proto.Decode(buffer[:n])
		if err != nil {
			log.Printf("Decode error: %v", err)
			continue
		}

		fmt.Printf("\nReceived packet from %s: %v\n", remoteAddr, pkt)
		fmt.Printf("Payload hex:\n%s", hex.Dump(pkt.Payload))

		// Re-encode and echo back
		encoded, err := proto.Encode(pkt)
		if err != nil {
			log.Printf("Encode error: %v", err)
			continue
		}

		_, err = conn.WriteTo(encoded, remoteAddr)
		if err != nil {
			log.Printf("Write error: %v", err)
			continue
		}

		log.Printf("Echoed packet (%d bytes encoded) back to %s", len(encoded), remoteAddr)
	}
}
