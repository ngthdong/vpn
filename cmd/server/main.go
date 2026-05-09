package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/ngthdong/vpn/internal/handshake"
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

		fmt.Printf("\nReceived packet from %s: type=0x%02x, payload_len=%d\n", remoteAddr, pkt.Type, len(pkt.Payload))

		// Handle different packet types
		switch pkt.Type {
		case proto.TypeHandshakeInit:
			// SERVER HANDSHAKE FLOW
			log.Println("Handling handshake init")

			// Create new handshake instance for this client
			hs, err := handshake.New()
			if err != nil {
				log.Printf("Failed to create handshake: %v", err)
				continue
			}

			// Call HandleInit to derive shared keys and generate response
			respPkt, err := hs.HandleInit(pkt)
			if err != nil {
				log.Printf("HandleInit error: %v", err)
				continue
			}

			// Encode the response packet
			encoded, err := proto.Encode(respPkt)
			if err != nil {
				log.Printf("Encode error: %v", err)
				continue
			}

			fmt.Printf("\nSending HandshakeResp packet\n")
			fmt.Printf("Type: 0x%02x, Payload length: %d bytes\n", respPkt.Type, len(respPkt.Payload))
			fmt.Printf("Encoded (%d bytes):\n%s", len(encoded), hex.Dump(encoded))

			// Send response back
			_, err = conn.WriteTo(encoded, remoteAddr)
			if err != nil {
				log.Printf("Write error: %v", err)
				continue
			}

			// Verify handshake is complete
			if !hs.Done() {
				log.Printf("Handshake not complete after HandleInit")
				continue
			}

			// Print fingerprint
			fmt.Printf("handshake complete, key fingerprint: %x\n", hs.SessionKeys.RecvKey[:8])
			log.Println("Handshake complete")

		case proto.TypeData:
			// Data packet (not yet implemented for encryption)
			fmt.Printf("Data packet: payload=%s\n", string(pkt.Payload))
			fmt.Printf("Payload hex:\n%s", hex.Dump(pkt.Payload))

			// Echo back for now
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

		default:
			log.Printf("Unexpected packet type: 0x%02x", pkt.Type)
		}
	}
}
