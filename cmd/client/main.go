package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ngthdong/vpn/internal/proto"
)

func main() {
	conn, err := net.Dial("udp", "localhost:9000")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to UDP server at localhost:9000")

	// Create a proto.Packet with test payload
	testPayload := []byte("hello vpn")
	pkt := proto.Packet{
		Type:    proto.TypeData,
		Payload: testPayload,
	}

	// Encode the packet
	encoded, err := proto.Encode(pkt)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}

	fmt.Printf("\nSending packet\n")
	fmt.Printf("Type: 0x%02x, Payload: %s\n", pkt.Type, string(pkt.Payload))
	fmt.Printf("Encoded (%d bytes):\n%s", len(encoded), hex.Dump(encoded))

	// Send the encoded packet
	n, err := conn.Write(encoded)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	if n != len(encoded) {
		log.Fatalf("Write incomplete: wrote %d bytes, expected %d", n, len(encoded))
	}

	log.Printf("Sent %d bytes", n)

	// Set a read deadline to avoid blocking indefinitely
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Fatalf("Failed to set deadline: %v", err)
	}

	// Read the echo back
	buffer := make([]byte, 1500)
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	// Decode the response
	receivedPkt, err := proto.Decode(buffer[:n])
	if err != nil {
		log.Fatalf("Decode failed: %v", err)
	}

	fmt.Printf("\nReceived packet\n")
	fmt.Printf("Type: 0x%02x, Payload: %s\n", receivedPkt.Type, string(receivedPkt.Payload))
	fmt.Printf("Encoded (%d bytes):\n%s", n, hex.Dump(buffer[:n]))

	// Assert they match byte-for-byte
	if len(receivedPkt.Payload) != len(pkt.Payload) {
		log.Fatalf("Payload size mismatch: received %d bytes, sent %d bytes", len(receivedPkt.Payload), len(pkt.Payload))
	}

	if string(receivedPkt.Payload) != string(pkt.Payload) {
		log.Fatalf("Payload mismatch:\n  Sent:     %s\n  Received: %s", pkt.Payload, receivedPkt.Payload)
	}

	if receivedPkt.Type != pkt.Type {
		log.Fatalf("Packet type mismatch: received 0x%02x, sent 0x%02x", receivedPkt.Type, pkt.Type)
	}
}
