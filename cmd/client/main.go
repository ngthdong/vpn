package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/proto"
)

func main() {
	conn, err := net.Dial("udp", "localhost:9000")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to UDP server at localhost:9000")

	// CLIENT HANDSHAKE FLOW
	log.Println("\n=== Starting handshake ===")

	// 1. Create handshake instance
	hs, err := handshake.New()
	if err != nil {
		log.Fatalf("Failed to create handshake: %v", err)
	}

	// 2. Generate InitPacket
	initPkt, err := hs.InitPacket()
	if err != nil {
		log.Fatalf("Failed to generate init packet: %v", err)
	}

	// 3. Encode and send the initial packet
	encoded, err := proto.Encode(initPkt)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}

	fmt.Printf("\nSending HandshakeInit packet\n")
	fmt.Printf("Type: 0x%02x, Payload length: %d bytes\n", initPkt.Type, len(initPkt.Payload))
	fmt.Printf("Encoded (%d bytes):\n%s", len(encoded), hex.Dump(encoded))

	n, err := conn.Write(encoded)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	if n != len(encoded) {
		log.Fatalf("Write incomplete: wrote %d bytes, expected %d", n, len(encoded))
	}

	log.Printf("Sent %d bytes", n)

	// 4. Set read deadline and wait for server response
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Fatalf("Failed to set deadline: %v", err)
	}

	// 5. Read the response
	buffer := make([]byte, 1500)
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	// 6. Decode the response
	respPkt, err := proto.Decode(buffer[:n])
	if err != nil {
		log.Fatalf("Decode failed: %v", err)
	}

	fmt.Printf("\nReceived packet\n")
	fmt.Printf("Type: 0x%02x, Payload length: %d bytes\n", respPkt.Type, len(respPkt.Payload))
	fmt.Printf("Encoded (%d bytes):\n%s", n, hex.Dump(buffer[:n]))

	// 7. Verify packet type is TypeHandshakeResp
	if respPkt.Type != proto.TypeHandshakeResp {
		log.Fatalf("Expected TypeHandshakeResp (0x%02x), got 0x%02x", proto.TypeHandshakeResp, respPkt.Type)
	}

	// 8. Call HandleResp to compute shared keys
	err = hs.HandleResp(respPkt)
	if err != nil {
		log.Fatalf("HandleResp failed: %v", err)
	}

	// 9. Verify handshake is complete
	if !hs.Done() {
		log.Fatalf("Handshake not complete after HandleResp")
	}

	// 10. Print fingerprint
	fmt.Printf("\nhandshake complete, key fingerprint: %x\n", hs.SessionKeys.SendKey[:8])

	// Data exchange would happen here in a full implementation
	log.Println("\n=== Handshake successful ===")
}
