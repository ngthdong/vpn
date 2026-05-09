package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("udp", "localhost:9000")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to UDP server at localhost:9000")

	// Test payload
	testPayload := []byte("hello vpn")

	// Write the payload
	fmt.Printf("\n Sending %d bytes\n", len(testPayload))
	fmt.Println(hex.Dump(testPayload))

	n, err := conn.Write(testPayload)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	if n != len(testPayload) {
		log.Fatalf("Write incomplete: wrote %d bytes, expected %d", n, len(testPayload))
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

	received := buffer[:n]

	fmt.Printf("\nReceived %d bytes\n", n)
	fmt.Println(hex.Dump(received))

	// Assert they match byte-for-byte
	if n != len(testPayload) {
		log.Fatalf("Size mismatch: received %d bytes, sent %d bytes", n, len(testPayload))
	}

	if string(received) != string(testPayload) {
		log.Fatalf("Payload mismatch:\n  Sent:     %s\n  Received: %s", testPayload, received)
	}

	fmt.Println("\nEcho test passed: sent and received match!")
}
