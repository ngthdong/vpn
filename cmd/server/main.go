package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
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

		// Hex-dump the received data
		fmt.Printf("\nReceived %d bytes from %s\n", n, remoteAddr)
		fmt.Println(hex.Dump(buffer[:n]))

		// Echo back to sender
		_, err = conn.WriteTo(buffer[:n], remoteAddr)
		if err != nil {
			log.Printf("Write error: %v", err)
			continue
		}

		log.Printf("Echoed %d bytes back to %s", n, remoteAddr)
	}
}
