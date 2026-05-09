package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
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

	// Create handshake instance
	hs, err := handshake.New()
	if err != nil {
		log.Fatalf("Failed to create handshake: %v", err)
	}

	// Generate InitPacket
	initPkt, err := hs.InitPacket()
	if err != nil {
		log.Fatalf("Failed to generate init packet: %v", err)
	}

	// Encode and send the initial packet
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

	// Set read deadline and wait for server response
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Fatalf("Failed to set deadline: %v", err)
	}

	// Read the response
	buffer := make([]byte, 1500)
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	// Decode the response
	respPkt, err := proto.Decode(buffer[:n])
	if err != nil {
		log.Fatalf("Decode failed: %v", err)
	}

	fmt.Printf("\nReceived packet\n")
	fmt.Printf("Type: 0x%02x, Payload length: %d bytes\n", respPkt.Type, len(respPkt.Payload))
	fmt.Printf("Encoded (%d bytes):\n%s", n, hex.Dump(buffer[:n]))

	// Verify packet type is TypeHandshakeResp
	if respPkt.Type != proto.TypeHandshakeResp {
		log.Fatalf("Expected TypeHandshakeResp (0x%02x), got 0x%02x", proto.TypeHandshakeResp, respPkt.Type)
	}

	// Call HandleResp to compute shared keys
	err = hs.HandleResp(respPkt)
	if err != nil {
		log.Fatalf("HandleResp failed: %v", err)
	}

	// Verify handshake is complete
	if !hs.Done() {
		log.Fatalf("Handshake not complete after HandleResp")
	}

	fmt.Printf("\nhandshake complete, key fingerprint: %x\n", hs.SessionKeys.SendKey[:8])
	log.Println("=== Handshake successful ===")

	log.Println("\n=== Starting encrypted data exchange ===")

	// Create session from derived keys
	sess, err := session.NewSession(hs.SessionKeys)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Prepare plaintext message
	plaintext := []byte("hello vpn")
	log.Printf("Encrypting message: %s", plaintext)

	// Construct AAD: proto header with plaintext length
	aad := makeAAD(len(plaintext))
	fmt.Printf("AAD (%d bytes): %s\n", len(aad), hex.EncodeToString(aad))

	// Encrypt plaintext
	encryptedPkt, err := sess.Encrypt(plaintext, aad)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	log.Printf("Encrypted packet: Type=0x%02x, Payload length=%d", encryptedPkt.Type, len(encryptedPkt.Payload))
	fmt.Printf("Nonce+Ciphertext: %s\n", hex.EncodeToString(encryptedPkt.Payload))

	// Encode encrypted packet for transmission
	encodedData, err := proto.Encode(encryptedPkt)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}

	log.Printf("Sending encrypted data packet (%d bytes)", len(encodedData))
	fmt.Printf("Wire format:\n%s", hex.Dump(encodedData))

	// Send encrypted packet
	_, err = conn.Write(encodedData)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	// Wait for echo response
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Fatalf("Failed to set deadline: %v", err)
	}

	buffer2 := make([]byte, 1500)
	n, err = conn.Read(buffer2)
	if err != nil {
		log.Fatalf("Read echo failed: %v", err)
	}

	log.Printf("Received response (%d bytes)", n)
	fmt.Printf("Wire format:\n%s", hex.Dump(buffer2[:n]))

	// Decode response
	respDataPkt, err := proto.Decode(buffer2[:n])
	if err != nil {
		log.Fatalf("Decode response failed: %v", err)
	}

	if respDataPkt.Type != proto.TypeData {
		log.Fatalf("Expected TypeData (0x%02x), got 0x%02x", proto.TypeData, respDataPkt.Type)
	}

	// Decrypt response using same AAD
	decrypted, err := sess.Decrypt(respDataPkt, aad)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("\nDecrypted echo response: %s\n", string(decrypted))
	log.Println("=== Data exchange complete ===")
}

// makeAAD constructs the Additional Authenticated Data for AEAD
// AAD format: Magic (4 bytes) + Type (1 byte) + Length (2 bytes)
// The length is the plaintext length, not the ciphertext length
func makeAAD(plaintextLen int) []byte {
	aad := make([]byte, 7)
	binary.BigEndian.PutUint32(aad[0:4], proto.Magic)
	aad[4] = proto.TypeData
	binary.BigEndian.PutUint16(aad[5:7], uint16(plaintextLen))
	return aad
}
