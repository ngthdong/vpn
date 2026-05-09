package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/ngthdong/vpn/internal/handshake"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/session"
)

func main() {
	// Listen on UDP port 9000
	conn, err := net.ListenPacket("udp", ":9000")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Println("UDP server listening on :9000")

	// Track sessions per client address
	sessions := make(map[string]*session.Session)

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

			// Create session from derived keys and store it
			sess, err := session.NewSession(hs.SessionKeys)
			if err != nil {
				log.Printf("Failed to create session: %v", err)
				continue
			}

			sessions[remoteAddr.String()] = sess
			log.Printf("Session created for %s", remoteAddr)

		case proto.TypeData:
			// Retrieve session for this client
			sess, ok := sessions[remoteAddr.String()]
			if !ok {
				log.Printf("No session for %s, dropping packet", remoteAddr)
				continue
			}

			log.Printf("Data packet from %s: payload_len=%d", remoteAddr, len(pkt.Payload))
			fmt.Printf("Encrypted payload: %s\n", hex.EncodeToString(pkt.Payload))

			// Decrypt the packet
			// AAD must use plaintext length: len(payload) - nonce(12) - tag(16)
			plaintextLen := len(pkt.Payload) - 12 - 16
			if plaintextLen < 0 {
				log.Printf("Invalid payload length from %s: %d", remoteAddr, len(pkt.Payload))
				continue
			}

			aad := makeAAD(plaintextLen)
			fmt.Printf("AAD (%d bytes): %s\n", len(aad), hex.EncodeToString(aad))

			plaintext, err := sess.Decrypt(pkt, aad)
			if err != nil {
				log.Printf("Decrypt failed from %s: %v", remoteAddr, err)
				continue
			}

			fmt.Printf("Decrypted plaintext: %s\n", string(plaintext))
			log.Printf("Received message: %s", plaintext)

			// Echo back the same message
			echoAAD := makeAAD(len(plaintext))
			echoPkt, err := sess.Encrypt(plaintext, echoAAD)
			if err != nil {
				log.Printf("Encryption failed: %v", err)
				continue
			}

			log.Printf("Encrypted echo packet: Type=0x%02x, Payload length=%d", echoPkt.Type, len(echoPkt.Payload))
			fmt.Printf("Nonce+Ciphertext: %s\n", hex.EncodeToString(echoPkt.Payload))

			// Encode for transmission
			encoded, err := proto.Encode(echoPkt)
			if err != nil {
				log.Printf("Encode error: %v", err)
				continue
			}

			log.Printf("Sending echo response (%d bytes)", len(encoded))
			fmt.Printf("Wire format:\n%s", hex.Dump(encoded))

			_, err = conn.WriteTo(encoded, remoteAddr)
			if err != nil {
				log.Printf("Write error: %v", err)
				continue
			}

			log.Printf("Echoed response to %s", remoteAddr)

		default:
			log.Printf("Unexpected packet type: 0x%02x", pkt.Type)
		}
	}
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
