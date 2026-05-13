package session

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ngthdong/vpn/internal/crypto"
)

func TestSessionRoundtrip(t *testing.T) {
	// Simulate a completed handshake
	secret := make([]byte, 32)
	rand.Read(secret)
	aliceKeys, _ := crypto.DeriveKeys(secret, true)
	bobKeys, _ := crypto.DeriveKeys(secret, false)

	alice, _ := NewSession(aliceKeys)
	bob, _ := NewSession(bobKeys)

	plaintext := []byte("this is a secret IP packet")
	aad := crypto.BuildAAD(0x01, uint16(len(plaintext)))

	// Alice encrypts
	pkt, err := alice.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts
	recovered, err := bob.Decrypt(pkt, aad)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("plaintext mismatch:\n got: %x\nwant: %x", recovered, plaintext)
	}
}

func TestTamperDetection(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	aliceKeys, _ := crypto.DeriveKeys(secret, true)
	bobKeys, _ := crypto.DeriveKeys(secret, false)
	alice, _ := NewSession(aliceKeys)
	bob, _ := NewSession(bobKeys)

	plaintext := []byte("hello")
	aad := crypto.BuildAAD(0x01, uint16(len(plaintext)))
	pkt, _ := alice.Encrypt(plaintext, aad)

	// Flip one bit in the ciphertext
	pkt.Payload[20] ^= 0xFF

	_, err := bob.Decrypt(pkt, aad)
	if err == nil {
		t.Fatal("tampered ciphertext was accepted — authentication broken")
	}
}
