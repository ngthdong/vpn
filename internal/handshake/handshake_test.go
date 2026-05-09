package handshake_test

import (
	"bytes"
	"testing"

	"github.com/ngthdong/vpn/internal/handshake"
)

func TestHandshakeRoundtrip(t *testing.T) {
	alice, _ := handshake.New()
	bob, _ := handshake.New()

	// Alice initiates
	initPkt, _ := alice.InitPacket()

	// Bob responds
	respPkt, err := bob.HandleInit(initPkt)
	if err != nil {
		t.Fatal(err)
	}

	// Alice completes
	if err := alice.HandleResp(respPkt); err != nil {
		t.Fatal(err)
	}

	if !alice.Done() || !bob.Done() {
		t.Fatal("handshake not complete")
	}

	// Keys must be symmetric
	if !bytes.Equal(alice.SessionKeys.SendKey[:], bob.SessionKeys.RecvKey[:]) {
		t.Fatal("key mismatch")
	}
	if !bytes.Equal(alice.SessionKeys.RecvKey[:], bob.SessionKeys.SendKey[:]) {
		t.Fatal("key mismatch")
	}
}
