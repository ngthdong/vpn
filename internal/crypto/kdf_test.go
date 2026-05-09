package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ngthdong/vpn/internal/constant"
)

func TestKeyDerivationSymmetry(t *testing.T) {
	secret := make([]byte, constant.KeySize)
	rand.Read(secret)

	initiator, _ := DeriveKeys(secret, true)
	responder, _ := DeriveKeys(secret, false)

	if !bytes.Equal(initiator.SendKey[:], responder.RecvKey[:]) {
		t.Fatal("initiator SendKey != responder RecvKey")
	}
	if !bytes.Equal(initiator.RecvKey[:], responder.SendKey[:]) {
		t.Fatal("initiator RecvKey != responder SendKey")
	}
}
