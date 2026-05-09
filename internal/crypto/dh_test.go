package crypto

import (
	"bytes"
	"testing"
)

func TestDHSymmetry(t *testing.T) {
	kpA, _ := GenerateKeypair()
	kpB, _ := GenerateKeypair()
	sharedA, _ := SharedSecret(kpA.Private, kpB.Public)
	sharedB, _ := SharedSecret(kpB.Private, kpA.Public)
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatal("shared secrets do not match — DH broken")
	}
}
