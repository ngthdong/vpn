package crypto

import (
	"bytes"
	"testing"
)

func TestNonceMonotonic(t *testing.T) {
	var nc NonceCounter
	prev, _ := nc.Next()
	for i := 0; i < 1000; i++ {
		next, err := nc.Next()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(prev[:], next[:]) {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		prev = next
	}
}

func TestNonceEncoding(t *testing.T) {
	var nc NonceCounter
	nc.val = 1
	n, _ := nc.Next()
	// counter=1 should be in bytes [4:12], big-endian
	if n[11] != 0x01 {
		t.Fatalf("wrong nonce encoding: % x", n[:])
	}
}
