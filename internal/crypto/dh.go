package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/ngthdong/vpn/internal/constant"
	"golang.org/x/crypto/curve25519"
)

type Keypair struct {
	Private [constant.KeySize]byte
	Public  [constant.KeySize]byte
}

func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}

	priv[0] &= 248  // clear 3 lowest bits
	priv[31] &= 127 // clear highest bit
	priv[31] |= 64  // set second-highest bit

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}

	var kp Keypair
	copy(kp.Private[:], priv[:])
	copy(kp.Public[:], pub)
	return kp, nil
}

func SharedSecret(localPriv, remotePub [constant.KeySize]byte,) ([]byte, error) {
	out, err := curve25519.X25519(localPriv[:], remotePub[:])
	if err != nil {
		return nil, err
	}

	var zeros [constant.KeySize]byte
	if subtle.ConstantTimeCompare(out, zeros[:]) == 1 {
		return nil, errors.New("degenerate shared secret: possible low-order point")
	}

	return out, nil
}
