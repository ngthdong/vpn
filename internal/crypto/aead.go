package crypto

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/ngthdong/vpn/internal/constant"
	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead      cipher.AEAD
	sendNonce NonceCounter
}

func NewCipher(key [constant.KeySize]byte) (*Cipher, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Seal(plaintext, aad []byte) (nonce [constant.NonceSize]byte, ciphertext []byte, err error) {
	nonce, err = c.sendNonce.Next()
	if err != nil {
		return [constant.NonceSize]byte{}, nil, err
	}
	ct := c.aead.Seal(nil, nonce[:], plaintext, aad)
	return nonce, ct, nil
}

func (c *Cipher) Open(nonce [constant.NonceSize]byte, ciphertext, aad []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce[:], ciphertext, aad)
}

// BuildAAD constructs Additional Authenticated Data from packet type and length
func BuildAAD(pktType uint8, length uint16) []byte {
	aad := make([]byte, 3)
	aad[0] = pktType
	binary.BigEndian.PutUint16(aad[1:3], length)
	return aad
}
