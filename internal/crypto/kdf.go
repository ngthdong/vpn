package crypto

import (
	"crypto/sha256"
	"io"

	"github.com/ngthdong/vpn/internal/constant"
	"golang.org/x/crypto/hkdf"
)

type SessionKeys struct {
	SendKey [constant.KeySize]byte
	RecvKey [constant.KeySize]byte
}

func DeriveKeys(sharedSecret []byte, isInitiator bool) (SessionKeys, error) {
	salt := []byte("vpn-salt-v1") // fixed, non-secret, domain-separating
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(constant.Info))

	var keyMaterial [64]byte
	if _, err := io.ReadFull(h, keyMaterial[:]); err != nil {
		return SessionKeys{}, err
	}

	var keys SessionKeys

	if isInitiator {
		copy(keys.SendKey[:], keyMaterial[:constant.KeySize])
		copy(keys.RecvKey[:], keyMaterial[constant.KeySize:])
	} else {
		copy(keys.RecvKey[:], keyMaterial[:constant.KeySize])
		copy(keys.SendKey[:], keyMaterial[constant.KeySize:])
	}
	return keys, nil
}
