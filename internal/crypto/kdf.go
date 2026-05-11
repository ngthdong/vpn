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

// DeriveKeys derives deterministic session keys using HKDF with domain separation.
// isInitiator determines the role: true for client (initiator), false for server (responder).
//
// This design ensures:
// - client.SendKey (derived with "client->server") == server.RecvKey
// - client.RecvKey (derived with "server->client") == server.SendKey
// - No ambiguous key ordering; each direction has an explicit label
// - AEAD authentication failures are eliminated by ensuring both sides derive identical keys
func DeriveKeys(sharedSecret []byte, isInitiator bool) (SessionKeys, error) {
	salt := []byte(constant.HKDFSalt)

	// Derive client->server key (SendKey for initiator, RecvKey for responder)
	hC2S := hkdf.New(sha256.New, sharedSecret, salt, []byte("client->server"))
	var c2sKey [constant.KeySize]byte
	if _, err := io.ReadFull(hC2S, c2sKey[:]); err != nil {
		return SessionKeys{}, err
	}

	// Derive server->client key (RecvKey for initiator, SendKey for responder)
	hS2C := hkdf.New(sha256.New, sharedSecret, salt, []byte("server->client"))
	var s2cKey [constant.KeySize]byte
	if _, err := io.ReadFull(hS2C, s2cKey[:]); err != nil {
		return SessionKeys{}, err
	}

	var keys SessionKeys

	if isInitiator {
		// Client/Initiator: sends on client->server, receives on server->client
		copy(keys.SendKey[:], c2sKey[:])
		copy(keys.RecvKey[:], s2cKey[:])
	} else {
		// Server/Responder: sends on server->client, receives on client->server
		copy(keys.SendKey[:], s2cKey[:])
		copy(keys.RecvKey[:], c2sKey[:])
	}

	return keys, nil
}
