package session

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ngthdong/vpn/internal/constant"
	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/proto"
)

type Session struct {
	sendCipher   *crypto.Cipher
	recvCipher   *crypto.Cipher
	replayWindow crypto.ReplayWindow
}

func NewSession(keys crypto.SessionKeys) (*Session, error) {
	send, err := crypto.NewCipher(keys.SendKey)
	if err != nil {
		return nil, err
	}

	recv, err := crypto.NewCipher(keys.RecvKey)
	if err != nil {
		return nil, err
	}

	return &Session{sendCipher: send, recvCipher: recv}, nil
}

func (s *Session) Encrypt(plaintext, aad []byte) (proto.Packet, error) {
	nonce, ct, err := s.sendCipher.Seal(plaintext, aad)
	if err != nil {
		return proto.Packet{}, err
	}

	payload := make([]byte, constant.NonceSize + len(ct))
	copy(payload[:constant.NonceSize], nonce[:])
	copy(payload[constant.NonceSize:], ct)

	return proto.Packet{Type: proto.TypeData, Payload: payload}, nil
}

func (s *Session) Decrypt(pkt proto.Packet, aad []byte) ([]byte, error) {
	if len(pkt.Payload) < constant.NonceSize + constant.TagSize { 
		return nil, errors.New("packet too short to contain nonce and tag")
	}

	var nonce [constant.NonceSize]byte
	copy(nonce[:], pkt.Payload[:constant.NonceSize])
	ct := pkt.Payload[constant.NonceSize:]

	// Extract counter from nonce for replay check
	counter := binary.BigEndian.Uint64(nonce[4:])
	if err := s.replayWindow.Check(counter); err != nil {
		return nil, fmt.Errorf("replay check failed: %w", err)
	}

	return s.recvCipher.Open(nonce, ct, aad)
}
