package handshake

import (
	"fmt"

	"github.com/ngthdong/vpn/internal/crypto"
	"github.com/ngthdong/vpn/internal/proto"
	"github.com/ngthdong/vpn/internal/constant"
)

type State int

const (
	StateIdle     State = iota
	StateSentInit       // initiator: waiting for response
	StateComplete       // both sides: keys ready
)

type Handshake struct {
	state       State
	localKP     crypto.Keypair
	SessionKeys crypto.SessionKeys
}

func New() (*Handshake, error) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return &Handshake{localKP: kp}, nil
}

// InitPacket: called by the initiator. Returns the packet to send.
func (h *Handshake) InitPacket() (proto.Packet, error) {
	h.state = StateSentInit
	return proto.Packet{
		Type:    proto.TypeHandshakeInit,
		Payload: h.localKP.Public[:],
	}, nil
}

// HandleInit: called by the responder on receiving TypeHandshakeInit.
// Returns the response packet to send back.
func (h *Handshake) HandleInit(pkt proto.Packet) (proto.Packet, error) {
	defer zeroBytes(h.localKP.Private[:])

	if len(pkt.Payload) != constant.KeySize {
		return proto.Packet{}, fmt.Errorf("bad pubkey length: %d", len(pkt.Payload))
	}

	var remotePub [constant.KeySize]byte
	copy(remotePub[:], pkt.Payload)

	shared, err := crypto.SharedSecret(h.localKP.Private, remotePub)
	if err != nil {
		return proto.Packet{}, err
	}

	h.SessionKeys, err = crypto.DeriveKeys(shared, false)
	if err != nil {
		return proto.Packet{}, err
	}

	h.state = StateComplete
	return proto.Packet{
		Type:    proto.TypeHandshakeResp,
		Payload: h.localKP.Public[:],
	}, nil
}

// HandleResp: called by the initiator on receiving TypeHandshakeResp.
func (h *Handshake) HandleResp(pkt proto.Packet) error {
	defer zeroBytes(h.localKP.Private[:])

	if h.state != StateSentInit {
		return fmt.Errorf("unexpected HandshakeResp in state %d", h.state)
	}

	if len(pkt.Payload) != constant.KeySize {
		return fmt.Errorf("bad pubkey length: %d", len(pkt.Payload))
	}

	var remotePub [constant.KeySize]byte
	copy(remotePub[:], pkt.Payload)

	shared, err := crypto.SharedSecret(h.localKP.Private, remotePub)
	if err != nil {
		return err
	}

	h.SessionKeys, err = crypto.DeriveKeys(shared, true)
	if err != nil {
		return err
	}

	h.state = StateComplete
	return nil
}

func (h *Handshake) Destroy() {
    zeroBytes(h.localKP.Private[:])
    zeroBytes(h.SessionKeys.SendKey[:])
    zeroBytes(h.SessionKeys.RecvKey[:])
}

func (h *Handshake) Done() bool {
	return h.state == StateComplete
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
