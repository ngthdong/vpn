package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire format (big-endian):
// [0:4]  Magic   uint32  = 0x56504E21  (= "VPN!")
// [4]    Type    uint8
// [5:7]  Length  uint16  (payload length only, not including header)
// [7:]   Payload []byte
//
// Minimum packet: 7 bytes (header only, no payload)
// Maximum packet: 65535 bytes

const (
	HeaderLen  = 7
	PayloadLen = 65535

	TypeData          uint8 = 0x01
	TypeHandshakeInit uint8 = 0x02
	TypeHandshakeResp uint8 = 0x03
	TypeKeepAlive     uint8 = 0x04
	TypeClose         uint8 = 0x05
)

const Magic uint32 = 0x56504E21

type Packet struct {
	Type    uint8
	Payload []byte
}

func Encode(p Packet) ([]byte, error) {
	if len(p.Payload) > PayloadLen {
		return nil, errors.New("payload exceeds max length")
	}

	buf := make([]byte, HeaderLen+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = p.Type
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(p.Payload)))
	copy(buf[7:], p.Payload)
	return buf, nil
}

func Decode(b []byte) (Packet, error) {
	if len(b) < HeaderLen {
		return Packet{}, fmt.Errorf("packet too short: %d bytes", len(b))
	}

	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return Packet{}, errors.New("invalid magic bytes")
	}

	pktType := b[4]
	payloadLen := binary.BigEndian.Uint16(b[5:7])
	if int(payloadLen) > len(b)-HeaderLen {
		return Packet{}, fmt.Errorf("length field %d exceeds available bytes %d",
			payloadLen, len(b)-HeaderLen)
	}

	payload := make([]byte, payloadLen)
	copy(payload, b[HeaderLen:HeaderLen+int(payloadLen)])
	return Packet{Type: pktType, Payload: payload}, nil
}
