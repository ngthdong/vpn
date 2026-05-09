package proto

import (
	"encoding/binary"
	"testing"
)

// Table-driven tests for Encode/Decode
var encodeDecodeTests = []struct {
	name    string
	pkt     Packet
	wantErr bool
}{
	{
		name:    "empty payload",
		pkt:     Packet{Type: TypeData, Payload: []byte{}},
		wantErr: false,
	},
	{
		name:    "small payload",
		pkt:     Packet{Type: TypeData, Payload: []byte("hello")},
		wantErr: false,
	},
	{
		name:    "large payload",
		pkt:     Packet{Type: TypeHandshakeInit, Payload: make([]byte, 10000)},
		wantErr: false,
	},
	{
		name:    "max payload size",
		pkt:     Packet{Type: TypeKeepAlive, Payload: make([]byte, PayloadLen)},
		wantErr: false,
	},
	{
		name:    "different type",
		pkt:     Packet{Type: TypeClose, Payload: []byte("closing")},
		wantErr: false,
	},
}

func TestEncode(t *testing.T) {
	pkt := Packet{Type: TypeData, Payload: []byte("hello")}
	b, err := Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != HeaderLen+5 {
		t.Fatalf("wrong length: %d", len(b))
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		t.Fatal("bad magic")
	}
	if b[4] != TypeData {
		t.Fatal("wrong type")
	}
	if binary.BigEndian.Uint16(b[5:7]) != 5 {
		t.Fatal("wrong payload length")
	}
	if string(b[7:]) != "hello" {
		t.Fatal("wrong payload")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, tt := range encodeDecodeTests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := Encode(tt.pkt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Encode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Decode
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			// Verify
			if decoded.Type != tt.pkt.Type {
				t.Errorf("Type mismatch: got %d, want %d", decoded.Type, tt.pkt.Type)
			}
			if string(decoded.Payload) != string(tt.pkt.Payload) {
				t.Errorf("Payload mismatch: got %d bytes, want %d bytes", len(decoded.Payload), len(tt.pkt.Payload))
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "too short",
			data:    []byte{0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "bad magic",
			data:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "length exceeds available data",
			data:    []byte{0x56, 0x50, 0x4E, 0x21, 0x01, 0x00, 0x10}, // Length=16 but only 0 bytes available
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Decode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Fuzz test
func FuzzEncodeDecode(f *testing.F) {
	f.Add(uint8(TypeData), []byte("test"))
	f.Add(uint8(TypeHandshakeInit), []byte{})
	f.Add(uint8(TypeKeepAlive), make([]byte, 1000))

	f.Fuzz(func(t *testing.T, typ uint8, payload []byte) {
		if len(payload) > PayloadLen {
			t.Skip("payload too large")
		}

		pkt := Packet{Type: typ, Payload: payload}
		encoded, err := Encode(pkt)
		if err != nil {
			t.Skip("encode failed")
		}

		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.Type != typ {
			t.Errorf("Type mismatch")
		}
		if string(decoded.Payload) != string(payload) {
			t.Errorf("Payload mismatch")
		}
	})
}
