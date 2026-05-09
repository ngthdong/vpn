package crypto

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"

	"github.com/ngthdong/vpn/internal/constant"
)

type NonceCounter struct {
	mu  sync.Mutex
	val uint64
}

func (n *NonceCounter) Next() ([constant.NonceSize]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.val == math.MaxUint64 {
		return [constant.NonceSize]byte{}, errors.New("nonce counter exhausted — must rekey")
	}

	var nonce [constant.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], n.val)
	n.val += 1
	return nonce, nil
}

func (n *NonceCounter) Uint64() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.val
}
