package crypto

import (
	"errors"
	"sync"

	"github.com/ngthdong/vpn/internal/constant"
)

type ReplayWindow struct {
	mu       sync.Mutex
	maxNonce uint64
	window   uint64 // bitmask: bit i = nonce (maxNonce - i) was seen
}

func (r *ReplayWindow) Check(nonce uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if nonce > r.maxNonce {
		// advance the window
		shift := nonce - r.maxNonce
		if shift >= constant.WindowSize {
			r.window = 0
		} else {
			r.window <<= shift
		}

		r.window |= 1
		r.maxNonce = nonce
		return nil
	}

	diff := r.maxNonce - nonce
	if diff >= constant.WindowSize {
		return errors.New("nonce too old: outside replay window")
	}

	bit := uint64(1) << diff
	if r.window&bit != 0 {
		return errors.New("duplicate nonce: replay detected")
	}
	
	r.window |= bit
	return nil
}
