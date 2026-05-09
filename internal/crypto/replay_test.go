package crypto

import "testing"

func TestReplayWindow(t *testing.T) {
	var rw ReplayWindow

	// Accept in order
	for i := uint64(0); i < 10; i++ {
		if err := rw.Check(i); err != nil {
			t.Fatalf("rejected valid nonce %d: %v", i, err)
		}
	}
	// Reject duplicate
	if err := rw.Check(5); err == nil {
		t.Fatal("accepted duplicate nonce 5")
	}
	// Accept out-of-order but within window
	if err := rw.Check(8); err == nil {
		t.Fatal("accepted already-seen nonce 8")
	}
	// Reject too-old nonce
	if err := rw.Check(0); err == nil {
		t.Fatal("accepted nonce outside window")
	}
	// Accept future nonce (advances window)
	if err := rw.Check(100); err != nil {
		t.Fatalf("rejected future nonce: %v", err)
	}
}
