package httpsign

import (
	"testing"

	"github.com/mailgun/holster/v3/clock"
)

func TestInCache(t *testing.T) {
	clock.Freeze(clock.Now())
	defer clock.Unfreeze()

	// setup
	nc, err := NewNonceCache(
		100,
		1,
	)
	if err != nil {
		t.Error("Got unexpected error from NewNonceCache:", err)
	}

	// nothing in cache, it should be valid
	inCache := nc.InCache("0")
	if inCache {
		t.Error("Check should be valid, but failed.")
	}

	// second time around it shouldn't be
	inCache = nc.InCache("0")
	if !inCache {
		t.Error("Check should be invalid, but passed.")
	}

	// check some other value
	clock.Advance(999 * clock.Millisecond)
	inCache = nc.InCache("1")
	if inCache {
		t.Error("Check should be valid, but failed.", err)
	}

	// age off first value, then it should be valid
	clock.Advance(1 * clock.Millisecond)
	inCache = nc.InCache("0")
	if inCache {
		t.Error("Check should be valid, but failed.")
	}
}
