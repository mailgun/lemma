package secret

import (
	"crypto/subtle"
	"fmt"
	"testing"

	"github.com/mailgun/lemma/random"
)

var _ = fmt.Printf // for testing

func TestEncryptDecryptCycle(t *testing.T) {
	randomProvider = &random.FakeRNG{}

	key, err := NewKey()
	if err != nil {
		t.Errorf("Got unexpected response from NewKey: %v", err)
	}

	s, err := NewWithKeyBytes(key)
	if err != nil {
		t.Errorf("Got unexpected response from NewWithKeyBytes: %v", err)
	}

	message := []byte("hello, box!")
	sealed, err := s.Seal(message)
	if err != nil {
		t.Errorf("Got unexpected response from Seal: %v", err)
	}

	out, err := s.Open(sealed)
	if err != nil {
		t.Errorf("Got unexpected response from Open: %v", err)
	}

	// compare the messages
	if subtle.ConstantTimeCompare(message, out) != 1 {
		t.Errorf("Contents do not match: %v, %v", message, out)
	}
}

func TestEncryptDecryptCycleWithKey(t *testing.T) {
	randomProvider = &random.FakeRNG{}

	// try and create new service with no key, should fail
	s, err := New(&Config{})
	if err == nil {
		t.Errorf("Somehow got a Service, should not have gotten on (no key path given)")
	}

	// now get a service that has no key, by passing in a nil key
	s, err = NewWithKeyBytes(nil)
	if err != nil {
		t.Errorf("Got unexpected response from NewWithKeyBytes: %v", err)
	}

	// try and seal, should fail because we didn't pass in a key
	message := []byte("hello, box!")
	sealed, err := s.Seal(message)
	if err == nil {
		t.Errorf("Got unexpected response from Seal: %v", err)
	}

	// should fail, again, no key
	out, err := s.Open(sealed)
	if err == nil {
		t.Errorf("Got unexpected response from Open: %v", err)
	}

	// setup key to use, the spec zeros this array, so the key is all zeros (0x00, 0x00, 0x00, ...)
	var secretKey [SecretKeyLength]byte

	// should be able to seal because we passed in a key
	sealed, err = s.SealWithKey(message, &secretKey)
	if err != nil {
		t.Errorf("Got unexpected response from Seal: %v", err)
	}

	// should be able to open now, passing in key
	out, err = s.OpenWithKey(sealed, &secretKey)
	if err != nil {
		t.Errorf("Got unexpected response from Open: %v", err)
	}

	// compare the messages
	if subtle.ConstantTimeCompare(message, out) != 1 {
		t.Errorf("Contents do not match: %v, %v", message, out)
	}
}
