package random

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

// Interface for our random number generator. We need this
// to fake random  values in tests.
type RandomProvider interface {
	Bytes(bytes int) ([]byte, error)
	HexDigest(bytes int) (string, error)
}

// Real random values, used in production
type CSPRNG struct{}

// Return n-bytes of random values from the CSPRNG.
func (c *CSPRNG) Bytes(bytes int) ([]byte, error) {
	n := make([]byte, bytes)

	// get bytes-bit random number from /dev/urandom
	_, err := io.ReadFull(rand.Reader, n)
	if err != nil {
		return nil, err
	}

	return n, nil
}

// Return n-bytes of random values from the CSPRNG but as a
// hex-encoded (base16) string.
func (c *CSPRNG) HexDigest(bytes int) (string, error) {
	b, err := c.Bytes(bytes)
	if err != nil {
		return "", err
	}

	// hex encode and return
	return hex.EncodeToString(b), nil
}

// Fake random, used in tests. never use this in production!
type FakeRNG struct{}

// Fake random number generator, never use in production. Always
// returns a predictable sequence of bytes that looks like: 0x00,
// 0x01, 0x02, 0x03, ...
func (f *FakeRNG) Bytes(bytes int) ([]byte, error) {
	// create bytes long array
	b := make([]byte, bytes)

	for i := 0; i < len(b); i++ {
		b[i] = byte(i)
	}

	return b, nil
}

// Fake random number generator, never use in production. Always returns
// a predictable hex-encoded (base16) string that looks like "00010203..."
func (f *FakeRNG) HexDigest(bytes int) (string, error) {
	b, err := f.Bytes(bytes)
	if err != nil {
		return "", err
	}

	// encode and return it
	return hex.EncodeToString(b), nil
}
