/*
Package secret provides tools for encrypting and decrypting authenticated messages.
See docs/secret.md for more details.
*/
package secret

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"github.com/mailgun/lemma/random"
)

// Config is used to configure a secret service. It contains the keypath to the
// secret key as well as the version of the secret service that will be used.
type Config struct {
	Keypath string
}

// SealedBytes contains the ciphertext and nonce for a sealed message.
type SealedBytes struct {
	Ciphertext []byte
	Nonce      []byte
}

// A Service can be used to seal/open (encrypt/decrypt and authenticate) messages.
type Service struct {
	secretKey *[SecretKeyLength]byte
}

// New returns a new Service. Config can not be nil.
func New(config *Config) (*Service, error) {
	// read in the key from disk
	keyBytes, err := readKeyFromDisk(config.Keypath)
	if err != nil {
		return nil, err
	}

	return NewWithKeyBytes(keyBytes)
}

// NewWithKeyBytes returns a new service with the key bytes passed in.
func NewWithKeyBytes(keyBytes *[SecretKeyLength]byte) (*Service, error) {
	return &Service{
		secretKey: keyBytes,
	}, nil
}

// Seal takes plaintext and returns encrypted and authenticated ciphertext.
func (s *Service) Seal(value []byte) (*SealedBytes, error) {
	return s.SealWithKey(value, s.secretKey)
}

// SealWithKey does the same thing as Seal, but a different key can be passed in.
func (s *Service) SealWithKey(value []byte, secretKey *[SecretKeyLength]byte) (*SealedBytes, error) {
	// check that we either initialized with a key or one was passed in
	if secretKey == nil {
		return nil, fmt.Errorf("secret key is nil")
	}

	// generate nonce
	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %v", err)
	}

	// use nacl secret box to encrypt plaintext
	var encrypted []byte
	encrypted = secretbox.Seal(encrypted, value, nonce, secretKey)

	// return sealed ciphertext
	return &SealedBytes{
		Ciphertext: encrypted,
		Nonce:      nonce[:],
	}, nil
}

// Open authenticates the ciphertext and if valid, decrypts and returns plaintext.
func (s *Service) Open(e *SealedBytes) ([]byte, error) {
	return s.OpenWithKey(e, s.secretKey)
}

// OpenWithKey is the same as Open, but a different key can be passed in.
func (s *Service) OpenWithKey(e *SealedBytes, secretKey *[SecretKeyLength]byte) ([]byte, error) {
	// check that we either initialized with a key or one was passed in
	if secretKey == nil {
		return nil, fmt.Errorf("secret key is nil")
	}

	// convert nonce to an array
	nonce, err := nonceSliceToArray(e.Nonce)
	if err != nil {
		return nil, err
	}

	// decrypt
	var decrypted []byte
	decrypted, ok := secretbox.Open(decrypted, e.Ciphertext, nonce, secretKey)
	if !ok {
		return nil, fmt.Errorf("unable to decrypt message")
	}

	return decrypted, nil
}

func readKeyFromDisk(keypath string) (*[SecretKeyLength]byte, error) {
	// load key from disk
	keyBytes, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	// strip newline (\n or 0x0a) if it's at the end
	keyBytes = bytes.TrimSuffix(keyBytes, []byte("\n"))

	// decode string and convert to array and return it
	return EncodedStringToKey(string(keyBytes))
}

func keySliceToArray(bytes []byte) (*[SecretKeyLength]byte, error) {
	// check that the lengths match
	if len(bytes) != SecretKeyLength {
		return nil, fmt.Errorf("wrong key length: %v", len(bytes))
	}

	// copy bytes into array
	var keyBytes [SecretKeyLength]byte
	copy(keyBytes[:], bytes)

	return &keyBytes, nil
}

func nonceSliceToArray(bytes []byte) (*[NonceLength]byte, error) {
	// check that the lengths match
	if len(bytes) != NonceLength {
		return nil, fmt.Errorf("wrong nonce length: %v", len(bytes))
	}

	// copy bytes into array
	var nonceBytes [NonceLength]byte
	copy(nonceBytes[:], bytes)

	return &nonceBytes, nil
}

func generateNonce() (*[NonceLength]byte, error) {
	// get b-bytes of random from /dev/urandom
	bytes, err := randomProvider.Bytes(NonceLength)
	if err != nil {
		return nil, err
	}

	return nonceSliceToArray(bytes)
}

var randomProvider random.RandomProvider

// init sets the package level randomProvider to be a real csprng. this is done
// so during tests, we can use a fake random number generator.
func init() {
	randomProvider = &random.CSPRNG{}
}
