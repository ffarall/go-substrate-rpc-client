package signature

import (
	"errors"

	"github.com/vedhavyas/go-subkey"
	"github.com/vedhavyas/go-subkey/sr25519"
	"golang.org/x/crypto/blake2b"
)

// Sr25519Scheme implements Scheme for sr25519 (Substrate).
type Sr25519Scheme struct{}

// DeriveKeyPair derives a KeyringPair using sr25519 and SS58 address format.
func (Sr25519Scheme) DeriveKeyPair(uri string, network uint8) (KeyringPair, error) {
	scheme := sr25519.Scheme{}
	kyr, err := subkey.DeriveKeyPair(scheme, uri)
	if err != nil {
		return KeyringPair{}, err
	}

	ss58Address, err := kyr.SS58Address(network)
	if err != nil {
		return KeyringPair{}, err
	}

	var pk = kyr.Public()

	return KeyringPair{
		URI:       uri,
		Address:   ss58Address,
		PublicKey: pk,
	}, nil
}

// Sign signs data with sr25519 under the given URI.
func (Sr25519Scheme) Sign(data []byte, uri string) ([]byte, error) {
	if len(data) > 256 {
		h := blake2b.Sum256(data)
		data = h[:]
	}

	scheme := sr25519.Scheme{}
	kyr, err := subkey.DeriveKeyPair(scheme, uri)
	if err != nil {
		return nil, err
	}

	signature, err := kyr.Sign(data)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify verifies an sr25519 signature.
func (Sr25519Scheme) Verify(data []byte, sig []byte, uri string) (bool, error) {
	if len(data) > 256 {
		h := blake2b.Sum256(data)
		data = h[:]
	}

	scheme := sr25519.Scheme{}
	kyr, err := subkey.DeriveKeyPair(scheme, uri)
	if err != nil {
		return false, err
	}

	if len(sig) != 64 {
		return false, errors.New("wrong signature length")
	}

	return kyr.Verify(data, sig), nil
} 