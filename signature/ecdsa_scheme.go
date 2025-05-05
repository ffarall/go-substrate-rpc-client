package signature

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

// EcdsaScheme implements Scheme for Ethereum ECDSA signatures.
type EcdsaScheme struct{}

// DeriveKeyPair derives a KeyringPair from a hex-encoded private key URI.
func (EcdsaScheme) DeriveKeyPair(uri string, _ uint8) (KeyringPair, error) {
	keyHex := strings.TrimPrefix(uri, "0x")
	privBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return KeyringPair{}, fmt.Errorf("invalid private key hex: %w", err)
	}
	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		return KeyringPair{}, fmt.Errorf("could not parse ECDSA private key: %w", err)
	}
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	pubBytes := crypto.FromECDSAPub(pubKey)
	addr := crypto.PubkeyToAddress(*pubKey).Hex()

	return KeyringPair{
		URI:       "0x" + keyHex,
		PublicKey: pubBytes,
		Address:   addr,
	}, nil
}

// Sign signs data using Ethereum ECDSA (keccak256 hash if needed).
func (EcdsaScheme) Sign(data []byte, uri string) ([]byte, error) {
	// If the data is longer than 256 bytes, Substrate chains will hash it and sign the hash,
	// using BLAKE2b-256.
	if len(data) > 256 {
		h := blake2b.Sum256(data)
		data = h[:]
	}
	
	keyHex := strings.TrimPrefix(uri, "0x")
	privKey, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	// The data needs to always be hashed with Keccak256, mirroring Frontier's verify logic.
	// See: https://github.com/polkadot-evm/frontier/blob/c59a6c1aa2e60d835d81aa5db3eb1d54fac9cd60/primitives/account/src/lib.rs#L195
	data = crypto.Keccak256(data)

	sig, err := crypto.Sign(data, privKey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify verifies an ECDSA signature.
func (EcdsaScheme) Verify(data []byte, sig []byte, uri string) (bool, error) {
	keyHex := strings.TrimPrefix(uri, "0x")
	privKey, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return false, fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(data) != 32 {
		data = crypto.Keccak256(data)
	}
	// signature must be 65 bytes
	if len(sig) != 65 {
		return false, errors.New("wrong signature length")
	}
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	// VerifySignature expects uncompressed public key without prefix
	pubBytes := crypto.FromECDSAPub(pubKey)[1:]
	return crypto.VerifySignature(pubBytes, data, sig[:64]), nil
} 