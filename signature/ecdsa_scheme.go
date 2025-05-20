package signature

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
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
	// Prepare the message hash, identical to the Sign method.
	// If the data is longer than 256 bytes, Substrate chains will hash it and sign the hash,
	// using BLAKE2b-256.
	messageToHash := data
	if len(messageToHash) > 256 {
		h := blake2b.Sum256(messageToHash)
		messageToHash = h[:]
	}

	// The data needs to always be hashed with Keccak256, mirroring Frontier's verify logic.
	finalHash := crypto.Keccak256(messageToHash)

	// The signature must be 65 bytes long for Ecrecover [R || S || V]
	if len(sig) != 65 {
		return false, fmt.Errorf("invalid signature length: expected 65, got %d", len(sig))
	}

	// Recover the public key from the signature and the final hash.
	// Ecrecover returns the public key in 64-byte uncompressed format (X, Y coordinates).
	recoveredPubKeyBytes, err := crypto.Ecrecover(finalHash, sig)
	if err != nil {
		// This typically means the signature is invalid.
		return false, fmt.Errorf("could not recover public key from signature: %w", err)
	}

	// Derive the expected public key from the provided URI (private key hex).
	keyHex := strings.TrimPrefix(uri, "0x")
	privKey, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return false, fmt.Errorf("invalid private key hex for deriving expected public key: %w", err)
	}
	expectedPubKeyECDSA := privKey.Public().(*ecdsa.PublicKey)
	// crypto.FromECDSAPub returns the public key in 65-byte uncompressed format (0x04 + X + Y).
	expectedPubKeyBytesWithPrefix := crypto.FromECDSAPub(expectedPubKeyECDSA)

	if len(expectedPubKeyBytesWithPrefix) != 65 {
		return false, fmt.Errorf("unexpected length for derived expected public key: expected 65, got %d", len(expectedPubKeyBytesWithPrefix))
	}

	// Compare the 64-byte recovered public key with the X, Y part of the expected public key.
	return bytes.Equal(recoveredPubKeyBytes, expectedPubKeyBytesWithPrefix), nil
} 