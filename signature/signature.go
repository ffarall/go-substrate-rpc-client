// Go Substrate RPC Client (GSRPC) provides APIs and types around Polkadot and any Substrate-based chain RPC calls
//
// Copyright 2019 Centrifuge GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signature

import (
	"fmt"
	"os"
	"strconv"

	"github.com/snowfork/go-substrate-rpc-client/v4/scale"
)

type KeyringPair struct {
	// URI is the derivation path for the private key in subkey
	URI string
	// Address is an SS58 address if the scheme is SR25519, otherwise it's an Ethereum address for ECDSA
	Address string
	// PublicKey
	PublicKey []byte
	// Scheme used for signing and verifying
	Scheme Scheme
}

// TestKeyringPairAlice is a predefined test pair using sr25519
var TestKeyringPairAlice, _ = NewSr25519KeyringPair("//Alice", 42)
var TestKeyringPairAlith, _ = NewEcdsaKeyringPair("//Alice")

// LoadKeyringPairFromEnv looks up whether the env variable TEST_PRIV_KEY is set
// Assumes that the network is Substrate, so it returns a Sr25519KeyringPair
func LoadKeyringPairFromEnv() (kp KeyringPair, ok bool) {
	networkString := os.Getenv("TEST_NETWORK")
	network, err := strconv.ParseInt(networkString, 10, 8)
	if err != nil {
		network = 42
	}
	priv, ok := os.LookupEnv("TEST_PRIV_KEY")
	if !ok || priv == "" {
		return kp, false
	}
	kp, err = NewSr25519KeyringPair(priv, uint8(network))
	if err != nil {
		panic(fmt.Errorf("cannot load keyring pair from env or use fallback: %v", err))
	}
	return kp, true
}

// NewSr25519KeyringPair constructs a KeyringPair for sr25519.
func NewSr25519KeyringPair(uri string, network uint8) (KeyringPair, error) {
	kp, err := Sr25519Scheme{}.DeriveKeyPair(uri, network)
	if err != nil {
		return kp, err
	}
	kp.Scheme = Sr25519Scheme{}
	return kp, nil
}

// NewEcdsaKeyringPair constructs a KeyringPair for Ethereum ECDSA.
func NewEcdsaKeyringPair(privateKeyHex string) (KeyringPair, error) {
	kp, err := EcdsaScheme{}.DeriveKeyPair(privateKeyHex, 0)
	if err != nil {
		return kp, err
	}
	kp.Scheme = EcdsaScheme{}
	return kp, nil
}

// Sign signs data using the KeyringPair's underlying scheme.
func (kp KeyringPair) Sign(data []byte) ([]byte, error) {
	return kp.Scheme.Sign(data, kp.URI)
}

// Verify verifies a signature using the KeyringPair's underlying scheme.
func (kp KeyringPair) Verify(data []byte, sig []byte) (bool, error) {
	return kp.Scheme.Verify(data, sig, kp.URI)
}

func (kp *KeyringPair) Decode(decoder scale.Decoder) error {
	err := decoder.Decode(&kp.URI)
	if err != nil {
		return fmt.Errorf("failed to decode URI: %w", err)
	}

	err = decoder.Decode(&kp.Address)
	if err != nil {
		return fmt.Errorf("failed to decode Address: %w", err)
	}

	err = decoder.Decode(&kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode PublicKey: %w", err)
	}

	var schemeType byte
	err = decoder.Decode(&schemeType)
	if err != nil {
		return fmt.Errorf("failed to decode scheme type: %w", err)
	}

	switch schemeType {
	case 0:
		kp.Scheme = Sr25519Scheme{}
	case 1:
		kp.Scheme = EcdsaScheme{}
	default:
		return fmt.Errorf("unknown scheme type: %d", schemeType)
	}

	return nil
}

func (kp KeyringPair) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(kp.URI)
	if err != nil {
		return fmt.Errorf("failed to encode URI: %w", err)
	}

	err = encoder.Encode(kp.Address)
	if err != nil {
		return fmt.Errorf("failed to encode Address: %w", err)
	}

	err = encoder.Encode(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode PublicKey: %w", err)
	}

	var schemeType byte
	switch kp.Scheme.(type) {
	case Sr25519Scheme:
		schemeType = 0
	case EcdsaScheme:
		schemeType = 1
	default:
		return fmt.Errorf("unknown or nil scheme type: %T", kp.Scheme)
	}

	err = encoder.Encode(schemeType)
	if err != nil {
		return fmt.Errorf("failed to encode scheme type: %w", err)
	}

	return nil
}
