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

package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/snowfork/go-substrate-rpc-client/v4/scale"
	"github.com/snowfork/go-substrate-rpc-client/v4/signature"
)

const (
	EthExtrinsicBitSigned      = 0x80
	EthExtrinsicBitUnsigned    = 0
	EthExtrinsicUnmaskVersion  = 0x7f
	EthExtrinsicDefaultVersion = 1
	EthExtrinsicVersionUnknown = 0 // v0 is unknown
	EthExtrinsicVersion1       = 1
	EthExtrinsicVersion2       = 2
	EthExtrinsicVersion3       = 3
	EthExtrinsicVersion4       = 4
)

// Extrinsic is a piece of Args bundled into a block that expresses something from the "external" (i.e. off-chain)
// world. There are, broadly speaking, two types of extrinsic: transactions (which tend to be signed) and
// inherents (which don't).
//
// In particular, this is the type for Ethereum compatible transactions, like for Frontier-enabled chains.
type EthExtrinsic struct {
	// Version is the encoded version flag (which encodes the raw transaction version and signing information in one byte)
	Version byte
	// Signature is the EthExtrinsicSignatureV5, it's presence depends on the Version flag
	Signature EthExtrinsicSignatureV5
	// Method is the call this extrinsic wraps
	Method Call
}

// NewEthExtrinsic creates a new EthExtrinsic from the provided Call
func NewEthExtrinsic(c Call) EthExtrinsic {
	return EthExtrinsic{
		Version: ExtrinsicVersion4,
		Method:  c,
	}
}

// UnmarshalJSON fills Extrinsic with the JSON encoded byte array given by bz
func (e *EthExtrinsic) UnmarshalJSON(bz []byte) error {
	var tmp string
	if err := json.Unmarshal(bz, &tmp); err != nil {
		return err
	}

	// HACK 11 Jan 2019 - before https://github.com/paritytech/substrate/pull/1388
	// extrinsics didn't have the length, cater for both approaches. This is very
	// inconsistent with any other `Vec<u8>` implementation
	var l UCompact
	err := DecodeFromHexString(tmp, &l)
	if err != nil {
		return err
	}

	prefix, err := EncodeToHexString(l)
	if err != nil {
		return err
	}

	// determine whether length prefix is there
	if strings.HasPrefix(tmp, prefix) {
		return DecodeFromHexString(tmp, e)
	}

	// not there, prepend with compact encoded length prefix
	dec, err := HexDecodeString(tmp)
	if err != nil {
		return err
	}
	length := NewUCompactFromUInt(uint64(len(dec)))
	bprefix, err := EncodeToBytes(length)
	if err != nil {
		return err
	}
	prefixed := append(bprefix, dec...)
	return DecodeFromBytes(prefixed, e)
}

// MarshalJSON returns a JSON encoded byte array of EthExtrinsic
func (e EthExtrinsic) MarshalJSON() ([]byte, error) {
	s, err := EncodeToHexString(e)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// IsSigned returns true if the extrinsic is signed
func (e EthExtrinsic) IsSigned() bool {
	return e.Version&EthExtrinsicBitSigned == EthExtrinsicBitSigned
}

// Type returns the raw transaction version (not flagged with signing information)
func (e EthExtrinsic) Type() uint8 {
	return e.Version & EthExtrinsicUnmaskVersion
}

// Sign adds a signature to the extrinsic
func (e *EthExtrinsic) Sign(signer signature.KeyringPair, o SignatureOptions) error {
	if e.Type() != EthExtrinsicVersion4 {
		return fmt.Errorf("unsupported extrinsic version: %v (isSigned: %v, type: %v)", e.Version, e.IsSigned(), e.Type())
	}

	mb, err := EncodeToBytes(e.Method)
	if err != nil {
		return err
	}

	era := o.Era
	if !o.Era.IsMortalEra {
		era = ExtrinsicEra{IsImmortalEra: true}
	}

	payload := ExtrinsicPayloadV5{
		ExtrinsicPayloadV4: ExtrinsicPayloadV4{
			ExtrinsicPayloadV3: ExtrinsicPayloadV3{
				Method:      mb,
				Era:         era,
				Nonce:       o.Nonce,
				Tip:         o.Tip,
				SpecVersion: o.SpecVersion,
				GenesisHash: o.GenesisHash,
				BlockHash:   o.BlockHash,
			},
			TransactionVersion: o.TransactionVersion,
		},
		CheckMetadataMode: o.CheckMetadataMode,
		CheckMetadataHash: o.CheckMetadataHash,
	}

	ethAddr, err := NewEthAddress(signer.Address)
	if err != nil {
		return err
	}

	sig, err := payload.Sign(signer)
	if err != nil {
		return err
	}

	extSig := EthExtrinsicSignatureV5{
		Signer:            ethAddr,
		Signature:         EthSignature{Signature: NewEcdsaSignature(sig)},
		Era:               era,
		Nonce:             o.Nonce,
		Tip:               o.Tip,
		CheckMetadataMode: o.CheckMetadataMode,
	}

	e.Signature = extSig

	// mark the extrinsic as signed
	e.Version |= ExtrinsicBitSigned

	return nil
}

func (e *EthExtrinsic) Decode(decoder scale.Decoder) error {
	// compact length encoding (1, 2, or 4 bytes) (may not be there for Extrinsics older than Jan 11 2019)
	_, err := decoder.DecodeUintCompact()
	if err != nil {
		return err
	}

	// version, signature bitmask (1 byte)
	err = decoder.Decode(&e.Version)
	if err != nil {
		return err
	}

	// signature
	if e.IsSigned() {
		if e.Type() != ExtrinsicVersion4 {
			return fmt.Errorf("unsupported extrinsic version: %v (isSigned: %v, type: %v)", e.Version, e.IsSigned(),
				e.Type())
		}

		err = decoder.Decode(&e.Signature)
		if err != nil {
			return err
		}
	}

	// call
	err = decoder.Decode(&e.Method)
	if err != nil {
		return err
	}

	return nil
}

func (e EthExtrinsic) Encode(encoder scale.Encoder) error {
	if e.Type() != EthExtrinsicVersion4 {
		return fmt.Errorf("unsupported extrinsic version: %v (isSigned: %v, type: %v)", e.Version, e.IsSigned(),
			e.Type())
	}

	// create a temporary buffer that will receive the plain encoded transaction (version, signature (optional),
	// method/call)
	var bb = bytes.Buffer{}
	tempEnc := scale.NewEncoder(&bb)

	// encode the version of the extrinsic
	err := tempEnc.Encode(e.Version)
	if err != nil {
		return err
	}

	// encode the signature if signed
	if e.IsSigned() {
		err = tempEnc.Encode(e.Signature)
		if err != nil {
			return err
		}
	}

	// encode the method
	err = tempEnc.Encode(e.Method)
	if err != nil {
		return err
	}

	// take the temporary buffer to determine length, write that as prefix
	eb := bb.Bytes()
	err = encoder.EncodeUintCompact(*big.NewInt(0).SetUint64(uint64(len(eb))))
	if err != nil {
		return err
	}

	// write the actual encoded transaction
	err = encoder.Write(eb)
	if err != nil {
		return err
	}

	return nil
}
