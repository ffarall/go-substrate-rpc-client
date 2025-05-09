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
	"fmt"

	"github.com/snowfork/go-substrate-rpc-client/v4/scale"
)

// EthSignature
type EthSignature struct {
	Signature EcdsaSignature
}

func (m *EthSignature) Decode(decoder scale.Decoder) error {
	// If there are only 65 bytes, it's an EthSignature
	var encodedBytes []byte
	err := decoder.Decode(&encodedBytes)
	if err != nil {
		return err
	}

	if len(encodedBytes) == 65 {
		copy(m.Signature[:], encodedBytes)
		return nil
	} else {
		return fmt.Errorf("invalid length for EthSignature (should be 65 bytes): %v", len(encodedBytes))
	}
}

func (m EthSignature) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(m.Signature)
	if err != nil {
		return err
	}

	return nil
}
