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

type ExtrinsicSignatureV3 struct {
	Signer    Address
	Signature Signature
	Era       ExtrinsicEra // extra via system::CheckEra
	Nonce     UCompact     // extra via system::CheckNonce (Compact<Index> where Index is u32))
	Tip       UCompact     // extra via balances::TakeFees (Compact<Balance> where Balance is u128))
}

type ExtrinsicSignatureV4 struct {
	Signer    MultiAddress
	Signature MultiSignature
	Era       ExtrinsicEra // extra via system::CheckEra
	Nonce     UCompact     // extra via system::CheckNonce (Compact<Index> where Index is u32))
	Tip       UCompact     // extra via balances::TakeFees (Compact<Balance> where Balance is u128))
}

type ExtrinsicSignatureV5 struct {
	Signer    		  EthAddress
	Signature 		  EthSignature
	Era               ExtrinsicEra      // extra via system::CheckEra
	Nonce             UCompact          // extra via system::CheckNonce (Compact<Index> where Index is u32))
	Tip               UCompact          // extra via balances::TakeFees (Compact<Balance> where Balance is u128))
	CheckMetadataMode CheckMetadataMode // additional via frame_metadata_hash_extension::CheckMetadataHash
}

type SignatureOptions struct {
	Era                ExtrinsicEra      // extra via system::CheckEra
	Nonce              UCompact          // extra via system::CheckNonce (Compact<Index> where Index is u32)
	Tip                UCompact          // extra via balances::TakeFees (Compact<Balance> where Balance is u128)
	SpecVersion        U32               // additional via system::CheckSpecVersion
	GenesisHash        Hash              // additional via system::CheckGenesis
	BlockHash          Hash              // additional via system::CheckEra
	TransactionVersion U32               // additional via system::CheckTxVersion
	CheckMetadataMode  CheckMetadataMode // additional via frame_metadata_hash_extension::CheckMetadataHash
	CheckMetadataHash  CheckMetadataHash // additional via frame_metadata_hash_extension::CheckMetadataHash}
}
