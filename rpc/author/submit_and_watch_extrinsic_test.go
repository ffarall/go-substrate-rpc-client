package author_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	gsrpc "github.com/snowfork/go-substrate-rpc-client/v4"
	"github.com/snowfork/go-substrate-rpc-client/v4/config"
	"github.com/snowfork/go-substrate-rpc-client/v4/rpc/author"
	"github.com/snowfork/go-substrate-rpc-client/v4/signature"
	"github.com/snowfork/go-substrate-rpc-client/v4/types"
	"github.com/stretchr/testify/assert"
)

func TestAuthor_SubmitAndWatchExtrinsic(t *testing.T) {
	// Instantiate the API
	api, err := gsrpc.NewSubstrateAPI(config.Default().RPCURL)
	assert.NoError(t, err)

	meta, err := api.RPC.State.GetMetadataLatest()
	assert.NoError(t, err)

	// Create a call, transferring 12345 units to Bob
	bob, err := types.NewEthAddress("0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
	assert.NoError(t, err)

	amount := types.NewUCompactFromUInt(12345)
	c, err := types.NewCall(meta, "Balances.transfer_allow_death", bob, amount)
	assert.NoError(t, err)

	var sub *author.ExtrinsicStatusSubscription
	for {
		// Create the extrinsic
		ext := types.NewExtrinsic(c)
		genesisHash, err := api.RPC.Chain.GetBlockHash(0)
		assert.NoError(t, err)

		rv, err := api.RPC.State.GetRuntimeVersionLatest()
		assert.NoError(t, err)

		// Get the nonce for Alith
		alithAddressBytes, err := hex.DecodeString(strings.TrimPrefix(signature.TestKeyringPairAlith.Address, "0x"))
		if err != nil {
			panic(err)
		}
		key, err := types.CreateStorageKey(meta, "System", "Account", alithAddressBytes)
		assert.NoError(t, err)

		var accountInfo types.AccountInfo
		ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
		assert.NoError(t, err)
		assert.True(t, ok)
		nonce := uint32(accountInfo.Nonce)
		o := types.SignatureOptions{
			BlockHash:          genesisHash,
			Era:                types.ExtrinsicEra{IsMortalEra: false},
			GenesisHash:        genesisHash,
			Nonce:              types.NewUCompactFromUInt(uint64(nonce)),
			SpecVersion:        rv.SpecVersion,
			Tip:                types.NewUCompactFromUInt(0),
			TransactionVersion: rv.TransactionVersion,
		}

		fmt.Printf("Sending %v from %#x to %#x with nonce %v\n", amount, signature.TestKeyringPairAlith.Address, bob.Address, nonce)

		// Sign the transaction using Alith's default account
		err = ext.Sign(signature.TestKeyringPairAlith, o)
		assert.NoError(t, err)

		// Do the transfer and track the actual status
		sub, err = api.RPC.Author.SubmitAndWatchExtrinsic(ext)
		if err != nil {
			t.Logf("extrinsic submit failed: %v", err)
			continue
		}

		break
	}
	defer sub.Unsubscribe()
	for {
		status := <-sub.Chan()

		// wait until finalisation
		if status.IsInBlock || status.IsFinalized {
			break
		}

		t.Log("waiting for the extrinsic to be included/finalized")
	}

}
