package types_test

import (
	"testing"

	"github.com/snowfork/go-substrate-rpc-client/v4/types"
	"github.com/stretchr/testify/assert"
)

// Verify that (Decode . Encode) outputs the input.
func TestMetadataV14EncodeDecodeRoundtrip(t *testing.T) {
	// Decode the metadata
	var metadata types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &metadata)
	assert.EqualValues(t, metadata.Version, 14)
	assert.NoError(t, err)

	// Now encode it
	encoded, err := types.EncodeToHexString(metadata)
	assert.NoError(t, err)

	// Verify the encoded metadata equals the original one
	assert.Equal(t, types.MetadataV14Data, encoded)

	// Verify that decoding the encoded metadata
	// equals the decoded original metadata
	var decodedMetadata types.Metadata
	err = types.DecodeFromHexString(encoded, &decodedMetadata)
	assert.NoError(t, err)
	assert.EqualValues(t, metadata, decodedMetadata)
}

/* Test Metadata interface functions for v14 */

func TestMetadataV14_TestFindCallIndexWithUnknownFunction(t *testing.T) {
	var metadata types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &metadata)
	assert.EqualValues(t, metadata.Version, 14)
	assert.NoError(t, err)

	_, err = metadata.FindCallIndex("Module2_14.unknownFunction")
	assert.Error(t, err)
}

// Verify that we can find the index of a valid call
func TestMetadataV14FindCallIndex(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)
	index, err := meta.FindCallIndex("Balances.transfer")
	assert.NoError(t, err)
	assert.Equal(t, index, types.CallIndex{SectionIndex: 5, MethodIndex: 0})
}

// Verify that we get an error when querying for an invalid
// call with FindCallIndex.
func TestMetadataV14FindCallIndexNonExistent(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)
	_, err = meta.FindCallIndex("Doesnt.Exist")
	assert.Error(t, err)
}

// Verify that we obtain the right modName, varName pair for a given Event id
func TestMetadataV14FindEventNamesForEventID(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	modName, varName, err := meta.FindEventNamesForEventID(types.EventID{5, 2})
	assert.NoError(t, err)
	assert.Equal(t, modName, types.NewText("Balances"))
	assert.Equal(t, varName, types.NewText("Transfer"))
}

// Verify that we get an error when passing an invalid module ID
func TestMetadataV14FindEventNamesInvalidModuleID(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	_, _, err = meta.FindEventNamesForEventID(types.EventID{100, 2})
	assert.Error(t, err)
}

// Verify that we get an error when passing an invalid event ID
func TestMetadataV14FindEventNamesInvalidEventID(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	_, _, err = meta.FindEventNamesForEventID(types.EventID{5, 42})
	assert.Error(t, err)
}

func TestMetadataV14FindStorageEntryMetadata(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	_, err = meta.FindStorageEntryMetadata("System", "Account")
	assert.NoError(t, err)
}

// Verify FindStorageEntryMetadata returns an err when
// the given module can't be found.
func TestMetadataV14FindStorageEntryMetadataInvalidModule(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	_, err = meta.FindStorageEntryMetadata("SystemZ", "Account")
	assert.Error(t, err)
}

// Verify FindStorageEntryMetadata returns an err when
// it doesn't find a storage within an existing module.
func TestMetadataV14FindStorageEntryMetadataInvalidStorage(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	assert.NoError(t, err)

	_, err = meta.FindStorageEntryMetadata("System", "Accountz")
	assert.Error(t, err)
}

func TestMetadataV14ExistsModuleMetadata(t *testing.T) {
	var meta types.Metadata
	err := types.DecodeFromHexString(types.MetadataV14Data, &meta)
	if err != nil {
		t.Fatal(err)
	}
	res := meta.ExistsModuleMetadata("System")
	assert.True(t, res)
}

/* Unit tests covering decoding/encoding of nested Metadata v14 types */

func TestMetadataV14PalletEmpty(t *testing.T) {
	var pallet = types.PalletMetadataV14{
		Name:       types.NewText("System"),
		HasStorage: false,
		HasCalls:   false,
		HasEvents:  false,
		Constants:  nil,
		HasErrors:  false,
		Index:      42,
	}

	encoded, err := types.EncodeToBytes(pallet)
	assert.NoError(t, err)

	var encodedPallets types.PalletMetadataV14
	err = types.DecodeFromBytes(encoded, &encodedPallets)
	assert.NoError(t, err)

	// Verify they are the same value
	assert.EqualValues(t, encodedPallets, pallet)
}

func TestMetadataV14PalletFilled(t *testing.T) {
	var pallet = types.PalletMetadataV14{
		Name:       types.NewText("System"),
		HasStorage: true,
		Storage: types.StorageMetadataV14{
			Prefix: "Pre-fix",
			Items: []types.StorageEntryMetadataV14{
				{
					Name:     "StorageName",
					Modifier: types.StorageFunctionModifierV0{IsOptional: true},
					Type: types.StorageEntryTypeV14{
						IsPlainType: false,
						IsMap:       true,
						AsMap: types.MapTypeV14{
							Hashers: []types.StorageHasherV10{
								{IsBlake2_128: true}, {IsBlake2_256: true},
							},
							Key:   types.NewSi1LookupTypeIDFromUInt(3),
							Value: types.NewSi1LookupTypeIDFromUInt(4),
						},
					},
				},
				{
					Name: "Account",
					Modifier: types.StorageFunctionModifierV0{
						IsOptional: false,
						IsDefault:  true,
						IsRequired: false,
					},
					Type: types.StorageEntryTypeV14{
						IsPlainType: false,
						IsMap:       true,
						AsMap: types.MapTypeV14{
							Hashers: []types.StorageHasherV10{
								{
									IsBlake2_128:       false,
									IsBlake2_256:       false,
									IsBlake2_128Concat: true,
									IsTwox128:          false,
									IsTwox256:          false,
									IsTwox64Concat:     false,
									IsIdentity:         false,
								},
							},
						},
					},
					Fallback: types.Bytes{
						0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
					},
					Documentation: []types.Text{" The full account information for a particular account ID."},
				},
			},
		},
		HasCalls:  true,
		Calls:     types.FunctionMetadataV14{Type: types.NewSi1LookupTypeIDFromUInt(24)},
		HasEvents: true,
		Events:    types.EventMetadataV14{Type: types.NewSi1LookupTypeIDFromUInt(72)},
		Constants: []types.ConstantMetadataV14{
			{
				Name:  types.NewText("Yellow"),
				Type:  types.NewSi1LookupTypeIDFromUInt(83),
				Value: []byte("Valuez"),
				Docs:  []types.Text{"README", "Contribute"},
			},
		},
		HasErrors: true,
		Errors:    types.ErrorMetadataV14{Type: types.NewSi1LookupTypeIDFromUInt(57)},
		Index:     42,
	}

	encoded, err := types.EncodeToBytes(pallet)
	assert.NoError(t, err)

	var encodedPallets types.PalletMetadataV14
	err = types.DecodeFromBytes(encoded, &encodedPallets)
	assert.NoError(t, err)

	// Verify they are the same
	assert.Equal(t, encodedPallets, pallet)
}

func TestSi1TypeDecodeEncode(t *testing.T) {
	type Si1Type struct {
		Path   types.Si1Path
		Params []types.Si1TypeParameter
		Def    types.Si1TypeDef
		Docs   []types.Text
	}

	// Replicate the first Si1Type we get from rpc json, marsh it, and aside encode it, and decode it
	var ti = Si1Type{
		Path: []types.Text{"sp_core", "crypto", "AccountId32"},
		Def: types.Si1TypeDef{
			IsComposite: true,
			Composite: types.Si1TypeDefComposite{
				Fields: []types.Si1Field{
					{
						Type:        types.NewSi1LookupTypeIDFromUInt(1),
						HasTypeName: true,
						TypeName:    types.NewText("[u8; 32]"),
					},
				},
			},
		},
	}

	// Verify that (decode . encode) equals the original value
	encoded, err := types.EncodeToHexString(ti)
	assert.NoError(t, err)

	var decoded Si1Type
	types.DecodeFromHexString(encoded, &decoded)

	assert.Equal(t, ti, decoded)
}
