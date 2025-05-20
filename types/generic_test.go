package types_test

import (
	"testing"

	. "github.com/snowfork/go-substrate-rpc-client/v4/types"

	fuzz "github.com/google/gofuzz"
	codec "github.com/snowfork/go-substrate-rpc-client/v4/types/codec"
	. "github.com/snowfork/go-substrate-rpc-client/v4/types/test_utils"
	"github.com/stretchr/testify/assert"
)

var (
	optionFuzzOpts = []FuzzOpt{
		WithFuzzFuncs(func(o *Option[U64], c fuzz.Continue) {
			if c.RandBool() {
				*o = NewEmptyOption[U64]()
				return
			}

			var u U64

			c.Fuzz(&u)

			*o = NewOption(u)
		}),
	}
)

func TestOption_EncodeDecode(t *testing.T) {
	AssertRoundTripFuzz[Option[U64]](t, 100, optionFuzzOpts...)
	AssertEncodeEmptyObj[Option[U64]](t, 1)

	testOptionEncodeLen[U64](11, t)

	accountID := NewAccountID([]byte{1, 2, 3})
	testOptionEncodeLen(accountID, t)
}

func testOptionEncodeLen[T any](testVal T, t *testing.T) {
	valEnc, err := codec.Encode(testVal)
	assert.NoError(t, err)

	opt := NewOption(testVal)
	optEnc, err := codec.Encode(opt)
	assert.NoError(t, err)

	assert.Equal(t, len(optEnc), len(valEnc)+1)
}

func TestOption_OptionMethods(t *testing.T) {
	testOptionMethods[U64](11, t)

	accountID := NewAccountID([]byte{1, 2, 3})

	testOptionMethods(&accountID, t)
	testOptionMethods(accountID, t)
}

func testOptionMethods[T any](testVal T, t *testing.T) {
	o := NewEmptyOption[T]()

	var emptyVal T

	hasValue, value := o.Unwrap()
	assert.False(t, hasValue)
	assert.Equal(t, emptyVal, value)

	o.SetSome(testVal)

	hasValue, value = o.Unwrap()
	assert.True(t, hasValue)
	assert.Equal(t, testVal, value)

	o.SetNone()
	hasValue, value = o.Unwrap()
	assert.False(t, hasValue)
	assert.Equal(t, emptyVal, value)
}
