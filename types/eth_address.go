package types

import (
	"fmt"

	"github.com/snowfork/go-substrate-rpc-client/v4/scale"
)

type EthAddress struct {
	Address [20]byte
}

func NewEthAddress(str string) (EthAddress, error) {
	b, err := HexDecodeString(str)
	if err != nil {
		return EthAddress{}, err
	}
	var address [20]byte
	copy(address[:], b)

	return EthAddress{Address: address}, nil
}

func (m EthAddress) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(m.Address)
	if err != nil {
		return err
	}

	return nil
}

func (m *EthAddress) Decode(decoder scale.Decoder) error {
	// If the length is 20, it's an EthAddress
	var encodedBytes []byte
	err := decoder.Decode(&encodedBytes)
	if err != nil {
		return err
	}

	if len(encodedBytes) == 20 {
		copy(m.Address[:], encodedBytes)
		return nil
	} else {
		return fmt.Errorf("invalid length for EthAddress (should be 20 bytes): %v", len(encodedBytes))
	}
}
