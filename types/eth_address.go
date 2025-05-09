package types

import (
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
	err := decoder.Decode(&m.Address)
	if err != nil {
		return err
	}

	return nil
}
