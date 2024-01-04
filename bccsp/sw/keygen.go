package sw

import (
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
)

type sm2KeyGenerator struct {
}

func (gm *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	privKey, err := sm2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating GMSM2 key  [%s]", err)
	}

	return &sm2PrivateKey{privKey}, nil
}

type sm4KeyGenerator struct {
}

func (gm *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	lowLevelKey, err := GetRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("Failed generating GMSM4 %d key [%s]", 16, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}

