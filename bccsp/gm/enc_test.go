package gm

import (
	"errors"
	"reflect"
	"testing"

	"github.com/hyperledger/fabric/bccsp/gm/mocks"
	mocks2 "github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{}
	expectedPlaintext := []byte{1, 2, 3, 4}
	expectedOpts := &mocks2.EncrypterOpts{}
	expectedCiphertext := []byte{0, 1, 2, 3, 4}
	expectedErr := errors.New("no error")

	encryptors := make(map[reflect.Type]Encryptor)
	encryptors[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Encryptor{
		KeyArg:       expectedKey,
		PlaintextArg: expectedPlaintext,
		OptsArg:      expectedOpts,
		EncValue:     expectedCiphertext,
		EncErr:       expectedErr,
	}

	csp := CSP{Encryptors: encryptors}

	ct, err := csp.Encrypt(expectedKey, expectedPlaintext, expectedOpts)
	assert.Equal(t, expectedCiphertext, ct)
	assert.Equal(t, expectedErr, err)
}
