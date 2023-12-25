package gm

import (
	"testing"

	"github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/stretchr/testify/assert"
)

func TestNewDummyKeyStore(t *testing.T) {
	t.Parallel()

	ks := NewDummyKeyStore()
	assert.NotNil(t, ks)
}

func TestDummyKeyStore_GetKey(t *testing.T) {
	t.Parallel()

	ks := NewDummyKeyStore()
	_, err := ks.GetKey([]byte{0, 1, 2, 3, 4})
	assert.Error(t, err)
}

func TestDummyKeyStore_ReadOnly(t *testing.T) {
	t.Parallel()

	ks := NewDummyKeyStore()
	assert.True(t, ks.ReadOnly())
}

func TestDummyKeyStore_StoreKey(t *testing.T) {
	t.Parallel()

	ks := NewDummyKeyStore()
	err := ks.StoreKey(&mocks.MockKey{})
	assert.Error(t, err)
}
