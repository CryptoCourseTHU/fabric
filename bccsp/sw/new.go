/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SHA2", keyStore)
}

// NewWithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	// 设置默认的安全等级、Hash函数
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	gmbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4CBCPKCS7Encryptor{})

	// Set the Decryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4CBCPKCS7Decryptor{})

	// Set the Signers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2Signer{})

	// Set the Verifiers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyVerifier{})
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyVerifier{})

	// Set the Hashers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.hashFunction})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: sm3.New})

	// Set the key generators
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{})

	// Set the key importers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PKIXPublicKeyImportOpts{}), &sm2PKIXPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{}), &sm2GoPublicKeyImportOptsKeyImporter{})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: gmbccsp})

	return gmbccsp, nil
}
