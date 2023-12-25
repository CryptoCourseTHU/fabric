/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	gmsmx509 "github.com/tjfoc/gmsm/x509"
)

// LoadPrivateKey loads a private key from a file in keystorePath.  It looks
// for a file ending in "_sk" and expects a PEM-encoded PKCS8 EC private key.
func LoadPrivateKey(keystorePath string) (*sm2.PrivateKey, error) {
	var priv *sm2.PrivateKey

	walkFunc := func(path string, info os.FileInfo, pathErr error) error {
		if !strings.HasSuffix(path, "_sk") {
			return nil
		}

		rawKey, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		priv, err = parsePrivateKeyPEM(rawKey)
		if err != nil {
			return errors.WithMessage(err, path)
		}

		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return priv, err
}

func parsePrivateKeyPEM(rawKey []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, errors.New("bytes are not PEM encoded")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "pem bytes are not PKCS8 encoded ")
	}

	priv, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("pem bytes do not contain an EC private key")
	}
	return priv, nil
}

// GeneratePrivateKey creates an EC private key using a P-256 curve and stores
// it in keystorePath.
func GeneratePrivateKey(keystorePath string) (bccsp.Key, error) {
	var err error
	var priv bccsp.Key
	var csp bccsp.BCCSP

	if factory.GetDefaultOpts().Default == "SW" {
		csp, err = factory.GetBCCSPFromOpts(&factory.FactoryOpts{
			Default: "SW",
			SW: &factory.SwOpts{
				Hash:     "SHA2",
				Security: 256,

				FileKeystore: &factory.FileKeystoreOpts{
					KeyStorePath: keystorePath,
				},
			},
		})
	} else {
		csp, err = factory.GetBCCSPFromOpts(&factory.FactoryOpts{
			Default: "GM",
			GM: &factory.SwOpts{
				Hash:     "SM3",
				Security: 256,

				FileKeystore: &factory.FileKeystoreOpts{
					KeyStorePath: keystorePath,
				},
			},
		})
	}

	if err == nil {
		// generate a key
		if factory.GetDefaultOpts().Default == "SW" {
			priv, err = csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
		} else {
			priv, err = csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		}
		if err == nil {
			// create a crypto.Signer
			_, err = signer.New(csp, priv)
		}
	}
	return priv, err
}

/*
*
ECDSA signer implements the crypto.Signer interface for ECDSA keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.
*/
type ECDSASigner struct {
	PrivateKey *ecdsa.PrivateKey
}

// Public returns the ecdsa.PublicKey associated with PrivateKey.
func (e *ECDSASigner) Public() crypto.PublicKey {
	return &e.PrivateKey.PublicKey
}

// Sign signs the digest and ensures that signatures use the Low S value.
func (e *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, e.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// ensure Low S signatures
	sig := toLowSForECDSA(
		e.PrivateKey.PublicKey,
		ECDSASignature{
			R: r,
			S: s,
		},
	)

	// return marshaled signature
	return asn1.Marshal(sig)
}

/*
*
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowSForECDSA creates
signatures in this canonical form.
*/
func toLowSForECDSA(key ecdsa.PublicKey, sig ECDSASignature) ECDSASignature {
	// calculate half order of the curve
	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
	// check if s is greater than half order of curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(key.Params().N, sig.S)
	}
	return sig
}

type ECDSASignature struct {
	R, S *big.Int
}

/*
*
ECDSA signer implements the crypto.Signer interface for ECDSA keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.
*/
type SM2Signer struct {
	PrivateKey *sm2.PrivateKey
}

// Public returns the ecdsa.PublicKey associated with PrivateKey.
func (e *SM2Signer) Public() crypto.PublicKey {
	return &e.PrivateKey.PublicKey
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	one := new(big.Int).SetInt64(1)
	if random == nil {
		random = rand.Reader // If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func Sm2Sign(random io.Reader, priv *sm2.PrivateKey, digest []byte) (r, s *big.Int, err error) {
	one := new(big.Int).SetInt64(1)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errors.New("zero parameter")
	}
	var k *big.Int
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, random)
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

// Sign signs the digest and ensures that signatures use the Low S value.
func (e *SM2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sm2Sign(rand, e.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// ensure Low S signatures
	sig := toLowSForSM2(
		e.PrivateKey.PublicKey,
		SM2Signature{
			R: r,
			S: s,
		},
	)

	// return marshaled signature
	return asn1.Marshal(sig)
}

/*
*
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowSForSM2 creates
signatures in this canonical form.
*/
func toLowSForSM2(key sm2.PublicKey, sig SM2Signature) SM2Signature {
	// calculate half order of the curve
	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
	// check if s is greater than half order of curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(key.Params().N, sig.S)
	}
	return sig
}

type SM2Signature struct {
	R, S *big.Int
}

func GetSM2PublicKey(priv bccsp.Key) (*sm2.PublicKey, error) {
	// get the public key
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}
	// unmarshal using pkix
	sm2PubKey, err := gmsmx509.ParseSm2PublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return sm2PubKey, nil
}
