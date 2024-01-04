/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"time"
	"github.com/tjfoc/gmsm/sm2"
)

func (p *CertKeyPair) PrivKeyString() string {
	return base64.StdEncoding.EncodeToString(p.Key)
}

func (p *CertKeyPair) PubKeyString() string {
	return base64.StdEncoding.EncodeToString(p.Cert)
}

func newPrivKey() (interface{}, []byte, error) {
	if (false) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, privBytes, nil
	} else {
		privateKey, err := sm2.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := sm2.MarshalSm2PrivateKey(privateKey, nil)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, privBytes, nil
	}
}

func newCertTemplate() (interface{}, error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if (false) {
		if err != nil {
			return x509.Certificate{}, err
		}
		return x509.Certificate{
			Subject:      pkix.Name{SerialNumber: sn.String()},
			NotBefore:    time.Now().Add(time.Hour * (-24)),
			NotAfter:     time.Now().Add(time.Hour * 24),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			SerialNumber: sn,
		}, nil
	} else {
		if err != nil {
			return sm2.Certificate{}, err
		}
		return sm2.Certificate{
			Subject:      pkix.Name{SerialNumber: sn.String()},
			NotBefore:    time.Now().Add(time.Hour * (-24)),
			NotAfter:     time.Now().Add(time.Hour * 24),
			KeyUsage:     sm2.KeyUsageKeyEncipherment | sm2.KeyUsageDigitalSignature,
			SerialNumber: sn,
		}, nil
	}
}

func newCertKeyPair(isCA bool, isServer bool, host string, certSigner crypto.Signer, parent interface{}) (*CertKeyPair, error) {
	privateKey, privBytes, err := newPrivKey()
	if err != nil {
		return nil, err
	}

	templateInterface, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)
	if (false) {
		template := templateInterface.(x509.Certificate)
		if isCA {
			template.NotAfter = tenYearsFromNow
			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
			template.BasicConstraintsValid = true
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		if isServer {
			template.NotAfter = tenYearsFromNow
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
		// If no parent cert, it's a self signed cert
		if parent == nil || certSigner == nil {
			parent = &template
			certSigner = privateKey.(*ecdsa.PrivateKey)
		}
		rawBytes, err := x509.CreateCertificate(rand.Reader, &template, parent.(*x509.Certificate), &privateKey.(*ecdsa.PrivateKey).PublicKey, certSigner)
		if err != nil {
			return nil, err
		}
		pubKey := encodePEM("CERTIFICATE", rawBytes)

		block, _ := pem.Decode(pubKey)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		privKey := encodePEM("EC PRIVATE KEY", privBytes)
		return &CertKeyPair{
			Key:     privKey,
			Cert:    pubKey,
			Signer:  privateKey.(*ecdsa.PrivateKey),
			TLSCert: cert,
		}, nil
	} else {
		template := templateInterface.(sm2.Certificate)
		if isCA {
			template.NotAfter = tenYearsFromNow
			template.IsCA = true
			template.KeyUsage |= sm2.KeyUsageCertSign | sm2.KeyUsageCRLSign
			template.ExtKeyUsage = []sm2.ExtKeyUsage{sm2.ExtKeyUsageAny}
			template.BasicConstraintsValid = true
		} else {
			template.ExtKeyUsage = []sm2.ExtKeyUsage{sm2.ExtKeyUsageClientAuth}
		}
		if isServer {
			template.NotAfter = tenYearsFromNow
			template.ExtKeyUsage = append(template.ExtKeyUsage, sm2.ExtKeyUsageServerAuth)
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
		// If no parent cert, it's a self signed cert
		if parent == nil || certSigner == nil {
			parent = &template
			certSigner = privateKey.(*sm2.PrivateKey)
		}
		rawBytes, err := sm2.CreateCertificate(rand.Reader, &template, parent.(*sm2.Certificate), &privateKey.(*sm2.PrivateKey).PublicKey, certSigner)
		if err != nil {
			return nil, err
		}
		pubKey := encodePEM("CERTIFICATE", rawBytes)

		block, _ := pem.Decode(pubKey)
		cert, err := sm2.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		privKey := encodePEM("EC PRIVATE KEY", privBytes)
		return &CertKeyPair{
			Key:     privKey,
			Cert:    pubKey,
			Signer:  privateKey.(*sm2.PrivateKey),
			TLSCert: cert,
		}, nil
	}
}

func encodePEM(keyType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: data})
}

// CertKeyPairFromString converts the given strings in base64 encoding to a CertKeyPair
func CertKeyPairFromString(privKey string, pubKey string) (*CertKeyPair, error) {
	priv, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	return &CertKeyPair{
		Key:  priv,
		Cert: pub,
	}, nil
}
