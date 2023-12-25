/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	gmsmx509 "github.com/tjfoc/gmsm/x509"
)

type CA struct {
	Name               string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	Signer             crypto.Signer
	SignCert           interface{}
	SignKey            bccsp.Key
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) (*CA, error) {
	var response error
	var ca *CA

	err := os.MkdirAll(baseDir, 0o755)
	if err != nil {
		return nil, err
	}
	priv, err := csp.GeneratePrivateKey(baseDir)
	response = err
	if err == nil {
		// get public signing certificate
		sm2PubKey, err := csp.GetSM2PublicKey(priv)
		response = err
		if err == nil {
			template := x509Template()
			// this is a CA
			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageDigitalSignature |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign
			template.ExtKeyUsage = []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			}

			// set the organization for the subject
			subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
			subject.Organization = []string{org}
			subject.CommonName = name

			template.Subject = subject
			template.SubjectKeyId = priv.SKI()

			sm2Cert := gm.ParseX509Certificate2Sm2(&template)
			sm2Cert.PublicKey = sm2PubKey
			x509Cert, err := genCertificateSM2(baseDir, name, sm2Cert, sm2Cert, sm2PubKey, priv)

			response = err
			if err == nil {
				ca = &CA{
					Name: name,
					// Signer:             signer,
					Country:            country,
					Province:           province,
					Locality:           locality,
					OrganizationalUnit: orgUnit,
					StreetAddress:      streetAddress,
					PostalCode:         postalCode,
					SignCert:           x509Cert,
					SignKey:            priv,
				}
			}
		}
	}

	return ca, response
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub interface{},
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) (*gmsmx509.Certificate, error) {
	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	// set the organization for the subject
	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject
	for _, san := range alternateNames {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	if ca.SignCert == nil || ca.SignCert.(*gmsmx509.Certificate).PublicKey == nil {
		return nil, fmt.Errorf("Sign cert can not be nil")
	}

	sm2Tpl := gm.ParseX509Certificate2Sm2(&template)
	cert, err := genCertificateSM2(baseDir, name, sm2Tpl, ca.SignCert.(*gmsmx509.Certificate), pub.(*sm2.PublicKey), ca.SignKey)

	if err != nil {
		return nil, err
	}

	return cert, nil

}

// compute Subject Key Identifier using RFC 7093, Section 2, Method 4
func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}

// compute Subject Key Identifier using RFC 7093, Section 2, Method 4
func computeSKIForSM2(privKey *sm2.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sm3.Sm3Sum(raw)
	return hash[:]
}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// Additional for X509 subject
func subjectTemplateAdditional(
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) pkix.Name {
	name := subjectTemplate()
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

// default template for X509 certificates
func x509Template() x509.Certificate {
	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	// basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return x509
}

// generate a signed X509 certificate using ECDSA
func genCertificateECDSA(
	baseDir,
	name string,
	template,
	parent *x509.Certificate,
	pub *ecdsa.PublicKey,
	priv interface{},
) (*x509.Certificate, error) {
	// create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	// write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	// pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

// LoadCertificateECDSA load a ecdsa cert from a file in cert path
func LoadCertificateECDSA(certPath string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Errorf("%s: wrong DER encoding", path)
			}
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}

// generate a signed X509 certificate using SM2
func genCertificateSM2(
	baseDir,
	name string,
	template,
	parent *gmsmx509.Certificate,
	pub *sm2.PublicKey,
	priv interface{},
) (*gmsmx509.Certificate, error) {
	certBytes, err := gm.CreateCertificateToPem(template, parent, pub, priv.(bccsp.Key))
	if err != nil {
		return nil, err
	}

	// write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	// pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	// x509Cert, err := x509.ParseCertificate(certBytes)
	x509Cert, err := gmsmx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

// LoadCertificateSM2 load a sm2 cert from a file in cert path
func LoadCertificateSM2(certPath string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Errorf("%s: wrong DER encoding", path)
			}
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}
