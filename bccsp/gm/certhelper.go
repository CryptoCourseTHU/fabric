package gm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
	gmsmx509 "github.com/tjfoc/gmsm/x509"
)

// 调用SM2接口生成SM2证书
func CreateCertificateToPem(template, parent *gmsmx509.Certificate, pub *sm2.PublicKey, key bccsp.Key) (cert []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("Sign should not be emtpy")
	}
	pk := key.(*sm2PrivateKey).privKey
	der, err := gmsmx509.CreateCertificate(template, parent, pub, pk)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return block.Bytes, nil
}

// 调用SM2接口生成SM2证书请求
func CreateSm2CertificateRequestToMem(certificateRequest *gmsmx509.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	pk := key.(*sm2PrivateKey).privKey
	csr, err = gmsmx509.CreateCertificateRequestToPem(certificateRequest, pk)
	return
}

// X509 证书请求转换 SM2证书请求
func ParseX509CertificateRequest2Sm2(x509req *x509.CertificateRequest) *gmsmx509.CertificateRequest {
	sm2req := &gmsmx509.CertificateRequest{
		Raw:                      x509req.Raw,                      // Complete ASN.1 DER content (CSR, signature algorithm and signature).
		RawTBSCertificateRequest: x509req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
		RawSubjectPublicKeyInfo:  x509req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
		RawSubject:               x509req.RawSubject,               // DER encoded Subject.

		Version:            x509req.Version,
		Signature:          x509req.Signature,
		SignatureAlgorithm: gmsmx509.SignatureAlgorithm(x509req.SignatureAlgorithm),

		PublicKeyAlgorithm: gmsmx509.PublicKeyAlgorithm(x509req.PublicKeyAlgorithm),
		PublicKey:          x509req.PublicKey,

		Subject: x509req.Subject,

		// Attributes is the dried husk of a bug and shouldn't be used.
		Attributes: x509req.Attributes,

		// Extensions contains raw X.509 extensions. When parsing CSRs, this
		// can be used to extract extensions that are not parsed by this
		// package.
		Extensions: x509req.Extensions,

		// ExtraExtensions contains extensions to be copied, raw, into any
		// marshaled CSR. Values override any extensions that would otherwise
		// be produced based on the other fields but are overridden by any
		// extensions specified in Attributes.
		//
		// The ExtraExtensions field is not populated when parsing CSRs, see
		// Extensions.
		ExtraExtensions: x509req.ExtraExtensions,

		// Subject Alternate Name values.
		DNSNames:       x509req.DNSNames,
		EmailAddresses: x509req.EmailAddresses,
		IPAddresses:    x509req.IPAddresses,
	}
	return sm2req
}

// X509证书格式转换为 SM2证书格式
func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *gmsmx509.Certificate {
	sm2cert := &gmsmx509.Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: gmsmx509.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: gmsmx509.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     gmsmx509.KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		// ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:                  x509Cert.IsCA,
		MaxPathLen:            x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, gmsmx509.ExtKeyUsage(val))
	}

	return sm2cert
}

// sm2 证书转换 x509 证书
func ParseSm2Certificate2X509(sm2Cert *gmsmx509.Certificate) *x509.Certificate {
	if sm2Cert == nil {
		return nil
	}
	x509cert := &x509.Certificate{
		Raw:                     sm2Cert.Raw,
		RawTBSCertificate:       sm2Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: sm2Cert.RawSubjectPublicKeyInfo,
		RawSubject:              sm2Cert.RawSubject,
		RawIssuer:               sm2Cert.RawIssuer,

		Signature:          sm2Cert.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(sm2Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(sm2Cert.PublicKeyAlgorithm),
		PublicKey:          sm2Cert.PublicKey,

		Version:      sm2Cert.Version,
		SerialNumber: sm2Cert.SerialNumber,
		Issuer:       sm2Cert.Issuer,
		Subject:      sm2Cert.Subject,
		NotBefore:    sm2Cert.NotBefore,
		NotAfter:     sm2Cert.NotAfter,
		KeyUsage:     x509.KeyUsage(sm2Cert.KeyUsage),

		Extensions: sm2Cert.Extensions,

		ExtraExtensions: sm2Cert.ExtraExtensions,

		UnhandledCriticalExtensions: sm2Cert.UnhandledCriticalExtensions,

		// ExtKeyUsage:	[]x509.ExtKeyUsage(sm2Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: sm2Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: sm2Cert.BasicConstraintsValid,
		IsCA:                  sm2Cert.IsCA,
		MaxPathLen:            sm2Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: sm2Cert.MaxPathLenZero,

		SubjectKeyId:   sm2Cert.SubjectKeyId,
		AuthorityKeyId: sm2Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            sm2Cert.OCSPServer,
		IssuingCertificateURL: sm2Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       sm2Cert.DNSNames,
		EmailAddresses: sm2Cert.EmailAddresses,
		IPAddresses:    sm2Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: sm2Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         sm2Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: sm2Cert.CRLDistributionPoints,

		PolicyIdentifiers: sm2Cert.PolicyIdentifiers,
	}
	for _, val := range sm2Cert.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}

// 随机生成序列号
func getRandBigInt() *big.Int {
	serialNumber := make([]byte, 20)
	// _, err := io.ReadFull(rand.Reader, serialNumber)
	// if err != nil {
	// 	// return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	// }
	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F
	// template.SerialNumber = new(big.Int).SetBytes(serialNumber)
	return new(big.Int).SetBytes(serialNumber)
}
