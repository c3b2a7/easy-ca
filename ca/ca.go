package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"io"
	"net"
	"time"
)

var (
	ErrInvalidCertOptions = errors.New("invalid certificate options")
	ErrEmptyPublicKey     = errors.New("empty public key")
)

var (
	// DomainValidated policy identifiers of 2.23.140.1.2.1
	//
	// Certificate issued in compliance with the TLS Baseline Requirements – No entity identity asserted
	DomainValidated = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
)

const (
	MaxTLSHours = 825 * 24      // 825 days
	MaxCAHours  = 20 * 365 * 24 // 20 years
)

// GetKeyPairGenerator returns a KeyPairGenerator
// The following algorithm are currently supported: ECDSA, RSA, ED25519
// Unsupported key algorithm will return an ErrUnknownAlgorithm error.
func GetKeyPairGenerator(algorithm KeyAlgorithm, opts ...KeyOption) (KeyPairGenerator, error) {
	keyGenerator := GetKeyGenerator(algorithm)
	if keyGenerator == nil {
		return nil, ErrUnknownAlgorithm
	}
	kopts := defaultKeyOptions
	for _, opt := range opts {
		opt.apply(&kopts)
	}
	return &commonKeyPairGenerator{
		generate: keyGenerator,
		opts:     kopts,
	}, nil
}

// CreateSelfSignedRootCertificate create a self-signed root certificate
func CreateSelfSignedRootCertificate(keyPair KeyPair, certOpts ...CertificateOption) (*x509.Certificate, error) {
	if keyPair.PublicKey == nil || keyPair.PrivateKey == nil {
		return nil, errors.New("empty keypair")
	}
	opts := applyDefaultCertificateOptions(certOpts...)
	if template, err := toCertificateTemplate(opts); err != nil {
		return nil, err
	} else {
		return createCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	}
}

// CreateCertificateWithIssuer create a certificate signed by specified issuer
func CreateCertificateWithIssuer(keyPair KeyPair, certOpts ...CertificateOption) (*x509.Certificate, error) {
	opts := applyDefaultCertificateOptions(certOpts...)
	if opts.Issuer == nil || opts.IssuerPrivateKey == nil {
		return nil, ErrInvalidCertOptions
	}
	if keyPair.PublicKey == nil {
		return nil, ErrEmptyPublicKey
	}
	if template, err := toCertificateTemplate(opts); err != nil {
		return nil, err
	} else {
		return createCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
	}
}

func EncodeCertificateChain(out io.Writer, certificates []*x509.Certificate) (err error) {
	var blocks []*pem.Block
	for _, certificate := range certificates {
		blocks = append(blocks, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
	}
	return encodeToWriter(out, blocks...)
}

func EncodePKCS1PrivateKey(out io.Writer, privateKey any) (err error) {
	var b []byte
	var pemType string
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(k)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		b, err = x509.MarshalECPrivateKey(k)
		pemType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		err = errors.New("unsupported private key type: ed25591")
	default:
		err = ErrUnknownAlgorithm
	}

	if err != nil {
		return
	}
	return encodeToWriter(out, &pem.Block{
		Type:  pemType,
		Bytes: b,
	})
}

func EncodePKCS8PrivateKey(out io.Writer, privateKey any) (err error) {
	var b []byte
	if b, err = x509.MarshalPKCS8PrivateKey(privateKey); err == nil {
		return encodeToWriter(out, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		})
	}
	return
}

func EncodePKCS8PublicKey(out io.Writer, publicKey any) (err error) {
	var b []byte
	if b, err = x509.MarshalPKIXPublicKey(publicKey); err == nil {
		return encodeToWriter(out, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		})
	}
	return
}

func createCertificate(random io.Reader, template, parent *x509.Certificate, pub, priv any) (cert *x509.Certificate, err error) {
	template.SubjectKeyId, err = internal.CalculateKeyID(pub)
	if err != nil {
		return nil, err
	}
	if template != parent {
		template.AuthorityKeyId = parent.SubjectKeyId
	}
	var der []byte
	if der, err = x509.CreateCertificate(random, template, parent, pub, priv); err == nil {
		return x509.ParseCertificate(der)
	}
	return
}

func applyDefaultCertificateOptions(certOpts ...CertificateOption) certificateOptions {
	opts := defaultCertificateOptions
	for _, opt := range certOpts {
		opt.apply(&opts)
	}
	return opts
}

func toCertificateTemplate(opts certificateOptions) (*x509.Certificate, error) {
	template := &x509.Certificate{
		Version:               opts.Version,
		SerialNumber:          opts.SerialNumber,
		IsCA:                  opts.IsCA,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
	}

	var err error
	var subject pkix.Name
	if subject, err = internal.ParsePKIXName(opts.Subject); err != nil {
		return nil, err
	}
	template.Subject = subject

	// General Certificate
	if opts.IsCA == false {
		var ipAddresses []net.IP
		var dnsNames []string
		if ipAddresses, err = internal.ParseIPs(opts.IPs); err != nil {
			return nil, err
		}
		if dnsNames, err = internal.ParseDomains(opts.Domains); err != nil {
			return nil, err
		}
		template.IPAddresses = ipAddresses
		template.DNSNames = dnsNames

		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if opts.NotAfter.Sub(opts.NotBefore) > MaxTLSHours*time.Hour {
			template.NotAfter = opts.NotBefore.Add(MaxTLSHours * time.Hour)
		}
		template.PolicyIdentifiers = []asn1.ObjectIdentifier{DomainValidated}
	} else {
		// Certificate authority
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if opts.NotAfter.Sub(opts.NotBefore) > MaxCAHours*time.Hour {
			template.NotAfter = opts.NotBefore.Add(MaxCAHours * time.Hour)
		}
		if opts.Issuer != nil && opts.IssuerPrivateKey != nil {
			// Intermediate certificate authority
			template.KeyUsage |= x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			template.MaxPathLenZero = true
			template.PolicyIdentifiers = []asn1.ObjectIdentifier{DomainValidated}
		}
	}
	return template, nil
}

func encodeToWriter(out io.Writer, blocks ...*pem.Block) error {
	buf := new(bytes.Buffer)
	for _, block := range blocks {
		if err := pem.Encode(buf, block); err != nil {
			return err
		}
	}
	_, err := io.CopyBuffer(out, buf, make([]byte, 4096))
	return err
}
