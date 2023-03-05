package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/c3b2a7/easy-ca/ca/constants"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"io"
	"strings"
	"time"
)

var (
	ErrInvalidCertOptions = errors.New("invalid certificate options")
)

// GetKeyPairGenerator returns a KeyPairGenerator
// The following algorithm are currently supported: ECDSA, RSA, ED25591
// Unsupported algorithm result in an error.
func GetKeyPairGenerator(algorithm string, opts ...KeyOption) (KeyPairGenerator, error) {
	algorithm = strings.ToUpper(algorithm)
	if choice, ok := generateList[algorithm]; ok {
		kopts := defaultKeyOptions
		for _, opt := range opts {
			opt.apply(&kopts)
		}
		return &keyPairGenerator{
			generate: choice,
			opts:     kopts,
		}, nil
	}
	return nil, ErrUnknownAlgorithm
}

// CreateSelfSignedRootCertificate create a self-signed root certificate
func CreateSelfSignedRootCertificate(keyPair KeyPair, certOpts ...CertificateOption) (*x509.Certificate, error) {
	if keyPair.PublicKey == nil || keyPair.PrivateKey == nil {
		return nil, errors.New("empty keypair")
	}
	opts := applyDefaultCertificateOptions(certOpts...)
	template := toCertificateTemplate(opts)
	return createCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
}

// CreateMiddleRootCertificate using parent certificate and parent private key to create a middle root certificate
func CreateMiddleRootCertificate(keyPair KeyPair, certOpts ...CertificateOption) (*x509.Certificate, error) {
	opts := applyDefaultCertificateOptions(certOpts...)
	if opts.Issuer == nil || opts.IssuerPrivateKey == nil {
		return nil, ErrInvalidCertOptions
	}
	if keyPair.PublicKey == nil {
		return nil, errors.New("empty public key")
	}
	template := toCertificateTemplate(opts)
	return createCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
}

// CreateGeneralCertificate create a general certificate signed by parent private key
func CreateGeneralCertificate(keyPair KeyPair, certOpts ...CertificateOption) (*x509.Certificate, error) {
	opts := applyDefaultCertificateOptions(certOpts...)
	if opts.Issuer == nil || opts.IssuerPrivateKey == nil {
		return nil, ErrInvalidCertOptions
	}
	if keyPair.PublicKey == nil {
		return nil, errors.New("empty public key")
	}
	template := toCertificateTemplate(opts)
	return createCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
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

func createCertificate(random io.Reader, template, parent *x509.Certificate, pub, priv any) (cert *x509.Certificate, err error) {
	template.SubjectKeyId = internal.CalculateKeyID(pub)
	template.AuthorityKeyId = parent.SubjectKeyId
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

func toCertificateTemplate(opts certificateOptions) *x509.Certificate {
	template := &x509.Certificate{
		Version:               opts.Version,
		SerialNumber:          opts.SerialNumber,
		IsCA:                  opts.IsCA,
		Subject:               opts.Subject,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
	}

	// General Certificate
	if opts.IsCA == false {
		template.IPAddresses = opts.IPs
		template.DNSNames = opts.Domains
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if opts.NotAfter.Sub(opts.NotBefore) > constants.MaxTLSHours*time.Hour {
			template.NotAfter = opts.NotBefore.Add(constants.MaxTLSHours * time.Hour)
		}
	} else {
		// Root Certificate
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if opts.NotAfter.Sub(opts.NotBefore) > constants.MaxCAHours*time.Hour {
			template.NotAfter = opts.NotBefore.Add(constants.MaxCAHours * time.Hour)
		}
		if opts.Issuer != nil && opts.IssuerPrivateKey != nil {
			// Middle Root Certificate
			template.MaxPathLen = 1
		}
	}
	return template
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
