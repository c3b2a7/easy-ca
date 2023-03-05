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
	"github.com/c3b2a7/easy-ca/ca/internal"
	"io"
	"strings"
)

var ErrInvalidCertOptions = errors.New("invalid certificate options")

func GetKeyPairGenerator(algorithm string, opts KeyOptions) (KeyPairGenerator, error) {
	algorithm = strings.ToUpper(algorithm)
	if choice, ok := generateList[algorithm]; ok {
		return &keyPairGenerator{
			generate: choice,
			opts:     opts,
		}, nil
	}
	return nil, ErrUnknownAlgorithm
}

func CreateSelfSignedCACertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if !opts.IsRootCA() {
		return nil, ErrInvalidCertOptions
	}
	template := opts.ToX509Template()
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	return createCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
}

func CreateMiddleCACertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if !opts.IsMiddleCA() {
		return nil, ErrInvalidCertOptions
	}
	template := opts.ToX509Template()
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	template.MaxPathLen = 1
	return createCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
}

func CreateGeneralCertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if opts.IsRootCA() || opts.IsMiddleCA() {
		return nil, ErrInvalidCertOptions
	}
	template := opts.ToX509Template()
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return createCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
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
	var bytes []byte
	var pemType string
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		bytes = x509.MarshalPKCS1PrivateKey(k)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		bytes, err = x509.MarshalECPrivateKey(k)
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
		Bytes: bytes,
	})
}

func EncodePKCS8PrivateKey(out io.Writer, privateKey any) (err error) {
	var bytes []byte
	if bytes, err = x509.MarshalPKCS8PrivateKey(privateKey); err == nil {
		return encodeToWriter(out, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		})
	}
	return
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
