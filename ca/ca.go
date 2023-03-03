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

func GetKeyPairGenerator(algorithm string, opts KeyOptions) (KeyPairGenerator, error) {
	algorithm = strings.ToUpper(algorithm)
	if choice, ok := generateList[algorithm]; ok {
		return &keyPairGenerator{
			generate: choice,
			opts:     opts,
		}, nil
	}
	return nil, UnknownAlgorithmError
}

func CreateSelfSignedCACertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if !opts.IsRootCA() {
		return nil, errors.New("invalid certificate options")
	}

	subjectKeyId := internal.CalculateKeyID(keyPair.PublicKey)

	template := opts.ToX509Template()
	template.BasicConstraintsValid = true
	template.SubjectKeyId = subjectKeyId
	template.AuthorityKeyId = subjectKeyId
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature

	der, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func CreateMiddleCACertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if !opts.IsMiddleCA() {
		return nil, errors.New("invalid certificate options")
	}

	template := opts.ToX509Template()
	template.BasicConstraintsValid = true
	template.SubjectKeyId = internal.CalculateKeyID(keyPair.PublicKey)
	template.AuthorityKeyId = opts.Issuer.SubjectKeyId
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	template.MaxPathLen = 1

	der, err := x509.CreateCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func CreateCertificate(keyPair KeyPair, opts CertificateOptions) (*x509.Certificate, error) {
	if opts.IsRootCA() || opts.IsMiddleCA() {
		return nil, errors.New("invalid certificate options")
	}

	template := opts.ToX509Template()
	template.SubjectKeyId = internal.CalculateKeyID(keyPair.PublicKey)
	template.AuthorityKeyId = opts.Issuer.SubjectKeyId
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	der, err := x509.CreateCertificate(rand.Reader, template, opts.Issuer, keyPair.PublicKey, opts.IssuerPrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func EncodeCertificateChain(out io.Writer, certificates []*x509.Certificate) (err error) {
	buf := new(bytes.Buffer)
	for _, certificate := range certificates {
		err = pem.Encode(buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
		if err != nil {
			return
		}
	}
	_, err = io.CopyBuffer(out, buf, make([]byte, 4096))
	return
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
		err = UnknownAlgorithmError
	}

	if err != nil {
		return
	}
	return pem.Encode(out, &pem.Block{
		Type:  pemType,
		Bytes: bytes,
	})
}

func EncodePKCS8PrivateKey(out io.Writer, privateKey any) error {
	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	return pem.Encode(out, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})
}
