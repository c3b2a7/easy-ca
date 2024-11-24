package ca

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"github.com/c3b2a7/easy-ca/ca/internal/testdata"
	"os"
	"testing"
	"time"
)

func TestCreateSelfSignedCACertificate(t *testing.T) {
	kpg, _ := GetKeyPairGenerator("ECDSA", WithCurve(elliptic.P384()))
	rootKeyPair, _ := kpg.GenerateKeyPair()

	root, err := CreateSelfSignedRootCertificate(rootKeyPair, WithCA(true), WithSubject(testdata.RootCASubjectName))
	if err != nil {
		t.Fatal(err)
	}
	rootCertFile, _ := os.OpenFile("./root_cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootCertFile.Close()
	EncodeCertificateChain(rootCertFile, []*x509.Certificate{root})
	rootKeyFile, _ := os.OpenFile("./root_key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootKeyFile.Close()
	EncodePKCS1PrivateKey(rootKeyFile, rootKeyPair.PrivateKey)

	middleKeyPair, _ := kpg.GenerateKeyPair()
	middle, err := CreateCertificateWithIssuer(middleKeyPair,
		WithCA(true),
		WithSubject(testdata.IntermediateCASubjectName),
		WithIssuer(root),
		WithIssuerPrivateKey(rootKeyPair.PrivateKey),
		WithNotAfter(time.Now().AddDate(10, 0, 0)),
	)
	if err != nil {
		t.Fatal(err)
	}

	middleCertfile, _ := os.OpenFile("./cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleCertfile.Close()
	EncodeCertificateChain(middleCertfile, []*x509.Certificate{middle, root})
	middleKeyFile, _ := os.OpenFile("./key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleKeyFile.Close()
	EncodePKCS1PrivateKey(middleKeyFile, middleKeyPair.PrivateKey)
}

func TestEncodePKCS8PublicKey(t *testing.T) {
	const publicKeyPEM = testdata.PublicKeyPEM

	block, _ := pem.Decode([]byte(publicKeyPEM))
	publicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)

	var buf bytes.Buffer
	if err := EncodePKCS8PublicKey(&buf, publicKey); err != nil {
		t.Errorf("error to encode public key in PKCS8 format: %s", err)
	}

	if buf.String() != publicKeyPEM {
		t.Errorf("expected: %s, got: %s", publicKeyPEM, buf.String())
	}
}
