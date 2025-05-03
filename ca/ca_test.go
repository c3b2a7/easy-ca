package ca

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"github.com/c3b2a7/easy-ca/ca/internal/testdata"
	"testing"
	"time"
)

func TestCreateSelfSignedCACertificate(t *testing.T) {
	kpg, _ := GetKeyPairGenerator(ECDSA, WithCurve(elliptic.P384()))
	rootKeyPair, _ := kpg.GenerateKeyPair()

	rootCA, err := CreateSelfSignedRootCertificate(rootKeyPair, WithCA(true), WithSubject(testdata.RootCASubjectName))
	if err != nil {
		t.Fatal(err)
	}

	certBuffer := &bytes.Buffer{}
	if err = EncodeCertificateChain(certBuffer, []*x509.Certificate{rootCA}); err != nil {
		t.Fatalf("EncodeCertificateChain() error = %v", err)
	}

	keyBuffer := &bytes.Buffer{}
	if err = EncodePKCS1PrivateKey(keyBuffer, rootKeyPair.PrivateKey); err != nil {
		t.Fatalf("EncodePKCS1PrivateKey() error = %v", err)
	}

	middleKeyPair, _ := kpg.GenerateKeyPair()
	intermediateCA, err := CreateCertificateWithIssuer(middleKeyPair,
		WithCA(true),
		WithSubject(testdata.IntermediateCASubjectName),
		WithIssuer(rootCA),
		WithIssuerPrivateKey(rootKeyPair.PrivateKey),
		WithNotAfter(time.Now().AddDate(10, 0, 0)),
	)
	if err != nil {
		t.Fatalf("CreateCertificateWithIssuer() error = %v", err)
	}

	certBuffer.Reset()
	keyBuffer.Reset()

	if err = EncodeCertificateChain(certBuffer, []*x509.Certificate{intermediateCA, rootCA}); err != nil {
		t.Fatalf("EncodeCertificateChain() error = %v", err)
	}
	if err = EncodePKCS1PrivateKey(keyBuffer, middleKeyPair.PrivateKey); err != nil {
		t.Fatalf("EncodePKCS1PrivateKey() error = %v", err)
	}
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
