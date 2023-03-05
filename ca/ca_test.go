package ca

import (
	"crypto/elliptic"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

func TestCreateSelfSignedCACertificate(t *testing.T) {
	kpg, _ := GetKeyPairGenerator("ECDSA", WithCurve(elliptic.P384()))
	rootKeyPair, _ := kpg.GenerateKeyPair()

	root, _ := CreateSelfSignedRootCertificate(rootKeyPair, WithCA(true), WithSubject("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy Root CA"))
	rootCertFile, _ := os.OpenFile("./root_cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootCertFile.Close()
	EncodeCertificateChain(rootCertFile, []*x509.Certificate{root})
	rootKeyFile, _ := os.OpenFile("./root_key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootKeyFile.Close()
	EncodePKCS1PrivateKey(rootKeyFile, rootKeyPair.PrivateKey)

	middleKeyPair, _ := kpg.GenerateKeyPair()
	middle, _ := CreateMiddleRootCertificate(middleKeyPair,
		WithCA(true),
		WithSubject("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy CA Authority R1"),
		WithIssuer(root),
		WithIssuerPrivateKey(rootKeyPair.PrivateKey),
		WithNotAfter(time.Now().AddDate(10, 0, 0)),
	)
	middleCertfile, _ := os.OpenFile("./cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleCertfile.Close()
	EncodeCertificateChain(middleCertfile, []*x509.Certificate{middle, root})
	middleKeyFile, _ := os.OpenFile("./key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleKeyFile.Close()
	EncodePKCS1PrivateKey(middleKeyFile, middleKeyPair.PrivateKey)
}
