package ca

import (
	"crypto/elliptic"
	"crypto/x509"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"os"
	"runtime/debug"
	"testing"
)

func TestCreateSelfSignedCACertificate(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Errorf("Generate certificate with err : %s \nstack: %s", err, string(debug.Stack()))
		}
	}()

	kpg, _ := GetKeyPairGenerator("ECDSA", NewKeyOptionBuilder().WithCurve(elliptic.P384()).Build())
	rootKeyPair, _ := kpg.GenerateKeyPair()

	var certificateOptionsBuilder *CertificateOptionsBuilder
	certificateOptionsBuilder = NewCertificationOptionBuilder()
	certificateOptionsBuilder.WithCA(true)
	certificateOptionsBuilder.WithSubject(internal.ParsePKIXName("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy Root CA"))
	root, _ := CreateSelfSignedCACertificate(rootKeyPair, certificateOptionsBuilder.Build())

	rootCertFile, _ := os.OpenFile("./root_cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootCertFile.Close()
	EncodeCertificateChain(rootCertFile, []*x509.Certificate{root})
	rootKeyFile, _ := os.OpenFile("./root_key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer rootKeyFile.Close()
	EncodePKCS1PrivateKey(rootKeyFile, rootKeyPair.PrivateKey)

	middleKeyPair, _ := kpg.GenerateKeyPair()
	certificateOptionsBuilder = NewCertificationOptionBuilder()
	certificateOptionsBuilder.WithCA(true)
	certificateOptionsBuilder.WithSubject(internal.ParsePKIXName("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy CA Authority R1")).Build()
	certificateOptionsBuilder.WithIssuer(root)
	certificateOptionsBuilder.WithIssuerPrivateKey(rootKeyPair.PrivateKey)
	middle, _ := CreateMiddleCACertificate(middleKeyPair, certificateOptionsBuilder.Build())
	middleCertfile, _ := os.OpenFile("./cert.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleCertfile.Close()
	EncodeCertificateChain(middleCertfile, []*x509.Certificate{middle, root})
	middleKeyFile, _ := os.OpenFile("./key.pem", os.O_CREATE|os.O_WRONLY, 0600)
	defer middleKeyFile.Close()
	EncodePKCS1PrivateKey(middleKeyFile, middleKeyPair.PrivateKey)
}
