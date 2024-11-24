package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/c3b2a7/easy-ca/ca/internal/testdata"
	"testing"
)

func TestParsePKIXName(t *testing.T) {
	tests := []struct {
		name     string
		pkixName string
		expect   pkix.Name
	}{
		{"RootCA", testdata.RootCASubjectName, pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"Easy CA"},
			CommonName:   "Easy CA Root",
		}},
		{"IntermediateCA", testdata.IntermediateCASubjectName, pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Guangdong"},
			Locality:           []string{"Shenzhen"},
			Organization:       []string{"Easy CA"},
			OrganizationalUnit: []string{"IT Dept."},
			CommonName:         "Easy CA Authority R1",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if pkixName, err := ParsePKIXName(test.pkixName); err != nil {
				t.Error(err)
			} else if test.expect.String() != pkixName.String() {
				t.Errorf("error to parse pkix name, expect %s, got %s", test.expect.String(), pkixName.String())
			}
		})
	}
}

func TestCalculateKeyID(t *testing.T) {
	block, _ := pem.Decode([]byte(testdata.PublicKeyPEM))
	publicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)

	skid, err := CalculateKeyID(publicKey)
	if err != nil {
		t.Error(err)
	}
	if x := fmt.Sprintf("%x", skid); x != testdata.SKID {
		t.Errorf("calculate SKID(Subject Key Identifier, expect: %s, got: %s", testdata.SKID, x)
	}
}

func TestCalculateKeyFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		argResolver func() any
	}{
		{"PublicKey", func() any {
			block, _ := pem.Decode([]byte(testdata.PublicKeyPEM))
			publicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
			return publicKey
		}},
		{"Certificate", func() any {
			block, _ := pem.Decode([]byte(testdata.CertPEM))
			x509Cert, _ := x509.ParseCertificate(block.Bytes)
			return x509Cert
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fingerprint, err := CalculateKeyFingerprint(test.argResolver())
			if err != nil {
				t.Error(err)
			}
			if fingerprint != testdata.PKSIFingerprint {
				t.Errorf("[%s] calculate PKSI Fingerprint, expect: %s, got: %s", test.name, testdata.PKSIFingerprint, fingerprint)
			}
		})
	}
}
