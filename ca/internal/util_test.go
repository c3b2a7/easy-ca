package internal

import (
	"crypto/x509/pkix"
	"testing"
)

func TestParsePKIXName(t *testing.T) {
	pkixName := ParsePKIXName("/C=CN/O=Easy CA/OU=IT Dept./CN=Easy Root CA")
	if pkixName.String() == "" {
		t.Errorf("error to parse pkix name")
	}

	actualPkixName := pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"Easy CA"},
		OrganizationalUnit: []string{"IT Dept."},
		CommonName:         "Easy Root CA",
	}

	if actualPkixName.String() != pkixName.String() {
		t.Errorf("error to parse pkix name")
	}
}
