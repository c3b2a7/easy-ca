package ca

import (
	"crypto/elliptic"
	"fmt"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"testing"
	"time"
)

func TestNewCertificationOptionBuilder(t *testing.T) {
	var builder *CertificateOptionsBuilder
	builder = NewCertificationOptionBuilder()
	builder.WithCA(true)
	builder.WithNotAfter(time.Now().AddDate(10, 0, 0))
	fmt.Println(builder.Build())

	builder = NewCertificationOptionBuilder()
	builder.WithCA(false)
	builder.WithNotAfter(time.Now().AddDate(0, 0, 825))
	builder.WithSubject(internal.ParsePKIXName("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy Root CA"))
	builder.WithIPs(internal.ParseIPs([]string{"127.0.0.1", "192.168.0.1"}))
	builder.WithDomains(internal.ParseDomains([]string{"localhost", "localhost.dev"}))
	fmt.Println(builder.Build())
}

func TestNewKeyOptionBuilder(t *testing.T) {
	var builder *KeyOptionsBuilder
	builder = NewKeyOptionBuilder()
	builder.WithKeySize(2048)
	builder.WithCurve(elliptic.P521())
	fmt.Println(builder.Build())

	builder = NewKeyOptionBuilder()
	builder.WithKeySize(1024)
	builder.WithCurve(elliptic.P256())
	fmt.Println(builder.Build())
}
