package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/c3b2a7/easy-ca/ca/constants"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"io"
	"net"
	"os"
	"time"
)

var (
	defaultKeyOptions = KeyOptions{
		Random:  rand.Reader,
		KeySize: 2048,
		Curve:   elliptic.P384(),
	}

	defaultCertificateOptions = CertificateOptions{
		IsCA:      true,
		Subject:   lookupSubjectFromEnv(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(20, 0, 0),
	}
)

func lookupSubjectFromEnv() pkix.Name {
	return internal.ParsePKIXName(lookupEnv("SUBJECT", constants.DefaultCASubject))
}

func lookupEnv(envName, def string) string {
	if v, ok := os.LookupEnv(envName); ok {
		return v
	}
	return def
}

func NewCertificationOptionBuilder() *CertificateOptionsBuilder {
	return &CertificateOptionsBuilder{}
}

func NewKeyOptionBuilder() *KeyOptionsBuilder {
	return &KeyOptionsBuilder{}
}

type CertificateOptions struct {
	IsCA             bool
	Issuer           *x509.Certificate
	IssuerPrivateKey any

	Subject   pkix.Name
	NotBefore time.Time
	NotAfter  time.Time
	IPs       []net.IP
	Domains   []string
}

func (c *CertificateOptions) ToX509Template() *x509.Certificate {
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: internal.SerialNumber(-1),

		Subject:   c.Subject,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,

		BasicConstraintsValid: true,
		IsCA:                  c.IsCA,
	}

	if !c.IsRootCA() && !c.IsMiddleCA() {
		template.IPAddresses = c.IPs
		template.DNSNames = c.Domains
	}
	if !template.IsCA {
		if template.NotAfter.Sub(template.NotBefore) > constants.MaxTLSHours*time.Hour {
			template.NotAfter = template.NotBefore.Add(constants.MaxTLSHours * time.Hour)
		}
	} else {
		if template.NotAfter.Sub(template.NotBefore) > constants.MaxCAHours*time.Hour {
			template.NotAfter = template.NotBefore.Add(constants.MaxCAHours * time.Hour)
		}
	}

	return template
}

func (c *CertificateOptions) IsRootCA() bool {
	return (c.IsCA && !c.IsMiddleCA()) || c.IsCA
}

func (c *CertificateOptions) IsMiddleCA() bool {
	return c.IsCA && c.Issuer != nil && c.IssuerPrivateKey != nil
}

type certificateOption func(*CertificateOptions)

type CertificateOptionsBuilder struct {
	opts []certificateOption
}

func (b *CertificateOptionsBuilder) appendOpt(opt func(*CertificateOptions)) {
	b.opts = append(b.opts, opt)
}

func (b *CertificateOptionsBuilder) Build() CertificateOptions {
	opts := defaultCertificateOptions
	for _, opt := range b.opts {
		opt(&opts)
	}
	return opts
}

func (b *CertificateOptionsBuilder) WithCA(isCA bool) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.IsCA = isCA
	})
	return b
}

func (b *CertificateOptionsBuilder) WithIssuer(issuer *x509.Certificate) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.Issuer = issuer
	})
	return b
}

func (b *CertificateOptionsBuilder) WithIssuerPrivateKey(issuerPrivateKey any) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.IssuerPrivateKey = issuerPrivateKey
	})
	return b
}

func (b *CertificateOptionsBuilder) WithSubject(subject pkix.Name) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.Subject = subject
	})
	return b
}

func (b *CertificateOptionsBuilder) WithNotBefore(notBefore time.Time) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.NotBefore = notBefore
	})
	return b
}

func (b *CertificateOptionsBuilder) WithNotAfter(notAfter time.Time) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.NotAfter = notAfter
	})
	return b
}

func (b *CertificateOptionsBuilder) WithIPs(ips []net.IP) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.IPs = ips
	})
	return b
}

func (b *CertificateOptionsBuilder) WithDomains(domains []string) *CertificateOptionsBuilder {
	b.appendOpt(func(options *CertificateOptions) {
		options.Domains = domains
	})
	return b
}

type KeyOptions struct {
	Random  io.Reader
	KeySize int
	Curve   elliptic.Curve
}

type keyOption func(*KeyOptions)

type KeyOptionsBuilder struct {
	opts []keyOption
}

func (b *KeyOptionsBuilder) appendOpt(opt func(options *KeyOptions)) {
	b.opts = append(b.opts, opt)
}

func (b *KeyOptionsBuilder) Build() KeyOptions {
	opts := defaultKeyOptions
	for _, opt := range b.opts {
		opt(&opts)
	}
	return opts
}

func (b *KeyOptionsBuilder) WithRandom(random io.Reader) *KeyOptionsBuilder {
	b.appendOpt(func(options *KeyOptions) {
		options.Random = random
	})
	return b
}

func (b *KeyOptionsBuilder) WithKeySize(keySize int) *KeyOptionsBuilder {
	b.appendOpt(func(options *KeyOptions) {
		options.KeySize = keySize
	})
	return b
}

func (b *KeyOptionsBuilder) WithCurve(curve elliptic.Curve) *KeyOptionsBuilder {
	b.appendOpt(func(options *KeyOptions) {
		options.Curve = curve
	})
	return b
}
