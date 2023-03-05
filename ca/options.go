package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/c3b2a7/easy-ca/ca/constants"
	"github.com/c3b2a7/easy-ca/ca/internal"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	defaultKeyOptions = keyOptions{
		Random:  rand.Reader,
		KeySize: 2048,
		Curve:   elliptic.P384(),
	}

	defaultCertificateOptions = certificateOptions{
		Version:      3,
		SerialNumber: internal.SerialNumber(-1),
		IsCA:         true,
		Subject:      lookupSubjectFromEnv(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(20, 0, 0),
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

type KeyOption interface {
	apply(*keyOptions)
}

type CertificateOption interface {
	apply(*certificateOptions)
}

type funcKeyOption struct {
	f func(*keyOptions)
}

func (f funcKeyOption) apply(opts *keyOptions) {
	f.f(opts)
}

type funcCertificateOption struct {
	f func(*certificateOptions)
}

func (f funcCertificateOption) apply(opts *certificateOptions) {
	f.f(opts)
}

func newFuncKeyOption(opt func(*keyOptions)) KeyOption {
	return &funcKeyOption{opt}
}

func newFuncCertificateOption(opt func(*certificateOptions)) CertificateOption {
	return &funcCertificateOption{opt}
}

type keyOptions struct {
	Random  io.Reader
	KeySize int
	Curve   elliptic.Curve
}

type certificateOptions struct {
	Version          int
	SerialNumber     *big.Int
	IsCA             bool
	Issuer           *x509.Certificate
	IssuerPrivateKey any

	Subject   pkix.Name
	NotBefore time.Time
	NotAfter  time.Time
	IPs       []net.IP
	Domains   []string
}

func WithVersion(version int) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.Version = version
	})
}

func WithSerialNumber(serialNumber *big.Int) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.SerialNumber = serialNumber
	})
}

func WithCA(isCA bool) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.IsCA = isCA
	})
}

func WithIssuer(issuer *x509.Certificate) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.Issuer = issuer
	})
}

func WithIssuerPrivateKey(issuerPrivateKey any) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.IssuerPrivateKey = issuerPrivateKey
	})
}

func WithSubject(subject string) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.Subject = internal.ParsePKIXName(subject)
	})
}

func WithNotBefore(notBefore time.Time) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.NotBefore = notBefore
	})
}

func WithNotAfter(notAfter time.Time) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.NotAfter = notAfter
	})
}

func WithIPs(ips []string) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.IPs = internal.ParseIPs(ips)
	})
}

func WithDomains(domains []string) CertificateOption {
	return newFuncCertificateOption(func(options *certificateOptions) {
		options.Domains = internal.ParseDomains(domains)
	})
}

func WithRandom(random io.Reader) KeyOption {
	return newFuncKeyOption(func(options *keyOptions) {
		options.Random = random
	})
}

func WithKeySize(keySize int) KeyOption {
	return newFuncKeyOption(func(options *keyOptions) {
		options.KeySize = keySize
	})
}

func WithCurve(curve elliptic.Curve) KeyOption {
	return newFuncKeyOption(func(options *keyOptions) {
		options.Curve = curve
	})
}
