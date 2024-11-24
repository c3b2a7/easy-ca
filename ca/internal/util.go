package internal

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"regexp"
	"strings"
)

func SerialNumber(x int64) *big.Int {
	if x > 0 {
		return big.NewInt(x)
	}
	b, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return big.NewInt(1)
	}
	return b
}

// CalculateKeyID calculate the subject key identifier
// as described in RFC 5280, Section 4.2.1.2, see
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
//
// The keyIdentifier is composed of the 160-bit SHA-1 hash of the
// value of the BIT STRING subjectPublicKey (excluding the tag,
// length, and number of unused bits).
func CalculateKeyID(pubKey any) ([]byte, error) {
	pkixByte, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var pkiInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err = asn1.Unmarshal(pkixByte, &pkiInfo); err != nil {
		return nil, err
	}
	skid := sha1.Sum(pkiInfo.SubjectPublicKey.Bytes)
	return skid[:], nil
}

// CalculateKeyFingerprint calculate the public key fingerprint
// as known as Public-Key-Pins, see RFC 7469, Section Appendix A.
//
// Similar to:
//
//	openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der |\
//	openssl dgst -sha256 -binary | openssl enc -base64
func CalculateKeyFingerprint(x any) (string, error) {
	pubKeyBytes, err := retrievePublicKey(x)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pubKeyBytes)
	pin := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(pin, sum[:])
	return string(pin), nil
}

func retrievePublicKey(x any) (b []byte, err error) {
	switch x.(type) {
	case *x509.Certificate:
		b = x.(*x509.Certificate).RawSubjectPublicKeyInfo
	default:
		b, err = x509.MarshalPKIXPublicKey(x)
	}
	return
}

func ParseDomains(domainStr []string) ([]string, error) {
	var domains []string
	re := regexp.MustCompile("^[A-Za-z0-9-.*]+$")
	for _, s := range domainStr {
		if re.MatchString(s) {
			domains = append(domains, s)
		} else {
			return nil, fmt.Errorf("invalid domain: %s", s)
		}
	}

	return domains, nil
}

func ParseIPs(ipStr []string) ([]net.IP, error) {
	var ips []net.IP
	for _, s := range ipStr {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid ip: %s", s)
		}
		ips = append(ips, p)
	}
	return ips, nil
}

type pkixNameOpt func(*pkix.Name, string)

var pkixNameOptMap = map[string]pkixNameOpt{
	"C": func(name *pkix.Name, value string) {
		name.Country = append(name.Country, value)
	},
	"ST": func(name *pkix.Name, value string) {
		name.Province = append(name.Province, value)
	},
	"L": func(name *pkix.Name, value string) {
		name.Locality = append(name.Locality, value)
	},
	"O": func(name *pkix.Name, value string) {
		name.Organization = append(name.Organization, value)
	},
	"OU": func(name *pkix.Name, value string) {
		name.OrganizationalUnit = append(name.OrganizationalUnit, value)
	},
	"CN": func(name *pkix.Name, value string) {
		name.CommonName = value
	},
	"SERIALNUMBER": func(name *pkix.Name, value string) {
		name.SerialNumber = value
	},
	"POSTALCODE": func(name *pkix.Name, value string) {
		name.PostalCode = append(name.PostalCode, value)
	},
}

func ParsePKIXName(name string) (pkix.Name, error) {
	var pkixName pkix.Name
	var errFormat = fmt.Errorf("subject name is expected to be in the format "+
		"/type0=value0/type1=value1/type2=... where characters may be escaped by \\. "+
		"This name is not in that format: '%s'", name)

	if name = strings.TrimSpace(name); name == "" {
		return pkixName, errors.New("empty subject name")
	}

	nTok := NewTokenizer(name, '/')
	for nTok.HasMoreTokens() {
		token := nTok.NextToken()
		if token != "" {
			vTok := NewTokenizer(token, '=')
			attribute := strings.TrimSpace(vTok.NextToken())
			if !vTok.HasMoreTokens() {
				return pkixName, errFormat
			}
			value := strings.TrimSpace(vTok.NextToken())
			if vTok.HasMoreTokens() {
				return pkixName, errFormat
			}
			if attribute == "" || value == "" {
				return pkixName, errFormat
			}
			if opt, ok := pkixNameOptMap[strings.ToUpper(attribute)]; ok {
				opt(&pkixName, value)
			} else {
				return pkixName, fmt.Errorf("unknown subject name attribute: %s", attribute)
			}
		}
	}
	return pkixName, nil
}
