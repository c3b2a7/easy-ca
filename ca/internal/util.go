package internal

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

func CalculateKeyID(pubKey any) []byte {
	pkixByte, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		panic(err)
	}

	var pkiInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pkixByte, &pkiInfo)
	if err != nil {
		panic(err)
	}
	skid := sha1.Sum(pkiInfo.SubjectPublicKey.Bytes)
	return skid[:]
}

func ParseDomains(domainStr []string) []string {
	var domains []string
	re := regexp.MustCompile("^[A-Za-z0-9-.*]+$")
	for _, s := range domainStr {
		if re.MatchString(s) {
			domains = append(domains, s)
		} else {
			panic(fmt.Sprintf("invalid domain %s", s))
		}
	}

	return domains
}

func ParseIPs(ipStr []string) []net.IP {
	var ips []net.IP
	for _, s := range ipStr {
		p := net.ParseIP(s)
		if p == nil {
			panic(fmt.Sprintf("invalid IP %s", s))
		}
		ips = append(ips, p)
	}
	return ips
}

var applierList = map[string]func(name *pkix.Name, value any){
	"C": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.Country = []string{value.(string)}
		} else {
			name.Country = value.([]string)
		}
	},
	"O": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.Organization = []string{value.(string)}
		} else {
			name.Organization = value.([]string)
		}
	},
	"OU": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.OrganizationalUnit = []string{value.(string)}
		} else {
			name.OrganizationalUnit = value.([]string)
		}
	},
	"CN": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.CommonName = value.(string)
		} else {
			name.CommonName = value.([]string)[0]
		}
	},
	"SERIALNUMBER": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.SerialNumber = value.(string)
		} else {
			name.SerialNumber = value.([]string)[0]
		}
	},
	"L": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.Locality = []string{value.(string)}
		} else {
			name.Locality = value.([]string)
		}
	},
	"ST": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.Province = []string{value.(string)}
		} else {
			name.Province = value.([]string)
		}
	},
	"POSTALCODE": func(name *pkix.Name, value any) {
		if _, ok := value.(string); ok {
			name.PostalCode = []string{value.(string)}
		} else {
			name.PostalCode = value.([]string)
		}
	},
}

func ParsePKIXName(name string) (pkixName pkix.Name) {
	nTok := NewTokenizer(name, '/')
	for nTok.HasMoreTokens() {
		token := nTok.NextToken()

		if strings.Contains(token, "+") {
			pTok := NewTokenizer(token, '+')
			vTok := NewTokenizer(pTok.NextToken(), '=')

			attribute := vTok.NextToken()
			if !vTok.HasMoreTokens() {
				panic("badly formatted directory string")
			}
			applier, ok := applierList[strings.ToUpper(attribute)]
			if !ok {
				panic("unknown attribute")
			}

			value := vTok.NextToken()

			if pTok.HasMoreTokens() {
				values := []string{value}
				for pTok.HasMoreTokens() {
					values = append(values, pTok.NextToken())
				}
				applier(&pkixName, values)
			} else {
				applier(&pkixName, value)
			}
		} else if token != "" {
			vTok := NewTokenizer(token, '=')
			attribute := vTok.NextToken()
			if !vTok.HasMoreTokens() {
				panic("badly formatted directory string")
			}
			value := vTok.NextToken()
			if applier, ok := applierList[strings.ToUpper(attribute)]; ok {
				applier(&pkixName, value)
			}
		}
	}
	return
}
