package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
)

var errUnmarshalNilLevel = errors.New("can't unmarshal a nil *KeyAlgorithm")

type KeyAlgorithm int8

const (
	RSA KeyAlgorithm = 1 << iota
	ECDSA
	ED25519
)

func (k KeyAlgorithm) String() string {
	switch k {
	case RSA:
		return "rsa"
	case ECDSA:
		return "ecdsa"
	case ED25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

func ParseKeyAlgorithm(text string) (KeyAlgorithm, error) {
	var keyAlgorithm KeyAlgorithm
	err := keyAlgorithm.UnmarshalText([]byte(text))
	return keyAlgorithm, err
}

// MarshalText marshals the KeyAlgorithm to text.
func (l KeyAlgorithm) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

// UnmarshalText unmarshal text to a KeyAlgorithm. Like MarshalText.
func (l *KeyAlgorithm) UnmarshalText(text []byte) error {
	if l == nil {
		return errUnmarshalNilLevel
	}
	if !l.unmarshalText(text) && !l.unmarshalText(bytes.ToLower(text)) {
		return fmt.Errorf("unrecognized KeyAlgorithm: %q", text)
	}
	return nil
}

func (l *KeyAlgorithm) unmarshalText(text []byte) bool {
	switch string(text) {
	case "rsa", "RSA", "": // make the zero value useful
		*l = RSA
	case "ecdsa", "ECDSA":
		*l = ECDSA
	case "ed25519", "ED25519":
		*l = ED25519
	default:
		return false
	}
	return true
}

type KeyGenerator func(opts keyOptions) (crypto.PrivateKey, error)

var generateList = map[KeyAlgorithm]KeyGenerator{
	RSA: func(opts keyOptions) (crypto.PrivateKey, error) {
		return rsa.GenerateKey(opts.Random, opts.KeySize)
	},
	ECDSA: func(opts keyOptions) (crypto.PrivateKey, error) {
		return ecdsa.GenerateKey(opts.Curve, opts.Random)
	},
	ED25519: func(opts keyOptions) (crypto.PrivateKey, error) {
		_, priv, err := ed25519.GenerateKey(opts.Random)
		return priv, err
	},
}

func GetKeyGenerator(keyType KeyAlgorithm) KeyGenerator {
	return generateList[keyType]
}
