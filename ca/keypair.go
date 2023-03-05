package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
)

var (
	ErrUnknownPrivateKey = errors.New("unknown private key")
	ErrUnknownAlgorithm  = errors.New("unknown algorithm")
)

type KeyPair struct {
	PublicKey  any
	PrivateKey any
}

type KeyPairGenerator interface {
	GenerateKeyPair() (KeyPair, error)
}

type keyPairGenerator struct {
	generate generator
	opts     KeyOptions
}

type generator func(opts KeyOptions) (any, error)

var generateList = map[string]generator{
	"ECDSA": func(opts KeyOptions) (any, error) {
		return ecdsa.GenerateKey(opts.Curve, opts.Random)
	},
	"RSA": func(opts KeyOptions) (any, error) {
		return rsa.GenerateKey(opts.Random, opts.KeySize)
	},
	"ED25591": func(opts KeyOptions) (any, error) {
		_, priv, err := ed25519.GenerateKey(opts.Random)
		return priv, err
	},
}

func (kpg *keyPairGenerator) GenerateKeyPair() (KeyPair, error) {
	privateKey, err := kpg.generate(kpg.opts)
	if err != nil {
		return KeyPair{}, err
	}
	return NewKeyPair(privateKey)
}

func NewKeyPair(privateKey any) (KeyPair, error) {
	var kp KeyPair
	var publicKey any
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	case ed25519.PrivateKey:
		publicKey = k.Public().(ed25519.PublicKey)
	default:
		return kp, ErrUnknownPrivateKey
	}
	kp.PublicKey = publicKey
	kp.PrivateKey = privateKey
	return kp, nil
}
