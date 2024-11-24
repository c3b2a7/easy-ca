package ca

import (
	"crypto"
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
	PublicKey  crypto.PublicKey
	PrivateKey crypto.PrivateKey
}

type KeyPairGenerator interface {
	GenerateKeyPair() (KeyPair, error)
}

type keyPairGenerator struct {
	generate generator
	opts     keyOptions
}

type generator func(opts keyOptions) (crypto.PrivateKey, error)

var generateList = map[string]generator{
	"ECDSA": func(opts keyOptions) (crypto.PrivateKey, error) {
		return ecdsa.GenerateKey(opts.Curve, opts.Random)
	},
	"RSA": func(opts keyOptions) (crypto.PrivateKey, error) {
		return rsa.GenerateKey(opts.Random, opts.KeySize)
	},
	"ED25591": func(opts keyOptions) (crypto.PrivateKey, error) {
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

	type PrivateKey interface {
		Public() crypto.PublicKey
	}
	if priv, ok := privateKey.(PrivateKey); ok {
		kp.PublicKey = priv.Public()
		kp.PrivateKey = priv
		return kp, nil
	}

	return kp, ErrUnknownPrivateKey
}
