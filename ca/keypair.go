package ca

import (
	"crypto"
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

type commonKeyPairGenerator struct {
	generate KeyGenerator
	opts     keyOptions
}

func (kpg *commonKeyPairGenerator) GenerateKeyPair() (KeyPair, error) {
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
