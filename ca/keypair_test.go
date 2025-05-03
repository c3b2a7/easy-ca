package ca

import (
	"errors"
	"testing"
)

func TestGetKeyPairGenerator(t *testing.T) {
	tests := []struct {
		keyAlgorithm KeyAlgorithm
	}{
		{RSA},
		{ECDSA},
		{ED25519},
	}
	for _, test := range tests {
		t.Run(test.keyAlgorithm.String(), func(t *testing.T) {
			if _, err := GetKeyPairGenerator(test.keyAlgorithm); err != nil {
				t.Errorf("failed to get %s keypair Generator, err: %s\n", test.keyAlgorithm, err)
			}
		})
	}
}

func TestErrUnknownAlgorithm(t *testing.T) {
	var alg KeyAlgorithm
	_, err := GetKeyPairGenerator(alg)
	if !errors.Is(err, ErrUnknownAlgorithm) {
		t.Error("unexpected error: ", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		keyAlgorithm KeyAlgorithm
	}{
		{RSA},
		{ECDSA},
		{ED25519},
	}
	for _, test := range tests {
		t.Run(test.keyAlgorithm.String(), func(t *testing.T) {
			var kgp KeyPairGenerator
			var err error
			if kgp, err = GetKeyPairGenerator(test.keyAlgorithm); err != nil {
				t.Errorf("failed to get %s keypair Generator, err: %s\n", test.keyAlgorithm, err)
			}
			if _, err = kgp.GenerateKeyPair(); err != nil {
				t.Errorf("failed to generate %s keypair, err: %s\n", test.keyAlgorithm, err)
			}
		})
	}
}

func TestNewKeyPair(t *testing.T) {
	if _, err := NewKeyPair(nil); !errors.Is(err, ErrUnknownPrivateKey) {
		t.Error("unexpected error: ", err)
	}
}
