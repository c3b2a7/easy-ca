package ca

import (
	"testing"
)

func TestGetKeyPairGenerator(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"ECDSA"},
		{"RSA"},
		{"ED25591"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GetKeyPairGenerator(test.name); err != nil {
				t.Errorf("failed to get %s keypair generator, err: %s\n", test.name, err)
			}
		})
	}
}

func TestErrUnknownAlgorithm(t *testing.T) {
	_, err := GetKeyPairGenerator("Unknown")
	if err != ErrUnknownAlgorithm {
		t.Error("unexpected error: ", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"ECDSA"},
		{"RSA"},
		{"ED25591"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var kgp KeyPairGenerator
			var err error
			if kgp, err = GetKeyPairGenerator(test.name); err != nil {
				t.Errorf("failed to get %s keypair generator, err: %s\n", test.name, err)
			}
			if _, err = kgp.GenerateKeyPair(); err != nil {
				t.Errorf("failed to generate %s keypair, err: %s\n", test.name, err)
			}
		})
	}
}

func TestNewKeyPair(t *testing.T) {
	if _, err := NewKeyPair(nil); err != ErrUnknownPrivateKey {
		t.Error("unexpected error: ", err)
	}
}
