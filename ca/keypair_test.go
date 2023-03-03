package ca

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

func TestGetInstance(t *testing.T) {
	var kpg KeyPairGenerator

	kpg, _ = GetKeyPairGenerator("ECDSA", NewKeyOptionBuilder().WithCurve(elliptic.P256()).Build())
	fmt.Println(kpg.GenerateKeyPair())
	fmt.Println(kpg.GenerateKeyPair())

	kpg, _ = GetKeyPairGenerator("RSA", NewKeyOptionBuilder().Build())
	fmt.Println(kpg.GenerateKeyPair())
	fmt.Println(kpg.GenerateKeyPair())

	kpg, _ = GetKeyPairGenerator("RSA", NewKeyOptionBuilder().WithKeySize(1024).Build())
	fmt.Println(kpg.GenerateKeyPair())
	fmt.Println(kpg.GenerateKeyPair())
}
