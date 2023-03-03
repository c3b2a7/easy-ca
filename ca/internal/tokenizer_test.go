package internal

import (
	"testing"
)

func TestNewTokenizer(t *testing.T) {
	tokenizer := NewTokenizer("C=CN,O=Easy CA,OU=IT Dept.,CN=Easy Root CA", ',')
	if !tokenizer.HasMoreTokens() {
		t.Error("should has more tokens")
	}
	for tokenizer.HasMoreTokens() {
		if tokenizer.NextToken() == "" {
			t.Error("next token is not empty")
		}
	}
}
