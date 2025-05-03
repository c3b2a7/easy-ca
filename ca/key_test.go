package ca

import (
	"reflect"
	"testing"
)

func TestKeyAlgorithm_MarshalText(t *testing.T) {
	tests := []struct {
		name    string
		l       KeyAlgorithm
		want    []byte
		wantErr bool
	}{
		{"rsa", RSA, []byte("rsa"), false},
		{"ecdsa", ECDSA, []byte("ecdsa"), false},
		{"ed25519", ED25519, []byte("ed25519"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.l.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalText() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		k    KeyAlgorithm
		want string
	}{
		{"rsa", RSA, "rsa"},
		{"ecdsa", ECDSA, "ecdsa"},
		{"ed25519", ED25519, "ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyAlgorithm_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	tests := []struct {
		name    string
		l       KeyAlgorithm
		args    args
		wantErr bool
	}{
		{"rsa", RSA, args{[]byte("rsa")}, false},
		{"rsa-upper", RSA, args{[]byte("RSA")}, false},
		{"ecdsa", ECDSA, args{[]byte("ecdsa")}, false},
		{"ecdsa-upper", ECDSA, args{[]byte("ECDSA")}, false},
		{"ed25519", ED25519, args{[]byte("ed25519")}, false},
		{"ed25519-upper", ED25519, args{[]byte("ED25519")}, false},
		// error tests
		{name: "unknown", args: args{[]byte("unknown")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.l.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseKeyAlgorithm(t *testing.T) {
	type args struct {
		text string
	}
	tests := []struct {
		name    string
		args    args
		want    KeyAlgorithm
		wantErr bool
	}{
		{"rsa", args{"rsa"}, RSA, false},
		{"rsa-upper", args{"RSA"}, RSA, false},
		{"ecdsa", args{"ecdsa"}, ECDSA, false},
		{"ecdsa-upper", args{"ECDSA"}, ECDSA, false},
		{"ed25519", args{"ed25519"}, ED25519, false},
		{"ed25519-upper", args{"ED25519"}, ED25519, false},
		// error tests
		{name: "unknown", args: args{"unknown"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyAlgorithm(tt.args.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKeyAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseKeyAlgorithm() got = %v, want %v", got, tt.want)
			}
		})
	}
}
