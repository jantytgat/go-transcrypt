package transcrypt

import (
	"reflect"
	"testing"
)

func TestDecrypt(t *testing.T) {
	type args struct {
		key  string
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    any
		wantErr bool
	}{
		{
			name: "empty_key",
			args: args{
				key:  "",
				data: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty_data",
			args: args{
				key:  "key",
				data: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid_data",
			args: args{
				key:  "key",
				data: "invalid_data",
			},
			want:    "hello world",
			wantErr: true,
		},
		{
			name: "invalid_key",
			args: args{
				key:  "key",
				data: "00:5a412cac418ecf54f86c0da4:20001500da412cac418ecf54f86c0da472bb69380c4abb66a0f8542e4b147d01fa503589bb4e3a37c2e2f979d4721da17397089d1477:737472696e67",
			},
			want:    "hello world",
			wantErr: true,
		},
		{
			name: "valid_string",
			args: args{
				key:  "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
				data: "00:871aff80f75249b3ac600fe0:20001c00871aff80f75249b3ac600fe03e01c718667b2646f4056563fee9e636d375f225e0bd4e4b5243b6b3c32d2b86b01ec5e3050fae81eb3c0294b1",
			},
			want:    "hello world",
			wantErr: false,
		},
		{
			name: "valid_int",
			args: args{
				key:  "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
				data: "00:b55fc3fc3e290a9f18e79b71:20001300b55fc3fc3e290a9f18e79b710f527c8162f7a92e498d5ea120bd38fa1ef3cd1288c1612e588a5fb143db4d81f6cc5e21",
			},
			want:    123456,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.key, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	type args struct {
		key         string
		cipherSuite CipherSuite
		d           any
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty_key",
			args: args{
				key:         "",
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			wantErr: true,
		},
		{
			name: "empty_data",
			args: args{
				key:         "key",
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			wantErr: true,
		},
		{
			name: "unsupported_type",
			args: args{
				key:         "key",
				cipherSuite: AES_256_GCM,
				d:           map[string]int{"a": 1},
			},
			wantErr: true,
		},
		{
			name: "unknown_cipher_suite",
			args: args{
				key:         "key",
				cipherSuite: CipherSuite(99),
				d:           "hello world",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:         "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
				cipherSuite: AES_256_GCM,
				d:           "hello world",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encrypt(tt.args.key, tt.args.cipherSuite, tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			// The nonce is random per call, so we cannot assert an exact string;
			// verify the output is well-formed instead.
			if !regexEncryptedString.MatchString(got) {
				t.Errorf("Encrypt() produced malformed output: %q", got)
			}
		})
	}
}
