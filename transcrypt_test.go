package transcrypt

import (
	"reflect"
	"testing"
)

func TestDecrypt(t *testing.T) {
	type args struct {
		key  []byte
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
				key:  nil,
				data: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty_data",
			args: args{
				key:  []byte("key"),
				data: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid_data",
			args: args{
				key:  []byte("key"),
				data: "invalid_data",
			},
			want:    "hello world",
			wantErr: true,
		},
		{
			name: "invalid_key",
			args: args{
				key:  []byte("key"),
				data: "00:5a412cac418ecf54f86c0da4:20001500da412cac418ecf54f86c0da472bb69380c4abb66a0f8542e4b147d01fa503589bb4e3a37c2e2f979d4721da17397089d1477:737472696e67",
			},
			want:    "hello world",
			wantErr: true,
		},
		{
			name: "valid_string",
			args: args{
				key:  testKey,
				data: "00:616734a069f0cebeabfb905dff7c3d1637139cf8d8381230b6fa691eea783390:20001c0098c2bc63f2bfc02c8600d6380113c530ad902181ff8da69aacbd2510d2013da18dfc0b509bf46bd18e14f2f93b92a8a8b0bbf83e09581b3012",
			},
			want:    "hello world",
			wantErr: false,
		},
		{
			name: "valid_int",
			args: args{
				key:  testKey,
				data: "00:4bbe6ff7011dcb0a75370bb6caf5a8c0b1e166effbe1e841b391c9ae5f1ed600:20001300e4d8db67265310571fa78b1de79b9e87fefd9b7e7b1f0ba1b65888dd928d927267bd789a9b8a99b5aacbecf78819f2fa",
			},
			want:    123456,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt[any](tt.args.key, tt.args.data)
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

// TestDecrypt_LegacyStringKey pins the migration promise of the []byte key
// change: ciphertext produced by the old string-key API stays readable by
// passing []byte(oldStringKey). The key and both ciphertexts are frozen
// pre-migration vectors (the string-key era fed the string's bytes to HKDF,
// so []byte of that same string derives the identical key) and must never be
// regenerated — regenerating them would turn this back into a round-trip test.
func TestDecrypt_LegacyStringKey(t *testing.T) {
	const legacyStringKey = "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a"
	tests := []struct {
		name string
		data string
		want any
	}{
		{
			name: "legacy_string",
			data: "00:1dd908719ff16e1f5d701e97f3a0345ac08d888a24080b50482108a5ae85a4e8:20001c00aa2c6d981e121c07b6e2ee3f259b1c63e4a52bb6838b8aa300adc075b5f074a02d5ca88c0c8c658f5fb0aa09f4ffe9bc6e9c27166c4af8135f",
			want: "hello world",
		},
		{
			name: "legacy_int",
			data: "00:10c26724d88604f99d29f2882bf2177c028ffeece92656004da06f8fc0263242:20001300cd7cb3d924d15379607a23ee1dd3edb91f5cec25fb7fdadbc4357df92d68a924719a1306afaa9e5c50732b3f03b9ea74",
			want: 123456,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt[any]([]byte(legacyStringKey), tt.data)
			if err != nil {
				t.Fatalf("Decrypt() error = %v, want legacy ciphertext to stay readable", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	type args struct {
		key         []byte
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
				key:         nil,
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			wantErr: true,
		},
		{
			name: "short_key",
			args: args{
				// 15 bytes: one short of the minimum.
				key:         []byte("0123456789abcde"),
				cipherSuite: AES_256_GCM,
				d:           "hello world",
			},
			wantErr: true,
		},
		{
			name: "empty_data",
			args: args{
				key:         testKey,
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			wantErr: true,
		},
		{
			name: "unsupported_type",
			args: args{
				key:         testKey,
				cipherSuite: AES_256_GCM,
				d:           map[string]int{"a": 1},
			},
			wantErr: true,
		},
		{
			name: "unknown_cipher_suite",
			args: args{
				key:         testKey,
				cipherSuite: CipherSuite(99),
				d:           "hello world",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:         testKey,
				cipherSuite: AES_256_GCM,
				d:           "hello world",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encrypt[string](tt.args.key, tt.args.cipherSuite, tt.args.d)
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
