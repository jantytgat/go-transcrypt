package transcrypt

import (
	"fmt"
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
				data: "00:5a412cac418ecf54f86c0da4:20001500da412cac418ecf54f86c0da472bb69380c4abb66a0f8542e4b147d01fa503589bb4e3a37c2e2f979d4721da17397089d1477:737472696e67",
			},
			want:    "hello world",
			wantErr: false,
		},
		{
			name: "valid_int",
			args: args{
				key:  "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
				data: "00:41ce7b530435c9189a203937:20000f00c1ce7b530435c9189a20393717bf895ce6d904a75640a6de8d2e33ab3c2fb3751e2825e9f6f2b23f5bf4df12:696e74",
			},
			want:    123456,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.key, tt.args.data)
			if err != nil {
				if (err != nil) != tt.wantErr {
					t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
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
		salt        []byte
		cipherSuite CipherSuite
		d           any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "empty_key",
			args: args{
				key:         "",
				salt:        nil,
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "empty_data",
			args: args{
				key:         "key",
				salt:        nil,
				cipherSuite: AES_256_GCM,
				d:           nil,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "invalid_salt",
			args: args{
				key:         "key",
				salt:        []byte("invalid"),
				cipherSuite: AES_256_GCM,
				d:           "data",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:         "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a",
				salt:        []byte("saltsaltsalt"),
				cipherSuite: AES_256_GCM,
				d:           "hello world",
			},
			want:    "00:73616c7473616c7473616c74:20001500f3616c7473616c7473616c74da182aeef9d1060ec5564b974689147f32bf626db98a13a0f4f6adf6df675dd07fa1463e3d1e:737472696e67",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encrypt(tt.args.key, tt.args.salt, tt.args.cipherSuite, tt.args.d)
			if err != nil {
				if (err != nil) != tt.wantErr {
					t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				fmt.Println(err)
				return
			}
			if got != tt.want {
				t.Errorf("Encrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
