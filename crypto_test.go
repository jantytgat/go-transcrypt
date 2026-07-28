package transcrypt

import (
	"reflect"
	"testing"
)

func Test_CreateKey(t *testing.T) {
	tests := []struct {
		name     string
		byteSize int
		wantErr  bool
	}{
		{
			name:     "invalid_size_0",
			byteSize: 0,
			wantErr:  true,
		},
		{
			name:     "invalid_size_15",
			byteSize: 15,
			wantErr:  true,
		},
		{
			name:     "valid_size_16",
			byteSize: 16,
			wantErr:  false,
		},
		{
			name:     "valid_size_32",
			byteSize: 32,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := CreateKey(tt.byteSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(key) != tt.byteSize {
				t.Errorf("CreateKey() len = %d, want %d", len(key), tt.byteSize)
			}
		})
	}
}

func Test_createCryptoConfig(t *testing.T) {
	type args struct {
		key    []byte
		cipher []byte
		salt   []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty_key",
			args: args{
				key:    nil,
				cipher: []byte("cipher"),
				salt:   nil,
			},
			wantErr: true,
		},
		{
			name: "empty_cipher",
			args: args{
				key:    []byte("test"),
				cipher: nil,
				salt:   nil,
			},
			wantErr: true,
		},
		{
			name: "short_salt",
			args: args{
				key:    []byte("test"),
				cipher: []byte("cipher"),
				salt:   []byte("short"),
			},
			wantErr: true,
		},
		{
			name: "valid_generated_salt",
			args: args{
				key:    []byte("test"),
				cipher: []byte("cipher"),
				salt:   nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, salt, err := createCryptoConfig(tt.args.key, tt.args.cipher, tt.args.salt, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCryptoConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			// A generated salt must be saltLength bytes and the config populated.
			if len(salt) != saltLength {
				t.Errorf("createCryptoConfig() salt len = %d, want %d", len(salt), saltLength)
			}
			if len(cfg.Key) != 32 || cfg.Nonce == nil {
				t.Errorf("createCryptoConfig() config not populated: keyLen=%d nonce=%v", len(cfg.Key), cfg.Nonce)
			}
		})
	}
}

func Test_getKindForString(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want reflect.Kind
	}{
		{
			name: "bool",
			kind: "bool",
			want: reflect.Bool,
		},
		{
			name: "int",
			kind: "int",
			want: reflect.Int,
		},
		{
			name: "int8",
			kind: "int8",
			want: reflect.Int8,
		},
		{
			name: "int16",
			kind: "int16",
			want: reflect.Int16,
		},
		{
			name: "int32",
			kind: "int32",
			want: reflect.Int32,
		},
		{
			name: "int64",
			kind: "int64",
			want: reflect.Int64,
		},
		{
			name: "uint",
			kind: "uint",
			want: reflect.Uint,
		},
		{
			name: "uint8",
			kind: "uint8",
			want: reflect.Uint8,
		},
		{
			name: "uint16",
			kind: "uint16",
			want: reflect.Uint16,
		},
		{
			name: "uint32",
			kind: "uint32",
			want: reflect.Uint32,
		},
		{
			name: "uint64",
			kind: "uint64",
			want: reflect.Uint64,
		},
		{
			name: "float32",
			kind: "float32",
			want: reflect.Float32,
		},
		{
			name: "float64",
			kind: "float64",
			want: reflect.Float64,
		},
		{
			name: "complex64",
			kind: "complex64",
			want: reflect.Complex64,
		},
		{
			name: "complex128",
			kind: "complex128",
			want: reflect.Complex128,
		},
		{
			name: "slice",
			kind: "slice",
			want: reflect.Slice,
		},
		{
			name: "string",
			kind: "string",
			want: reflect.String,
		},
		// Kinds the converters do not support must map to reflect.Invalid,
		// including the previously dead "unsafepointer" mapping.
		{
			name: "unsupported_uintptr",
			kind: "uintptr",
			want: reflect.Invalid,
		},
		{
			name: "unsupported_map",
			kind: "map",
			want: reflect.Invalid,
		},
		{
			name: "unsupported_struct",
			kind: "struct",
			want: reflect.Invalid,
		},
		{
			name: "unsupported_ptr",
			kind: "ptr",
			want: reflect.Invalid,
		},
		{
			name: "unsupported_unsafepointer",
			kind: "unsafepointer",
			want: reflect.Invalid,
		},
		{
			name: "default",
			kind: "default",
			want: reflect.Invalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKindForString(tt.kind); got != tt.want {
				t.Errorf("getKindForString() = %v, want %v", got, tt.want)
			}
		})
	}
}
