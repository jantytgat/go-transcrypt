package transcrypt

import (
	"reflect"
	"testing"
)

func Test_CreateHexKey(t *testing.T) {
	type args struct {
		bitSize int
	}
	tests := []struct {
		name    string
		bitSize int
		wantErr bool
	}{
		{
			name:    "invalid_size_0",
			bitSize: 0,
			wantErr: true,
		},
		{
			name:    "invalid_size_11",
			bitSize: 11,
			wantErr: true,
		},
		{
			name:    "valid_size_12",
			bitSize: 12,
			wantErr: false,
		},
		{
			name:    "valid_size_256",
			bitSize: 256,
			wantErr: false,
		},
		{
			name:    "valid_size_1024",
			bitSize: 1024,
			wantErr: false,
		},
		{
			name:    "valid_size_2048",
			bitSize: 2048,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateHexKey(tt.bitSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateHexKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_CreateSalt(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "success",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateSalt()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSalt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_createCryptoConfig(t *testing.T) {
	type args struct {
		key    string
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
				key:    "test",
				cipher: nil,
				salt:   nil,
			},
			wantErr: true,
		},
		{
			name: "empty_cipher",
			args: args{
				key:    "test",
				cipher: nil,
				salt:   nil,
			},
			wantErr: true,
		},
		{
			name: "invalid_salt",
			args: args{
				key:    "test",
				cipher: []byte("cipher"),
				salt:   []byte("salt"),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:    "test",
				cipher: []byte("cipher"),
				salt:   nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createCryptoConfig(tt.args.key, tt.args.cipher, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCryptoConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
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
			name: "uintptr",
			kind: "uintptr",
			want: reflect.Uintptr,
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
			name: "array",
			kind: "array",
			want: reflect.Array,
		},
		{
			name: "chan",
			kind: "chan",
			want: reflect.Chan,
		},
		{
			name: "func",
			kind: "func",
			want: reflect.Func,
		},
		{
			name: "interface",
			kind: "interface",
			want: reflect.Interface,
		},
		{
			name: "map",
			kind: "map",
			want: reflect.Map,
		},
		{
			name: "pointer",
			kind: "pointer",
			want: reflect.Pointer,
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
		{
			name: "struct",
			kind: "struct",
			want: reflect.Struct,
		},
		{
			name: "unsafepointer",
			kind: "unsafepointer",
			want: reflect.UnsafePointer,
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
