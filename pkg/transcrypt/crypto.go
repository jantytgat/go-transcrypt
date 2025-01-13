package transcrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"
)

// createCryptoConfig creates a sio.config from the supplied key, cipher and optional salt.
// It returns an error if either key or cipher is empty.
// It also returns an error if the supplied salt is less than 12 bytes long.
func createCryptoConfig(key string, cipher []byte, salt []byte) (sio.Config, error) {
	if key == "" {
		return sio.Config{}, errors.New("key is empty")
	}

	if cipher == nil {
		return sio.Config{}, errors.New("cipher is empty")
	}

	var err error
	// If salt is nil, create a new salt that can be used for encryption
	if salt == nil {
		if salt, err = createSalt(); err != nil {
			return sio.Config{}, fmt.Errorf("could not create salt: %w", err)
		}
	}

	if len(salt) < 12 {
		return sio.Config{}, fmt.Errorf("salt needs to be at least 12 bytes, got %d", len(salt))
	}

	// Create encryption key
	kdf := hkdf.New(sha256.New, []byte(key), salt[:12], nil)
	var encKey [32]byte
	if _, err = io.ReadFull(kdf, encKey[:]); err != nil {
		return sio.Config{}, fmt.Errorf("failed to derive encryption encKey: %w", err)
	}

	return sio.Config{
		CipherSuites: cipher,
		Key:          encKey[:],
		Nonce:        (*[12]byte)(salt[:]),
	}, nil
}

// createSalt creates a random salt for use with the encrypt/decrypt functionality.
func createSalt() ([]byte, error) {
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to read random data for nonce: %w", err)
	}

	return nonce[:], nil
}

// getKindFromString converts a string to its representative reflect.Kind.
// It returns a reflect.Invalid by default if the supplied string cannot be found.
func getKindForString(s string) reflect.Kind {
	switch s {
	case "bool":
		return reflect.Bool
	case "int":
		return reflect.Int
	case "int8":
		return reflect.Int8
	case "int16":
		return reflect.Int16
	case "int32":
		return reflect.Int32
	case "int64":
		return reflect.Int64
	case "uint":
		return reflect.Uint
	case "uint8":
		return reflect.Uint8
	case "uint16":
		return reflect.Uint16
	case "uint32":
		return reflect.Uint32
	case "uint64":
		return reflect.Uint64
	case "uintptr":
		return reflect.Uintptr
	case "float32":
		return reflect.Float32
	case "float64":
		return reflect.Float64
	case "complex64":
		return reflect.Complex64
	case "complex128":
		return reflect.Complex128
	case "array":
		return reflect.Array
	case "chan":
		return reflect.Chan
	case "func":
		return reflect.Func
	case "interface":
		return reflect.Interface
	case "map":
		return reflect.Map
	case "pointer":
		return reflect.Pointer
	case "slice":
		return reflect.Slice
	case "string":
		return reflect.String
	case "struct":
		return reflect.Struct
	case "unsafepointer":
		return reflect.UnsafePointer
	default:
		return reflect.Invalid
	}
}
