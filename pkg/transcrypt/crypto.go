package transcrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"
)

// CreateHexKey generates a random hex-encoded key which can be used for encryption.
// It reads byteSize cryptographically secure random bytes and hex-encodes them.
// The key is used purely as high-entropy input keying material for HKDF, so byteSize
// is the number of random bytes and must be at least 16 (128 bits of entropy).
func CreateHexKey(byteSize int) (string, error) {
	if byteSize < 16 {
		return "", errors.New("byte size must be at least 16")
	}

	b := make([]byte, byteSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random data for key: %w", err)
	}

	return hex.EncodeToString(b), nil
}

// createCryptoConfig creates a sio.Config from the supplied key, cipher and nonce.
// The same 12-byte nonce is used both as the HKDF salt (to derive the encryption
// key) and as the sio AEAD nonce. If nonce is nil, a fresh random one is generated;
// this is the encryption path, and generating it per call guarantees the (key,
// nonce) pair is never reused. On decryption the nonce is passed in from the
// encoded string. It returns an error if key or cipher is empty, or if a supplied
// nonce is shorter than 12 bytes.
func createCryptoConfig(key string, cipher []byte, nonce []byte) (sio.Config, error) {
	if key == "" {
		return sio.Config{}, errors.New("key is empty")
	}

	if cipher == nil {
		return sio.Config{}, errors.New("cipher is empty")
	}

	var err error
	// If no nonce is supplied, generate a fresh random one for this encryption.
	if nonce == nil {
		var n [12]byte
		if _, err = io.ReadFull(rand.Reader, n[:]); err != nil {
			return sio.Config{}, fmt.Errorf("failed to read random data for nonce: %w", err)
		}
		nonce = n[:]
	}

	if len(nonce) < 12 {
		return sio.Config{}, fmt.Errorf("nonce needs to be at least 12 bytes, got %d", len(nonce))
	}

	// Create encryption key
	kdf := hkdf.New(sha256.New, []byte(key), nonce[:12], nil)
	var encKey [32]byte
	if _, err = io.ReadFull(kdf, encKey[:]); err != nil {
		return sio.Config{}, fmt.Errorf("failed to derive encryption encKey: %w", err)
	}

	return sio.Config{
		CipherSuites: cipher,
		Key:          encKey[:],
		Nonce:        (*[12]byte)(nonce[:]),
	}, nil
}

// getKindForString converts a stored kind name to its reflect.Kind.
// It recognizes exactly the kinds the converters support, keeping it in sync with
// convertValueToHexString/convertHexStringToValue; "slice" denotes a []byte
// payload. Any other name (including reflect.Kind names for unsupported types)
// returns reflect.Invalid.
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
	case "float32":
		return reflect.Float32
	case "float64":
		return reflect.Float64
	case "complex64":
		return reflect.Complex64
	case "complex128":
		return reflect.Complex128
	case "string":
		return reflect.String
	case "slice":
		return reflect.Slice
	default:
		return reflect.Invalid
	}
}
