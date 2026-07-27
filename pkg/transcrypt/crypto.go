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

// minKeyLength is the minimum accepted length, in bytes, for a caller-supplied
// encryption key. HKDF stretches the key but cannot add entropy, so a floor here
// guards against trivially weak keys reaching Encrypt. It matches CreateHexKey's
// 16-byte minimum. It is enforced on encryption only: Decrypt stays able to read
// data produced by any key so existing ciphertext never becomes unreadable.
const minKeyLength = 16

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

// saltLength is the size, in bytes, of the random HKDF salt generated per
// encryption. At 256 bits the salt makes the derived key unique per message to a
// ~2^128 birthday bound, which is what decouples key uniqueness from the 96-bit
// AEAD nonce (see createCryptoConfig).
const saltLength = 32

// minSaltLength is the smallest salt createCryptoConfig will accept when one is
// supplied (i.e. on the decryption path). It is a defensive floor; well-formed
// encoded strings always carry a saltLength-byte salt.
const minSaltLength = 16

// createCryptoConfig creates a sio.Config from the supplied key, cipher and salt.
// It derives BOTH the 32-byte encryption key and the 12-byte AEAD nonce from the
// salt via HKDF-SHA256, and returns the salt that was used so the caller can
// store it. If salt is nil a fresh random saltLength-byte one is generated (the
// encryption path); on decryption the salt is passed in from the encoded string.
//
// Deriving the key from a 256-bit salt makes it unique per message with
// overwhelming probability, so the (key, nonce) pair can never repeat even though
// the nonce itself is only 96 bits. This is what raises the safe-message ceiling
// from the ~2^48 birthday bound of a bare 96-bit nonce to ~2^128.
//
// It returns an error if key or cipher is empty, or if a supplied salt is shorter
// than minSaltLength bytes.
func createCryptoConfig(key string, cipher []byte, salt []byte) (sio.Config, []byte, error) {
	if key == "" {
		return sio.Config{}, nil, errors.New("key is empty")
	}

	if cipher == nil {
		return sio.Config{}, nil, errors.New("cipher is empty")
	}

	var err error
	// If no salt is supplied, generate a fresh random one for this encryption.
	if salt == nil {
		salt = make([]byte, saltLength)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil {
			return sio.Config{}, nil, fmt.Errorf("failed to read random data for salt: %w", err)
		}
	}

	if len(salt) < minSaltLength {
		return sio.Config{}, nil, fmt.Errorf("salt needs to be at least %d bytes, got %d", minSaltLength, len(salt))
	}

	// Derive the encryption key and the AEAD nonce from a single HKDF stream: the
	// first 32 bytes are the key, the next 12 are the nonce.
	kdf := hkdf.New(sha256.New, []byte(key), salt, nil)
	var derived [32 + 12]byte
	if _, err = io.ReadFull(kdf, derived[:]); err != nil {
		return sio.Config{}, nil, fmt.Errorf("failed to derive key material: %w", err)
	}

	var encKey [32]byte
	var nonce [12]byte
	copy(encKey[:], derived[:32])
	copy(nonce[:], derived[32:])

	return sio.Config{
		CipherSuites: cipher,
		Key:          encKey[:],
		Nonce:        &nonce,
	}, salt, nil
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
