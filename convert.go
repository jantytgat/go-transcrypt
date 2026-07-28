package transcrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"

	"github.com/minio/sio"
)

// Defines the default layout of a string representing encrypted data.
// The string is divided in sections delimited by a colon.
//  1. Cipher suite  - one hex-encoded byte (2 lowercase hex chars, e.g. "0a")
//  2. Salt          - 32 hex-encoded bytes (64 lowercase hex chars); the HKDF salt
//     from which both the encryption key and the AEAD nonce derive
//  3. Data          - hex-encoded ciphertext (non-empty)
//
// The pattern is anchored so the whole string must match, every field must be
// valid lowercase hex, and the ciphertext field may not be empty. The original
// type is no longer a separate field: it is carried inside the authenticated
// ciphertext (see encodeInnerPayload) so it cannot be tampered with undetected.
var regexEncryptedString = regexp.MustCompile(`^[0-9a-f]{2}:[0-9a-f]{64}:[0-9a-f]+$`)

// encodeInnerPayload frames the type tag together with the hex-encoded value so
// that both are encrypted as a single unit. The layout is "<kind>:<hexPayload>"
// where kind is a reflect.Kind name (lowercase letters/digits only) and
// hexPayload is the lowercase-hex value produced by convertValueToHexString.
// Because the delimiter never appears in a kind name, the first colon splits the
// two fields unambiguously. Framing the kind here (rather than as a plaintext
// outer field) means it is covered by the AEAD and cannot be altered without
// failing decryption.
func encodeInnerPayload(kind string, hexPayload string) string {
	return kind + ":" + hexPayload
}

// decodeInnerPayload splits the decrypted inner payload back into its kind name
// and hex payload. It returns an error if the delimiter is missing.
func decodeInnerPayload(s string) (kind string, hexPayload string, err error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed payload: missing type tag")
	}
	return parts[0], parts[1], nil
}

// convertHexStringToValue converts a hex-encoded payload back to a reflect.Value.
// It hex-decodes the payload internally, mirroring convertValueToHexString, and
// returns an error if the hex is invalid or the reflect.Kind is unsupported.
// The set of supported kinds is kept symmetric with convertValueToHexString.
// reflect.Slice denotes a []byte payload (the only supported slice element type).
func convertHexStringToValue(s string, k reflect.Kind) (reflect.Value, error) {
	d, err := hex.DecodeString(s)
	if err != nil {
		return reflect.Value{}, fmt.Errorf("cannot decode payload hex: %w", err)
	}

	switch k {
	case reflect.Bool:
		if len(d) != 1 {
			return reflect.Value{}, fmt.Errorf("cannot decode bool: expected 1 byte, got %d", len(d))
		}
		return reflect.ValueOf(d[0] != 0), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode %v: expected 8 bytes, got %d", k, len(d))
		}
		return intValue(k, int64(binary.BigEndian.Uint64(d)))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode %v: expected 8 bytes, got %d", k, len(d))
		}
		return uintValue(k, binary.BigEndian.Uint64(d))
	case reflect.Float32:
		if len(d) != 4 {
			return reflect.Value{}, fmt.Errorf("cannot decode float32: expected 4 bytes, got %d", len(d))
		}
		return reflect.ValueOf(math.Float32frombits(binary.BigEndian.Uint32(d))), nil
	case reflect.Float64:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode float64: expected 8 bytes, got %d", len(d))
		}
		return reflect.ValueOf(math.Float64frombits(binary.BigEndian.Uint64(d))), nil
	case reflect.Complex64:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode complex64: expected 8 bytes, got %d", len(d))
		}
		re := math.Float32frombits(binary.BigEndian.Uint32(d[0:4]))
		im := math.Float32frombits(binary.BigEndian.Uint32(d[4:8]))
		return reflect.ValueOf(complex(re, im)), nil
	case reflect.Complex128:
		if len(d) != 16 {
			return reflect.Value{}, fmt.Errorf("cannot decode complex128: expected 16 bytes, got %d", len(d))
		}
		re := math.Float64frombits(binary.BigEndian.Uint64(d[0:8]))
		im := math.Float64frombits(binary.BigEndian.Uint64(d[8:16]))
		return reflect.ValueOf(complex(re, im)), nil
	case reflect.String:
		return reflect.ValueOf(string(d)), nil
	case reflect.Slice:
		return reflect.ValueOf(d), nil
	default:
		return reflect.Value{}, fmt.Errorf("unknown type %v", k)
	}
}

// intValue rebuilds a signed integer of the given kind from an int64.
func intValue(k reflect.Kind, n int64) (reflect.Value, error) {
	switch k {
	case reflect.Int:
		// int is platform-sized; on 32-bit platforms a value that fits int64 may not fit int.
		if int64(int(n)) != n {
			return reflect.Value{}, fmt.Errorf("cannot decode int: value %d overflows int on this platform", n)
		}
		return reflect.ValueOf(int(n)), nil
	case reflect.Int8:
		return reflect.ValueOf(int8(n)), nil
	case reflect.Int16:
		return reflect.ValueOf(int16(n)), nil
	case reflect.Int32:
		return reflect.ValueOf(int32(n)), nil
	case reflect.Int64:
		return reflect.ValueOf(n), nil
	default:
		return reflect.Value{}, fmt.Errorf("unknown type %v", k)
	}
}

// uintValue rebuilds an unsigned integer of the given kind from a uint64.
func uintValue(k reflect.Kind, n uint64) (reflect.Value, error) {
	switch k {
	case reflect.Uint:
		// uint is platform-sized; on 32-bit platforms a value that fits uint64 may not fit uint.
		if uint64(uint(n)) != n {
			return reflect.Value{}, fmt.Errorf("cannot decode uint: value %d overflows uint on this platform", n)
		}
		return reflect.ValueOf(uint(n)), nil
	case reflect.Uint8:
		return reflect.ValueOf(uint8(n)), nil
	case reflect.Uint16:
		return reflect.ValueOf(uint16(n)), nil
	case reflect.Uint32:
		return reflect.ValueOf(uint32(n)), nil
	case reflect.Uint64:
		return reflect.ValueOf(n), nil
	default:
		return reflect.Value{}, fmt.Errorf("unknown type %v", k)
	}
}

// convertValueToHexString serializes a value and hex-encodes it.
// It returns an empty string and an error if the value's reflect.Kind is unsupported.
// The set of supported kinds is kept symmetric with convertHexStringToValue.
// Signed integers are widened to 8-byte int64 and unsigned to 8-byte uint64, so
// every integer kind decodes from a fixed 8-byte payload. A slice is only
// supported when its element type is byte (i.e. []byte).
func convertValueToHexString(v reflect.Value) (string, error) {
	buf := bytes.NewBuffer(make([]byte, 0))

	switch v.Kind() {
	case reflect.Bool:
		if err := binary.Write(buf, binary.BigEndian, v.Bool()); err != nil {
			return "", err
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if err := binary.Write(buf, binary.BigEndian, v.Int()); err != nil {
			return "", err
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if err := binary.Write(buf, binary.BigEndian, v.Uint()); err != nil {
			return "", err
		}
	case reflect.Float32:
		if err := binary.Write(buf, binary.BigEndian, float32(v.Float())); err != nil {
			return "", err
		}
	case reflect.Float64:
		if err := binary.Write(buf, binary.BigEndian, v.Float()); err != nil {
			return "", err
		}
	case reflect.Complex64:
		if err := binary.Write(buf, binary.BigEndian, complex64(v.Complex())); err != nil {
			return "", err
		}
	case reflect.Complex128:
		if err := binary.Write(buf, binary.BigEndian, v.Complex()); err != nil {
			return "", err
		}
	case reflect.String:
		return hex.EncodeToString([]byte(v.String())), nil
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.Uint8 {
			return "", fmt.Errorf("unknown type %v", v.Type())
		}
		// The format does not distinguish a nil []byte from an empty one: both
		// encode to an empty payload and decode back to an empty, non-nil []byte.
		return hex.EncodeToString(v.Bytes()), nil
	default:
		return "", fmt.Errorf("unknown type %v", v.Kind())
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// decodeHexString decodes data into the pieces that make up the encrypted data.
// It takes an encryption key and data string and returns the actual encrypted
// data as a byte-slice and the encryption config. The original type is not
// returned here: it lives inside the authenticated ciphertext and is recovered
// only after decryption (see decodeInnerPayload).
// It returns an error if the data string is empty or invalid, or any of the steps to get the encrypted data fails.
func decodeHexString(key string, data string) ([]byte, sio.Config, error) {
	if key == "" {
		return nil, sio.Config{}, fmt.Errorf("key is empty")
	}
	if data == "" {
		return nil, sio.Config{}, fmt.Errorf("value is empty")
	}

	if !regexEncryptedString.MatchString(data) {
		return nil, sio.Config{}, fmt.Errorf("value is not valid")
	}

	var split []string
	split = strings.Split(data, ":")

	var err error
	var cipherSuiteBytes []byte
	if cipherSuiteBytes, err = hex.DecodeString(split[0]); err != nil {
		return nil, sio.Config{}, fmt.Errorf("cannot decode ciphersuite: %w", err)
	}
	// The suite byte is the only field outside the AEAD, so reject an unknown
	// value here with a clear error (matching decryptFile) instead of letting it
	// fail deep inside sio. The regex guarantees exactly one byte.
	if !CipherSuite(cipherSuiteBytes[0]).isValid() {
		return nil, sio.Config{}, fmt.Errorf("unknown cipher suite: %d", cipherSuiteBytes[0])
	}

	var salt []byte
	if salt, err = hex.DecodeString(split[1]); err != nil {
		return nil, sio.Config{}, fmt.Errorf("cannot decode salt: %w", err)
	}

	var encryptedBytes []byte
	if encryptedBytes, err = hex.DecodeString(split[2]); err != nil {
		return nil, sio.Config{}, fmt.Errorf("cannot decode encrypted data: %w", err)
	}

	var cryptoConfig sio.Config
	if cryptoConfig, _, err = createCryptoConfig(key, cipherSuiteBytes, salt, nil); err != nil {
		return nil, sio.Config{}, fmt.Errorf("cannot create crypto config: %w", err)
	}

	return encryptedBytes, cryptoConfig, nil
}
