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
// 1. Cipher suite  - one hex-encoded byte (2 lowercase hex chars, e.g. "0a")
// 2. Salt/nonce    - 12 hex-encoded bytes (24 lowercase hex chars)
// 3. Data          - hex-encoded ciphertext (non-empty)
// 4. Original type - hex-encoded reflect.Kind name (non-empty)
// The pattern is anchored so the whole string must match, every field must be
// valid lowercase hex, and the ciphertext/kind fields may not be empty.
var regexEncryptedString = regexp.MustCompile(`^[0-9a-f]{2}:[0-9a-f]{24}:[0-9a-f]+:[0-9a-f]+$`)

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
		return hex.EncodeToString(v.Bytes()), nil
	default:
		return "", fmt.Errorf("unknown type %v", v.Kind())
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// decodeHexString decodes data into the pieces that make up the encrypted data.
// It takes an encrypted key and data string and returns the actual encrypted data as a byte-slice, reflect.Kind and the encryption config.
// It returns an error if the data string is empty or invalid, or any of the steps to get the encrypted data fails.
func decodeHexString(key string, data string) ([]byte, reflect.Kind, sio.Config, error) {
	if key == "" {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("key is empty")
	}
	if data == "" {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("value is empty")
	}

	if !regexEncryptedString.MatchString(data) {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("value is not valid")
	}

	var split []string
	split = strings.Split(data, ":")

	var err error
	var cipherSuiteBytes []byte
	if cipherSuiteBytes, err = hex.DecodeString(split[0]); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode cipersuite: %w", err)
	}

	var nonce []byte
	if nonce, err = hex.DecodeString(split[1]); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode nonce: %w", err)
	}

	var encryptedBytes []byte
	if encryptedBytes, err = hex.DecodeString(split[2]); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode encrypted data: %w", err)
	}

	var kindBytes []byte
	if kindBytes, err = hex.DecodeString(split[3]); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode kindBytes: %w", err)
	}

	var kind reflect.Kind
	if kind = getKindForString(string(kindBytes)); kind == reflect.Invalid {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode kind %q", string(kindBytes))
	}

	var cryptoConfig sio.Config
	if cryptoConfig, err = createCryptoConfig(key, cipherSuiteBytes, nonce); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot create crypto config: %w", err)
	}

	return encryptedBytes, kind, cryptoConfig, nil
}
