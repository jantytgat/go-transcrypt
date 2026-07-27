package transcrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

// convertBytesToValue converts a byte-array to a reflect.Value.
// It takes a byte-slice and a reflect.Kind and returns an error if the conversion fails.
func convertBytesToValue(d []byte, k reflect.Kind) (reflect.Value, error) {
	switch k {
	case reflect.Int:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode int: expected 8 bytes, got %d", len(d))
		}
		n := int64(binary.BigEndian.Uint64(d))
		// int is platform-sized; on 32-bit platforms a value that fits int64 may not fit int.
		if int64(int(n)) != n {
			return reflect.Value{}, fmt.Errorf("cannot decode int: value %d overflows int on this platform", n)
		}
		v := reflect.New(reflect.TypeOf(0))
		v.Elem().SetInt(n)
		return reflect.ValueOf(v.Elem().Interface()), nil
	case reflect.Uint64:
		if len(d) != 8 {
			return reflect.Value{}, fmt.Errorf("cannot decode uint64: expected 8 bytes, got %d", len(d))
		}
		v := reflect.New(reflect.TypeOf(uint64(0)))
		v.Elem().SetUint(binary.BigEndian.Uint64(d))
		return reflect.ValueOf(v.Elem().Interface()), nil
	case reflect.String:
		return reflect.ValueOf(string(d)), nil
	default:
		return reflect.Value{}, fmt.Errorf("unknown type %v", k)
	}
}

// convertValueToHexString converts a value to a hex-encoded string.
// It returns an empty string and an error if the value is a kind reflect.Int and cannot be converted.
func convertValueToHexString(v reflect.Value) (string, error) {
	var err error
	switch v.Kind() {
	case reflect.Int:
		bufWriter := bytes.NewBuffer(make([]byte, 0))
		if err = binary.Write(bufWriter, binary.BigEndian, v.Int()); err != nil {
			return "", err
		}
		return hex.EncodeToString(bufWriter.Bytes()), nil
	case reflect.String:
		return hex.EncodeToString([]byte(v.String())), nil
	default:
		return "", fmt.Errorf("unknown type %v", v.Kind())
	}
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

	var salt []byte
	if salt, err = hex.DecodeString(split[1]); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode salt: %w", err)
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
	if cryptoConfig, err = createCryptoConfig(key, cipherSuiteBytes, salt); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot create crypto config: %w", err)
	}

	return encryptedBytes, kind, cryptoConfig, nil
}
