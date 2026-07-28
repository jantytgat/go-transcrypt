// Package transcrypt provides functionality to encrypt arbitrary data into a hex encoded string for safe on-disk storage, and decrypt said string.
// A single pair of generic entry points serves every supported shape: the type
// parameter of Encrypt/Decrypt selects the encryption mode. A string target
// encrypts a single value into the encoded format; a struct target maps a
// plain struct onto its encrypted mirror field by field (see structs.go), with
// a mirror field typed Ciphertext as the encrypted leaf.
package transcrypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/minio/sio"
)

// Encrypt encrypts d into the target type E. The type parameter selects the
// encryption mode:
//
//   - E is a string type (string, Ciphertext, or any other named type of kind
//     string): d must be a single supported value (scalars, string or []byte)
//     and is encrypted into the hex-encoded, colon-delimited string format;
//   - E is a struct type: E is the encrypted mirror of d's struct type, and
//     every mirror field typed Ciphertext is encrypted individually (each with
//     its own salt, derived key and nonce), identical types are copied
//     verbatim, and mirrored composite types recurse.
//
// E appears only in the result, so it is never inferred; calls always name the
// target explicitly: Encrypt[string](key, suite, 42) for single values,
// Encrypt[SecureData](key, suite, data) for structs.
//
// It returns an error if the key is shorter than minKeyLength bytes or the
// data is nil, if the cipher suite is unknown, or if d does not fit the target
// type E. A fresh random salt is generated for every encrypted value, so
// encrypting twice never reuses the same (key, nonce) pair.
func Encrypt[E any](key string, cipherSuite CipherSuite, d any) (E, error) {
	var zero E
	encType := reflect.TypeOf((*E)(nil)).Elem()

	switch encType.Kind() {
	case reflect.String:
		encrypted, err := encryptScalar(key, cipherSuite, d)
		if err != nil {
			return zero, err
		}
		return reflect.ValueOf(encrypted).Convert(encType).Interface().(E), nil
	case reflect.Struct:
		if d == nil {
			return zero, errors.New("plain value is nil")
		}
		plainValue := reflect.ValueOf(d)
		if plainValue.Kind() != reflect.Struct {
			return zero, fmt.Errorf("plain value must be a struct, got %T", d)
		}
		out, err := encryptValue(key, cipherSuite, plainValue, encType, "")
		if err != nil {
			return zero, err
		}
		return out.Interface().(E), nil
	default:
		return zero, fmt.Errorf("unsupported encryption target %s: use a string type for single values or a mirror struct type", encType)
	}
}

// Decrypt decrypts data back into the target type P, mirroring Encrypt:
//
//   - P is an interface type (typically any): data must be an encoded string;
//     the value is returned as whatever type was stored, recovered from inside
//     the authenticated ciphertext;
//   - P is a non-struct concrete type: data must be an encoded string; the
//     decrypted value must have P's kind (named types of the same kind are
//     converted, a kind mismatch is an error);
//   - P is a struct type: data is the encrypted mirror struct and P the plain
//     struct to rebuild, with every Ciphertext field decrypted individually.
//
// Calls name the target explicitly: Decrypt[any](key, s) keeps the stored
// type, Decrypt[int64](key, s) enforces it, Decrypt[Data](key, secureData)
// rebuilds a struct.
func Decrypt[P any](key string, data any) (P, error) {
	var zero P
	plainType := reflect.TypeOf((*P)(nil)).Elem()

	switch plainType.Kind() {
	case reflect.Interface:
		encoded, err := encodedString(data)
		if err != nil {
			return zero, err
		}
		decrypted, err := decryptScalar(key, encoded)
		if err != nil {
			return zero, err
		}
		out, ok := decrypted.(P)
		if !ok {
			return zero, fmt.Errorf("decrypted value of type %T does not implement %s", decrypted, plainType)
		}
		return out, nil
	case reflect.Struct:
		if data == nil {
			return zero, errors.New("encrypted value is nil")
		}
		encValue := reflect.ValueOf(data)
		if encValue.Kind() != reflect.Struct {
			return zero, fmt.Errorf("encrypted value must be a struct, got %T", data)
		}
		out, err := decryptValue(key, encValue, plainType, "")
		if err != nil {
			return zero, err
		}
		return out.Interface().(P), nil
	default:
		encoded, err := encodedString(data)
		if err != nil {
			return zero, err
		}
		decrypted, err := decryptScalar(key, encoded)
		if err != nil {
			return zero, err
		}
		out, err := fitValue(reflect.ValueOf(decrypted), plainType)
		if err != nil {
			return zero, err
		}
		return out.Interface().(P), nil
	}
}

// encodedString extracts the encoded-string form from data for the single-value
// decryption paths. Any value of kind string is accepted (string, Ciphertext,
// other named string types).
func encodedString(data any) (string, error) {
	v := reflect.ValueOf(data)
	if !v.IsValid() || v.Kind() != reflect.String {
		return "", fmt.Errorf("encrypted data must be a string, got %T", data)
	}
	return v.String(), nil
}

// fitValue fits a decrypted value into the target type. An exact type match is
// returned as-is and a named type of the same kind is converted, but a kind
// mismatch is an error: the kind recovered from the authenticated ciphertext
// always wins, so a stored value can never be relabeled as a different kind.
func fitValue(v reflect.Value, target reflect.Type) (reflect.Value, error) {
	if v.Type() == target {
		return v, nil
	}
	if v.Kind() == target.Kind() && v.Type().ConvertibleTo(target) {
		return v.Convert(target), nil
	}
	return reflect.Value{}, fmt.Errorf("decrypted value has kind %s, which does not fit target type %s", v.Kind(), target)
}

// decryptScalar decrypts a supplied hex-encoded data string using the supplied secret key.
// It will return an error if either the key or the data is empty.
// If the hex-encoded string data cannot be converted into proper encrypted data, decryption will also fail with an error.
func decryptScalar(key string, data string) (any, error) {
	if key == "" {
		return nil, errors.New("key is empty")
	}
	if data == "" {
		return nil, errors.New("data is empty")
	}

	var err error
	var encryptedData []byte
	var cryptoConfig sio.Config

	if encryptedData, cryptoConfig, err = decodeHexString(key, data); err != nil {
		return nil, err
	}

	var decryptedData *bytes.Buffer
	decryptedData = bytes.NewBuffer(make([]byte, 0))
	if _, err = sio.Decrypt(decryptedData, bytes.NewBuffer(encryptedData), cryptoConfig); err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	// Recover the type tag from the authenticated plaintext. Because it was inside
	// the ciphertext, a tampered tag would already have failed sio.Decrypt above.
	var kindName, hexPayload string
	if kindName, hexPayload, err = decodeInnerPayload(decryptedData.String()); err != nil {
		return nil, err
	}

	kind := getKindForString(kindName)
	if kind == reflect.Invalid {
		return nil, fmt.Errorf("cannot decode kind %q", kindName)
	}

	var outputValue reflect.Value
	if outputValue, err = convertHexStringToValue(hexPayload, kind); err != nil {
		return nil, err
	}

	return outputValue.Interface(), nil
}

// encryptScalar encrypts a single supported value using the supplied secret key and cipher suite.
// It will return an error if the key is shorter than minKeyLength bytes or the data is nil.
// Additionally, if the necessary cryptographic configuration cannot be created using the supplied cipherSuite, it will return an error.
// A fresh random nonce is generated for every call, so encrypting twice never
// reuses the same (key, nonce) pair.
func encryptScalar(key string, cipherSuite CipherSuite, d any) (string, error) {
	if len(key) < minKeyLength {
		return "", fmt.Errorf("key must be at least %d bytes", minKeyLength)
	}

	if d == nil {
		return "", errors.New("data is nil")
	}

	if !cipherSuite.isValid() {
		return "", fmt.Errorf("unknown cipher suite: %d", cipherSuite)
	}

	var err error
	var hexPayload string
	// Convert input data to reflect.Value before serialization
	if hexPayload, err = convertValueToHexString(reflect.ValueOf(d)); err != nil {
		return "", err
	}

	// Frame the type tag together with the payload so both are encrypted as one
	// unit; this keeps the type authenticated by the AEAD and immune to tampering.
	plaintext := encodeInnerPayload(reflect.TypeOf(d).Kind().String(), hexPayload)

	// A nil salt makes createCryptoConfig generate a fresh random one per call and
	// return it so it can be stored; the AEAD nonce is derived from it.
	var cryptoConfig sio.Config
	var salt []byte
	if cryptoConfig, salt, err = createCryptoConfig(key, []byte{byte(cipherSuite)}, nil); err != nil {
		return "", err
	}

	encryptedData := bytes.NewBuffer(make([]byte, 0))
	if _, err = sio.Encrypt(encryptedData, bytes.NewBufferString(plaintext), cryptoConfig); err != nil {
		return "", err
	}

	// Encode all details in hex before joining together. Field 2 is the HKDF salt
	// (the nonce is derived from it); the type tag lives inside the ciphertext.
	encryptedString := strings.Join(
		[]string{
			hex.EncodeToString([]byte{byte(cipherSuite)}),
			hex.EncodeToString(salt),
			hex.EncodeToString(encryptedData.Bytes()),
		}, ":",
	)

	if !regexEncryptedString.MatchString(encryptedString) {
		return "", fmt.Errorf("could not validate encrypted data")
	}

	return encryptedString, nil
}
