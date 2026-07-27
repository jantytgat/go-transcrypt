// Package transcrypt provides functionality to encrypt arbitrary data into a hex encoded string for safe on-disk storage, and decrypt said string.
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

// Decrypt decrypts a supplied hex-encoded data string using the supplied secret key.
// It will return an error if either the key or the data is empty.
// If the hex-encoded string data cannot be converted into proper encrypted data, decryption will also fail with an error.
func Decrypt(key string, data string) (any, error) {
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

// Encrypt encrypts the supplied data using the supplied secret key and cipher suite.
// It will return an error if the key is shorter than minKeyLength bytes or the data is nil.
// Additionally, if the necessary cryptographic configuration cannot be created using the supplied cipherSuite, it will return an error.
// A fresh random nonce is generated for every call, so encrypting twice never
// reuses the same (key, nonce) pair.
func Encrypt(key string, cipherSuite CipherSuite, d any) (string, error) {
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

	// A nil nonce makes createCryptoConfig generate a fresh random one per call.
	var cryptoConfig sio.Config
	if cryptoConfig, err = createCryptoConfig(key, []byte{byte(cipherSuite)}, nil); err != nil {
		return "", err
	}

	encryptedData := bytes.NewBuffer(make([]byte, 0))
	if _, err = sio.Encrypt(encryptedData, bytes.NewBufferString(plaintext), cryptoConfig); err != nil {
		return "", err
	}

	// Encode all details in hex before joining together. The type tag is no longer
	// a separate field: it lives inside the ciphertext above.
	encryptedString := strings.Join(
		[]string{
			hex.EncodeToString([]byte{byte(cipherSuite)}),
			hex.EncodeToString(cryptoConfig.Nonce[:]),
			hex.EncodeToString(encryptedData.Bytes()),
		}, ":",
	)

	if !regexEncryptedString.MatchString(encryptedString) {
		return "", fmt.Errorf("could not validate encrypted data")
	}

	return encryptedString, nil
}
