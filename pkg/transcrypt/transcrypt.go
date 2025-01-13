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

// Encrypt encrypts the supplied data using the supplied secret key and cipher suite.
// It will return an error if either the key is empty or the data is nil.
// Additionally, if the necessary cryptographic configuration cannot be created using the supplied cipherSuite, it will return an error.
// If a salt is provided, it must be at least 12 bytes.
// If salt is nil, the function will automatically create one on-the-fly.
func Encrypt(key string, salt []byte, cipherSuite CipherSuite, d any) (string, error) {
	if key == "" {
		return "", errors.New("key is empty")
	}

	if d == nil {
		return "", errors.New("data is nil")
	}

	if salt != nil && len(salt) < 12 {
		return "", fmt.Errorf("salt needs to be at least 12 bytes, got %d", len(salt))
	}

	var err error
	var data string
	// Convert input data to reflect.Value before serialization
	if data, err = convertValueToHexString(reflect.ValueOf(d)); err != nil {
		return "", err
	}

	var cryptoConfig sio.Config
	if cryptoConfig, err = createCryptoConfig(key, []byte{byte(cipherSuite)}, salt); err != nil {
		return "", err
	}

	encryptedData := bytes.NewBuffer(make([]byte, 0))
	if _, err = sio.Encrypt(encryptedData, bytes.NewBuffer([]byte(data)), cryptoConfig); err != nil {
		return "", err
	}

	// Encode all details in hex before joining together
	encryptedString := strings.Join(
		[]string{
			hex.EncodeToString([]byte{byte(cipherSuite)}),
			hex.EncodeToString(cryptoConfig.Nonce[:]),
			hex.EncodeToString(encryptedData.Bytes()),
			hex.EncodeToString([]byte(reflect.TypeOf(d).Kind().String())),
		}, ":",
	)

	if !regexEncryptedString.MatchString(encryptedString) {
		return "", fmt.Errorf("could not validate encrypted data")
	}

	return encryptedString, nil
}

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
	var kind reflect.Kind
	var cryptoConfig sio.Config

	if encryptedData, kind, cryptoConfig, err = decodeHexString(key, data); err != nil {
		return nil, err
	}

	var decryptedHexData *bytes.Buffer
	decryptedHexData = bytes.NewBuffer(make([]byte, 0))
	if _, err = sio.Decrypt(decryptedHexData, bytes.NewBuffer(encryptedData), cryptoConfig); err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	var decryptedData []byte
	if decryptedData, err = hex.DecodeString(string(decryptedHexData.Bytes())); err != nil {
		return nil, fmt.Errorf("decode decrypted hex data failed: %w", err)
	}

	var outputValue reflect.Value
	if outputValue, err = convertBytesToValue(decryptedData, kind); err != nil {
		return nil, err
	}

	return outputValue.Interface(), nil
}
