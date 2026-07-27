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

	var outputValue reflect.Value
	if outputValue, err = convertHexStringToValue(decryptedHexData.String(), kind); err != nil {
		return nil, err
	}

	return outputValue.Interface(), nil
}

// Encrypt encrypts the supplied data using the supplied secret key and cipher suite.
// It will return an error if either the key is empty or the data is nil.
// Additionally, if the necessary cryptographic configuration cannot be created using the supplied cipherSuite, it will return an error.
// A fresh random nonce is generated for every call, so encrypting twice never
// reuses the same (key, nonce) pair.
func Encrypt(key string, cipherSuite CipherSuite, d any) (string, error) {
	if key == "" {
		return "", errors.New("key is empty")
	}

	if d == nil {
		return "", errors.New("data is nil")
	}

	var err error
	var data string
	// Convert input data to reflect.Value before serialization
	if data, err = convertValueToHexString(reflect.ValueOf(d)); err != nil {
		return "", err
	}

	// A nil nonce makes createCryptoConfig generate a fresh random one per call.
	var cryptoConfig sio.Config
	if cryptoConfig, err = createCryptoConfig(key, []byte{byte(cipherSuite)}, nil); err != nil {
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
