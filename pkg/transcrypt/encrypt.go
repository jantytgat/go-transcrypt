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
