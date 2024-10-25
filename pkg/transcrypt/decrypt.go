package transcrypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/minio/sio"
)

func Decrypt(key string, data string) (any, error) {
	if key == "" {
		return nil, errors.New("key is empty")
	}
	if data == "" {
		return nil, errors.New("data is nil")
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
