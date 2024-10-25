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

var regexEncryptedString = regexp.MustCompile(`\d{2}:[\w\d]{24}:[\w\d]*:[\w\d]*`)

func convertValueToHexString(v reflect.Value) (string, error) {
	var err error
	switch v.Kind() {
	case reflect.Int:
		buf := make([]byte, 0)
		bufWriter := bytes.NewBuffer(buf)
		err = binary.Write(bufWriter, binary.BigEndian, v.Int())
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(bufWriter.Bytes()), nil
	default:
		return hex.EncodeToString([]byte(v.String())), nil
	}
}

func convertBytesToValue(d []byte, k reflect.Kind) (reflect.Value, error) {
	switch k {
	case reflect.Int:
		decodedInt := binary.BigEndian.Uint64(d)
		return reflect.ValueOf(int(decodedInt)), nil
	default:
		return reflect.ValueOf(string(d)), nil
	}
}

func decodeHexString(key string, data string) ([]byte, reflect.Kind, sio.Config, error) {
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
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot decode kind: %w", err)
	}

	var cryptoConfig sio.Config
	if cryptoConfig, err = createCryptoConfig(key, cipherSuiteBytes, nonce); err != nil {
		return nil, reflect.Invalid, sio.Config{}, fmt.Errorf("cannot create crypto config: %w", err)
	}

	return encryptedBytes, kind, cryptoConfig, nil
}
