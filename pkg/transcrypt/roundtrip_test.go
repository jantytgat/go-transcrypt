package transcrypt

import (
	"reflect"
	"testing"
)

// testKey is a valid hex-encoded key reused across round-trip tests so we do not
// pay for RSA key generation in every case.
const testKey = "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d423843415141434167773341674d42414145434167635a41674537416745314167455441674578416745780a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a"

// TestEncryptDecryptRoundTrip exercises the full Encrypt -> Decrypt path for
// every supported type across both cipher suites, catching converter drift that
// hardcoded vectors miss.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	values := []struct {
		name string
		in   any
	}{
		{"string", "hello world"},
		{"int_positive", 123456},
		{"int_zero", 0},
		{"int_negative", -987654},
	}
	suites := []struct {
		name  string
		suite CipherSuite
	}{
		{"AES_256_GCM", AES_256_GCM},
		{"CHACHA20_POLY1305", CHACHA20_POLY1305},
	}

	for _, s := range suites {
		for _, v := range values {
			t.Run(s.name+"/"+v.name, func(t *testing.T) {
				encrypted, err := Encrypt(testKey, nil, s.suite, v.in)
				if err != nil {
					t.Fatalf("Encrypt() error = %v", err)
				}
				got, err := Decrypt(testKey, encrypted)
				if err != nil {
					t.Fatalf("Decrypt() error = %v", err)
				}
				if !reflect.DeepEqual(got, v.in) {
					t.Errorf("round-trip got = %v (%T), want %v (%T)", got, got, v.in, v.in)
				}
			})
		}
	}
}

// TestEncryptUnsupportedType asserts that unsupported input types fail cleanly
// instead of being silently mishandled.
func TestEncryptUnsupportedType(t *testing.T) {
	for _, v := range []any{true, uint64(5), int64(5), 3.14, int32(5)} {
		if _, err := Encrypt(testKey, nil, AES_256_GCM, v); err == nil {
			t.Errorf("Encrypt(%T) expected error, got nil", v)
		}
	}
}

// TestConvertHexStringToValue_ShortBuffer verifies the int decode path returns
// an error rather than panicking on undersized input ("0102" decodes to 2 bytes).
func TestConvertHexStringToValue_ShortBuffer(t *testing.T) {
	if _, err := convertHexStringToValue("0102", reflect.Int); err == nil {
		t.Error("convertHexStringToValue(short, int) expected error, got nil")
	}
}
