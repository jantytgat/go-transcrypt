package transcrypt

import (
	"reflect"
	"strings"
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
		{"bool_true", true},
		{"bool_false", false},
		{"int_positive", 123456},
		{"int_zero", 0},
		{"int_negative", -987654},
		{"int8", int8(-12)},
		{"int16", int16(1234)},
		{"int32", int32(-70000)},
		{"int64", int64(9_000_000_000)},
		{"uint", uint(42)},
		{"uint8", uint8(255)},
		{"uint16", uint16(65535)},
		{"uint32", uint32(4_000_000_000)},
		{"uint64", uint64(18_000_000_000_000_000_000)},
		{"float32", float32(3.14159)},
		{"float64", 2.718281828459045},
		{"complex64", complex64(complex(1, -2))},
		{"complex128", complex(3, -4)},
		{"bytes", []byte{0xde, 0xad, 0xbe, 0xef}},
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
				encrypted, err := Encrypt(testKey, s.suite, v.in)
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

// TestEncryptUnsupportedType asserts that unsupported input types (composite and
// reference kinds, including non-byte slices) fail cleanly instead of being
// silently mishandled.
func TestEncryptUnsupportedType(t *testing.T) {
	ch := make(chan int)
	n := 0
	for _, v := range []any{
		[]int{1, 2, 3},
		map[string]int{"a": 1},
		struct{ A int }{A: 1},
		&n,
		ch,
	} {
		if _, err := Encrypt(testKey, AES_256_GCM, v); err == nil {
			t.Errorf("Encrypt(%T) expected error, got nil", v)
		}
	}
}

// TestEncryptNonceUniqueness proves that encrypting the same value with the same
// key twice produces a different nonce (and thus a different ciphertext) each
// time, so the (key, nonce) pair is never reused. Both outputs must still decrypt.
func TestEncryptNonceUniqueness(t *testing.T) {
	const value = "sensitive value"

	a, err := Encrypt(testKey, AES_256_GCM, value)
	if err != nil {
		t.Fatalf("Encrypt() first call error = %v", err)
	}
	b, err := Encrypt(testKey, AES_256_GCM, value)
	if err != nil {
		t.Fatalf("Encrypt() second call error = %v", err)
	}

	// Field 2 of the colon-delimited output is the nonce.
	nonceA := strings.Split(a, ":")[1]
	nonceB := strings.Split(b, ":")[1]
	if nonceA == nonceB {
		t.Errorf("nonce reused across two encryptions: %s", nonceA)
	}
	if a == b {
		t.Error("two encryptions of the same value produced identical output")
	}

	for _, enc := range []string{a, b} {
		got, err := Decrypt(testKey, enc)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if got != value {
			t.Errorf("Decrypt() got = %v, want %v", got, value)
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
