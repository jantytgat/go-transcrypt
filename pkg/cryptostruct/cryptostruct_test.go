package cryptostruct

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

const testKey = "0123456789abcdef0123456789abcdef"

// Inner / SecureInner mirror a nested struct with one encrypted and one
// plain-copied field.
type Inner struct {
	Note   string
	Public int
}

type SecureInner struct {
	Note   Ciphertext
	Public int
}

// Outer / SecureOuter exercise every supported shape: leaves of several
// kinds, a plain-copied field, nested structs, pointers, slices of structs
// and of leaves, maps, and arrays.
type Outer struct {
	Name     string
	Count    int
	Ratio    float64
	Flag     bool
	Blob     []byte
	Plain    string
	Inner    Inner
	InnerPtr *Inner
	Inners   []Inner
	Tags     []string
	Meta     map[string]string
	Fixed    [2]int
}

type SecureOuter struct {
	Name     Ciphertext
	Count    Ciphertext
	Ratio    Ciphertext
	Flag     Ciphertext
	Blob     Ciphertext
	Plain    string
	Inner    SecureInner
	InnerPtr *SecureInner
	Inners   []SecureInner
	Tags     []Ciphertext
	Meta     map[string]Ciphertext
	Fixed    [2]Ciphertext
}

func testOuter() Outer {
	return Outer{
		Name:     "top secret",
		Count:    42,
		Ratio:    3.14,
		Flag:     true,
		Blob:     []byte{0xde, 0xad},
		Plain:    "stays readable",
		Inner:    Inner{Note: "inner note", Public: 7},
		InnerPtr: &Inner{Note: "pointer note", Public: 8},
		Inners: []Inner{
			{Note: "first", Public: 1},
			{Note: "second", Public: 2},
		},
		Tags:  []string{"alpha", "beta"},
		Meta:  map[string]string{"k1": "v1", "k2": "v2"},
		Fixed: [2]int{10, 20},
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	in := testOuter()

	enc, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	out, err := Decrypt[Outer](testKey, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in: %#v\nout: %#v", in, out)
	}
}

func TestEncryptFieldHandling(t *testing.T) {
	in := testOuter()

	enc, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if enc.Plain != in.Plain {
		t.Errorf("plain field not copied verbatim: got %q, want %q", enc.Plain, in.Plain)
	}
	if enc.Inner.Public != in.Inner.Public {
		t.Errorf("nested plain field not copied: got %d, want %d", enc.Inner.Public, in.Inner.Public)
	}
	if strings.Contains(string(enc.Name), in.Name) {
		t.Errorf("encrypted field still contains plaintext: %q", enc.Name)
	}
	// Every Ciphertext must be a well-formed transcrypt string, decryptable on
	// its own — fields are encrypted individually.
	v, err := transcrypt.Decrypt(testKey, string(enc.Inner.Note))
	if err != nil {
		t.Fatalf("field is not independently decryptable: %v", err)
	}
	if v != in.Inner.Note {
		t.Errorf("independent decrypt: got %v, want %q", v, in.Inner.Note)
	}
	// Same plaintext in different fields must yield different ciphertexts
	// (fresh salt per field).
	in2 := in
	enc2, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in2)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc.Name == enc2.Name {
		t.Error("same plaintext encrypted twice produced identical ciphertext")
	}
}

func TestNilValuesPreserved(t *testing.T) {
	in := Outer{Blob: []byte{1}} // everything else zero / nil

	enc, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc.InnerPtr != nil {
		t.Error("nil pointer became non-nil")
	}
	if enc.Inners != nil {
		t.Error("nil slice became non-nil")
	}
	if enc.Meta != nil {
		t.Error("nil map became non-nil")
	}

	out, err := Decrypt[Outer](testKey, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if out.InnerPtr != nil || out.Inners != nil || out.Tags != nil || out.Meta != nil {
		t.Error("nil composite values not preserved through round trip")
	}
}

func TestNamedLeafTypes(t *testing.T) {
	type UserID int
	type Login string
	type User struct {
		ID    UserID
		Login Login
	}
	type SecureUser struct {
		ID    Ciphertext
		Login Ciphertext
	}

	in := User{ID: 1234, Login: "jan"}
	enc, err := Encrypt[SecureUser](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	out, err := Decrypt[User](testKey, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch: in %#v, out %#v", in, out)
	}
}

func TestUnexportedFieldsIgnored(t *testing.T) {
	type P struct {
		Name   string
		hidden string
	}
	type E struct {
		Name    Ciphertext
		private int
	}

	in := P{Name: "visible", hidden: "dropped"}
	enc, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	out, err := Decrypt[P](testKey, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if out.Name != in.Name {
		t.Errorf("exported field lost: got %q, want %q", out.Name, in.Name)
	}
	if out.hidden != "" || enc.private != 0 {
		t.Error("unexported fields should stay zero")
	}
}

func TestMissingFieldErrors(t *testing.T) {
	type P struct {
		A string
		B string
	}
	type MissingB struct {
		A Ciphertext
	}
	type ExtraC struct {
		A Ciphertext
		B Ciphertext
		C Ciphertext
	}

	if _, err := Encrypt[MissingB](testKey, transcrypt.AES_256_GCM, P{}); err == nil {
		t.Error("expected error for plain field missing in encrypted struct")
	}
	if _, err := Encrypt[ExtraC](testKey, transcrypt.AES_256_GCM, P{}); err == nil {
		t.Error("expected error for encrypted field missing in plain struct")
	}
}

func TestKindMismatchErrors(t *testing.T) {
	type P struct{ A int }
	type E struct{ A bool }

	if _, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, P{A: 1}); err == nil {
		t.Error("expected error for kind mismatch between plain and encrypted field")
	}

	type PSlice struct{ A []int }
	type ESlice struct{ A []bool }
	if _, err := Encrypt[ESlice](testKey, transcrypt.AES_256_GCM, PSlice{A: []int{1}}); err == nil {
		t.Error("expected error for element kind mismatch")
	}
}

func TestUnsupportedLeafErrors(t *testing.T) {
	// A struct field cannot be flattened into a single Ciphertext: the mirror
	// must declare a mirrored struct instead.
	type P struct{ A Inner }
	type E struct{ A Ciphertext }
	if _, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, P{}); err == nil {
		t.Error("expected error when encrypting a struct field into a Ciphertext leaf")
	}
}

func TestDecryptKindGuard(t *testing.T) {
	// Encrypt an int, then try to decrypt it into a struct whose field is a
	// string: the authenticated kind must win and the call must fail.
	type PInt struct{ A int }
	type PString struct{ A string }
	type E struct{ A Ciphertext }

	enc, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, PInt{A: 7})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err = Decrypt[PString](testKey, enc); err == nil {
		t.Error("expected error when decrypted kind does not match plain field type")
	}
}

func TestWrongKeyFails(t *testing.T) {
	in := testOuter()
	enc, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err = Decrypt[Outer]("ffffffffffffffffffffffffffffffff", enc); err == nil {
		t.Error("expected decrypt with wrong key to fail")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	type P struct{ A string }
	type E struct{ A Ciphertext }

	enc, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, P{A: "payload"})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	s := string(enc.A)
	last := s[len(s)-1]
	flip := byte('0')
	if last == '0' {
		flip = '1'
	}
	enc.A = Ciphertext(s[:len(s)-1] + string(flip))

	if _, err = Decrypt[P](testKey, enc); err == nil {
		t.Error("expected decrypt of tampered ciphertext to fail")
	}
}

func TestTopLevelValidation(t *testing.T) {
	type P struct{ A string }
	type E struct{ A Ciphertext }

	if _, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, nil); err == nil {
		t.Error("expected error for nil plain value")
	}
	if _, err := Encrypt[E](testKey, transcrypt.AES_256_GCM, "not a struct"); err == nil {
		t.Error("expected error for non-struct plain value")
	}
	if _, err := Encrypt[Ciphertext](testKey, transcrypt.AES_256_GCM, P{}); err == nil {
		t.Error("expected error for non-struct encrypted type")
	}
	if _, err := Decrypt[P](testKey, nil); err == nil {
		t.Error("expected error for nil encrypted value")
	}
	if _, err := Decrypt[P](testKey, 12); err == nil {
		t.Error("expected error for non-struct encrypted value")
	}
	if _, err := Decrypt[string](testKey, E{}); err == nil {
		t.Error("expected error for non-struct plain type")
	}
}

func TestShortKeyFails(t *testing.T) {
	type P struct{ A string }
	type E struct{ A Ciphertext }

	if _, err := Encrypt[E]("short", transcrypt.AES_256_GCM, P{A: "x"}); err == nil {
		t.Error("expected error for key below the transcrypt minimum")
	}
}

func TestErrorPathsAreReported(t *testing.T) {
	type PInner struct{ A Inner }
	type EInner struct{ A Ciphertext }

	_, err := Encrypt[EInner](testKey, transcrypt.AES_256_GCM, PInner{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "A") {
		t.Errorf("error should carry the field path, got: %v", err)
	}

	in := testOuter()
	enc, err := Encrypt[SecureOuter](testKey, transcrypt.AES_256_GCM, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	enc.Inners[1].Note = "garbage"
	_, err = Decrypt[Outer](testKey, enc)
	if err == nil {
		t.Fatal("expected error for corrupted nested field")
	}
	if !strings.Contains(err.Error(), "Inners[1].Note") {
		t.Errorf("error should carry the nested path, got: %v", err)
	}
}

func TestChaCha20Suite(t *testing.T) {
	in := testOuter()
	enc, err := Encrypt[SecureOuter](testKey, transcrypt.CHACHA20_POLY1305, in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	out, err := Decrypt[Outer](testKey, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatal("round trip mismatch with CHACHA20_POLY1305")
	}
}
