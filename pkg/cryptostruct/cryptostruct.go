// Package cryptostruct encrypts and decrypts structs field by field using the
// transcrypt package. The caller defines a "plain" struct and an equivalent
// "encrypted" mirror struct; the mirror's field types are the single source of
// truth for what happens to each field:
//
//   - a mirror field of type Ciphertext is encrypted with transcrypt.Encrypt
//     (each field gets its own salt, derived key and nonce, and carries its
//     original type inside the authenticated ciphertext);
//   - a mirror field with the identical type as the plain field is copied
//     verbatim;
//   - mirrored composite types (struct/slice/array/map/pointer pairs) are
//     traversed recursively.
//
// There are no struct tags and no interfaces to implement: declaring a field
// as Ciphertext in the mirror struct is the only marker needed, so the
// definition of "what is encrypted" cannot drift from the encrypted type.
//
// Fields are matched by name, and matching is strict in both directions: an
// exported field present on one side but missing on the other is an error, so
// data can never be dropped silently. Unexported fields are ignored on both
// sides (like encoding/json); anonymous (embedded) fields are matched by their
// type name, so embedding is only supported when both sides embed a type with
// the same name. Nil pointers, slices and maps are preserved as nil. Map keys
// are never encrypted, only map values.
package cryptostruct

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

// Ciphertext marks a field of an encrypted mirror struct as the encrypted
// counterpart of the plain struct's field with the same name. Its value is the
// self-describing encoded string produced by transcrypt.Encrypt, so it
// marshals naturally to JSON/YAML and needs no side-channel metadata.
type Ciphertext string

var ciphertextType = reflect.TypeOf(Ciphertext(""))

// Encrypt converts plain into its encrypted mirror type E. Every field of E
// typed Ciphertext is encrypted individually with transcrypt.Encrypt using the
// supplied key and cipher suite; fields with identical types on both sides are
// copied as-is. The type parameter cannot be inferred, so calls name the
// mirror type explicitly: cryptostruct.Encrypt[SecureData](key, suite, data).
func Encrypt[E any](key string, cipherSuite transcrypt.CipherSuite, plain any) (E, error) {
	var zero E

	encType := reflect.TypeOf(zero)
	if encType == nil || encType.Kind() != reflect.Struct {
		return zero, fmt.Errorf("encrypted type %T must be a struct", zero)
	}
	if plain == nil {
		return zero, errors.New("plain value is nil")
	}
	plainValue := reflect.ValueOf(plain)
	if plainValue.Kind() != reflect.Struct {
		return zero, fmt.Errorf("plain value must be a struct, got %T", plain)
	}

	out, err := encryptValue(key, cipherSuite, plainValue, encType, "")
	if err != nil {
		return zero, err
	}
	return out.Interface().(E), nil
}

// Decrypt converts an encrypted mirror struct back into its plain type P.
// Every Ciphertext field is decrypted individually with transcrypt.Decrypt;
// the decrypted value's kind is recovered from the authenticated ciphertext
// and must match the plain field's type, so a value cannot be smuggled into a
// field of a different kind. Calls name the plain type explicitly:
// cryptostruct.Decrypt[Data](key, secureData).
func Decrypt[P any](key string, encrypted any) (P, error) {
	var zero P

	plainType := reflect.TypeOf(zero)
	if plainType == nil || plainType.Kind() != reflect.Struct {
		return zero, fmt.Errorf("plain type %T must be a struct", zero)
	}
	if encrypted == nil {
		return zero, errors.New("encrypted value is nil")
	}
	encValue := reflect.ValueOf(encrypted)
	if encValue.Kind() != reflect.Struct {
		return zero, fmt.Errorf("encrypted value must be a struct, got %T", encrypted)
	}

	out, err := decryptValue(key, encValue, plainType, "")
	if err != nil {
		return zero, err
	}
	return out.Interface().(P), nil
}

// joinPath extends a field path for error messages, e.g. "Details.Name".
// Index and map-key segments (produced as "[...]") attach without a dot, so
// paths read naturally: "Inners[2].Note".
func joinPath(path, elem string) string {
	if path == "" {
		return elem
	}
	if len(elem) > 0 && elem[0] == '[' {
		return path + elem
	}
	return path + "." + elem
}

// pathErrorf prefixes an error with the field path it occurred at, keeping
// top-level errors free of a leading separator.
func pathErrorf(path, format string, args ...any) error {
	if path == "" {
		return fmt.Errorf(format, args...)
	}
	return fmt.Errorf("%s: %w", path, fmt.Errorf(format, args...))
}

// exportedFieldIndex maps the names of a struct type's exported fields to
// their field index. Unexported fields are excluded on purpose: they cannot be
// read or set via reflection, so both walkers ignore them entirely.
func exportedFieldIndex(t reflect.Type) map[string]int {
	m := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if f := t.Field(i); f.IsExported() {
			m[f.Name] = i
		}
	}
	return m
}
