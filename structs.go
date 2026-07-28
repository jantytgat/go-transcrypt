package transcrypt

// This file holds the struct-level half of the Encrypt/Decrypt API: when the
// type parameter names a struct, a "plain" struct is mapped onto an
// "encrypted" mirror struct and back, encrypting fields individually. The
// mirror's field types are the single source of truth for what happens to
// each field:
//
//   - a mirror field of type Ciphertext is encrypted as a single value (each
//     field gets its own salt, derived key and nonce, and carries its original
//     type inside the authenticated ciphertext);
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
// are never encrypted, only map values — and because error messages carry the
// field path, map keys can appear verbatim in errors (and thus in logs), so
// keys should never hold sensitive data.

import (
	"fmt"
	"reflect"
)

// Ciphertext marks a field of an encrypted mirror struct as the encrypted
// counterpart of the plain struct's field with the same name. Its value is the
// self-describing encoded string produced by Encrypt, so it marshals naturally
// to JSON/YAML and needs no side-channel metadata.
type Ciphertext string

var ciphertextType = reflect.TypeOf(Ciphertext(""))

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
