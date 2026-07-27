package cryptostruct

import (
	"fmt"
	"reflect"

	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

// decryptValue transforms an encrypted value back into the plain type
// plainType, mirroring encryptValue: Ciphertext leaves decrypt, identical
// types copy verbatim, and matching composite kinds recurse.
func decryptValue(key string, enc reflect.Value, plainType reflect.Type, path string) (reflect.Value, error) {
	if enc.Type() == plainType {
		return enc, nil
	}

	if enc.Type() == ciphertextType {
		return decryptLeaf(key, enc, plainType, path)
	}

	if enc.Kind() != plainType.Kind() {
		return reflect.Value{}, pathErrorf(path, "cannot map encrypted type %s to plain type %s", enc.Type(), plainType)
	}

	switch enc.Kind() {
	case reflect.Struct:
		return decryptStruct(key, enc, plainType, path)
	case reflect.Slice:
		if enc.IsNil() {
			return reflect.Zero(plainType), nil
		}
		out := reflect.MakeSlice(plainType, enc.Len(), enc.Len())
		for i := 0; i < enc.Len(); i++ {
			elem, err := decryptValue(key, enc.Index(i), plainType.Elem(), joinPath(path, indexPath(i)))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(elem)
		}
		return out, nil
	case reflect.Array:
		if enc.Len() != plainType.Len() {
			return reflect.Value{}, pathErrorf(path, "array length mismatch: encrypted %d, plain %d", enc.Len(), plainType.Len())
		}
		out := reflect.New(plainType).Elem()
		for i := 0; i < enc.Len(); i++ {
			elem, err := decryptValue(key, enc.Index(i), plainType.Elem(), joinPath(path, indexPath(i)))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(elem)
		}
		return out, nil
	case reflect.Map:
		if enc.Type().Key() != plainType.Key() {
			return reflect.Value{}, pathErrorf(path, "map key types must be identical (keys are never encrypted): encrypted %s, plain %s", enc.Type().Key(), plainType.Key())
		}
		if enc.IsNil() {
			return reflect.Zero(plainType), nil
		}
		out := reflect.MakeMapWithSize(plainType, enc.Len())
		iter := enc.MapRange()
		for iter.Next() {
			elem, err := decryptValue(key, iter.Value(), plainType.Elem(), joinPath(path, keyPath(iter.Key())))
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(iter.Key(), elem)
		}
		return out, nil
	case reflect.Pointer:
		if enc.IsNil() {
			return reflect.Zero(plainType), nil
		}
		elem, err := decryptValue(key, enc.Elem(), plainType.Elem(), path)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(plainType.Elem())
		out.Elem().Set(elem)
		return out, nil
	default:
		return reflect.Value{}, pathErrorf(path, "cannot map encrypted type %s to plain type %s", enc.Type(), plainType)
	}
}

// decryptLeaf decrypts a single Ciphertext field and fits the result into the
// plain field's type. The value's kind comes from inside the authenticated
// ciphertext, so it is trusted; converting to a named type of the same kind is
// allowed, but a kind mismatch with the destination field is an error — a
// ciphertext cannot be relabeled into a field of a different kind.
func decryptLeaf(key string, enc reflect.Value, plainType reflect.Type, path string) (reflect.Value, error) {
	decrypted, err := transcrypt.Decrypt(key, string(enc.String()))
	if err != nil {
		return reflect.Value{}, pathErrorf(path, "decrypt failed: %w", err)
	}

	out := reflect.ValueOf(decrypted)
	if out.Type() == plainType {
		return out, nil
	}
	if out.Kind() == plainType.Kind() && out.Type().ConvertibleTo(plainType) {
		return out.Convert(plainType), nil
	}
	return reflect.Value{}, pathErrorf(path, "decrypted value has kind %s, which does not fit plain field type %s", out.Kind(), plainType)
}

// decryptStruct maps every exported field of the encrypted struct onto the
// field with the same name in the plain struct, with the same strict
// two-directional matching as encryptStruct.
func decryptStruct(key string, enc reflect.Value, plainType reflect.Type, path string) (reflect.Value, error) {
	encType := enc.Type()
	encFields := exportedFieldIndex(encType)

	out := reflect.New(plainType).Elem()
	for i := 0; i < plainType.NumField(); i++ {
		plainField := plainType.Field(i)
		if !plainField.IsExported() {
			continue
		}
		encIndex, ok := encFields[plainField.Name]
		if !ok {
			return reflect.Value{}, pathErrorf(joinPath(path, plainField.Name), "plain struct %s has no matching field in encrypted struct %s", plainType, encType)
		}
		delete(encFields, plainField.Name)

		fieldValue, err := decryptValue(key, enc.Field(encIndex), plainField.Type, joinPath(path, plainField.Name))
		if err != nil {
			return reflect.Value{}, err
		}
		out.Field(i).Set(fieldValue)
	}

	for name := range encFields {
		return reflect.Value{}, pathErrorf(joinPath(path, name), "encrypted struct %s has no matching field in plain struct %s", encType, plainType)
	}

	return out, nil
}

// indexPath renders a slice/array index for error paths, e.g. "[2]".
func indexPath(i int) string {
	return fmt.Sprintf("[%d]", i)
}

// keyPath renders a map key for error paths, e.g. "[name]".
func keyPath(k reflect.Value) string {
	return fmt.Sprintf("[%v]", k.Interface())
}
