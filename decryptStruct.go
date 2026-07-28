package transcrypt

import (
	"fmt"
	"reflect"
)

// decryptValue transforms an encrypted value back into the plain type
// plainType, mirroring encryptValue: Ciphertext leaves decrypt, identical
// types copy verbatim, and matching composite kinds recurse. visiting guards
// against cyclic values exactly as in encryptValue; callers pass nil.
func decryptValue(key string, enc reflect.Value, plainType reflect.Type, path string, visiting map[uintptr]bool) (reflect.Value, error) {
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
		return decryptStruct(key, enc, plainType, path, visiting)
	case reflect.Slice:
		if enc.IsNil() {
			return reflect.Zero(plainType), nil
		}
		out := reflect.MakeSlice(plainType, enc.Len(), enc.Len())
		for i := 0; i < enc.Len(); i++ {
			elem, err := decryptValue(key, enc.Index(i), plainType.Elem(), joinPath(path, indexPath(i)), visiting)
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
			elem, err := decryptValue(key, enc.Index(i), plainType.Elem(), joinPath(path, indexPath(i)), visiting)
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
			elem, err := decryptValue(key, iter.Value(), plainType.Elem(), joinPath(path, keyPath(iter.Key())), visiting)
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
		ptr := enc.Pointer()
		if visiting[ptr] {
			return reflect.Value{}, pathErrorf(path, "cannot decrypt cyclic value: pointer already visited on this path")
		}
		if visiting == nil {
			visiting = make(map[uintptr]bool)
		}
		visiting[ptr] = true
		elem, err := decryptValue(key, enc.Elem(), plainType.Elem(), path, visiting)
		delete(visiting, ptr)
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
// plain field's type via fitValue: the value's kind comes from inside the
// authenticated ciphertext, so a ciphertext cannot be relabeled into a field
// of a different kind.
func decryptLeaf(key string, enc reflect.Value, plainType reflect.Type, path string) (reflect.Value, error) {
	decrypted, err := decryptScalar(key, enc.String())
	if err != nil {
		return reflect.Value{}, pathErrorf(path, "decrypt failed: %w", err)
	}

	out, err := fitValue(reflect.ValueOf(decrypted), plainType)
	if err != nil {
		return reflect.Value{}, pathErrorf(path, "%w", err)
	}
	return out, nil
}

// decryptStruct maps every exported field of the encrypted struct onto the
// field with the same name in the plain struct, with the same strict
// two-directional matching as encryptStruct.
func decryptStruct(key string, enc reflect.Value, plainType reflect.Type, path string, visiting map[uintptr]bool) (reflect.Value, error) {
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

		fieldValue, err := decryptValue(key, enc.Field(encIndex), plainField.Type, joinPath(path, plainField.Name), visiting)
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
