package transcrypt

import (
	"reflect"
)

// encryptValue transforms a plain value into the encrypted type encType. The
// encrypted type drives the walk: Ciphertext leaves encrypt, identical types
// copy verbatim, and matching composite kinds recurse. Any other combination
// is a mismatch between the plain struct and its mirror and returns an error
// carrying the field path.
//
// visiting holds the pointers on the current descent path so a cyclic value
// (only reachable through a pointer) fails with an error instead of recursing
// forever. It is nil until the first pointer is followed; callers pass nil.
// Pointers are removed on the way back up, so a shared (diamond) substructure
// is not mistaken for a cycle. Storing bare uintptr addresses is safe against
// GC address reuse: an address stays in the map only for the duration of the
// recursive call, and the reflect.Value passed into that call keeps the
// pointed-to object alive.
func encryptValue(key []byte, cipherSuite CipherSuite, plain reflect.Value, encType reflect.Type, path string, visiting map[uintptr]bool) (reflect.Value, error) {
	// Identical types are copied verbatim. This is checked before the
	// Ciphertext leaf case so a Ciphertext-typed field appearing on both
	// sides is copied, not encrypted a second time.
	if plain.Type() == encType {
		return plain, nil
	}

	if encType == ciphertextType {
		encrypted, err := encryptScalar(key, cipherSuite, plain.Interface())
		if err != nil {
			return reflect.Value{}, pathErrorf(path, "encrypt failed: %w", err)
		}
		return reflect.ValueOf(Ciphertext(encrypted)), nil
	}

	if plain.Kind() != encType.Kind() {
		return reflect.Value{}, pathErrorf(path, "cannot map plain type %s to encrypted type %s", plain.Type(), encType)
	}

	switch plain.Kind() {
	case reflect.Struct:
		return encryptStruct(key, cipherSuite, plain, encType, path, visiting)
	case reflect.Slice:
		if plain.IsNil() {
			return reflect.Zero(encType), nil
		}
		out := reflect.MakeSlice(encType, plain.Len(), plain.Len())
		for i := 0; i < plain.Len(); i++ {
			elem, err := encryptValue(key, cipherSuite, plain.Index(i), encType.Elem(), joinPath(path, indexPath(i)), visiting)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(elem)
		}
		return out, nil
	case reflect.Array:
		if plain.Len() != encType.Len() {
			return reflect.Value{}, pathErrorf(path, "array length mismatch: plain %d, encrypted %d", plain.Len(), encType.Len())
		}
		out := reflect.New(encType).Elem()
		for i := 0; i < plain.Len(); i++ {
			elem, err := encryptValue(key, cipherSuite, plain.Index(i), encType.Elem(), joinPath(path, indexPath(i)), visiting)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(elem)
		}
		return out, nil
	case reflect.Map:
		if plain.Type().Key() != encType.Key() {
			return reflect.Value{}, pathErrorf(path, "map key types must be identical (keys are never encrypted): plain %s, encrypted %s", plain.Type().Key(), encType.Key())
		}
		if plain.IsNil() {
			return reflect.Zero(encType), nil
		}
		out := reflect.MakeMapWithSize(encType, plain.Len())
		iter := plain.MapRange()
		for iter.Next() {
			elem, err := encryptValue(key, cipherSuite, iter.Value(), encType.Elem(), joinPath(path, keyPath(iter.Key())), visiting)
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(iter.Key(), elem)
		}
		return out, nil
	case reflect.Pointer:
		if plain.IsNil() {
			return reflect.Zero(encType), nil
		}
		ptr := plain.Pointer()
		if visiting[ptr] {
			return reflect.Value{}, pathErrorf(path, "cannot encrypt cyclic value: pointer already visited on this path")
		}
		if visiting == nil {
			visiting = make(map[uintptr]bool)
		}
		visiting[ptr] = true
		elem, err := encryptValue(key, cipherSuite, plain.Elem(), encType.Elem(), path, visiting)
		delete(visiting, ptr)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(encType.Elem())
		out.Elem().Set(elem)
		return out, nil
	default:
		return reflect.Value{}, pathErrorf(path, "cannot map plain type %s to encrypted type %s", plain.Type(), encType)
	}
}

// encryptStruct maps every exported field of the plain struct onto the field
// with the same name in the encrypted struct. Matching is strict in both
// directions so no exported field can be dropped silently.
func encryptStruct(key []byte, cipherSuite CipherSuite, plain reflect.Value, encType reflect.Type, path string, visiting map[uintptr]bool) (reflect.Value, error) {
	plainType := plain.Type()
	plainFields := exportedFieldIndex(plainType)

	out := reflect.New(encType).Elem()
	for i := 0; i < encType.NumField(); i++ {
		encField := encType.Field(i)
		if !encField.IsExported() {
			continue
		}
		plainIndex, ok := plainFields[encField.Name]
		if !ok {
			return reflect.Value{}, pathErrorf(joinPath(path, encField.Name), "encrypted struct %s has no matching field in plain struct %s", encType, plainType)
		}
		delete(plainFields, encField.Name)

		fieldValue, err := encryptValue(key, cipherSuite, plain.Field(plainIndex), encField.Type, joinPath(path, encField.Name), visiting)
		if err != nil {
			return reflect.Value{}, err
		}
		out.Field(i).Set(fieldValue)
	}

	for name := range plainFields {
		return reflect.Value{}, pathErrorf(joinPath(path, name), "plain struct %s has no matching field in encrypted struct %s", plainType, encType)
	}

	return out, nil
}
