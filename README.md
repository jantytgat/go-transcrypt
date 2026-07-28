# go-transcrypt

This library encrypts a typed value into a single hex-encoded, colon-delimited string for safe on-disk storage, and decrypts that string back to the original value. It supports the Go scalar types plus `[]byte` (see [Operations](#operations)).
A single generic `Encrypt`/`Decrypt` pair serves every shape: the type
parameter selects the mode. A string target encrypts a single value; a struct
target encrypts field by field into a mirror type (see [Structs](#structs)).

[![Go Reference](https://pkg.go.dev/badge/github.com/jantytgat/go-transcrypt.svg)](https://pkg.go.dev/github.com/jantytgat/go-transcrypt)

---

## Basics

### Add the package to your project

```bash
go get github.com/jantytgat/go-transcrypt
```

### Import

Next, you can manually add the import statement to your `.go` file, or have it added automatically when using it.

```go
import "github.com/jantytgat/go-transcrypt"
```

### Encryption key

The encryption key is a string used to encrypt the data with. `Encrypt` requires it
to be at least 16 bytes; HKDF stretches the key but cannot add entropy, so a short
key would weaken every ciphertext.
A function `CreateHexKey(byteSize int)` is available to create a random key from `byteSize`
cryptographically secure random bytes (minimum 16), returned as a hex-encoded string.

```go
var err error
var key string
if key, err = transcrypt.CreateHexKey(32); err != nil {
	panic(err)
}
```

### Salt and nonce

No salt or nonce needs to be supplied. `Encrypt` generates a fresh random 256-bit
salt for every call and stores it in the output; both the encryption key and the
AEAD nonce are derived from that salt via HKDF. Encrypting the same value twice
never produces the same result, and because the key is derived from a 256-bit salt
it is unique per message, so the `(key, nonce)` pair is never reused.

## Operations

The following data types are supported for encryption:

- `bool`
- `string`
- `int`, `int8`, `int16`, `int32`, `int64`
- `uint`, `uint8`, `uint16`, `uint32`, `uint64`
- `float32`, `float64`
- `complex64`, `complex128`
- `[]byte`

Composite and reference types (slices other than `[]byte`, arrays, maps, structs,
channels, functions, pointers) are not supported and return an error.

A nil `[]byte` decrypts back to an empty, non-nil `[]byte`: the encoded format does
not distinguish the two, so test for `len(b) == 0` rather than `b == nil`.

### Encrypt

The type parameter names the encryption target; for single values it is a
string type (any named type of kind string works, e.g. `transcrypt.Ciphertext`):

```go
var inputString = "hello world"
var encryptedString string
if encryptedString, err = transcrypt.Encrypt[string](key, transcrypt.AES_256_GCM, inputString); err != nil {
	panic(err)
}
```

### Decrypt

`Decrypt[any]` returns the value as `any`, typed as whatever was stored;
type-assert it back to the original type. Naming a concrete type instead
returns a typed value directly — the kind recovered from the authenticated
ciphertext must match (named types of the same kind are converted, a kind
mismatch is an error):

```go
var decryptedString any
if decryptedString, err = transcrypt.Decrypt[any](key, encryptedString); err != nil {
	panic(err)
}

// Or typed, without an assertion:
var typedString string
if typedString, err = transcrypt.Decrypt[string](key, encryptedString); err != nil {
	panic(err)
}
```

## Structs

Naming a struct type as the target of `Encrypt`/`Decrypt` encrypts structs
field by field. You define a "plain" struct and an equivalent "encrypted"
mirror struct; the mirror's field types decide what happens to each field —
there are no struct tags and no interfaces to implement:

- a mirror field typed `transcrypt.Ciphertext` is encrypted individually
  with `transcrypt.Encrypt` (own salt, derived key, and nonce per field; the
  original type travels inside the authenticated ciphertext);
- a mirror field with the identical type as the plain field is copied
  verbatim;
- mirrored composite types (structs, slices, arrays, maps, pointers) are
  traversed recursively. Map keys are never encrypted, only map values.

```go
type Account struct {
	Password string
	Enabled  bool
}

type SecureAccount struct {
	Password transcrypt.Ciphertext // encrypted
	Enabled  bool                  // copied as-is
}

secure, err := transcrypt.Encrypt[SecureAccount](key, transcrypt.AES_256_GCM, account)
restored, err := transcrypt.Decrypt[Account](key, secure)
```

Field matching is by name and strict in both directions: an exported field
present on one side but missing on the other is an error, so data is never
dropped silently. Unexported fields are ignored (like `encoding/json`). Nil
pointers, slices, and maps are preserved as nil. `Ciphertext` is a string
underneath, so encrypted structs marshal naturally to JSON or YAML.

## Example

Two examples are available in the [examples](https://github.com/jantytgat/go-transcrypt/tree/main/examples)
directory:

- [simple](https://github.com/jantytgat/go-transcrypt/tree/main/examples/simple)
  round-trips a value of every supported type listed under
  [Operations](#operations) and shows both cipher suites (`AES_256_GCM` and
  `CHACHA20_POLY1305`) in action.
- [structs](https://github.com/jantytgat/go-transcrypt/tree/main/examples/structs)
  encrypts a nested struct (including a slice of structs and a map) into its
  mirror type and back using `Encrypt`/`Decrypt` with struct type parameters.
