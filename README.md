# go-transcrypt

This library encrypts a typed value into a single hex-encoded, colon-delimited string for safe on-disk storage, and decrypts that string back to the original value. It supports the Go scalar types plus `[]byte` (see [Operations](#operations)).

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

### Nonce

No salt or nonce needs to be supplied. `Encrypt` generates a fresh random nonce
for every call and stores it in the output, so encrypting the same value twice
never produces the same result and the `(key, nonce)` pair is never reused.

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

### Encrypt

```go
var inputString = "hello world"
var encryptedString string
if encryptedString, err = transcrypt.Encrypt(key, transcrypt.AES_256_GCM, inputString); err != nil {
	panic(err)
}
```

### Decrypt

`Decrypt` returns the value as `any`; type-assert it back to the original type.

```go
var decryptedString any
if decryptedString, err = transcrypt.Decrypt(key, encryptedString); err != nil {
	panic(err)
}
```

## Example

An example is available in the [examples](https://github.com/jantytgat/go-transcrypt/tree/main/examples/simple)
directory.
