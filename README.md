# go-transcrypt

This library encrypts a typed value into a single hex-encoded, colon-delimited string for safe on-disk storage, and decrypts that string back to the original value. The supported value types are currently `string` and `int` (see [Operations](#operations)).

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

The encryption key is a string used to encrypt the data with.
A function `CreateHexKey(bitSize int)` is available to create a random key based on an RSA private key, returned
as a hex-encoded string.

```go
var err error
var key string
if key, err = transcrypt.CreateHexKey(2048); err != nil {
	panic(err)
}
```

### Salt

A salt is also required for proper encryption.
You can generate a new salt for every call by leaving the salt as `nil` when calling the `Encrypt` function.
If you want to use a specific salt, you can either provide it manually (at least 12 bytes) or generate one with `CreateSalt`.

```go
var salt []byte
if salt, err = transcrypt.CreateSalt(); err != nil {
	panic(err)
}
```

## Operations

Currently, the following data types are supported for encryption:

- string
- int

### Encrypt

```go
var inputString = "hello world"
var encryptedString string
if encryptedString, err = transcrypt.Encrypt(key, salt, transcrypt.AES_256_GCM, inputString); err != nil {
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
