# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`go-transcrypt` is a small Go library that encrypts arbitrary values into a single hex-encoded, colon-delimited string safe for on-disk storage, and decrypts that string back to the original typed value. Authenticated encryption is delegated to `github.com/minio/sio`; key derivation uses HKDF-SHA256 from `golang.org/x/crypto`.

The entire public API lives in `pkg/transcrypt`. There is no binary — `examples/simple/main.go` is a runnable usage demo, not part of the module's product surface.

## Commands

```bash
go build ./...                                    # build
go test ./...                                     # run all tests
go test ./pkg/transcrypt/                         # test the package
go test -run TestEncrypt ./pkg/transcrypt/        # run a single test by name
go test -v -cover ./pkg/transcrypt/               # verbose + coverage
go vet ./...                                       # vet
go run ./examples/simple                          # run the usage example
```

CI runs `go vet` + `go test -race -cover` on push/PR to `main` (`.github/workflows/test.yml`) and CodeQL security analysis (`.github/workflows/codeql.yml`). Still run `go test ./...` locally before pushing.

## Architecture

The round-trip flows through four files in `pkg/transcrypt`, split by responsibility:

- **`transcrypt.go`** — public `Encrypt`/`Decrypt` entry points. `Encrypt(key, salt, cipherSuite, data)` returns the encoded string; `Decrypt(key, data)` returns `any`.
- **`crypto.go`** — key/salt generation (`CreateHexKey`, `CreateSalt`) and `createCryptoConfig`, which HKDF-derives a 32-byte key and builds the `sio.Config`. Also holds `getKindForString` (string → `reflect.Kind`).
- **`cipherSuite.go`** — `CipherSuite` is a `byte` enum (`AES_256_GCM`, `CHACHA20_POLY1305`) mapping directly onto sio's cipher IDs. `GetCipherSuite(string)` parses a name back to the enum but **silently falls back to `CHACHA20_POLY1305`** on any unrecognized string (unlike `getKindForString`, which returns `reflect.Invalid`).
- **`convert.go`** — reflection-based (de)serialization of the payload and the `decodeHexString` splitter that parses the encoded format.

### Encoded string format

The output is four hex-encoded, colon-separated fields, validated on both ends by `regexEncryptedString` (`convert.go`):

```
<cipherSuite>:<nonce/salt>:<ciphertext>:<original-kind>
```

Field 4 stores `reflect.Kind.String()` so `Decrypt` can reconstruct the original Go type without the caller specifying it. When adding support for a new type you must update **both** halves: `convertValueToHexString` (encode) and `convertBytesToValue` (decode), and ensure the kind name round-trips through `getKindForString`.

### Type support is intentionally narrow — keep the two converters symmetric

This is the most important invariant. `Encrypt` only serializes `int` and `string` (`convertValueToHexString`); `Decrypt` only deserializes `int`, `uint64`, and `string` (`convertBytesToValue`). These lists are **not** in sync, and `getKindForString` recognizes far more kinds than either converter handles. When touching type support, change the converters together or `Decrypt` will fail (or silently mishandle) values `Encrypt` happily produced.

### Salt vs. nonce

`salt` and the sio `Nonce` are the same 12 bytes: `createCryptoConfig` feeds `salt[:12]` into HKDF *and* casts `salt[:]` to the `*[12]byte` nonce. Salt must be ≥12 bytes (validated in both `Encrypt` and `createCryptoConfig`); anything beyond 12 bytes is ignored. On decrypt, field 2 of the encoded string is this same value.

### Keys

`CreateHexKey(bitSize)` generates an RSA private key (min 1024 bits), PEM-encodes it, and hex-encodes that PEM — the "key" is just high-entropy string material fed to HKDF, not used for RSA operations. Any non-empty string works as a key; the RSA helper is only a convenience for generating one.
