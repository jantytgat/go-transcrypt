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

- **`transcrypt.go`** — public `Encrypt`/`Decrypt` entry points. `Encrypt(key, cipherSuite, data)` returns the encoded string; `Decrypt(key, data)` returns `any`.
- **`crypto.go`** — key generation (`CreateHexKey`) and `createCryptoConfig`, which generates/consumes the nonce, HKDF-derives a 32-byte key, and builds the `sio.Config`. Also holds `getKindForString` (string → `reflect.Kind`).
- **`cipherSuite.go`** — `CipherSuite` is a `byte` enum (`AES_256_GCM`, `CHACHA20_POLY1305`) mapping directly onto sio's cipher IDs. `GetCipherSuite(string) (CipherSuite, error)` parses a name back to the enum and returns an error on any unrecognized string (like `getKindForString`, it does not silently fall back to a default).
- **`convert.go`** — reflection-based (de)serialization of the payload and the `decodeHexString` splitter that parses the encoded format.

### Encoded string format

The output is three hex-encoded, colon-separated fields, validated on both ends by `regexEncryptedString` (`convert.go`):

```
<cipherSuite>:<salt>:<ciphertext>
```

The original type is **not** an outer field. `Encrypt` frames it together with the value as `<kind>:<hexPayload>` (see `encodeInnerPayload`) and encrypts that whole string, so the type tag is covered by the AEAD. `Decrypt` recovers it from the decrypted plaintext via `decodeInnerPayload`. This is deliberate: an earlier format kept the kind as a fourth *plaintext* field, which let an attacker relabel a stored value as a different same-width type (e.g. `int64`↔`float64`, both 8 bytes) without failing decryption. Keeping the kind inside the ciphertext makes any such tampering fail AEAD verification. Only `<cipherSuite>` remains outside the ciphertext (it must be readable to pick the cipher); tampering it merely breaks decryption, it cannot cause type confusion.

When adding support for a new type you must update **three** places: `convertValueToHexString` (encode), `convertHexStringToValue` (decode), and `getKindForString` (kind name → `reflect.Kind`).

### Keep the three type lists in sync

This is the most important invariant. Three lists must agree exactly: `convertValueToHexString` (encode), `convertHexStringToValue` (decode), and `getKindForString` (which recognizes only the supported kind names). If they drift, `Decrypt` will fail (or silently mishandle) values `Encrypt` produced.

Supported kinds: `bool`; `int`/`int8`/`int16`/`int32`/`int64`; `uint`/`uint8`/`uint16`/`uint32`/`uint64`; `float32`/`float64`; `complex64`/`complex128`; `string`; and `[]byte` (stored as kind `slice` — the only supported slice element type is `byte`). Signed integers are widened to 8-byte `int64` and unsigned to 8-byte `uint64`, so every integer kind decodes from a fixed 8-byte payload; `int`/`uint` additionally get a 32-bit-platform overflow check. Both converters own the inner-payload hex themselves — encode hex-encodes the serialized bytes, decode hex-decodes them — so `Decrypt` does not hex-decode separately.

### Salt (nonce is derived from it)

Field 2 of the encoded string is a **256-bit (32-byte) random HKDF salt**, generated fresh per `Encrypt` call. `createCryptoConfig` runs HKDF-SHA256 over `(key, salt)` and reads 44 bytes from the stream: the first 32 are the encryption key, the next 12 are the sio AEAD nonce. `Encrypt` passes a `nil` salt so one is generated and returned for storage; on decrypt, field 2 supplies the salt back and both key and nonce are re-derived from it.

Deriving both from a 256-bit salt is deliberate. An earlier design used a single random 12-byte value as *both* the HKDF salt and the AEAD nonce, so the derived key and the nonce shared one 96-bit source: a nonce collision (birthday bound ~2^48 messages) meant simultaneous key **and** nonce reuse — catastrophic for AEAD. With a 256-bit salt the derived key is unique per message to a ~2^128 bound, so the `(key, nonce)` pair can never repeat even though the nonce itself is only 96 bits. This raises the safe-message ceiling from ~2^48 to ~2^128.

### Keys

`CreateHexKey(byteSize)` reads `byteSize` random bytes (min 16) from `crypto/rand` and hex-encodes them — the "key" is just high-entropy string material fed to HKDF. `Encrypt` requires the key to be at least `minKeyLength` (16) bytes; HKDF stretches but cannot add entropy, so this floor guards against trivially weak keys. The floor is enforced on encryption only — `Decrypt` keeps its `key != ""` check so existing ciphertext stays readable regardless of the key that produced it. The helper is only a convenience for generating a suitable key.
