# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`go-transcrypt` is a small Go library that encrypts arbitrary values into a single hex-encoded, colon-delimited string safe for on-disk storage, and decrypts that string back to the original typed value. Authenticated encryption is delegated to `github.com/minio/sio`; key derivation uses HKDF-SHA256 from `golang.org/x/crypto`.

The public API lives in a single package at the repository root (import path `github.com/jantytgat/go-transcrypt`), and consists of one generic `Encrypt[E]`/`Decrypt[P]` pair: the type parameter selects the encryption mode (string-kind target → single value, struct target → mirror-struct field encryption, `File` target → streaming file encryption). There is no binary — `examples/simple/main.go`, `examples/structs/main.go` and `examples/files/main.go` are runnable usage demos, not part of the module's product surface.

## Commands

```bash
go build ./...                                    # build
go test ./...                                     # run all tests
go test .                                         # test the package
go test -run TestEncrypt .                        # run a single test by name
go test -v -cover .                               # verbose + coverage
go vet ./...                                       # vet
go run ./examples/simple                          # run the usage example
```

A `Makefile` wraps the common targets: `make test` (race), `make coverage`
(func report), `make example`, `make vet`, `make build`, `make coverage-html`,
and `make help`.

CI runs `go vet` + `go test -race -cover` plus a `govulncheck` job on push/PR to `main` (`.github/workflows/test.yml`) and CodeQL security analysis (`.github/workflows/codeql.yml`). Still run `go test ./...` locally before pushing.

## Architecture

The round-trip flows through four files at the repository root, split by responsibility:

- **`transcrypt.go`** — the public generic `Encrypt[E]`/`Decrypt[P]` entry points, which dispatch on the type parameter's kind, plus the single-value implementations `encryptScalar`/`decryptScalar` they and the struct walkers share. Both entry points first intercept `E`/`P` == `File` by concrete type (before the kind switch — `File` is itself a struct) and route to the file streaming path. `Encrypt[E]` otherwise accepts a string-kind `E` (encoded-string result, converted to `E` — so `Encrypt[Ciphertext]` works) or a struct `E` (mirror encryption); anything else, including `Encrypt[any]`, is an error. On the struct paths, a target type identical to the input value's type is rejected: the walkers copy identical types verbatim, so such a call would return the plaintext unchanged while looking like a successful encryption (and symmetrically for `Decrypt`). `Decrypt[P]` accepts an interface `P` (returns the stored type as-is), a struct `P` (mirror decryption), or any other concrete `P` (typed single value, fitted via `fitValue`: exact type or same-kind conversion, cross-kind is an error). Single-value decryption accepts any string-kind input (`string`, `Ciphertext`, ...). The type parameter appears only in the result position, so it is never inferred — every call names it explicitly.
- **`crypto.go`** — key generation (`CreateHexKey`) and `createCryptoConfig`, which generates/consumes the nonce, HKDF-derives a 32-byte key, and builds the `sio.Config`. The config pins `MinVersion`/`MaxVersion` to DARE 2.0: sio's default would also accept legacy 1.0 streams on decrypt, which lack the final-package flag and so can be truncated at a package boundary undetected; this library has only ever emitted 2.0, so the pin costs no compatibility. Its `info` parameter domain-separates the container formats: the string format passes `nil` (compatibility with existing ciphertext), the file format passes `fileHKDFInfo`. Also holds `getKindForString` (string → `reflect.Kind`).
- **`cipherSuite.go`** — `CipherSuite` is a `byte` enum (`AES_256_GCM`, `CHACHA20_POLY1305`) mapping directly onto sio's cipher IDs. `GetCipherSuite(string) (CipherSuite, error)` parses a name back to the enum and returns an error on any unrecognized string (like `getKindForString`, it does not silently fall back to a default).
- **`convert.go`** — reflection-based (de)serialization of the payload and the `decodeHexString` splitter that parses the encoded format.

### Struct encryption (`structs.go`, `encryptStruct.go`, `decryptStruct.go`)

When the type parameter names a struct, `Encrypt`/`Decrypt` map a "plain" struct onto an "encrypted" mirror struct and back, encrypting fields individually via `encryptScalar`/`decryptScalar`. The mirror struct's field types are the single source of truth — there are **no struct tags and no interfaces** (deliberately unlike `corelayer/go-cryptostruct`, which this design replaces):

- mirror field typed `Ciphertext` (`structs.go`) → encrypted leaf; each field gets its own salt/key/nonce and its type rides inside the AEAD, so no per-struct `CryptoParams` metadata is needed;
- identical type on both sides → copied verbatim (checked *before* the `Ciphertext` leaf case, so a `Ciphertext` field on both sides copies rather than double-encrypts);
- matching composite kinds (struct/slice/array/map/pointer) → recursed by the walkers in `encryptStruct.go`/`decryptStruct.go`, which mirror each other case for case — a change to one walker almost always needs the same change in the other.

Struct fields match by name, strictly in both directions (missing/extra exported fields are errors, never silent drops); unexported fields are ignored; nil pointers/slices/maps are preserved. Both walkers carry a `visiting` set of pointers on the current descent path, so a cyclic value fails with an error instead of recursing until stack overflow — pointers are removed on the way back up, so shared (diamond) substructures still work. On decrypt, the kind recovered from the authenticated ciphertext must match the plain field's kind (`decryptLeaf`) — named types of the same kind are converted, cross-kind never is. Errors carry the field path (e.g. `Inners[1].Note`). Anonymous embedding only works when both sides embed a same-named type; map keys are never encrypted. A `File` field appearing identically on both sides copies verbatim like any identical type — mirror encryption never touches the filesystem.

### File encryption (`file.go`)

When the type parameter is `File` (`{Source, Target string}`), the file at `Source` is streamed through sio into `Target` — constant memory regardless of size. An empty `Target` means in-place (`Target` defaults to `Source`); the returned `File` carries the resolved `Target`. The encoded-string format cannot serve here (it hex-encodes the whole ciphertext in memory), so files use a binary sibling format carrying the same fields: 4 magic bytes `TCRF`, 1 version byte, 1 cipher-suite byte, the 32-byte HKDF salt, then the raw DARE stream (`fileHeaderLength` = 38). Invariants to preserve:

- **Atomic replace**: `transformFile` streams into a temp file in `Target`'s directory (same filesystem → atomic rename), syncs, applies `Source`'s permission bits, renames over `Target` only on success, and best-effort-syncs the directory so the rename survives a crash; any failure removes the temp and leaves `Source`/`Target` untouched. This is load-bearing for correctness, not just tidiness: sio authenticates the final DARE package only at end of stream, so "decryption succeeded" is only known after the whole file is processed. It is also what makes `Source == Target` safe with no special casing.
- **Domain separation**: file keys derive with `fileHKDFInfo` as the HKDF `info` parameter while the string format uses `nil`, so ciphertext lifted out of one container and rewrapped in the other never authenticates (same DARE layout, same key/salt notwithstanding).
- **Sentinel byte**: `filePlaintextSentinel` is prepended to the plaintext before encryption and stripped after. It guarantees the plaintext is never empty, so sio always emits ≥1 authenticated package — without it an empty file encrypts to an empty DARE stream, and truncating any encrypted file to just its header would "decrypt" to empty content undetected.

The key floor (`minKeyLength`) applies on encrypt; decrypt only requires a non-empty key, matching the compat policy. Header tampering always fails — the salt feeds key derivation, and the suite byte, while not part of the derivation, selects the only cipher sio will accept while the DARE package headers (which name the cipher actually used) are authenticated as associated data. A `Target` that is a symlink is replaced as a link, not followed. Files never enter the reflection converters, so the three type lists are unaffected.

### Encoded string format

The output is three hex-encoded, colon-separated fields, validated on both ends by `regexEncryptedString` (`convert.go`):

```
<cipherSuite>:<salt>:<ciphertext>
```

The original type is **not** an outer field. `Encrypt` frames it together with the value as `<kind>:<hexPayload>` (see `encodeInnerPayload`) and encrypts that whole string, so the type tag is covered by the AEAD. `Decrypt` recovers it from the decrypted plaintext via `decodeInnerPayload`. This is deliberate: an earlier format kept the kind as a fourth *plaintext* field, which let an attacker relabel a stored value as a different same-width type (e.g. `int64`↔`float64`, both 8 bytes) without failing decryption. Keeping the kind inside the ciphertext makes any such tampering fail AEAD verification. Only `<cipherSuite>` remains outside the ciphertext (it must be readable to pick the cipher); `decodeHexString` rejects unknown suite values up front, and tampering a valid one merely breaks decryption, it cannot cause type confusion.

When adding support for a new type you must update **three** places: `convertValueToHexString` (encode), `convertHexStringToValue` (decode), and `getKindForString` (kind name → `reflect.Kind`).

### Keep the three type lists in sync

This is the most important invariant. Three lists must agree exactly: `convertValueToHexString` (encode), `convertHexStringToValue` (decode), and `getKindForString` (which recognizes only the supported kind names). If they drift, `Decrypt` will fail (or silently mishandle) values `Encrypt` produced.

Supported kinds: `bool`; `int`/`int8`/`int16`/`int32`/`int64`; `uint`/`uint8`/`uint16`/`uint32`/`uint64`; `float32`/`float64`; `complex64`/`complex128`; `string`; and `[]byte` (stored as kind `slice` — the only supported slice element type is `byte`). Signed integers are widened to 8-byte `int64` and unsigned to 8-byte `uint64`, so every integer kind decodes from a fixed 8-byte payload; `int`/`uint` additionally get a 32-bit-platform overflow check. Both converters own the inner-payload hex themselves — encode hex-encodes the serialized bytes, decode hex-decodes them — so `Decrypt` does not hex-decode separately.

### Salt (nonce is derived from it)

Field 2 of the encoded string is a **256-bit (32-byte) random HKDF salt**, generated fresh per `Encrypt` call. `createCryptoConfig` runs HKDF-SHA256 over `(key, salt)` and reads 44 bytes from the stream: the first 32 are the encryption key, the next 12 are the sio AEAD nonce. `Encrypt` passes a `nil` salt so one is generated and returned for storage; on decrypt, field 2 supplies the salt back and both key and nonce are re-derived from it.

Deriving both from a 256-bit salt is deliberate. An earlier design used a single random 12-byte value as *both* the HKDF salt and the AEAD nonce, so the derived key and the nonce shared one 96-bit source: a nonce collision (birthday bound ~2^48 messages) meant simultaneous key **and** nonce reuse — catastrophic for AEAD. With a 256-bit salt the derived key is unique per message to a ~2^128 bound, so the `(key, nonce)` pair can never repeat even though the nonce itself is only 96 bits. This raises the safe-message ceiling from ~2^48 to ~2^128.

### Keys

`CreateHexKey(byteSize)` reads `byteSize` random bytes (min 16) from `crypto/rand` and hex-encodes them — the "key" is just high-entropy string material fed to HKDF. `Encrypt` requires the key to be at least `minKeyLength` (16) bytes; HKDF stretches but cannot add entropy, so this floor guards against trivially weak keys. The floor is enforced on encryption only — `Decrypt` keeps its `key != ""` check so existing ciphertext stays readable regardless of the key that produced it. The helper is only a convenience for generating a suitable key.
