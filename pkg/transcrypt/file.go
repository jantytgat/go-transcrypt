package transcrypt

// This file holds the file half of the Encrypt/Decrypt API: when the type
// parameter is File, the value at File.Source is streamed through sio into
// File.Target, so memory use stays constant regardless of file size. The
// encoded-string format cannot serve here — it hex-encodes the whole
// ciphertext in memory — so files use a binary sibling format carrying the
// same fields:
//
//	offset 0:  magic "TCRF" (4 bytes)
//	offset 4:  format version (1 byte)
//	offset 5:  cipher suite (1 byte, the CipherSuite enum)
//	offset 6:  HKDF salt (saltLength bytes)
//	offset 38: raw DARE ciphertext stream produced by sio
//
// Everything after the header is protected exactly like the string format:
// tampering the cipher-suite or salt bytes changes the derived key and fails
// authentication. File keys are additionally derived with fileHKDFInfo as the
// HKDF info parameter, so ciphertext lifted out of one container format and
// replayed in the other never authenticates.
//
// The result is always written to a temporary file next to Target and renamed
// over it only on success, which both keeps failures from destroying data and
// makes in-place operation (Target == Source) safe.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/minio/sio"
)

// File identifies a file on disk for streaming encryption or decryption via
// Encrypt[File]/Decrypt[File]. Source is the file to read. Target is where the
// result is written; leaving it empty means in-place, i.e. the result
// atomically replaces Source once the operation completes. The returned File
// always carries the resolved Target.
type File struct {
	Source string
	Target string
}

var fileType = reflect.TypeOf(File{})

// fileMagic identifies a transcrypt-encrypted file. It allows decryptFile to
// reject foreign input with a clear error before touching any cryptography.
var fileMagic = [4]byte{'T', 'C', 'R', 'F'}

// fileFormatVersion is the current version of the binary file format, stored
// in the header so the layout can evolve without breaking old files.
const fileFormatVersion byte = 1

// fileHeaderLength is the size of the plaintext file header: magic, version,
// cipher suite, then the HKDF salt. The DARE stream starts right after.
const fileHeaderLength = len(fileMagic) + 1 + 1 + saltLength

// fileHKDFInfo is the HKDF info parameter for file keys. The encoded-string
// format derives with a nil info (its original derivation, kept for
// compatibility), so the two container formats can never decrypt each other's
// ciphertext even under the same key and salt.
var fileHKDFInfo = []byte("transcrypt/file")

// filePlaintextSentinel is a single byte prepended to the plaintext stream
// before encryption and stripped after decryption. It guarantees the plaintext
// is never empty, so sio always emits at least one authenticated DARE package:
// without it, encrypting an empty file produces an empty ciphertext stream,
// and a file truncated to just the plaintext header would "decrypt" to empty
// content without any authentication failure.
const filePlaintextSentinel byte = 0x01

// resolve validates the paths and applies the in-place default.
func (f File) resolve() (File, error) {
	if f.Source == "" {
		return File{}, errors.New("file source is empty")
	}
	if f.Target == "" {
		f.Target = f.Source
	}
	return f, nil
}

// encryptFile streams the file at f.Source into an encrypted file at f.Target.
// It enforces the same key floor as encryptScalar and returns the File with
// its resolved Target.
func encryptFile(key string, cipherSuite CipherSuite, f File) (File, error) {
	if len(key) < minKeyLength {
		return File{}, fmt.Errorf("key must be at least %d bytes", minKeyLength)
	}
	if !cipherSuite.isValid() {
		return File{}, fmt.Errorf("unknown cipher suite: %d", cipherSuite)
	}

	f, err := f.resolve()
	if err != nil {
		return File{}, err
	}

	err = transformFile(f, func(src, dst *os.File) error {
		// A nil salt makes createCryptoConfig generate a fresh random one per
		// call; it is stored in the header so decryption can re-derive the key
		// and nonce from it.
		cryptoConfig, salt, err := createCryptoConfig(key, []byte{byte(cipherSuite)}, nil, fileHKDFInfo)
		if err != nil {
			return err
		}

		header := make([]byte, 0, fileHeaderLength)
		header = append(header, fileMagic[:]...)
		header = append(header, fileFormatVersion, byte(cipherSuite))
		header = append(header, salt...)
		if _, err = dst.Write(header); err != nil {
			return fmt.Errorf("cannot write file header: %w", err)
		}

		plaintext := io.MultiReader(bytes.NewReader([]byte{filePlaintextSentinel}), src)
		if _, err = sio.Encrypt(dst, plaintext, cryptoConfig); err != nil {
			return fmt.Errorf("encrypt failed: %w", err)
		}
		return nil
	})
	if err != nil {
		return File{}, err
	}
	return f, nil
}

// decryptFile streams the encrypted file at f.Source back into a plain file at
// f.Target. Like the other decryption paths it only requires a non-empty key,
// so files stay readable regardless of the key that produced them. sio
// authenticates the final DARE package only at end of stream, so success is
// known only once the whole file has been processed — which is why the result
// reaches Target exclusively via transformFile's rename-on-success.
func decryptFile(key string, f File) (File, error) {
	if key == "" {
		return File{}, errors.New("key is empty")
	}

	f, err := f.resolve()
	if err != nil {
		return File{}, err
	}

	err = transformFile(f, func(src, dst *os.File) error {
		var header [fileHeaderLength]byte
		if _, err := io.ReadFull(src, header[:]); err != nil {
			return fmt.Errorf("cannot read file header: %w", err)
		}
		if !bytes.Equal(header[:len(fileMagic)], fileMagic[:]) {
			return errors.New("not a transcrypt-encrypted file")
		}
		if header[4] != fileFormatVersion {
			return fmt.Errorf("unsupported file format version %d", header[4])
		}
		if !CipherSuite(header[5]).isValid() {
			return fmt.Errorf("unknown cipher suite: %d", header[5])
		}

		cryptoConfig, _, err := createCryptoConfig(key, []byte{header[5]}, header[6:], fileHKDFInfo)
		if err != nil {
			return err
		}

		plaintext, err := sio.DecryptReader(src, cryptoConfig)
		if err != nil {
			return fmt.Errorf("decrypt failed: %w", err)
		}
		// The sentinel doubles as the emptiness guard: an empty ciphertext
		// stream yields no plaintext at all, so a file truncated to its header
		// fails here instead of decrypting to an empty file.
		var sentinel [1]byte
		if _, err = io.ReadFull(plaintext, sentinel[:]); err != nil {
			return fmt.Errorf("decrypt failed: %w", err)
		}
		if sentinel[0] != filePlaintextSentinel {
			return errors.New("decrypt failed: invalid plaintext sentinel")
		}
		if _, err = io.Copy(dst, plaintext); err != nil {
			return fmt.Errorf("decrypt failed: %w", err)
		}
		return nil
	})
	if err != nil {
		return File{}, err
	}
	return f, nil
}

// transformFile streams f.Source through transform into a temporary file and
// atomically renames it over f.Target on success. The temporary file lives in
// Target's directory so the rename never crosses a filesystem. On any error it
// is removed and both Source and Target are left untouched; because Source is
// only ever read and the result only lands on success, Source == Target
// (in-place replacement) needs no special handling. The temporary file is
// synced and given Source's permission bits before the rename. Note that if
// Target is a symlink, the rename replaces the link itself, not the file it
// points to.
func transformFile(f File, transform func(src, dst *os.File) error) (err error) {
	var src *os.File
	if src, err = os.Open(f.Source); err != nil {
		return fmt.Errorf("cannot open source file: %w", err)
	}
	defer src.Close()

	var info os.FileInfo
	if info, err = src.Stat(); err != nil {
		return fmt.Errorf("cannot stat source file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source %s is not a regular file", f.Source)
	}

	var tmp *os.File
	if tmp, err = os.CreateTemp(filepath.Dir(f.Target), ".transcrypt-*"); err != nil {
		return fmt.Errorf("cannot create temporary file: %w", err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	if err = transform(src, tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("cannot sync temporary file: %w", err)
	}
	if err = tmp.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("cannot set temporary file permissions: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("cannot close temporary file: %w", err)
	}
	if err = os.Rename(tmp.Name(), f.Target); err != nil {
		return fmt.Errorf("cannot replace target file: %w", err)
	}
	return nil
}
