package transcrypt

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey is a fixed key long enough for minKeyLength; file tests never need
// fresh entropy for the key itself.
const fileTestKey = "0123456789abcdef0123456789abcdef"

// writeTestFile creates a file with the given content and permissions inside
// dir and returns its path.
func writeTestFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("cannot write test file: %v", err)
	}
	return path
}

// patternBytes returns n deterministic non-repeating-friendly bytes; large
// sizes exercise multiple 64KiB DARE packages.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// assertNoTempLitter fails if a transformFile temporary file survived in dir.
func assertNoTempLitter(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".transcrypt-") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}
}

func Test_FileRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		size        int
		cipherSuite CipherSuite
	}{
		{name: "empty_aes", size: 0, cipherSuite: AES_256_GCM},
		{name: "small_aes", size: 13, cipherSuite: AES_256_GCM},
		{name: "multi_package_aes", size: 200_000, cipherSuite: AES_256_GCM},
		{name: "small_chacha", size: 13, cipherSuite: CHACHA20_POLY1305},
		{name: "multi_package_chacha", size: 200_000, cipherSuite: CHACHA20_POLY1305},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			content := patternBytes(tt.size)
			plain := writeTestFile(t, dir, "plain.bin", content)
			encPath := filepath.Join(dir, "plain.bin.enc")
			decPath := filepath.Join(dir, "restored.bin")

			enc, err := Encrypt[File](fileTestKey, tt.cipherSuite, File{Source: plain, Target: encPath})
			if err != nil {
				t.Fatalf("Encrypt[File]() error = %v", err)
			}
			if enc.Target != encPath {
				t.Errorf("Encrypt[File]() target = %s, want %s", enc.Target, encPath)
			}

			encContent, err := os.ReadFile(encPath)
			if err != nil {
				t.Fatalf("cannot read encrypted file: %v", err)
			}
			if !bytes.Equal(encContent[:len(fileMagic)], fileMagic[:]) {
				t.Errorf("encrypted file does not start with magic %q", fileMagic)
			}
			if len(encContent) <= fileHeaderLength {
				t.Errorf("encrypted file has no ciphertext after the header")
			}
			if tt.size > 0 && bytes.Contains(encContent, content[:min(tt.size, 64)]) {
				t.Errorf("encrypted file contains plaintext")
			}

			dec, err := Decrypt[File](fileTestKey, File{Source: encPath, Target: decPath})
			if err != nil {
				t.Fatalf("Decrypt[File]() error = %v", err)
			}
			if dec.Target != decPath {
				t.Errorf("Decrypt[File]() target = %s, want %s", dec.Target, decPath)
			}

			restored, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatalf("cannot read restored file: %v", err)
			}
			if !bytes.Equal(restored, content) {
				t.Errorf("restored content does not match original (len %d vs %d)", len(restored), len(content))
			}
			assertNoTempLitter(t, dir)
		})
	}
}

func Test_FileRoundTrip_InPlace(t *testing.T) {
	dir := t.TempDir()
	content := patternBytes(100_000)
	path := writeTestFile(t, dir, "data.bin", content)

	// An empty Target means the result replaces Source.
	enc, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: path})
	if err != nil {
		t.Fatalf("Encrypt[File]() error = %v", err)
	}
	if enc.Target != path {
		t.Errorf("Encrypt[File]() target = %s, want %s", enc.Target, path)
	}

	encContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read encrypted file: %v", err)
	}
	if bytes.Equal(encContent, content) {
		t.Fatalf("in-place encryption left the file unchanged")
	}

	if _, err = Decrypt[File](fileTestKey, File{Source: path}); err != nil {
		t.Fatalf("Decrypt[File]() error = %v", err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read restored file: %v", err)
	}
	if !bytes.Equal(restored, content) {
		t.Errorf("in-place round trip does not match original content")
	}
	assertNoTempLitter(t, dir)
}

func Test_FilePermissionsPreserved(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "data.bin", patternBytes(64))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("cannot chmod test file: %v", err)
	}

	if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: path}); err != nil {
		t.Fatalf("Encrypt[File]() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat encrypted file: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("encrypted file permissions = %o, want 640", info.Mode().Perm())
	}
}

func Test_FileDecrypt_Tamper(t *testing.T) {
	dir := t.TempDir()
	plain := writeTestFile(t, dir, "plain.bin", patternBytes(1024))
	encPath := filepath.Join(dir, "plain.bin.enc")
	if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: plain, Target: encPath}); err != nil {
		t.Fatalf("Encrypt[File]() error = %v", err)
	}
	original, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("cannot read encrypted file: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(b []byte)
	}{
		{name: "bad_magic", mutate: func(b []byte) { b[0] ^= 0xff }},
		{name: "bad_version", mutate: func(b []byte) { b[4] = 0xfe }},
		{name: "bad_cipher_suite", mutate: func(b []byte) { b[5] = 0x63 }},
		{name: "tampered_salt", mutate: func(b []byte) { b[6] ^= 0x01 }},
		{name: "tampered_ciphertext", mutate: func(b []byte) { b[fileHeaderLength] ^= 0x01 }},
		{name: "tampered_last_byte", mutate: func(b []byte) { b[len(b)-1] ^= 0x01 }},
		{name: "truncated", mutate: nil},
		// A file cut down to just its plaintext header must fail: the sentinel
		// byte guarantees valid plaintext is never empty, so an empty
		// ciphertext stream can never pass as a legitimate empty file.
		{name: "truncated_to_header", mutate: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := bytes.Clone(original)
			switch {
			case tt.mutate != nil:
				tt.mutate(tampered)
			case tt.name == "truncated_to_header":
				tampered = tampered[:fileHeaderLength]
			default:
				tampered = tampered[:len(tampered)-1]
			}
			src := writeTestFile(t, dir, "tampered-"+tt.name, tampered)
			target := filepath.Join(dir, "out-"+tt.name)

			if _, err := Decrypt[File](fileTestKey, File{Source: src, Target: target}); err == nil {
				t.Errorf("Decrypt[File]() succeeded on tampered input")
			}
			if _, err := os.Stat(target); err == nil {
				t.Errorf("failed decryption still produced target file")
			}
		})
	}
	assertNoTempLitter(t, dir)
}

// Test_FileDecrypt_FailureLeavesTargetIntact verifies the atomicity contract:
// a failed operation must leave a pre-existing target untouched, with no
// temporary files left behind.
func Test_FileDecrypt_FailureLeavesTargetIntact(t *testing.T) {
	dir := t.TempDir()
	content := patternBytes(4096)
	path := writeTestFile(t, dir, "data.bin", content)
	if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: path}); err != nil {
		t.Fatalf("Encrypt[File]() error = %v", err)
	}
	encContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read encrypted file: %v", err)
	}

	// In-place decryption with the wrong key must fail and leave the encrypted
	// file exactly as it was.
	if _, err = Decrypt[File]("another-key-thats-wrong", File{Source: path}); err == nil {
		t.Fatalf("Decrypt[File]() succeeded with the wrong key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot re-read encrypted file: %v", err)
	}
	if !bytes.Equal(after, encContent) {
		t.Errorf("failed decryption modified the source file")
	}
	assertNoTempLitter(t, dir)
}

func Test_File_Errors(t *testing.T) {
	dir := t.TempDir()
	plain := writeTestFile(t, dir, "plain.bin", patternBytes(16))

	t.Run("encrypt_empty_source", func(t *testing.T) {
		if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{}); err == nil {
			t.Errorf("Encrypt[File]() with empty source did not fail")
		}
	})
	t.Run("encrypt_short_key", func(t *testing.T) {
		if _, err := Encrypt[File]("short", AES_256_GCM, File{Source: plain}); err == nil {
			t.Errorf("Encrypt[File]() with short key did not fail")
		}
	})
	t.Run("encrypt_invalid_cipher_suite", func(t *testing.T) {
		if _, err := Encrypt[File](fileTestKey, CipherSuite(99), File{Source: plain}); err == nil {
			t.Errorf("Encrypt[File]() with invalid cipher suite did not fail")
		}
	})
	t.Run("encrypt_missing_source", func(t *testing.T) {
		if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: filepath.Join(dir, "missing")}); err == nil {
			t.Errorf("Encrypt[File]() with missing source did not fail")
		}
	})
	t.Run("encrypt_directory_source", func(t *testing.T) {
		if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: dir}); err == nil {
			t.Errorf("Encrypt[File]() with directory source did not fail")
		}
	})
	t.Run("encrypt_non_file_value", func(t *testing.T) {
		if _, err := Encrypt[File](fileTestKey, AES_256_GCM, "plain.bin"); err == nil {
			t.Errorf("Encrypt[File]() with a non-File value did not fail")
		}
	})
	t.Run("decrypt_empty_key", func(t *testing.T) {
		if _, err := Decrypt[File]("", File{Source: plain}); err == nil {
			t.Errorf("Decrypt[File]() with empty key did not fail")
		}
	})
	t.Run("decrypt_empty_source", func(t *testing.T) {
		if _, err := Decrypt[File](fileTestKey, File{}); err == nil {
			t.Errorf("Decrypt[File]() with empty source did not fail")
		}
	})
	t.Run("decrypt_non_file_value", func(t *testing.T) {
		if _, err := Decrypt[File](fileTestKey, "plain.bin"); err == nil {
			t.Errorf("Decrypt[File]() with a non-File value did not fail")
		}
	})
	t.Run("decrypt_plain_file", func(t *testing.T) {
		// A regular file without the transcrypt header must be rejected.
		if _, err := Decrypt[File](fileTestKey, File{Source: plain, Target: filepath.Join(dir, "out")}); err == nil {
			t.Errorf("Decrypt[File]() on a non-encrypted file did not fail")
		}
	})
	t.Run("decrypt_short_file", func(t *testing.T) {
		short := writeTestFile(t, dir, "short.bin", fileMagic[:])
		if _, err := Decrypt[File](fileTestKey, File{Source: short, Target: filepath.Join(dir, "out")}); err == nil {
			t.Errorf("Decrypt[File]() on a header-only file did not fail")
		}
	})
	assertNoTempLitter(t, dir)
}

// Test_File_CrossDomain verifies the HKDF domain separation between the two
// container formats: ciphertext lifted out of an encoded string and rewrapped
// as a file (or the reverse) must never authenticate, even though both carry
// the same DARE stream layout under the same key, cipher suite and salt.
func Test_File_CrossDomain(t *testing.T) {
	dir := t.TempDir()

	t.Run("string_ciphertext_as_file", func(t *testing.T) {
		encoded, err := Encrypt[string](fileTestKey, AES_256_GCM, "hello world")
		if err != nil {
			t.Fatalf("Encrypt[string]() error = %v", err)
		}
		parts := strings.Split(encoded, ":")
		salt, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("cannot decode salt: %v", err)
		}
		ciphertext, err := hex.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("cannot decode ciphertext: %v", err)
		}

		forged := append([]byte{}, fileMagic[:]...)
		forged = append(forged, fileFormatVersion, byte(AES_256_GCM))
		forged = append(forged, salt...)
		forged = append(forged, ciphertext...)
		src := writeTestFile(t, dir, "forged.bin", forged)

		if _, err = Decrypt[File](fileTestKey, File{Source: src, Target: filepath.Join(dir, "forged.out")}); err == nil {
			t.Errorf("Decrypt[File]() accepted ciphertext from the encoded-string format")
		}
	})

	t.Run("file_ciphertext_as_string", func(t *testing.T) {
		plain := writeTestFile(t, dir, "plain.bin", []byte("hello world"))
		encPath := filepath.Join(dir, "plain.bin.enc")
		if _, err := Encrypt[File](fileTestKey, AES_256_GCM, File{Source: plain, Target: encPath}); err != nil {
			t.Fatalf("Encrypt[File]() error = %v", err)
		}
		encContent, err := os.ReadFile(encPath)
		if err != nil {
			t.Fatalf("cannot read encrypted file: %v", err)
		}

		forged := strings.Join([]string{
			hex.EncodeToString(encContent[5:6]),
			hex.EncodeToString(encContent[6:fileHeaderLength]),
			hex.EncodeToString(encContent[fileHeaderLength:]),
		}, ":")

		if _, err = Decrypt[any](fileTestKey, forged); err == nil {
			t.Errorf("Decrypt[any]() accepted ciphertext from the file format")
		}
	})
}
