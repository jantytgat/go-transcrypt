package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jantytgat/go-transcrypt"
)

func main() {
	var err error
	var key []byte
	if key, err = transcrypt.CreateKey(32); err != nil {
		panic(err)
	}

	fmt.Println("Key: ", key)
	fmt.Println("###############")

	// Work in a temporary directory so the example leaves nothing behind.
	dir, err := os.MkdirTemp("", "transcrypt-files-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	plainPath := filepath.Join(dir, "secret.txt")
	if err = os.WriteFile(plainPath, []byte("files are streamed through sio, so size does not matter\n"), 0o600); err != nil {
		panic(err)
	}

	// Encrypt to a separate target file. The file's content is streamed
	// through the cipher, so memory use stays constant regardless of size.
	encrypted, err := transcrypt.Encrypt[transcrypt.File](key, transcrypt.AES_256_GCM,
		transcrypt.File{Source: plainPath, Target: plainPath + ".enc"})
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted to:", encrypted.Target)

	// Decrypt to yet another path.
	restored, err := transcrypt.Decrypt[transcrypt.File](key,
		transcrypt.File{Source: encrypted.Target, Target: filepath.Join(dir, "restored.txt")})
	if err != nil {
		panic(err)
	}
	content, err := os.ReadFile(restored.Target)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Restored %s: %s", restored.Target, content)

	// An empty Target means in-place: the result atomically replaces the
	// source file once the operation completes (via a temporary file and
	// rename, so a failure never destroys the original).
	if _, err = transcrypt.Encrypt[transcrypt.File](key, transcrypt.CHACHA20_POLY1305,
		transcrypt.File{Source: plainPath}); err != nil {
		panic(err)
	}
	fmt.Println("Encrypted in place:", plainPath)

	if _, err = transcrypt.Decrypt[transcrypt.File](key, transcrypt.File{Source: plainPath}); err != nil {
		panic(err)
	}
	if content, err = os.ReadFile(plainPath); err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted in place: %s", content)
}
