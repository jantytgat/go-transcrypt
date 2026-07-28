package main

import (
	"fmt"

	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

func main() {
	var err error
	var key string
	if key, err = transcrypt.CreateHexKey(32); err != nil {
		panic(err)
	}

	fmt.Println("Key: ", key)
	fmt.Println("###############")

	inputs := []any{
		"hello world",
		true,
		int(123456),
		int8(-12),
		int16(-1234),
		int32(-123456),
		int64(-1234567890),
		uint(123456),
		uint8(255),
		uint16(65535),
		uint32(4294967295),
		uint64(18446744073709551615),
		float32(3.14),
		float64(2.718281828459045),
		complex64(complex(1, 2)),
		complex128(complex(3.5, -4.5)),
		[]byte{0xde, 0xad, 0xbe, 0xef},
	}

	for _, input := range inputs {
		demo(key, transcrypt.AES_256_GCM, input)
	}

	fmt.Println("### CHACHA20_POLY1305 works the same way ###")
	demo(key, transcrypt.CHACHA20_POLY1305, "hello chacha")

	// Naming a concrete type parameter returns a typed value directly; the
	// kind stored inside the authenticated ciphertext must match.
	encrypted, err := transcrypt.Encrypt[string](key, transcrypt.AES_256_GCM, int64(42))
	if err != nil {
		panic(err)
	}
	answer, err := transcrypt.Decrypt[int64](key, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Typed decrypt: %d (%T)\n", answer, answer)
}

func demo(key string, suite transcrypt.CipherSuite, input any) {
	fmt.Printf("Input:     %v (%T)\n", input, input)

	var err error
	var encrypted string
	if encrypted, err = transcrypt.Encrypt[string](key, suite, input); err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", encrypted)

	var decrypted any
	if decrypted, err = transcrypt.Decrypt[any](key, encrypted); err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted: %v (%T)\n", decrypted, decrypted)
	fmt.Println("###############")
}
