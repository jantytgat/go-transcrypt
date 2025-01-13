package main

import (
	"fmt"

	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

func main() {
	var err error
	var key string
	if key, err = transcrypt.CreateHexKey(12); err != nil {
		panic(err)
	}

	var salt []byte
	// Uncomment the following lines if you want to use a pre-defined salt
	// if salt, err = transcrypt.CreateSalt(); err != nil {
	// 	panic(err)
	// }

	fmt.Println("Key: ", key)
	fmt.Println("###############")

	var inputString = "hello world"
	fmt.Println("input:", inputString)
	var encryptedString string
	if encryptedString, err = transcrypt.Encrypt(key, salt, transcrypt.AES_256_GCM, inputString); err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", encryptedString)

	var decryptedString any
	if decryptedString, err = transcrypt.Decrypt(key, encryptedString); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decryptedString)
	fmt.Println("###############")

	var inputInt = 123456
	fmt.Println("input:", inputInt)
	var encryptedInt string
	if encryptedInt, err = transcrypt.Encrypt(key, salt, transcrypt.AES_256_GCM, inputInt); err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", encryptedInt)

	var decryptedInt any
	if decryptedInt, err = transcrypt.Decrypt(key, encryptedInt); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decryptedInt)
}
