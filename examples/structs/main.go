package main

import (
	"encoding/json"
	"fmt"

	"github.com/jantytgat/go-transcrypt/pkg/cryptostruct"
	"github.com/jantytgat/go-transcrypt/pkg/transcrypt"
)

// Account is the plain struct as the application uses it.
type Account struct {
	Name     string            // encrypted
	Password string            // encrypted
	PIN      int               // encrypted
	Enabled  bool              // copied as-is
	Owner    Person            // nested struct, mirrored
	Backups  []Person          // slice of structs, mirrored
	Labels   map[string]string // map values encrypted, keys stay plain
}

// Person is a nested struct with mixed fields.
type Person struct {
	FullName string // encrypted
	Age      int    // copied as-is
}

// SecureAccount is the encrypted mirror of Account. A field typed
// cryptostruct.Ciphertext is encrypted; a field with the identical type is
// copied verbatim; mirrored struct/slice/map types recurse.
type SecureAccount struct {
	Name     string // NOTE: same type as plain → copied, NOT encrypted
	Password cryptostruct.Ciphertext
	PIN      cryptostruct.Ciphertext
	Enabled  bool
	Owner    SecurePerson
	Backups  []SecurePerson
	Labels   map[string]cryptostruct.Ciphertext
}

// SecurePerson is the encrypted mirror of Person.
type SecurePerson struct {
	FullName cryptostruct.Ciphertext
	Age      int
}

func main() {
	key, err := transcrypt.CreateHexKey(32)
	if err != nil {
		panic(err)
	}
	fmt.Println("Key: ", key)
	fmt.Println("###############")

	account := Account{
		Name:     "prod-database",
		Password: "s3cr3t-p4ssw0rd",
		PIN:      1234,
		Enabled:  true,
		Owner:    Person{FullName: "Jan Tytgat", Age: 40},
		Backups: []Person{
			{FullName: "First Backup", Age: 35},
			{FullName: "Second Backup", Age: 45},
		},
		Labels: map[string]string{"env": "production"},
	}
	dump("Plain", account)

	var secure SecureAccount
	if secure, err = cryptostruct.Encrypt[SecureAccount](key, transcrypt.AES_256_GCM, account); err != nil {
		panic(err)
	}
	dump("Encrypted", secure)

	var restored Account
	if restored, err = cryptostruct.Decrypt[Account](key, secure); err != nil {
		panic(err)
	}
	dump("Decrypted", restored)
}

func dump(label string, v any) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s:\n%s\n###############\n", label, out)
}
