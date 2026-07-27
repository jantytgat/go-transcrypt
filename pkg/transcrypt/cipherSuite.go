package transcrypt

import "fmt"

const (
	AES_256_GCM CipherSuite = iota
	CHACHA20_POLY1305
)

// CipherSuite defines which cipher suites can be used for transcryption of data.
// It is based on the types available in github.com/minio/sio .
type CipherSuite byte

// GetCipherSuite converts a string into its respective CipherSuite.
// It returns an error if the string does not name a known cipher suite, rather
// than silently falling back to a default, so a caller-supplied typo cannot
// select an unintended cipher.
func GetCipherSuite(s string) (CipherSuite, error) {
	switch s {
	case "AES_256_GCM":
		return AES_256_GCM, nil
	case "CHACHA20_POLY1305":
		return CHACHA20_POLY1305, nil
	default:
		return 0, fmt.Errorf("unknown cipher suite %q", s)
	}
}
