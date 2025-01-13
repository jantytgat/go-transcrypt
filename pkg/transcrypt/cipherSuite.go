package transcrypt

const (
	AES_256_GCM CipherSuite = iota
	CHACHA20_POLY1305
)

// CipherSuite defines which cipher suites can be used for transcryption of data.
// It is based on the types available in github.com/minio/sio .
type CipherSuite byte

// GetCipherSuite converts a string into its respective CipherSuite.
// It returns CHACHA20_POLY1305 by default if the string cannot be converted.
func GetCipherSuite(s string) CipherSuite {
	switch s {
	case "AES_256_GCM":
		return AES_256_GCM
	case "CHACHA20_POLY1305":
		return CHACHA20_POLY1305
	default:
		return CHACHA20_POLY1305
	}
}
