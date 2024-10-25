package transcrypt

type CipherSuite byte

const (
	AES_256_GCM CipherSuite = iota
	CHACHA20_POLY1305
)

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
