package transcrypt

import (
	"fmt"

	"github.com/minio/sio"
)

// The values are sio's own cipher IDs, converted explicitly so the coupling to
// the wire format is visible rather than an accident of declaration order.
// (sio names its AES suite AES_GCM; this library keeps the more precise
// AES_256_GCM since the derived keys are always 256 bits.)
const (
	AES_256_GCM       = CipherSuite(sio.AES_GCM)
	CHACHA20_POLY1305 = CipherSuite(sio.CHACHA20_POLY1305)
)

// CipherSuite defines which cipher suites can be used for transcryption of data.
// It is based on the types available in github.com/minio/sio .
type CipherSuite byte

// isValid reports whether c is one of the known cipher suites. It guards against
// callers passing an out-of-range value (e.g. CipherSuite(99)), which would
// otherwise only fail deep inside sio with an opaque error.
func (c CipherSuite) isValid() bool {
	switch c {
	case AES_256_GCM, CHACHA20_POLY1305:
		return true
	default:
		return false
	}
}

// String returns the cipher suite's name, matching the names GetCipherSuite
// accepts; an unknown value renders as "CipherSuite(n)".
func (c CipherSuite) String() string {
	switch c {
	case AES_256_GCM:
		return "AES_256_GCM"
	case CHACHA20_POLY1305:
		return "CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("CipherSuite(%d)", byte(c))
	}
}

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
