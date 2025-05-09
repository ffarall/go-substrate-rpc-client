package signature

// Scheme encapsulates key derivation, signing, and verification.
type Scheme interface {
	DeriveKeyPair(uri string, network uint8) (KeyringPair, error)
	Sign(data []byte, uri string) ([]byte, error)
	Verify(data []byte, sig []byte, uri string) (bool, error)
} 