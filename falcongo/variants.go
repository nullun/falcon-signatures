package falcongo

import (
	"github.com/algorand/falcon"
)

// Variant re-exports falcon.Variant so callers do not have to import the
// underlying binding package.
type Variant = falcon.Variant

const (
	Det1024  = falcon.Det1024
	Det512   = falcon.Det512
	Rand1024 = falcon.Rand1024
	Rand512  = falcon.Rand512
)

// Re-exported sentinel errors from the underlying binding.
var (
	ErrUnknownVariant  = falcon.ErrUnknownVariant
	ErrCTConvertNotDet = falcon.ErrCTConvertNotDet
)

// VariantKeyPair is a slice-based, variant-tagged keypair. Unlike the legacy
// KeyPair (which is fixed-size and det1024-only), this works for all four
// Falcon parameterisations.
type VariantKeyPair struct {
	Variant    Variant
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateVariantKeyPair generates a keypair for the given variant. If seed is
// empty a system-RNG seed is used.
func GenerateVariantKeyPair(v Variant, seed []byte) (VariantKeyPair, error) {
	pub, priv, err := falcon.GenerateKeyVariant(v, seed)
	if err != nil {
		return VariantKeyPair{Variant: v}, err
	}
	return VariantKeyPair{Variant: v, PublicKey: pub, PrivateKey: priv}, nil
}

// Sign produces a compressed-format signature over data. For randomised
// variants the result varies per call; for deterministic variants it is
// reproducible from (kp, data).
func (kp *VariantKeyPair) Sign(data []byte) ([]byte, error) {
	return falcon.SignCompressedVariant(kp.Variant, kp.PrivateKey, data)
}

// VerifyVariant verifies a compressed-format signature.
func VerifyVariant(v Variant, pub, sig, data []byte) error {
	return falcon.VerifyCompressedVariant(v, pub, sig, data)
}

// GetFixedLengthSignatureVariant converts a compressed-format signature to CT
// format. Returns falcon.ErrCTConvertNotDet for randomised variants.
func GetFixedLengthSignatureVariant(v Variant, sig []byte) ([]byte, error) {
	return falcon.ConvertCompressedToCTVariant(v, sig)
}
