package b1ref_test

import (
	"github.com/unicitynetwork/bft-go-base/crypto"
)

func nativeVerifier(pub []byte) (crypto.Verifier, error) { return crypto.NewVerifierSecp256k1(pub) }
