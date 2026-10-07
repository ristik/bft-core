package b1ref

import "github.com/unicitynetwork/bft-go-base/crypto"

// member is an admitted registry member, never a caller-carried preimage.
type member struct {
	weight uint64
	ver    crypto.Verifier
}
