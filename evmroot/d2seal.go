package evmroot

import (
	"fmt"
	"sort"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// D2 seal-witness cryptography. The re-review noted that
// VerifyCompanionWitnesses "still verifies assertions rather than proof
// bindings": it accepted a caller-supplied threshold, counted signer
// NAMES, and never checked a signature. This file gives the authentication
// boundary real, deterministic secp256k1 keys so the seal witness is
// verified against signatures over a statement that binds the exact O_-
// identity and the certified TRHash.
//
// D2 and D3 are independent tracks off D1, so this does not depend on D3 /
// d6seal.go — it is a D2-local copy of the same deterministic-key pattern.

// d2SealPriv derives a deterministic 32-byte private key for a model node.
func d2SealPriv(nodeID string) []byte { return sha256Slice([]byte("d2-seal-key:" + nodeID)) }

func d2SealSigner(nodeID string) abcrypto.Signer {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(d2SealPriv(nodeID))
	if err != nil {
		panic(fmt.Sprintf("d2: bad model seal key for %q: %v", nodeID, err))
	}
	return s
}

func d2SealPub(nodeID string) []byte {
	v, err := d2SealSigner(nodeID).Verifier()
	if err != nil {
		panic(err)
	}
	pk, err := v.MarshalPublicKey()
	if err != nil {
		panic(err)
	}
	return pk
}

// D2SealMember is one root-assignment member: node id, effective weight and
// the compressed secp256k1 consensus key its seal signature verifies
// against.
type D2SealMember struct {
	NodeID       string
	Weight       uint64
	ConsensusKey []byte
}

// D2TrustBase is the importer's authenticated view of the root assignment.
// It replaces the bare NodeID->weight map: the threshold is derived from
// it, and only members with a verifying signature count toward a quorum.
type D2TrustBase struct {
	Members []D2SealMember
}

func (t D2TrustBase) TotalWeight() uint64 {
	var w uint64
	for _, m := range t.Members {
		w += m.Weight
	}
	return w
}

// RootQuorumThreshold is ⌊2W/3⌋+1 — derived here, never accepted from the
// companion.
func (t D2TrustBase) RootQuorumThreshold() uint64 { return (2*t.TotalWeight())/3 + 1 }

func (t D2TrustBase) member(id string) (D2SealMember, bool) {
	for _, m := range t.Members {
		if m.NodeID == id {
			return m, true
		}
	}
	return D2SealMember{}, false
}

// D2SealWitnessStatement is the exact bytes a seal signature must cover:
// SHA-256(CBOR([ "UNICITY_D2_SEAL_WITNESS", originID, trHash ])). Binding
// both the O_- identity and the certified TRHash means a signature cannot
// be replayed onto a different rootInput or a swapped technical record.
func D2SealWitnessStatement(originID Hash32, trHash []byte) []byte {
	return sha256Slice(marshalCBOR(cArray{
		cText("UNICITY_D2_SEAL_WITNESS"), cBytes(originID[:]), cBytes(trHash),
	}))
}

// VerifiedSignerWeight sums the weight of assignment members whose
// signature over `stmt` verifies. A claimed signer with no signature, an
// unknown signer, a duplicate, or a bad signature contributes nothing.
func (t D2TrustBase) VerifiedSignerWeight(stmt []byte, sigs map[string][]byte) (weight uint64, ok bool) {
	seen := map[string]struct{}{}
	for id, sig := range sigs {
		if _, dup := seen[id]; dup {
			return 0, false
		}
		seen[id] = struct{}{}
		m, known := t.member(id)
		if !known {
			return 0, false
		}
		v, err := abcrypto.NewVerifierSecp256k1(m.ConsensusKey)
		if err != nil {
			return 0, false
		}
		if v.VerifyBytes(sig, stmt) != nil {
			return 0, false // a bad signature invalidates the witness, not just this entry
		}
		weight += m.Weight
	}
	return weight, len(sigs) > 0
}

// SignD2SealWitness produces the signature map for `ids` over `stmt`.
func SignD2SealWitness(stmt []byte, ids []string) map[string][]byte {
	c := append([]string(nil), ids...)
	sort.Strings(c)
	out := make(map[string][]byte, len(c))
	for _, id := range c {
		sig, err := d2SealSigner(id).SignBytes(stmt)
		if err != nil {
			panic(err)
		}
		out[id] = sig
	}
	return out
}
