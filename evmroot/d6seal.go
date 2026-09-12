package evmroot

import (
	"fmt"
	"sort"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// D6 shared-seal cryptographic model. The first-review anchor accepted a
// list of signer node-ids and a caller-supplied threshold as "evidence" —
// a name is not a signature and a supplied threshold can be zero. This
// file gives the model REAL secp256k1 keys (deterministic, so the golden
// vectors stay stable) so the seal is verified against signatures over the
// exact root state root, and the threshold is DERIVED from the
// authenticated assignment, never supplied.

// d6SealPriv derives a deterministic 32-byte secp256k1 private key for a
// model node id. SHA-256 of these fixed strings is overwhelmingly a valid
// scalar; NewInMemorySecp256K1SignerFromKey rejecting one would be a build
// failure of the fixture, so it panics.
func d6SealPriv(nodeID string) []byte { return sha256Bytes([]byte("d6-seal-key:" + nodeID)) }

func d6SealSigner(nodeID string) abcrypto.Signer {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(d6SealPriv(nodeID))
	if err != nil {
		panic(fmt.Sprintf("d6: bad model seal key for %q: %v", nodeID, err))
	}
	return s
}

// d6SealPub is the compressed public key matching d6SealSigner(nodeID).
func d6SealPub(nodeID string) []byte {
	v, err := d6SealSigner(nodeID).Verifier()
	if err != nil {
		panic(fmt.Sprintf("d6: cannot derive verifier for %q: %v", nodeID, err))
	}
	pk, err := v.MarshalPublicKey()
	if err != nil {
		panic(fmt.Sprintf("d6: cannot marshal public key for %q: %v", nodeID, err))
	}
	return pk
}

// d6Member is a D3 Member whose ConsensusKey is a REAL compressed secp256k1
// public key (not the d3Key stand-in), so its signatures verify.
func d6Member(nodeID string, weight uint64) Member {
	return Member{StakingID: "stake-" + nodeID, NodeID: nodeID, ConsensusKey: d6SealPub(nodeID), Weight: weight}
}

// d6Assignment is the baseline D6 assignment: the same weights as
// d3Assignment (10/6/5/2/1, W = 24, root quorum ⌊2·24/3⌋+1 = 17) but with
// real keys. f_W = 24 − 17 = 7.
func d6Assignment() WeightSet {
	return WeightSet{
		d6Member("root-a", 10),
		d6Member("root-b", 6),
		d6Member("root-c", 5),
		d6Member("root-d", 2),
		d6Member("root-e", 1),
	}
}

// SignAnchorSeal produces the signature map for `signerIDs` over `stmt`
// (the output of AnchorSealStatement). Deterministic: the same inputs give
// the same bytes, so vectors stay stable.
func SignAnchorSeal(stmt []byte, signerIDs []string) map[string][]byte {
	ids := append([]string(nil), signerIDs...)
	sort.Strings(ids)
	out := make(map[string][]byte, len(ids))
	for _, id := range ids {
		sig, err := d6SealSigner(id).SignBytes(stmt)
		if err != nil {
			panic(fmt.Sprintf("d6: cannot sign seal statement for %q: %v", id, err))
		}
		out[id] = sig
	}
	return out
}

// ForgeAnchorSignature signs `stmt` with a key that is NOT `nodeID`'s — for
// the "a forged signer entry does not count" negative fixture.
func ForgeAnchorSignature(stmt []byte, impersonated, actualKeyOwner string) map[string][]byte {
	sig, err := d6SealSigner(actualKeyOwner).SignBytes(stmt)
	if err != nil {
		panic(err)
	}
	return map[string][]byte{impersonated: sig}
}
