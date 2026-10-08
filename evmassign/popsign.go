package evmassign

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ErrPoPSigning reports a possession proof that cannot be made or assembled.
var ErrPoPSigning = errors.New("evmassign: EVM possession proof")

// popDigestFor is the digest member id's EVM key signs for a primary candidate: Election.popDigest over what the candidate itself names
// (result, snapshot, generation, key) and the attempt the election reserved the result under.
func popDigestFor(c Candidate, d ElectionDeployment, attempt uint64, m Identity) ([32]byte, uint64, error) {
	var out [32]byte
	if c.Kind != KindPrimary || c.Authorization == nil || len(c.Authorization.ResultID) != 32 || len(c.Authorization.SnapshotDigest) != 32 {
		return out, 0, fmt.Errorf("%w: not a primary candidate", ErrPoPSigning)
	}
	id, err := CustodyID(m.StakingID)
	if err != nil {
		return out, 0, errors.Join(ErrPoPSigning, err)
	}
	var result, snapshot [32]byte
	copy(result[:], c.Authorization.ResultID)
	copy(snapshot[:], c.Authorization.SnapshotDigest)
	return PoPDigest(d, result, PrimaryAssignmentID(result), snapshot, attempt, id, m.Generation, m.EVMKey), id, nil
}

// SignEVMPoP is the member's side: its EVM key signs the possession digest of the candidate's identity record that names that key. The
// signature is canonical (low s, v = 27/28), the form the election stores and the root verifies.
func SignEVMPoP(key *ecdsa.PrivateKey, c Candidate, d ElectionDeployment, attempt uint64) (EVMPoP, error) {
	pub := ethcrypto.CompressPubkey(&key.PublicKey)
	for _, m := range c.Identities {
		if !bytes.Equal(m.EVMKey, pub) {
			continue
		}
		digest, id, err := popDigestFor(c, d, attempt, m)
		if err != nil {
			return EVMPoP{}, err
		}
		sig, err := ethcrypto.Sign(digest[:], key)
		if err != nil {
			return EVMPoP{}, errors.Join(ErrPoPSigning, err)
		}
		sig[64] += 27
		return EVMPoP{ID: id, EVMKey: pub, Signature: sig}, nil
	}
	return EVMPoP{}, fmt.Errorf("%w: the key is not a member's EVM key in this candidate", ErrPoPSigning)
}

// AssemblePoPs is the relayer's side: it checks every collected proof against the candidate, requires exactly one per member, and returns
// them in ascending identity order together with the set digest the election will store.
func AssemblePoPs(c Candidate, d ElectionDeployment, attempt uint64, collected []EVMPoP) ([]EVMPoP, [32]byte, error) {
	var zero [32]byte
	ids, err := idsOf(c.Identities)
	if err != nil {
		return nil, zero, errors.Join(ErrPoPSigning, err)
	}
	byID := map[uint64]EVMPoP{}
	for _, p := range collected {
		if _, dup := byID[p.ID]; dup {
			return nil, zero, fmt.Errorf("%w: two proofs for member %d", ErrPoPSigning, p.ID)
		}
		byID[p.ID] = p
	}
	out := make([]EVMPoP, 0, len(ids))
	sigs := make([][]byte, 0, len(ids))
	for i, m := range c.Identities {
		p, ok := byID[ids[i]]
		if !ok {
			return nil, zero, fmt.Errorf("%w: no proof for member %d", ErrPoPSigning, ids[i])
		}
		digest, _, err := popDigestFor(c, d, attempt, m)
		if err != nil {
			return nil, zero, err
		}
		if !bytes.Equal(p.EVMKey, m.EVMKey) || !verifyEVMSignature(m.EVMKey, p.Signature, digest) {
			return nil, zero, fmt.Errorf("%w: member %d's proof does not verify", ErrPoPSigning, ids[i])
		}
		out = append(out, p)
		sigs = append(sigs, p.Signature)
		delete(byID, ids[i])
	}
	if len(byID) != 0 {
		return nil, zero, fmt.Errorf("%w: %d proofs for non-members", ErrPoPSigning, len(byID))
	}
	return out, PoPSetDigest(ids, sigs), nil
}
