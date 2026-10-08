package evmassign

import (
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// The digests custody keeps over an assignment's exposures, in custody's own ABI/Keccak formulas, which are normative for these three
// words (briefs/p85-pr1c-control-records.md section 7; unicity-pos-contracts StakeCustody._createExposure, _digestExposures,
// _digestKeys). The root derives them from the frozen identity records, never from a submitter's labels, so a CloseLiability binds the
// words custody will compare against its stored ones. Shared with custody through test/p85/fixtures/custody-digests.json, which
// custody itself generates.

var (
	custodyExposureDomain = ethcrypto.Keccak256Hash([]byte("unicity.p85.exposure"))
	exposureDigestDomain  = ethcrypto.Keccak256Hash([]byte("unicity.p85.exposure-digest"))
	keyDigestDomain       = ethcrypto.Keccak256Hash([]byte("unicity.p85.key-history-digest"))
	exposureChainDomain   = ethcrypto.Keccak256Hash([]byte("unicity.p85.exposure-chain"))
)

// ErrCustodyDigest reports identity records the custody digests cannot be formed from.
var ErrCustodyDigest = errors.New("evmassign: identity records do not fit the custody digests")

// Deployment names the custody deployment an exposure belongs to: the custody's network word (the one pinned in its manifest, not
// re-hashed), the chain id (an unsigned 256-bit big-endian word) and the custody address.
type Deployment struct {
	NetworkWord [32]byte
	ChainID     [32]byte
	Custody     [20]byte
}

func w64(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func wAddr(a []byte) []byte {
	w := make([]byte, 32)
	copy(w[12:], a)
	return w
}

func keccak(parts ...[]byte) (out [32]byte) {
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	copy(out[:], ethcrypto.Keccak256(all))
	return out
}

// CustodyID is the identity's uint64 StakingID as custody keys it: the 32-byte root StakingID must carry the id in its low eight
// bytes, nonzero, with the high 24 bytes zero.
func CustodyID(stakingID []byte) (uint64, error) {
	if len(stakingID) != StakingIDLen || !isZero(stakingID[:24]) {
		return 0, fmt.Errorf("%w: staking id %x does not fit a uint64", ErrCustodyDigest, stakingID)
	}
	var id uint64
	for _, b := range stakingID[24:] {
		id = id<<8 | uint64(b)
	}
	if id == 0 {
		return 0, fmt.Errorf("%w: staking id zero", ErrCustodyDigest)
	}
	return id, nil
}

// LotsDigest is Identity.ExposureDigest for a lot list: keccak256(abi.encode(uint256[] lotIDs)) with the lots in ascending order. The
// digest excludes the assignment, so an exact recovery K keeps the incumbent's lot commitments.
func LotsDigest(lotIDs []uint64) [32]byte {
	enc := append(w64(32), w64(uint64(len(lotIDs)))...)
	for _, l := range lotIDs {
		enc = append(enc, w64(l)...)
	}
	return keccak(enc)
}

// ExposureID is custody's exposure identifier of an identity in an assignment.
func ExposureID(d Deployment, assignmentID [32]byte, id uint64) [32]byte {
	return keccak(custodyExposureDomain[:], d.NetworkWord[:], d.ChainID[:], wAddr(d.Custody[:]), assignmentID[:], w64(id))
}

// ExposureChainStep appends one exposure to a generation's creation-ordered chain.
func ExposureChainStep(previous, exposureID [32]byte) [32]byte {
	return keccak(exposureChainDomain[:], previous[:], exposureID[:])
}

// ascendingCustodyIDs checks the identities are in strictly ascending custody id order, the order custody creates and folds them in.
func ascendingCustodyIDs(ids []Identity) ([]uint64, error) {
	out := make([]uint64, len(ids))
	for i, x := range ids {
		id, err := CustodyID(x.StakingID)
		if err != nil {
			return nil, err
		}
		if i > 0 && id <= out[i-1] {
			return nil, fmt.Errorf("%w: ids not strictly ascending at %d", ErrCustodyDigest, id)
		}
		out[i] = id
	}
	return out, nil
}

// AssignmentExposureDigest folds the assignment's exposures in ascending identity order, each as custody records it: its exposure id,
// identity, committed weight q, raw weight x, operator payee and lot-list digest.
func AssignmentExposureDigest(d Deployment, assignmentID [32]byte, ids []Identity) ([32]byte, error) {
	cids, err := ascendingCustodyIDs(ids)
	if err != nil {
		return [32]byte{}, err
	}
	digest := exposureDigestDomain
	for i, x := range ids {
		if len(x.OperatorPayee) != PayeeLen || len(x.ExposureDigest) != DigestLen {
			return [32]byte{}, fmt.Errorf("%w: malformed record %d", ErrCustodyDigest, cids[i])
		}
		eid := ExposureID(d, assignmentID, cids[i])
		digest = keccak(digest[:], eid[:], w64(cids[i]), w64(x.Weight), w64(x.RawWeight), wAddr(x.OperatorPayee), x.ExposureDigest)
	}
	return digest, nil
}

// KeyHistoryDigestFromHashes folds the frozen bindings by key hash. The hashes are keccak256 of the exact 33-byte compressed keys.
func KeyHistoryDigestFromHashes(ids []uint64, rootKeyHashes, evmKeyHashes [][32]byte) ([32]byte, error) {
	if len(ids) != len(rootKeyHashes) || len(ids) != len(evmKeyHashes) {
		return [32]byte{}, fmt.Errorf("%w: mismatched lists", ErrCustodyDigest)
	}
	digest := keyDigestDomain
	for i := range ids {
		digest = keccak(digest[:], w64(ids[i]), rootKeyHashes[i][:], evmKeyHashes[i][:])
	}
	return digest, nil
}

// KeyHistoryDigest folds the identities' frozen root and EVM keys, hashed over the exact compressed key bytes.
func KeyHistoryDigest(ids []Identity) ([32]byte, error) {
	cids, err := ascendingCustodyIDs(ids)
	if err != nil {
		return [32]byte{}, err
	}
	root := make([][32]byte, len(ids))
	evm := make([][32]byte, len(ids))
	for i, x := range ids {
		if len(x.RootKey) != KeyLen || len(x.EVMKey) != KeyLen {
			return [32]byte{}, fmt.Errorf("%w: malformed keys of %d", ErrCustodyDigest, cids[i])
		}
		root[i], evm[i] = keccak(x.RootKey), keccak(x.EVMKey)
	}
	return KeyHistoryDigestFromHashes(cids, root, evm)
}
