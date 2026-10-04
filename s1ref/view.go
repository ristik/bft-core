package s1ref

import (
	"crypto/sha256"
	"math"

	"github.com/unicitynetwork/bft-go-base/crypto"
)

// Trust view source kinds: 1 is the genesis V1 trust-base identity, 2 the D3
// V2 body identity.
const (
	SourceGenesisV1 = 1
	SourceD3V2      = 2
)

// member is one trust view entry.
type member struct {
	nodeID string
	key    []byte // compressed secp256k1, 33 bytes
	weight uint64
	ver    crypto.Verifier
}

// trustView is the decoded preimage of the context's viewHash for one epoch.
// It is an untrusted preimage of that commitment, never a caller-selected
// authority.
type trustView struct {
	network    uint16
	epoch      uint64
	sourceKind uint64
	bodyID     [32]byte
	members    []member
	hash       [32]byte
}

// scanView validates the structure of the deterministic CBOR TrustView
// [1, network, epoch, sourceKind, bodyID, members]. Only structure is checked
// here: ordering, emptiness, duplicates, weights and curve points are semantic
// (false, B1 v2) and are checked by check and decodePoints.
func scanView(raw []byte, tokens *int) (*trustView, error) {
	root, err := scanOne(raw, tokens)
	if err != nil {
		return nil, err
	}
	if !root.isArray(6) {
		return nil, ErrShape
	}
	k := root.kids
	if !k[0].isUint() || k[0].arg != 1 {
		if k[0].isUint() {
			return nil, ErrVersion
		}
		return nil, ErrShape
	}
	if !k[1].isUint() || !k[2].isUint() || !k[3].isUint() || !k[4].isHash() || k[5].major != majArray {
		return nil, ErrShape
	}
	if k[1].arg > math.MaxUint16 {
		return nil, ErrShape // must fit the native NetworkID
	}
	if k[3].arg != SourceGenesisV1 && k[3].arg != SourceD3V2 {
		return nil, ErrViewKind
	}
	if k[5].arg > MaxMembers {
		return nil, ErrTooManyMembers
	}
	v := &trustView{network: uint16(k[1].arg), epoch: k[2].arg, sourceKind: k[3].arg, hash: sha256.Sum256(raw)}
	copy(v.bodyID[:], k[4].data)
	v.members = make([]member, 0, len(k[5].kids))
	for i := range k[5].kids {
		m := &k[5].kids[i]
		if !m.isArray(3) || m.kids[0].major != majText || !m.kids[1].isBytes(crypto.CompressedSecp256K1PublicKeySize) || !m.kids[2].isUint() {
			return nil, ErrShape
		}
		if len(m.kids[0].data) > MaxNodeIDBytes {
			return nil, ErrNodeIDTooLong
		}
		v.members = append(v.members, member{nodeID: string(m.kids[0].data), key: m.kids[1].data, weight: m.kids[2].arg})
	}
	return v, nil
}

// check is the semantic validation of a decoded view, in a fixed order so the
// named reason is deterministic: empty, duplicate identity or key, ordering,
// weights. Every outcome is false; the order only selects the reason.
func (v *trustView) check() error {
	if len(v.members) == 0 && !skipped("view-empty") {
		return ErrViewEmpty
	}
	seenID := make(map[string]struct{}, len(v.members))
	seenKey := make(map[string]struct{}, len(v.members))
	for _, m := range v.members {
		if _, dup := seenID[m.nodeID]; dup && !skipped("view-duplicate") {
			return ErrViewDuplicate
		}
		seenID[m.nodeID] = struct{}{}
		if _, dup := seenKey[string(m.key)]; dup && !skipped("view-duplicate") {
			return ErrViewDuplicate
		}
		seenKey[string(m.key)] = struct{}{}
	}
	for i := 1; i < len(v.members); i++ {
		if v.members[i-1].nodeID > v.members[i].nodeID && !skipped("view-order") { // Go string order is raw UTF-8 byte order
			return ErrViewOrder
		}
	}
	for _, m := range v.members {
		if m.weight != 1 && !skipped("view-weight") {
			return ErrWeightProfile
		}
	}
	return nil
}

// decodePoints turns every member key into a curve point. It is the first
// expensive step of a call and runs only after the full charge is reserved. A
// bstr33 that is not a point is false (B1 v2), never malformed.
func (v *trustView) decodePoints() error {
	for i := range v.members {
		work("point")
		ver, err := crypto.NewVerifierSecp256k1(v.members[i].key)
		if err != nil {
			if skipped("view-key") {
				continue
			}
			return ErrViewKey
		}
		v.members[i].ver = ver
	}
	return nil
}

func (v *trustView) lookup(nodeID string) *member {
	for i := range v.members {
		if v.members[i].nodeID == nodeID {
			return &v.members[i]
		}
	}
	return nil
}
