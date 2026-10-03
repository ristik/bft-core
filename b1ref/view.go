package b1ref

import (
	"crypto/sha256"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
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

// trustView is the decoded preimage of the registry's viewHash for one epoch.
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

// scanView validates and decodes the deterministic CBOR TrustView
// [1, network, epoch, sourceKind, sourceBodyID, members].
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
		return nil, ErrVersion
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
	if k[5].arg == 0 {
		return nil, ErrViewEmpty
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
		ver, err := crypto.NewVerifierSecp256k1(m.kids[1].data)
		if err != nil {
			return nil, ErrViewKey
		}
		v.members = append(v.members, member{nodeID: string(m.kids[0].data), key: m.kids[1].data, weight: m.kids[2].arg, ver: ver})
	}
	for i := 1; i < len(v.members); i++ {
		if v.members[i-1].nodeID > v.members[i].nodeID { // Go string order is raw UTF-8 byte order
			return nil, ErrViewOrder
		}
	}
	return v, nil
}

// semantic checks of a decoded view that are false rather than malformed.
func (v *trustView) check() error {
	seenKey := make(map[string]struct{}, len(v.members))
	for i, m := range v.members {
		if i > 0 && v.members[i-1].nodeID == m.nodeID {
			return ErrViewDuplicate
		}
		if _, dup := seenKey[string(m.key)]; dup {
			return ErrViewDuplicate
		}
		seenKey[string(m.key)] = struct{}{}
		if m.weight != 1 {
			return ErrWeightProfile
		}
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

// threshold is floor(2W/3)+1 over the total weight; with profile 1 every
// weight is 1, so W is the member count (at most 64) and nothing can overflow.
func (v *trustView) threshold() uint64 {
	var w uint64
	for _, m := range v.members {
		w += m.weight
	}
	return evmroot.RootQuorumThreshold(w)
}
