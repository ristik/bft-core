package bridgeprofile

import (
	stdcrypto "crypto"
	"encoding/binary"
	"math/bits"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1state"
)

// RefB1 is the oracle's B1: anchor authentication is one CERT_BATCH_V2 call over the whole anchor table, evaluated by the Go
// reference (b1ref.Cert) against a format-2 registry holding the one admitted root trust base as its genesis and usable epoch, and
// membership calls the reference RSMT_MEMBER_V1. It simulates the admitted registry; it activates nothing.
type RefB1 struct {
	TB types.RootTrustBase
}

// refRound is the registry clock O of the simulated registry: every fixture certificate's root round is below it.
const refRound = 1 << 40

// registry renders the trust base as a ready format-2 registry: genesis epoch = usable epoch = import tip = the base's epoch, open
// from its start round, O = refRound.
func (r RefB1) registry() (b1ref.State, b1ref.Pins, error) {
	tb, ok := r.TB.(*types.RootTrustBaseV1)
	if !ok || tb == nil {
		return nil, b1ref.Pins{}, ErrAnchorAuth
	}
	id, err := tb.Hash(stdcrypto.SHA256)
	if err != nil {
		return nil, b1ref.Pins{}, ErrAnchorAuth
	}
	e := b1state.Entry{Epoch: tb.Epoch, BodyKind: 1, Start: tb.EpochStart, SigningScheme: 1, SigningConfigHash: H([]byte("bridgeprofile/RefB1 signing configuration"))}
	copy(e.BodyID[:], id)
	for _, n := range tb.RootNodes {
		if n == nil || len(n.SigKey) != 33 {
			return nil, b1ref.Pins{}, ErrAnchorAuth
		}
		m := b1state.Member{NodeID: n.NodeID, Weight: n.Stake}
		copy(m.Key[:], n.SigKey)
		e.Members = append(e.Members, m)
	}
	sort.Slice(e.Members, func(i, j int) bool { return e.Members[i].NodeID < e.Members[j].NodeID })
	m := b1ref.Model{GenesisCommitment: H([]byte("bridgeprofile/RefB1 genesis")), ProfileHash: H([]byte("bridgeprofile/RefB1 profile")), Phase: 2,
		Network: uint16(tb.NetworkID), GenesisEpoch: tb.Epoch, ImportedTip: tb.Epoch, OriginReady: true, Origin: tb.Epoch, RootRound: refRound,
		Epochs: []b1state.Entry{e}}
	return m.Words(), b1ref.Pins{GenesisCommitment: m.GenesisCommitment, ProfileHash: m.ProfileHash}, nil
}

// AuthenticateAnchors makes the one 0x0100 call over the anchor table: every anchor's UC verifies under the admitted authority for
// the anchor's partition, shard and configuration, with expectedStateRoot its input-record state hash and expectedIRHash the
// SHA-256 of its canonical input-record bytes. One verdict for the table.
func (r RefB1) AuthenticateAnchors(anchors []Anchor) error {
	st, pins, err := r.registry()
	if err != nil {
		return err
	}
	v, err := b1ref.Cert(CertBatchRequest(anchors), st, pins)
	if err != nil || !v.Valid {
		return ErrAnchorAuth
	}
	return nil
}

// CertBatchRequest is the CERT_BATCH_V2 request of an anchor table, in table order (contract section 5: one header, K = the table
// length): version 2 | flags 0 | K | (partition | shardLen | shard | shardConfHash | expectedStateRoot | expectedIRHash | ucLen | uc)*.
func CertBatchRequest(anchors []Anchor) []byte {
	out := []byte{2, 0}
	out = binary.BigEndian.AppendUint16(out, uint16(len(anchors)))
	for i := range anchors {
		a := &anchors[i]
		out = binary.BigEndian.AppendUint32(out, a.Partition)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.Shard)))
		out = append(out, a.Shard...)
		out = append(out, a.ShardConfHash[:]...)
		out = append(out, a.ExpectedStateRoot[:]...)
		out = append(out, a.ExpectedIRHash[:]...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(a.UC)))
		out = append(out, a.UC...)
	}
	return out
}

// MemberInput is the RSMT_MEMBER_V1 call input:
// header | root | key | valueLength:u32 | value | bitmap | siblings.
func MemberInput(root, key, value [32]byte, p LeafProof) []byte {
	in := []byte{1, 0, 0, 1}
	in = append(in, root[:]...)
	in = append(in, key[:]...)
	in = binary.BigEndian.AppendUint32(in, uint32(len(value)))
	in = append(in, value[:]...)
	in = append(in, p.Bitmap[:]...)
	for _, s := range p.Siblings {
		in = append(in, s[:]...)
	}
	return in
}

// VerifyMember runs RSMT_MEMBER_V1 over (root, key, raw 32-byte value, path).
func (RefB1) VerifyMember(root, key, value [32]byte, p LeafProof) error {
	pop := 0
	for _, x := range p.Bitmap {
		pop += bits.OnesCount8(x)
	}
	if pop != len(p.Siblings) {
		return ErrLeafProof
	}
	v, err := b1ref.Member(MemberInput(root, key, value, p))
	if err != nil || !v.Valid {
		return ErrLeafProof
	}
	return nil
}
