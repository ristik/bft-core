package bridgeprofile

import (
	"bytes"
	"encoding/binary"
	"math/bits"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// RefB1 is the oracle's B1: anchor authentication verifies the anchor's native
// UC against one admitted root trust base and the anchor's own tuple, and
// membership calls the A' reference oracle's RSMT_MEMBER_V1. It simulates the
// admitted registry; it activates nothing.
type RefB1 struct {
	TB types.RootTrustBase
}

// AuthenticateAnchor checks that the UC verifies under the admitted trust base
// for the anchor's partition, shard and configuration, that its input-record
// state hash is expectedStateRoot and that the SHA-256 of its canonical
// input-record bytes is expectedIRHash.
func (r RefB1) AuthenticateAnchor(a *Anchor) error {
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(a.UC, &uc); err != nil || uc.InputRecord == nil || uc.UnicitySeal == nil {
		return ErrAnchorAuth
	}
	if canon, err := types.Cbor.Marshal(&uc); err != nil || !bytes.Equal(canon, a.UC) {
		return ErrAnchorAuth
	}
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte("0x" + hx(a.Shard))); err != nil || !bytes.Equal(shard.Bytes(), a.Shard) {
		return ErrAnchorAuth
	}
	if r.TB == nil || uc.GetRootEpoch() != r.TB.GetEpoch() {
		return ErrAnchorAuth
	}
	if err := verifyNativeUC(r.TB, &uc, types.PartitionID(a.Partition), shard, a.ShardConfHash[:]); err != nil {
		return ErrAnchorAuth
	}
	if !bytes.Equal(uc.InputRecord.Hash, a.ExpectedStateRoot[:]) {
		return ErrAnchorAuth
	}
	ir, err := uc.InputRecord.Bytes()
	if err != nil || H(ir) != a.ExpectedIRHash {
		return ErrAnchorAuth
	}
	return nil
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
