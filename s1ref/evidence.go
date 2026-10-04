package s1ref

import (
	"bytes"
	"math"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// evidence is one decoded vote record
// C([scheme, author, VoteInfo, LedgerCommitInfo, voteSignature, sealSignature|null]).
// It is an extracted evidence record, not another encoding of the full VoteMsg:
// HighQC, Anchor and the transport signature map are not carried.
type evidence struct {
	scheme uint64
	author string
	// VoteInfo. timestamp is meaningful for scheme 1 only; scheme 2 does not sign it.
	epoch, round, parent, timestamp uint64
	exec                            [32]byte
	roundInfo                       *drctypes.RoundInfo // scheme 1: the native object
	seal                            types.UnicitySeal   // LedgerCommitInfo, signatures stripped
	voteSig, sealSig                []byte              // sealSig is nil when absent
}

// scanEvidence validates the structure of one evidence record and builds the
// native objects, requiring byte-exact native re-encoding so that null versus
// empty bytes survive. Nothing here is semantic.
func scanEvidence(raw []byte, tokens *int) (*evidence, error) {
	root, err := scanOne(raw, tokens)
	if err != nil {
		return nil, err
	}
	if !root.isArray(6) {
		return nil, ErrShape
	}
	k := root.kids
	if !k[0].isUint() {
		return nil, ErrShape
	}
	if k[0].arg != votesig.SchemeLegacy && k[0].arg != votesig.SchemeDomainBound {
		return nil, ErrScheme
	}
	e := &evidence{scheme: k[0].arg}
	if k[1].major != majText {
		return nil, ErrShape
	}
	if len(k[1].data) > MaxNodeIDBytes {
		return nil, ErrNodeIDTooLong
	}
	e.author = string(k[1].data)
	if e.scheme == votesig.SchemeLegacy {
		err = e.scanLegacyVoteInfo(&k[2], raw)
	} else {
		err = e.scanDomainVoteInfo(&k[2])
	}
	if err != nil {
		return nil, err
	}
	if err := e.scanCommitInfo(&k[3], raw); err != nil {
		return nil, err
	}
	if k[4].major != majBytes {
		return nil, ErrShape
	}
	if err := sigShape(k[4].data); err != nil {
		return nil, err
	}
	e.voteSig = k[4].data
	if !k[5].null {
		if k[5].major != majBytes {
			return nil, ErrShape
		}
		if err := sigShape(k[5].data); err != nil {
			return nil, err
		}
		e.sealSig = k[5].data
	}
	return e, nil
}

// sigShape is the structural signature rule: exactly 64 bytes, or 65 bytes
// whose recovery byte is 0 or 1. Anything else (including an empty string) is
// malformed; a well-shaped but invalid, zero or high-s signature is false.
func sigShape(sig []byte) error {
	if len(sig) == 64 || (len(sig) == 65 && sig[64] <= 1) {
		return nil
	}
	return ErrSigShape
}

// requireVersion accepts a uint item equal to 1; a wrong integer is an
// unsupported version, anything else a shape error.
func requireVersion(it *item) error {
	if !it.isUint() {
		return ErrShape
	}
	if it.arg != 1 {
		return ErrVersion
	}
	return nil
}

// scanLegacyVoteInfo reads the native RoundInfo, tag39007
// [1, round, epoch, timestamp, parent, exec:bstr32].
func (e *evidence) scanLegacyVoteInfo(it *item, raw []byte) error {
	body, ok := it.tagContent(types.RootPartitionRoundInfoTag)
	if !ok || !body.isArray(6) {
		return ErrShape
	}
	k := body.kids
	if err := requireVersion(&k[0]); err != nil {
		return err
	}
	if !k[1].isUint() || !k[2].isUint() || !k[3].isUint() || !k[4].isUint() || !k[5].isHash() {
		return ErrShape
	}
	e.round, e.epoch, e.timestamp, e.parent = k[1].arg, k[2].arg, k[3].arg, k[4].arg
	copy(e.exec[:], k[5].data)
	e.roundInfo = &drctypes.RoundInfo{Version: 1, RoundNumber: e.round, Epoch: e.epoch, Timestamp: e.timestamp,
		ParentRoundNumber: e.parent, CurrentRootHash: append(hex.Bytes{}, k[5].data...)}
	if again, err := e.roundInfo.MarshalCBOR(); err != nil || !bytes.Equal(again, raw[it.start:it.end]) {
		return ErrReencode
	}
	return nil
}

// scanDomainVoteInfo reads the untagged scheme 2 vote info
// [epoch, round, parent, exec:bstr32].
func (e *evidence) scanDomainVoteInfo(it *item) error {
	if !it.isArray(4) {
		return ErrShape
	}
	k := it.kids
	if !k[0].isUint() || !k[1].isUint() || !k[2].isUint() || !k[3].isHash() {
		return ErrShape
	}
	e.epoch, e.round, e.parent = k[0].arg, k[1].arg, k[2].arg
	copy(e.exec[:], k[3].data)
	return nil
}

// scanCommitInfo reads the native UnicitySeal with its signature map stripped,
// tag39005 [1, network, commitRound, commitEpoch, timestamp, previousHash,
// commitHash, null]. The commit hash is null, an empty byte string or bstr32,
// and the three stay distinct in the native encoding.
func (e *evidence) scanCommitInfo(it *item, raw []byte) error {
	body, ok := it.tagContent(types.UnicitySealTag)
	if !ok || !body.isArray(8) {
		return ErrShape
	}
	k := body.kids
	if err := requireVersion(&k[0]); err != nil {
		return err
	}
	if !k[1].isUint() || k[1].arg > math.MaxUint16 || !k[2].isUint() || !k[3].isUint() || !k[4].isUint() || !k[5].isHash() {
		return ErrShape
	}
	var hash hex.Bytes
	switch {
	case k[6].null:
	case k[6].major == majBytes && (len(k[6].data) == 0 || len(k[6].data) == 32):
		hash = append(hex.Bytes{}, k[6].data...)
	default:
		return ErrShape
	}
	if !k[7].null {
		return ErrShape // the transport signature map is stripped: exactly null
	}
	e.seal = types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(k[1].arg), RootChainRoundNumber: k[2].arg,
		Epoch: k[3].arg, Timestamp: k[4].arg, PreviousHash: append(hex.Bytes{}, k[5].data...), Hash: hash}
	if again, err := e.seal.MarshalCBOR(); err != nil || !bytes.Equal(again, raw[it.start:it.end]) {
		return ErrReencode
	}
	return nil
}
