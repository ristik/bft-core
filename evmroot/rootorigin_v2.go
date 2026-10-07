package evmroot

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ProfileVersionV2 is the inactive configured-genesis-origin profile of F4f §4.
const ProfileVersionV2 uint64 = 2

// OriginClassV2 is derived from the authenticated input-record shape; it is never a peer assertion.
type OriginClassV2 uint8

const (
	OriginInvalidV2 OriginClassV2 = iota
	OriginBootstrapV2
	OriginFirstCertifiedV2
	OriginOrdinaryV2
)

func (c OriginClassV2) String() string {
	switch c {
	case OriginBootstrapV2:
		return "bootstrap"
	case OriginFirstCertifiedV2:
		return "first-certified"
	case OriginOrdinaryV2:
		return "ordinary"
	default:
		return "invalid"
	}
}

// RootOriginV2 retains the actual authenticated statement, including genuine nil state fields.
type RootOriginV2 struct {
	NetworkID       uint64
	RootRound       uint64
	RootEpoch       uint64
	ReferenceTime   uint64
	UnicityTreeRoot []byte
	InputVersion    uint64 // authenticated IR.Version; validated but not duplicated in the canonical D1 tuple
	IR              ShardInputRecord
	TRHash          []byte
	ShardConfHash   []byte
}

func nullableV2(b []byte) cborItem {
	if b == nil {
		return cNull{}
	}
	return cBytes(b)
}
func (o RootOriginV2) canonicalBody() cArray {
	return cArray{
		cUint(o.NetworkID), cUint(o.RootRound), cUint(o.RootEpoch), cUint(o.ReferenceTime), cBytes(o.UnicityTreeRoot),
		cArray{cUint(o.IR.Round), cUint(o.IR.Epoch), nullableV2(o.IR.PreviousHash), nullableV2(o.IR.Hash), cUint(o.IR.Timestamp), nullableV2(o.IR.BlockHash)},
		cBytes(o.TRHash), cBytes(o.ShardConfHash),
	}
}
func (o RootOriginV2) Encode() []byte   { return marshalCBOR(o.canonicalBody()) }
func (o RootOriginV2) Identity() Hash32 { return sha256.Sum256(o.Encode()) }

func absentV2(b []byte) bool { return b == nil }
func wordV2(b []byte) bool   { return len(b) == 32 }

// Class validates the three exact F4f shapes and returns their derived class.
func (o RootOriginV2) Class() (OriginClassV2, error) {
	if o.InputVersion != 1 {
		return OriginInvalidV2, fmt.Errorf("evmroot: v2 requires authenticated input record version 1, got %d", o.InputVersion)
	}
	for n, h := range map[string][]byte{"UnicityTreeRoot": o.UnicityTreeRoot, "TRHash": o.TRHash, "ShardConfHash": o.ShardConfHash} {
		if len(h) != 32 {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 %s must be 32 bytes, got %d", n, len(h))
		}
	}
	// Allocated empty byte strings are not null in canonical CBOR and are never accepted as absence.
	for n, h := range map[string][]byte{"IR.PreviousHash": o.IR.PreviousHash, "IR.Hash": o.IR.Hash, "IR.BlockHash": o.IR.BlockHash} {
		if h != nil && len(h) == 0 {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 %s is empty bytes, not null", n)
		}
	}
	switch {
	case o.IR.Round == 0:
		if o.IR.Epoch != 0 || o.IR.Timestamp != 0 || !absentV2(o.IR.PreviousHash) || !absentV2(o.IR.Hash) || !absentV2(o.IR.BlockHash) {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 bootstrap must be round/epoch/time zero with null previous/state/block")
		}
		return OriginBootstrapV2, nil
	case absentV2(o.IR.PreviousHash):
		if !wordV2(o.IR.Hash) || !wordV2(o.IR.BlockHash) {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 first-certified origin needs null previous and 32-byte state/block")
		}
		return OriginFirstCertifiedV2, nil
	default:
		if !wordV2(o.IR.PreviousHash) || !wordV2(o.IR.Hash) {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 ordinary origin needs 32-byte previous/state")
		}
		quiet := bytes.Equal(o.IR.PreviousHash, o.IR.Hash)
		if quiet && !absentV2(o.IR.BlockHash) {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 quiet origin needs null block")
		}
		if !quiet && !wordV2(o.IR.BlockHash) {
			return OriginInvalidV2, fmt.Errorf("evmroot: v2 state-changing origin needs 32-byte block")
		}
		return OriginOrdinaryV2, nil
	}
}
func (o RootOriginV2) Validate() error { _, err := o.Class(); return err }

var ErrB1UpdateHash = errors.New("evmroot: B1 update hash must be 32 bytes")

// RootInputV2 is the inactive v2 tuple. It deliberately does not share v1 validation.
type RootInputV2 struct {
	Version, NetworkID, PartitionID        uint64
	ShardID                                []byte
	Round, CertifiedEpoch, AuthorizedEpoch uint64
	ParentHash                             []byte
	Origin                                 RootOriginV2
	TE                                     TechnicalRecord
	Transitions                            [][]byte
	B1UpdateHash                           []byte
}

func (ri RootInputV2) canonicalBody() cArray {
	te := cArray{cUint(ri.TE.Round), cUint(ri.TE.Epoch), cText(ri.TE.Leader), cBytes(ri.TE.StatHash), cBytes(ri.TE.FeeHash)}
	d := make(cArray, len(ri.Transitions))
	for i, b := range ri.Transitions {
		d[i] = cBytes(b)
	}
	body := cArray{cUint(ri.Version), cUint(ri.NetworkID), cUint(ri.PartitionID), cBytes(ri.ShardID), cUint(ri.Round), cUint(ri.CertifiedEpoch), cUint(ri.AuthorizedEpoch), cBytes(ri.ParentHash), ri.Origin.canonicalBody(), te, d}
	if ri.B1UpdateHash != nil {
		body = append(body, cBytes(ri.B1UpdateHash))
	}
	return body
}
func (ri RootInputV2) Encode() []byte    { return marshalCBOR(ri.canonicalBody()) }
func (ri RootInputV2) ExtraData() Hash32 { return sha256.Sum256(ri.Encode()) }
func (ri RootInputV2) Validate() error {
	if ri.B1UpdateHash != nil && len(ri.B1UpdateHash) != 32 {
		return ErrB1UpdateHash
	}
	if ri.Version != ProfileVersionV2 {
		return fmt.Errorf("evmroot: v2 rootInput version %d", ri.Version)
	}
	if ri.Round == 0 || ri.TE.Round != ri.Round {
		return fmt.Errorf("evmroot: v2 executable authorized round must be positive and equal TE round")
	}
	// Shard epochs are authenticated values, not constants. The certified epoch is the
	// certified input record's, the authorized epoch the technical record's. Ordinary
	// execution runs where they agree; the authorized epoch is ahead of the certified
	// one only while an assignment acknowledgement is pending, and then exactly one
	// transition must carry it. The bootstrap origin's epoch-zero rule is Class's.
	if ri.CertifiedEpoch != ri.Origin.IR.Epoch || ri.AuthorizedEpoch != ri.TE.Epoch {
		return fmt.Errorf("evmroot: v2 root input epochs differ from the certified origin and technical record")
	}
	if ri.AuthorizedEpoch < ri.CertifiedEpoch {
		return fmt.Errorf("evmroot: v2 authorized shard epoch %d is behind certified epoch %d", ri.AuthorizedEpoch, ri.CertifiedEpoch)
	}
	if ri.AuthorizedEpoch != ri.CertifiedEpoch && len(ri.Transitions) == 0 {
		return fmt.Errorf("evmroot: v2 authorized shard epoch %d is ahead of certified epoch %d without an acknowledgement transition", ri.AuthorizedEpoch, ri.CertifiedEpoch)
	}
	if len(ri.ParentHash) != 32 {
		return fmt.Errorf("evmroot: v2 parent hash must be 32 bytes, got %d", len(ri.ParentHash))
	}
	if err := ri.Origin.Validate(); err != nil {
		return err
	}
	if len(ri.Transitions) > 1 {
		return fmt.Errorf("evmroot: v2 supports at most one epoch transition")
	}
	for i, b := range ri.Transitions {
		if len(b) == 0 || len(b) > 16*1024 {
			return fmt.Errorf("evmroot: v2 transition D[%d] has invalid length", i)
		}
	}
	return nil
}

// CertifiedProjectionV2 is the four registry ABI words whose bootstrap representation differs from v1.
type CertifiedProjectionV2 struct {
	Round        uint64
	StateHash    Hash32
	HasBlockHash bool
	BlockHash    Hash32
}

func (o RootOriginV2) CertifiedProjection() (CertifiedProjectionV2, error) {
	c, err := o.Class()
	if err != nil {
		return CertifiedProjectionV2{}, err
	}
	if c == OriginBootstrapV2 {
		return CertifiedProjectionV2{}, nil
	}
	var p CertifiedProjectionV2
	p.Round = o.IR.Round
	copy(p.StateHash[:], o.IR.Hash)
	if o.IR.BlockHash != nil {
		p.HasBlockHash = true
		copy(p.BlockHash[:], o.IR.BlockHash)
	}
	return p, nil
}
