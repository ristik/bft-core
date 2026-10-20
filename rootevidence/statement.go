// Package rootevidence is the root vote evidence service (S3): a durable journal of the signed scheme 2 vote statements a root receives,
// observed before the consensus filters, a bounded export, and the retention rule that keeps a statement for as long as an obligation needs it.
// It admits nothing to consensus and signs nothing: a statement is kept as the voter signed it.
package rootevidence

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

// MaxStatementBytes bounds the encoding of one normalized statement; a larger one is refused before it is stored.
const MaxStatementBytes = 4 << 10

var (
	// ErrUnsupported is a vote the service does not keep: a legacy scheme vote, or one without a statement.
	ErrUnsupported = errors.New("rootevidence: unsupported vote")
	// ErrTooLarge is a statement above MaxStatementBytes.
	ErrTooLarge = errors.New("rootevidence: statement too large")
)

// Statement is one verified scheme 2 root vote statement, normalized to the fields the Evidence contract takes, with the original signatures
// and the exact preimage bytes the vote signature covers. Nothing here is re-signed or re-derived by the service after verification.
type Statement struct {
	_               struct{} `cbor:",toarray"`
	Parent          uint64
	Exec            []byte // 32 bytes: the executed state hash of the vote info
	Timestamp       uint64
	Committing      bool
	CommitHash      []byte // the committed state hash; empty on a non-committing vote
	CommitRound     uint64
	CommitEpoch     uint64
	CommitTimestamp uint64
	Signature       []byte // the vote signature over sha256(PV)
	SealSignature   []byte // the committing vote's signature over the native seal bytes; empty otherwise
	PV              []byte // the exact preimage the vote signature covers
}

// Digest is the identity of the statement: SHA-256 of its preimage. Two valid signature encodings of one statement are one statement.
func (s *Statement) Digest() [32]byte { return sha256.Sum256(s.PV) }

// Observation is a statement with the slot it occupies: one voter key, in one voting epoch and round.
type Observation struct {
	_      struct{} `cbor:",toarray"`
	Author string   // the voter's node id
	Key    []byte   // the voter's key of the voting epoch (authenticated by the trust base of that epoch when it was observed)
	Epoch  uint64
	Round  uint64
	S      Statement
}

// Slot identifies the (voter, epoch, round) a statement belongs to.
type Slot struct {
	Author string
	Epoch  uint64
	Round  uint64
}

// Slot is the observation's slot.
func (o *Observation) Slot() Slot { return Slot{o.Author, o.Epoch, o.Round} }

// Observe verifies the signed statement of a vote against the trust base and normalizes it. The vote's transport context (high QC, anchor,
// the round it arrived in) plays no part. Only scheme 2 votes are kept.
func Observe(v *abdrc.VoteMsg, tbs *trustbase.TrustBaseStore) (*Observation, error) {
	if v == nil || v.VoteInfo == nil || v.LedgerCommitInfo == nil {
		return nil, fmt.Errorf("%w: no statement", ErrUnsupported)
	}
	st, err := v.VerifyStatement(tbs)
	if err != nil {
		return nil, err
	}
	seal := v.LedgerCommitInfo
	o := &Observation{Author: v.Author, Key: st.Key, Epoch: v.VoteInfo.Epoch, Round: v.VoteInfo.RoundNumber, S: Statement{
		Parent: v.VoteInfo.ParentRoundNumber, Exec: bytes.Clone(v.VoteInfo.CurrentRootHash), Timestamp: v.VoteInfo.Timestamp,
		Committing: st.Committing, Signature: bytes.Clone(v.Signature), PV: st.PV,
	}}
	if st.Committing {
		o.S.CommitHash, o.S.CommitRound, o.S.CommitEpoch, o.S.CommitTimestamp = bytes.Clone(seal.Hash), seal.RootChainRoundNumber, seal.Epoch, seal.Timestamp
		o.S.SealSignature = bytes.Clone(v.SealSignature)
	}
	if raw, err := types.Cbor.Marshal(o); err != nil {
		return nil, err
	} else if len(raw) > MaxStatementBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	return o, nil
}
