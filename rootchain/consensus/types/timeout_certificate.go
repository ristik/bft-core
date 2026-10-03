package types

import (
	"bytes"
	"fmt"

	base "github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

type Timeout struct {
	_      struct{}     `cbor:",toarray"`
	Epoch  uint64       `json:"epoch"`            // Epoch to establish valid configuration
	Round  uint64       `json:"round"`            // Root round number
	HighQc *QuorumCert  `json:"highQc"`           // Highest quorum certificate of the validator
	Anchor *EpochAnchor `json:"anchor,omitempty"` // verified bootstrap parent, profile 2 only
}

type TimeoutVote struct {
	_         struct{}     `cbor:",toarray"`
	HqcRound  uint64       `json:"hqcRound"`  // round from timeout.high_qc.voteInfo.round
	Signature hex.Bytes    `json:"signature"` // timeout signature is TimeoutMsg signature - round, epoch, hqc_round, author
	Anchor    *EpochAnchor `json:"anchor,omitempty"`
}

type TimeoutCert struct {
	_          struct{}                `cbor:",toarray"`
	Timeout    *Timeout                `json:"timeout"`    // Round and epoch of the timeout event
	Signatures map[string]*TimeoutVote `json:"signatures"` // 2f+1 signatures from nodes confirming TC
}

// NewTimeout creates new Timeout for round (epoch) and highest QC seen
func NewTimeout(round, epoch uint64, hqc *QuorumCert) *Timeout {
	return &Timeout{Epoch: epoch, Round: round, HighQc: hqc}
}

func NewAnchorTimeout(round uint64, anchor *EpochAnchor) *Timeout {
	return &Timeout{Epoch: anchor.Epoch, Round: round, Anchor: anchor}
}

type timeoutLegacyWire struct {
	_      struct{} `cbor:",toarray"`
	Epoch  uint64
	Round  uint64
	HighQc *QuorumCert
}

type timeoutAnchorWire struct {
	_      struct{} `cbor:",toarray"`
	Epoch  uint64
	Round  uint64
	HighQc *QuorumCert
	Anchor *EpochAnchor
}

func (x *Timeout) MarshalCBOR() ([]byte, error) {
	if x.Anchor != nil {
		return base.Cbor.Marshal(timeoutAnchorWire{Epoch: x.Epoch, Round: x.Round, HighQc: x.HighQc, Anchor: x.Anchor})
	}
	return base.Cbor.Marshal(timeoutLegacyWire{Epoch: x.Epoch, Round: x.Round, HighQc: x.HighQc})
}

func (x *Timeout) UnmarshalCBOR(data []byte) error {
	var anchor timeoutAnchorWire
	if err := base.Cbor.Unmarshal(data, &anchor); err == nil {
		*x = Timeout{Epoch: anchor.Epoch, Round: anchor.Round, HighQc: anchor.HighQc, Anchor: anchor.Anchor}
		return nil
	}
	var legacy timeoutLegacyWire
	if err := base.Cbor.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*x = Timeout{Epoch: legacy.Epoch, Round: legacy.Round, HighQc: legacy.HighQc}
	return nil
}

type timeoutVoteLegacyWire struct {
	_         struct{} `cbor:",toarray"`
	HqcRound  uint64
	Signature hex.Bytes
}

type timeoutVoteAnchorWire struct {
	_         struct{} `cbor:",toarray"`
	HqcRound  uint64
	Signature hex.Bytes
	Anchor    *EpochAnchor
}

func (x *TimeoutVote) MarshalCBOR() ([]byte, error) {
	if x.Anchor != nil {
		return base.Cbor.Marshal(timeoutVoteAnchorWire{HqcRound: x.HqcRound, Signature: x.Signature, Anchor: x.Anchor})
	}
	return base.Cbor.Marshal(timeoutVoteLegacyWire{HqcRound: x.HqcRound, Signature: x.Signature})
}

func (x *TimeoutVote) UnmarshalCBOR(data []byte) error {
	var anchor timeoutVoteAnchorWire
	if err := base.Cbor.Unmarshal(data, &anchor); err == nil {
		*x = TimeoutVote{HqcRound: anchor.HqcRound, Signature: anchor.Signature, Anchor: anchor.Anchor}
		return nil
	}
	var legacy timeoutVoteLegacyWire
	if err := base.Cbor.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*x = TimeoutVote{HqcRound: legacy.HqcRound, Signature: legacy.Signature}
	return nil
}

func (x *Timeout) IsValid() error {
	if x.Anchor != nil {
		if x.HighQc != nil || x.Anchor.IsValid() != nil || x.Epoch != x.Anchor.Epoch || x.Round <= x.Anchor.Slot {
			return ErrEpochAnchor
		}
		return nil
	}
	if x.HighQc == nil {
		return fmt.Errorf("high QC is unassigned")
	}
	if err := x.HighQc.IsValid(); err != nil {
		return fmt.Errorf("invalid high QC: %w", err)
	}

	if x.Round <= x.HighQc.VoteInfo.RoundNumber {
		return fmt.Errorf("timeout round (%d) must be greater than high QC round (%d)", x.Round, x.HighQc.VoteInfo.RoundNumber)
	}

	return nil
}

// Verify verifies timeout vote received.
func (x *Timeout) Verify(tbs *trustbase.TrustBaseStore) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid timeout data: %w", err)
	}
	if x.Anchor != nil {
		// The consensus manager binds this anchor to its locally installed,
		// proof-verified epoch checkpoint before accepting a timeout.
		return nil
	}
	highQcTrustBase, err := tbs.GetByEpoch(x.HighQc.VoteInfo.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for high QC verification, epoch %d: %w", x.HighQc.VoteInfo.Epoch, err)
	}
	if err := x.HighQc.Verify(highQcTrustBase, tbs.GenesisPin()); err != nil {
		return fmt.Errorf("invalid high QC: %w", err)
	}

	return nil
}

func (x *Timeout) GetRound() uint64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *Timeout) GetHqcRound() uint64 {
	if x != nil {
		if x.Anchor != nil {
			return x.Anchor.Slot
		}
		return x.HighQc.GetRound()
	}
	return 0
}

func (x *TimeoutCert) GetRound() uint64 {
	if x != nil {
		return x.Timeout.GetRound()
	}
	return 0
}

func (x *TimeoutCert) GetHqcRound() uint64 {
	if x != nil {
		return x.Timeout.GetHqcRound()
	}
	return 0
}

func (x *TimeoutCert) GetAuthors() []string {
	authors := make([]string, 0, len(x.Signatures))
	for k := range x.Signatures {
		authors = append(authors, k)
	}
	return authors
}

func (x *TimeoutCert) Add(author string, timeout *Timeout, signature []byte) error {
	if x.Timeout.Round != timeout.Round {
		return fmt.Errorf("TC is for round %d not %d", x.Timeout.Round, timeout.Round)
	}
	// if already added then reject
	if _, found := x.Signatures[author]; found {
		return fmt.Errorf("%s already voted in round %d", author, x.Timeout.Round)
	}
	if timeout.Epoch != x.Timeout.Epoch || (timeout.Anchor != nil && timeout.IsValid() != nil) {
		return ErrEpochAnchor
	}
	if timeout.Anchor != nil {
		for _, previous := range x.Signatures {
			if previous.Anchor != nil && !bytes.Equal(previous.Anchor.GenesisID, timeout.Anchor.GenesisID) {
				return ErrEpochAnchor
			}
		}
	}

	// Keep the highest QC certificate
	hqcRound := timeout.GetHqcRound()
	// If received highest QC round was bigger than previously seen, replace timeout struct
	if timeout.HighQc != nil && (x.Timeout.Anchor != nil || hqcRound > x.Timeout.GetHqcRound()) {
		x.Timeout = timeout
	}
	x.Signatures[author] = &TimeoutVote{HqcRound: hqcRound, Signature: signature, Anchor: timeout.Anchor}
	return nil
}

func BytesFromTimeoutVote(t *Timeout, author string, vote *TimeoutVote) []byte {
	var b bytes.Buffer
	b.Write(util.Uint64ToBytes(t.Round))
	b.Write(util.Uint64ToBytes(t.Epoch))
	b.Write(util.Uint64ToBytes(vote.HqcRound))
	if vote.Anchor != nil {
		b.WriteByte(1)
		b.Write(vote.Anchor.GenesisID)
		b.Write(util.Uint64ToBytes(vote.Anchor.Epoch))
		b.Write(util.Uint64ToBytes(vote.Anchor.Slot))
	}
	b.Write([]byte(author))
	return b.Bytes()
}

func (x *TimeoutCert) IsValid() error {
	if x.Timeout == nil {
		return fmt.Errorf("timeout data is unassigned")
	}
	return nil
}

func (x *TimeoutCert) Verify(tbs *trustbase.TrustBaseStore) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	if err := x.Timeout.Verify(tbs); err != nil {
		return fmt.Errorf("invalid timeout data: %w", err)
	}

	tb, err := tbs.GetByEpoch(x.Timeout.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for vote verification, epoch %d: %w", x.Timeout.Epoch, err)
	}
	var signedVotes quorumweight.Tally
	var maxSignedRound uint64
	highQcRound := x.Timeout.GetHqcRound()
	// Check all signatures and remember the max QC round over all the signatures received
	for author, timeoutSig := range x.Signatures {
		if timeoutSig == nil || (timeoutSig.Anchor != nil && (timeoutSig.Anchor.IsValid() != nil || timeoutSig.Anchor.Epoch != x.Timeout.Epoch || timeoutSig.HqcRound != timeoutSig.Anchor.Slot)) {
			return ErrEpochAnchor
		}
		timeoutBytes := BytesFromTimeoutVote(x.Timeout, author, timeoutSig)
		stake, err := tb.VerifySignature(timeoutBytes, timeoutSig.Signature, author)
		if err != nil {
			return fmt.Errorf("timeout certificate signature verification failed: %w", err)
		}
		if err := signedVotes.Add(author, stake); err != nil {
			return fmt.Errorf("timeout certificate weight: %w", err)
		}
		if timeoutSig.Anchor == nil && maxSignedRound < timeoutSig.HqcRound {
			maxSignedRound = timeoutSig.HqcRound
		}
	}
	if !signedVotes.Reached(tb.GetQuorumThreshold()) {
		return fmt.Errorf("quorum requires %d votes but certificate has %d", tb.GetQuorumThreshold(), signedVotes.Weight())
	}
	// Verify that the highest quorum certificate stored has max QC round over all timeout votes received
	if x.Timeout.Anchor == nil && highQcRound != maxSignedRound {
		return fmt.Errorf("high QC round %d does not match max signed QC round %d", highQcRound, maxSignedRound)
	}
	if x.Timeout.Anchor != nil {
		if maxSignedRound != 0 {
			return ErrEpochAnchor
		}
		for _, vote := range x.Signatures {
			if vote.Anchor == nil || !bytes.Equal(vote.Anchor.GenesisID, x.Timeout.Anchor.GenesisID) || vote.Anchor.Slot != x.Timeout.Anchor.Slot {
				return ErrEpochAnchor
			}
		}
	}
	return nil
}
