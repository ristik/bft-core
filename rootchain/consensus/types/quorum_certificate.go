package types

import (
	"bytes"
	gocrypto "crypto"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

const (
	GenesisRootRound uint64 = 1
	GenesisRootEpoch uint64 = 1
)

var (
	errVoteInfoIsNil         = errors.New("vote info is nil")
	errLedgerCommitInfoIsNil = errors.New("ledger commit info is nil")
	errInvalidRoundInfoHash  = errors.New("round info hash is missing")
)

type QuorumCert struct {
	_                struct{}             `cbor:",toarray"`
	VoteInfo         *RoundInfo           `json:"voteInfo"`         // Consensus data
	LedgerCommitInfo *types.UnicitySeal   `json:"ledgerCommitInfo"` // Commit info
	Signatures       map[string]hex.Bytes `json:"signatures"`       // Node identifier to signature map (NB! aggregated signature schema in spec)
}

func NewQuorumCertificateFromVote(voteInfo *RoundInfo, commitInfo *types.UnicitySeal, signatures map[string]hex.Bytes) *QuorumCert {
	return &QuorumCert{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commitInfo,
		Signatures:       signatures,
	}
}

func (x *QuorumCert) GetRound() uint64 {
	if x != nil {
		return x.VoteInfo.GetRound()
	}
	return 0
}

func (x *QuorumCert) GetParentRound() uint64 {
	if x != nil {
		return x.VoteInfo.GetParentRound()
	}
	return 0
}

func (x *QuorumCert) GetCommitRound() uint64 {
	if x != nil && x.LedgerCommitInfo != nil {
		return x.LedgerCommitInfo.RootChainRoundNumber
	}
	return 0
}

func (x *QuorumCert) IsValid() error {
	if x.VoteInfo == nil {
		return errVoteInfoIsNil
	}
	if err := x.VoteInfo.IsValid(); err != nil {
		return fmt.Errorf("invalid vote info: %w", err)
	}

	// and must have valid ledger commit info
	if x.LedgerCommitInfo == nil {
		return errLedgerCommitInfoIsNil
	}
	// todo: should call x.LedgerCommitInfo.IsValid but that requires some refactoring
	// not to require trustbase parameter?
	// PreviousHash must not be empty, it always contains vote info hash (name is misleading)
	if len(x.LedgerCommitInfo.PreviousHash) < 1 {
		return errInvalidRoundInfoHash
	}

	return nil
}

// ErrNotGenesisQC refuses a quorum certificate of the genesis round that is not the local genesis QC. No QC of round 1 is ever signed: the
// genesis QC is fixed by the software, so any other certificate claiming round 1 has no signatures to check and nothing to vouch for it.
var ErrNotGenesisQC = errors.New("round-1 quorum certificate is not the local genesis QC")

// ErrPinNotGenesisRound refuses to pin a certificate whose vote round is not the genesis round: a pin made of a later certificate (the commit
// QC a block carries after it is committed) would refuse the genuine genesis QC.
var ErrPinNotGenesisRound = errors.New("pinned certificate is not of the genesis round")

// GenesisPinOf identifies a genesis QC: the hash of its vote info and the signed bytes of its commit info. The input must be of round 1.
func GenesisPinOf(genesis *QuorumCert) (*trustbase.GenesisPin, error) {
	if genesis == nil || genesis.VoteInfo == nil || genesis.LedgerCommitInfo == nil {
		return nil, errors.New("genesis QC is incomplete")
	}
	if genesis.VoteInfo.RoundNumber != GenesisRootRound {
		return nil, fmt.Errorf("%w: vote round %d", ErrPinNotGenesisRound, genesis.VoteInfo.RoundNumber)
	}
	h, err := genesis.VoteInfo.Hash(gocrypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("hashing the genesis vote info: %w", err)
	}
	bs, err := genesis.LedgerCommitInfo.SigBytes()
	if err != nil {
		return nil, fmt.Errorf("marshalling the genesis commit info: %w", err)
	}
	return &trustbase.GenesisPin{VoteInfoHash: h, CommitInfo: bs}, nil
}

// IsGenesisQC reports whether x is the genesis QC the pin identifies: the same vote info and the same signed commit info. Signatures it may
// carry are not part of its identity (the genesis QC has none to verify), so they neither help nor hurt.
func (x *QuorumCert) IsGenesisQC(pin *trustbase.GenesisPin) bool {
	if x == nil || pin == nil || x.VoteInfo == nil || x.LedgerCommitInfo == nil {
		return false
	}
	h, err := x.VoteInfo.Hash(gocrypto.SHA256)
	if err != nil || !bytes.Equal(h, pin.VoteInfoHash) {
		return false
	}
	bs, err := x.LedgerCommitInfo.SigBytes()
	return err == nil && bytes.Equal(bs, pin.CommitInfo)
}

// Verify checks the QC against the trust base. The genesis QC has no signatures to verify: it is accepted only when it is the local one, which
// the caller identifies by a pin (the store's GenesisPin); with no pin, or another round-1 QC, the QC is refused with ErrNotGenesisQC.
func (x *QuorumCert) Verify(tb types.RootTrustBase, pin ...*trustbase.GenesisPin) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid quorum certificate: %w", err)
	}
	// check vote info hash
	h, err := x.VoteInfo.Hash(gocrypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to hash vote info: %w", err)
	}
	if !bytes.Equal(h, x.LedgerCommitInfo.PreviousHash) {
		return fmt.Errorf("vote info hash verification failed")
	}
	/* todo: call LedgerCommitInfo.Verify but first refactor it so that it takes quorum param?
	if err := x.LedgerCommitInfo.Verify(rootTrust); err != nil {
		return fmt.Errorf("invalid commit info: %w", err)
	}*/

	if x.GetRound() == GenesisRootRound {
		if len(pin) == 1 && x.IsGenesisQC(pin[0]) {
			return nil
		}
		return ErrNotGenesisQC
	}

	bs, err := x.LedgerCommitInfo.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal ledger commit info: %w", err)
	}
	if err := tb.VerifyQuorumSignatures(bs, x.Signatures); err != nil {
		return fmt.Errorf("failed to verify quorum signatures: %w", err)
	}
	return nil
}

// SignatureBytes serializes signatures.
func (x *QuorumCert) SignatureBytes() []byte {
	var b bytes.Buffer
	if x != nil {
		// From QC signers (in the alphabetical order of signer ID!) must be included
		signatures := x.Signatures
		authors := make([]string, 0, len(signatures))
		for k := range signatures {
			authors = append(authors, k)
		}
		sort.Strings(authors)
		for _, author := range authors {
			b.Write(signatures[author])
		}
	}
	return b.Bytes()
}
