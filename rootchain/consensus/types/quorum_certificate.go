package types

import (
	"bytes"
	gocrypto "crypto"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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
	// Scheme is the signing scheme of the wire form: 0 or 1 legacy, 2 the domain-bound wrapper [2, payload]. Not part of the
	// legacy encoding. In a scheme 2 certificate Signatures are the vote signatures over PV and SealSignatures, present only
	// when the certificate commits, the same signers' signatures over the unchanged native seal bytes; VoteInfo carries the
	// four signed fields and no timestamp.
	Scheme         uint64               `cbor:"-" json:"-"`
	SealSignatures map[string]hex.Bytes `cbor:"-" json:"sealSignatures,omitempty"`
}

type qcWire QuorumCert

type qcVoteInfoV2 struct {
	_      struct{} `cbor:",toarray"`
	Epoch  uint64
	Round  uint64
	Parent uint64
	Exec   hex.Bytes
}

type qcV2Payload struct {
	_                struct{} `cbor:",toarray"`
	VoteInfo         qcVoteInfoV2
	LedgerCommitInfo *types.UnicitySeal
	VoteSignatures   map[string]hex.Bytes
	SealSignatures   map[string]hex.Bytes
}

// ErrMalformedQC is returned for a quorum certificate whose bytes are neither wire form: a payload of the wrong arity or
// type, or trailing or missing items. It wraps the decoder's own error.
var ErrMalformedQC = errors.New("malformed quorum certificate")

type qcV2Wire struct {
	_       struct{} `cbor:",toarray"`
	Scheme  uint64
	Payload qcV2Payload
}

// MarshalCBOR writes the legacy array, or the scheme wrapper for a scheme 2 certificate.
func (x QuorumCert) MarshalCBOR() ([]byte, error) {
	if x.Scheme == votesig.SchemeDomainBound {
		if x.VoteInfo == nil {
			return nil, fmt.Errorf("%w: scheme 2 certificate has no vote info", votesig.ErrStatement)
		}
		return types.Cbor.Marshal(qcV2Wire{Scheme: x.Scheme, Payload: qcV2Payload{
			VoteInfo:         qcVoteInfoV2{Epoch: x.VoteInfo.Epoch, Round: x.VoteInfo.RoundNumber, Parent: x.VoteInfo.ParentRoundNumber, Exec: x.VoteInfo.CurrentRootHash},
			LedgerCommitInfo: x.LedgerCommitInfo, VoteSignatures: x.Signatures, SealSignatures: x.SealSignatures}})
	}
	return types.Cbor.Marshal(qcWire(x))
}

// UnmarshalCBOR reads the legacy array or the scheme 2 wrapper; any other wrapper version is refused before verification.
func (x *QuorumCert) UnmarshalCBOR(data []byte) error {
	wrapped, err := votesig.PeekWrapper(data)
	if err != nil {
		return err
	}
	if wrapped {
		var w qcV2Wire
		if err := types.Cbor.Unmarshal(data, &w); err != nil {
			return fmt.Errorf("%w: %w", ErrMalformedQC, err)
		}
		p := w.Payload
		if p.LedgerCommitInfo == nil {
			return fmt.Errorf("%w: scheme 2 certificate has no commit info: %w", ErrMalformedQC, votesig.ErrStatement)
		}
		*x = QuorumCert{Scheme: votesig.SchemeDomainBound, LedgerCommitInfo: p.LedgerCommitInfo, Signatures: p.VoteSignatures, SealSignatures: p.SealSignatures,
			VoteInfo: &RoundInfo{Version: 1, RoundNumber: p.VoteInfo.Round, Epoch: p.VoteInfo.Epoch, ParentRoundNumber: p.VoteInfo.Parent, CurrentRootHash: p.VoteInfo.Exec}}
		return nil
	}
	var legacy qcWire
	if err := types.Cbor.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedQC, err)
	}
	*x = QuorumCert(legacy)
	x.Scheme, x.SealSignatures = 0, nil
	return nil
}

func (x *QuorumCert) signingScheme() uint64 {
	if x != nil && x.Scheme == votesig.SchemeDomainBound {
		return votesig.SchemeDomainBound
	}
	return votesig.SchemeLegacy
}

// DomainBoundStatement derives the signed statement of a scheme 2 vote or certificate from its fields: the preimage PV, and
// for a committing one the native seal bytes the second signature covers. The vote info hash must be the one the commit
// info carries, so that the two halves are one statement. sealSignaturePresent says whether the message carries a seal
// signature; a non-committing statement must not.
func DomainBoundStatement(cfg votesig.Config, info *RoundInfo, seal *types.UnicitySeal, sealSignaturePresent bool) (pv, sealBytes []byte, committing bool, err error) {
	if info == nil || seal == nil {
		return nil, nil, false, fmt.Errorf("%w: vote info or commit info is missing", votesig.ErrStatement)
	}
	if len(info.CurrentRootHash) != 32 {
		return nil, nil, false, fmt.Errorf("%w: executed state hash is %d bytes", votesig.ErrStatement, len(info.CurrentRootHash))
	}
	vi := votesig.VoteInfo{Epoch: info.Epoch, Round: info.RoundNumber, Parent: info.ParentRoundNumber}
	copy(vi.Exec[:], info.CurrentRootHash)
	vh, err := cfg.VoteInfoHash(vi)
	if err != nil {
		return nil, nil, false, err
	}
	if !bytes.Equal(vh[:], seal.PreviousHash) {
		return nil, nil, false, fmt.Errorf("%w: vote info hash does not match hash in commit info", votesig.ErrStatement)
	}
	var commit votesig.Commit
	committing = len(seal.Hash) != 0 || seal.RootChainRoundNumber != 0
	if committing {
		if seal.NetworkID != types.NetworkID(cfg.Network) || seal.Epoch == 0 || seal.Epoch > vi.Epoch {
			return nil, nil, false, fmt.Errorf("%w: commit info network or epoch", votesig.ErrStatement)
		}
		commit = votesig.Commit{Hash: seal.Hash, Round: seal.RootChainRoundNumber}
		if sealBytes, err = seal.SigBytes(); err != nil {
			return nil, nil, false, fmt.Errorf("failed to marshal unicity seal: %w", err)
		}
	} else if seal.Epoch != 0 || seal.NetworkID != 0 || seal.Timestamp != 0 || sealSignaturePresent {
		// a non-committing statement carries the empty native seal (only the vote info hash) and no seal signature
		return nil, nil, false, fmt.Errorf("%w: non-committing statement with commit data", votesig.ErrStatement)
	}
	if pv, err = cfg.VotePreimage(vi, commit); err != nil {
		return nil, nil, false, err
	}
	return pv, sealBytes, committing, nil
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
	if x.Scheme == votesig.SchemeDomainBound {
		// a scheme 2 certificate has no timestamp; its statement is validated by the scheme 2 rules
		if x.VoteInfo.RoundNumber == 0 || x.VoteInfo.ParentRoundNumber >= x.VoteInfo.RoundNumber || len(x.VoteInfo.CurrentRootHash) != 32 {
			return fmt.Errorf("invalid vote info: %w", votesig.ErrStatement)
		}
		if x.LedgerCommitInfo == nil {
			return errLedgerCommitInfoIsNil
		}
		if len(x.LedgerCommitInfo.PreviousHash) < 1 {
			return errInvalidRoundInfoHash
		}
		return nil
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
	if x.signingScheme() != votesig.SchemeLegacy {
		return fmt.Errorf("%w: a scheme 2 certificate is verified with its epoch's signing configuration (VerifyScheme)", votesig.ErrScheme)
	}
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
	// D3 section 3: an unknown or duplicate signer rejects the certificate; v1 still skips an invalid signature of a known member.
	if _, err := quorumweight.VerifySigned(tb, bs, x.Signatures); err != nil {
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

// VerifyScheme verifies the certificate by the rule of the epoch it names, given that epoch's signing configuration: the
// wire form must be the scheme the configuration requires, a legacy-form certificate is checked as before, and a scheme 2
// one by verifyDomainBound. A zero configuration is the legacy one.
func (x *QuorumCert) VerifyScheme(tb types.RootTrustBase, cfg votesig.Config, pin ...*trustbase.GenesisPin) error {
	want := cfg.Scheme
	if want == 0 {
		want = votesig.SchemeLegacy
	}
	if x.signingScheme() != want {
		return fmt.Errorf("%w: certificate is scheme %d, its epoch requires scheme %d", votesig.ErrScheme, x.signingScheme(), want)
	}
	if want == votesig.SchemeLegacy {
		return x.Verify(tb, pin...)
	}
	return x.verifyDomainBound(tb, cfg)
}

// VerifyWith resolves the certificate's own epoch in the store (its trust base and its signing configuration) and verifies
// it by that epoch's rule; the genesis pin is the store's.
func (x *QuorumCert) VerifyWith(tbs *trustbase.TrustBaseStore) error {
	if x == nil || x.VoteInfo == nil {
		return errVoteInfoIsNil
	}
	tb, err := tbs.GetByEpoch(x.VoteInfo.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for QC verification, epoch %d: %w", x.VoteInfo.Epoch, err)
	}
	cfg, err := tbs.SigningConfig(x.VoteInfo.Epoch)
	if err != nil {
		return err
	}
	return x.VerifyScheme(tb, cfg, tbs.GenesisPin())
}

func (x *QuorumCert) verifyDomainBound(tb types.RootTrustBase, cfg votesig.Config) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid quorum certificate: %w", err)
	}
	if x.GetRound() == GenesisRootRound {
		return ErrNotGenesisQC // the genesis QC is the local legacy one; a scheme 2 certificate of round 1 has nothing to vouch for it
	}
	pv, sealBytes, committing, err := DomainBoundStatement(cfg, x.VoteInfo, x.LedgerCommitInfo, len(x.SealSignatures) != 0)
	if err != nil {
		return fmt.Errorf("invalid quorum certificate: %w", err)
	}
	for id, sig := range x.Signatures {
		if err := votesig.CheckSignatureShape(sig); err != nil {
			return fmt.Errorf("vote signature of %q: %w", id, err)
		}
	}
	if committing {
		if len(x.SealSignatures) != len(x.Signatures) {
			return fmt.Errorf("%w: %d vote signatures and %d seal signatures", votesig.ErrSignerSets, len(x.Signatures), len(x.SealSignatures))
		}
		for id, sig := range x.SealSignatures {
			if _, ok := x.Signatures[id]; !ok {
				return fmt.Errorf("%w: %q signed the seal but not the vote", votesig.ErrSignerSets, id)
			}
			if err := votesig.CheckSignatureShape(sig); err != nil {
				return fmt.Errorf("seal signature of %q: %w", id, err)
			}
		}
	}
	// the scheme 2 certificate is strict: every signature of both maps must verify, no signer may be unknown, and the weight of
	// the (identical) signer set must reach the threshold under the checked arithmetic
	if _, err := quorumweight.VerifySignedStrict(tb, pv, x.Signatures); err != nil {
		return fmt.Errorf("failed to verify quorum vote signatures: %w", err)
	}
	if committing {
		if _, err := quorumweight.VerifySignedStrict(tb, sealBytes, x.SealSignatures); err != nil {
			return fmt.Errorf("failed to verify quorum seal signatures: %w", err)
		}
	}
	return nil
}
