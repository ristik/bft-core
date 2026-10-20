package abdrc

import (
	"bytes"
	gocrypto "crypto"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utbentry"
)

type VoteMsg struct {
	_                struct{}              `cbor:",toarray"`
	VoteInfo         *drctypes.RoundInfo   `json:"voteInfo"`         // Proposed block hash and resulting state hash
	LedgerCommitInfo *types.UnicitySeal    `json:"ledgerCommitInfo"` // Commit info
	HighQc           *drctypes.QuorumCert  `json:"highQc"`           // Sync with highest QC
	Anchor           *drctypes.EpochAnchor `json:"anchor,omitempty"`
	Author           string                `json:"author"`    // Voter node identifier
	Signature        hex.Bytes             `json:"signature"` // Vote signature on hash of consensus info
	// Scheme is the signing scheme of the wire form: 0 or 1 legacy, 2 the domain-bound wrapper [2, payload]. Not part of the
	// legacy encoding; the epoch of the vote decides which one a verifier accepts.
	Scheme uint64 `cbor:"-" json:"-"`
	// SealSignature is the second signature of a committing scheme 2 vote: the same key over the unchanged native
	// UnicitySeal.SigBytes(), so that a certificate built from the votes keeps its native seal authentication. Absent on a
	// non-committing vote and in the legacy form, whose single signature is over the seal bytes.
	SealSignature hex.Bytes `cbor:"-" json:"sealSignature,omitempty"`
	// Envelope is 0 for the historical wire forms and votesig.EnvelopeUTB for the envelope [3, inner, utb] of an epoch configured with
	// Config.UTB. UTB is the voter's endorsement of the unsigned successor entry, present exactly on a vote that commits the outgoing handoff.
	Envelope uint64            `cbor:"-" json:"-"`
	UTB      *drctypes.UTBVote `cbor:"-" json:"utb,omitempty"`
}

// voteV3Wire is the version 3 envelope: [3, inner, utb|null], inner being the unchanged scheme 1 or 2 encoding of the same vote.
type voteV3Wire struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Inner   cbor.RawMessage
	UTB     *drctypes.UTBVote
}

// voteInfoV2Wire carries the signed round data, appending time on new votes.
// Network, domain and root-chain genesis come from authenticated epoch configuration.
type voteInfoV2Wire = drctypes.DomainBoundVoteInfo

type voteV2Payload struct {
	_                struct{} `cbor:",toarray"`
	VoteInfo         voteInfoV2Wire
	LedgerCommitInfo *types.UnicitySeal
	HighQc           *drctypes.QuorumCert
	Author           string
	VoteSignature    hex.Bytes
	SealSignature    hex.Bytes
	Anchor           *drctypes.EpochAnchor
}

type voteV2Wire struct {
	_       struct{} `cbor:",toarray"`
	Scheme  uint64
	Payload voteV2Payload
}

type voteLegacyWire struct {
	_                struct{} `cbor:",toarray"`
	VoteInfo         *drctypes.RoundInfo
	LedgerCommitInfo *types.UnicitySeal
	HighQc           *drctypes.QuorumCert
	Author           string
	Signature        hex.Bytes
}

type voteAnchorWire struct {
	_                struct{} `cbor:",toarray"`
	VoteInfo         *drctypes.RoundInfo
	LedgerCommitInfo *types.UnicitySeal
	HighQc           *drctypes.QuorumCert
	Author           string
	Signature        hex.Bytes
	Anchor           *drctypes.EpochAnchor
}

func (x *VoteMsg) MarshalCBOR() ([]byte, error) {
	if x.Envelope == votesig.EnvelopeUTB {
		inner := *x
		inner.Envelope, inner.UTB = 0, nil
		ib, err := inner.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		return types.Cbor.Marshal(voteV3Wire{Version: votesig.EnvelopeUTB, Inner: ib, UTB: x.UTB})
	}
	if x.UTB != nil || x.Envelope != 0 {
		return nil, fmt.Errorf("%w: envelope %d", votesig.ErrEnvelope, x.Envelope)
	}
	if x.Scheme == votesig.SchemeDomainBound {
		if x.VoteInfo == nil {
			return nil, fmt.Errorf("%w: scheme 2 vote has no vote info", votesig.ErrStatement)
		}
		return types.Cbor.Marshal(voteV2Wire{Scheme: x.Scheme, Payload: voteV2Payload{
			VoteInfo:         voteInfoV2Wire{Epoch: x.VoteInfo.Epoch, Round: x.VoteInfo.RoundNumber, Parent: x.VoteInfo.ParentRoundNumber, Exec: x.VoteInfo.CurrentRootHash, Timestamp: x.VoteInfo.Timestamp},
			LedgerCommitInfo: x.LedgerCommitInfo, HighQc: x.HighQc, Author: x.Author, VoteSignature: x.Signature,
			SealSignature: x.SealSignature, Anchor: x.Anchor}})
	}
	if x.Anchor != nil {
		return types.Cbor.Marshal(voteAnchorWire{VoteInfo: x.VoteInfo, LedgerCommitInfo: x.LedgerCommitInfo,
			HighQc: x.HighQc, Author: x.Author, Signature: x.Signature, Anchor: x.Anchor})
	}
	return types.Cbor.Marshal(voteLegacyWire{VoteInfo: x.VoteInfo, LedgerCommitInfo: x.LedgerCommitInfo,
		HighQc: x.HighQc, Author: x.Author, Signature: x.Signature})
}

func (x *VoteMsg) UnmarshalCBOR(data []byte) error {
	if votesig.PeekEnvelopeUTB(data) {
		var w voteV3Wire
		if err := types.Cbor.Unmarshal(data, &w); err != nil {
			return err
		}
		if w.Version != votesig.EnvelopeUTB || votesig.PeekEnvelopeUTB(w.Inner) {
			return votesig.ErrEnvelope
		}
		var inner VoteMsg
		if err := inner.UnmarshalCBOR(w.Inner); err != nil {
			return err
		}
		inner.Envelope, inner.UTB = votesig.EnvelopeUTB, w.UTB
		*x = inner
		return nil
	}
	wrapped, err := votesig.PeekWrapper(data)
	if err != nil {
		return err
	}
	if wrapped {
		var w voteV2Wire
		if err := types.Cbor.Unmarshal(data, &w); err != nil {
			return err
		}
		p := w.Payload
		// The vote info is carried in the legacy in-memory shape so that the handlers in front of Verify can read its round;
		// historical votes omit time and use the scheme 2 rules, never RoundInfo.IsValid.
		*x = VoteMsg{Scheme: votesig.SchemeDomainBound, LedgerCommitInfo: p.LedgerCommitInfo, HighQc: p.HighQc, Anchor: p.Anchor,
			Author: p.Author, Signature: p.VoteSignature, SealSignature: p.SealSignature,
			VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: p.VoteInfo.Round, Epoch: p.VoteInfo.Epoch,
				ParentRoundNumber: p.VoteInfo.Parent, CurrentRootHash: p.VoteInfo.Exec, Timestamp: p.VoteInfo.Timestamp}}
		return nil
	}
	var anchor voteAnchorWire
	if err := types.Cbor.Unmarshal(data, &anchor); err == nil {
		*x = VoteMsg{VoteInfo: anchor.VoteInfo, LedgerCommitInfo: anchor.LedgerCommitInfo,
			HighQc: anchor.HighQc, Author: anchor.Author, Signature: anchor.Signature, Anchor: anchor.Anchor}
		return nil
	}
	var legacy voteLegacyWire
	if err := types.Cbor.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*x = VoteMsg{VoteInfo: legacy.VoteInfo, LedgerCommitInfo: legacy.LedgerCommitInfo,
		HighQc: legacy.HighQc, Author: legacy.Author, Signature: legacy.Signature}
	return nil
}

func (x *VoteMsg) Sign(signer crypto.Signer) error {
	if signer == nil {
		return errSignerIsNil
	}
	// sanity check, make sure commit info round info hash is set
	if len(x.LedgerCommitInfo.PreviousHash) < 1 {
		return fmt.Errorf("invalid round info hash")
	}
	bs, err := x.LedgerCommitInfo.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal unicity seal: %w", err)
	}
	signature, err := signer.SignBytes(bs)
	if err != nil {
		return fmt.Errorf("failed to sign vote: %w", err)
	}
	x.Signature = signature
	return nil
}

// signingScheme is the scheme of the wire form.
func (x *VoteMsg) signingScheme() uint64 {
	if x.Scheme == votesig.SchemeDomainBound {
		return votesig.SchemeDomainBound
	}
	return votesig.SchemeLegacy
}

// domainBoundStatement derives the signed statement of a scheme 2 vote from its fields: the vote info, the commit side, the
// preimage PV and, for a committing vote, the native seal bytes the second signature covers. The vote info hash must be the
// one the commit info carries, so that the two halves are one statement.
func (x *VoteMsg) domainBoundStatement(cfg votesig.Config) (pv, sealBytes []byte, committing bool, err error) {
	return drctypes.DomainBoundStatement(cfg, x.VoteInfo, x.LedgerCommitInfo, len(x.SealSignature) != 0)
}

// SignDomainBound signs a scheme 2 vote: the preimage PV, and for a committing vote also the native seal bytes, both with
// the same key. The commit info must already carry the scheme 2 vote info hash. It marks the message as scheme 2.
func (x *VoteMsg) SignDomainBound(signer crypto.Signer, cfg votesig.Config) error {
	if signer == nil {
		return errSignerIsNil
	}
	if x.VoteInfo == nil || x.LedgerCommitInfo == nil {
		return fmt.Errorf("%w: vote info or commit info is missing", votesig.ErrStatement)
	}
	pv, sealBytes, committing, err := x.domainBoundStatement(cfg)
	if err != nil {
		return err
	}
	sig, err := signer.SignBytes(pv)
	if err != nil {
		return fmt.Errorf("failed to sign vote: %w", err)
	}
	var sealSig []byte
	if committing {
		if sealSig, err = signer.SignBytes(sealBytes); err != nil {
			return fmt.Errorf("failed to sign unicity seal: %w", err)
		}
	}
	x.Signature, x.SealSignature, x.Scheme = sig, sealSig, votesig.SchemeDomainBound
	return nil
}

// verifyContext checks what a vote carries besides its own signature: the anchor or the high QC. The high QC is verified by the
// rule of its own epoch, and a certificate of the other scheme is refused rather than reinterpreted.
func (x *VoteMsg) verifyContext(tbs *trustbase.TrustBaseStore) error {
	if x.Anchor != nil {
		if x.HighQc != nil || x.Anchor.IsValid() != nil || x.VoteInfo.Epoch != x.Anchor.Epoch || x.VoteInfo.ParentRoundNumber != x.Anchor.Slot {
			return drctypes.ErrEpochAnchor
		}
	} else if x.HighQc == nil {
		return fmt.Errorf("vote from '%s' high QC is nil", x.Author)
	}
	if x.HighQc != nil && x.HighQc.VoteInfo == nil {
		return fmt.Errorf("vote from '%s' high QC is missing vote info", x.Author)
	}
	if x.HighQc != nil {
		if _, err := tbs.GetByEpoch(x.HighQc.VoteInfo.Epoch); err != nil {
			return fmt.Errorf("failed to get trust base for high QC verification epoch %d: %w", x.HighQc.VoteInfo.Epoch, err)
		}
		// the high QC is verified by the rule of its own epoch, in the wire form that epoch signs with
		if err := x.HighQc.VerifyWith(tbs); err != nil {
			return fmt.Errorf("vote from '%s' high QC error: %w", x.Author, err)
		}
	}
	return nil
}

// Verify checks the vote by its epoch's rule: the envelope the epoch's configuration requires, the signatures of the scheme the epoch signs with and,
// when the vote carries one, the trust-base endorsement.
func (x *VoteMsg) Verify(tbs *trustbase.TrustBaseStore) error {
	if x.VoteInfo != nil {
		cfg, err := tbs.SigningConfig(x.VoteInfo.Epoch)
		switch {
		case err == nil:
			if cfg.UTB != (x.Envelope == votesig.EnvelopeUTB) {
				return fmt.Errorf("%w: vote from '%s' envelope %d, epoch %d UTB=%v", votesig.ErrEnvelope, x.Author, x.Envelope, x.VoteInfo.Epoch, cfg.UTB)
			}
		case x.Envelope == votesig.EnvelopeUTB:
			// the envelope is chosen by the epoch's authenticated configuration only: without it a version 3 vote is not accepted on the
			// strength of whatever the signature checks that follow make of it
			return fmt.Errorf("%w: vote from '%s': no signing configuration for epoch %d: %w", votesig.ErrEnvelope, x.Author, x.VoteInfo.Epoch, err)
		}
	}
	if err := x.verifySignatures(tbs); err != nil {
		return err
	}
	return x.verifyUTB(tbs)
}

// verifyUTB checks the endorsement a vote carries: a committing vote of the epoch before the entry's, for the configured network, signed by the
// voter over exactly the unsigned entry bytes. That the entry is the one the committed state implies is checked where the executed block is known.
func (x *VoteMsg) verifyUTB(tbs *trustbase.TrustBaseStore) error {
	if x.UTB == nil {
		return nil
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: vote from '%s': "+format, append([]any{votesig.ErrUTB, x.Author}, a...)...)
	}
	cfg, err := tbs.SigningConfig(x.VoteInfo.Epoch)
	if err != nil {
		return err
	}
	if !cfg.UTB || x.Envelope != votesig.EnvelopeUTB {
		return bad("outside a UTB epoch")
	}
	if x.LedgerCommitInfo.RootChainRoundNumber == 0 { // the one committing predicate: a commit round
		return bad("a non-committing vote carries one")
	}
	entry, err := utbentry.Decode(x.UTB.Unsigned)
	if err != nil {
		return bad("%v", err)
	}
	if entry.Epoch != x.VoteInfo.Epoch+1 || uint64(entry.NetworkID) != cfg.Network {
		return bad("entry epoch %d network %d, vote epoch %d network %d", entry.Epoch, entry.NetworkID, x.VoteInfo.Epoch, cfg.Network)
	}
	if err := votesig.CheckSignatureShape(x.UTB.Signature); err != nil {
		return bad("%v", err)
	}
	tb, err := tbs.GetByEpoch(x.VoteInfo.Epoch)
	if err != nil {
		return err
	}
	if _, err := tb.VerifySignature(x.UTB.Unsigned, x.UTB.Signature, x.Author); err != nil {
		return bad("signature: %v", votesig.BadSignature(err))
	}
	return nil
}

func (x *VoteMsg) verifySignatures(tbs *trustbase.TrustBaseStore) error {
	if x.Author == "" {
		return fmt.Errorf("author is missing")
	}
	if x.VoteInfo == nil {
		return fmt.Errorf("vote from '%s' is missing vote info", x.Author)
	}
	if x.LedgerCommitInfo == nil {
		return fmt.Errorf("vote from '%s' ledger commit info (unicity seal) is missing", x.Author)
	}
	// The wire form must be the scheme the vote's epoch signs with: a legacy vote is never accepted in a domain-bound
	// epoch, a domain-bound one never before it, and neither is reinterpreted as the other.
	cfg, cfgErr := tbs.SigningConfig(x.VoteInfo.Epoch)
	if x.signingScheme() == votesig.SchemeDomainBound {
		if cfgErr != nil {
			return cfgErr
		}
		if cfg.Scheme != votesig.SchemeDomainBound {
			return fmt.Errorf("%w: vote is scheme 2, epoch %d requires scheme %d", votesig.ErrScheme, x.VoteInfo.Epoch, cfg.Scheme)
		}
		return x.verifyDomainBound(tbs, cfg)
	}
	if cfgErr == nil && cfg.Scheme != votesig.SchemeLegacy {
		return fmt.Errorf("%w: vote is scheme 1, epoch %d requires scheme %d", votesig.ErrScheme, x.VoteInfo.Epoch, cfg.Scheme)
	}
	if err := x.VoteInfo.IsValid(); err != nil {
		return fmt.Errorf("vote from '%s' vote info error: %w", x.Author, err)
	}
	// Verify hash of vote info
	hash, err := x.VoteInfo.Hash(gocrypto.SHA256)
	if err != nil {
		return fmt.Errorf("vote from '%s' vote info hash error: %w", x.Author, err)
	}
	if !bytes.Equal(hash, x.LedgerCommitInfo.PreviousHash) {
		return fmt.Errorf("vote from '%s' vote info hash does not match hash in commit info", x.Author)
	}
	if err := x.verifyContext(tbs); err != nil {
		return err
	}
	bs, err := x.LedgerCommitInfo.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal unicity seal: %w", err)
	}
	voteTrustBase, err := tbs.GetByEpoch(x.VoteInfo.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for vote verification, epoch %d: %w", x.VoteInfo.Epoch, err)
	}
	if _, err := voteTrustBase.VerifySignature(bs, x.Signature, x.Author); err != nil {
		return fmt.Errorf("vote from '%s' signature verification error: %w", x.Author, votesig.BadSignature(err))
	}
	return nil
}

func (x *VoteMsg) verifyDomainBound(tbs *trustbase.TrustBaseStore, cfg votesig.Config) error {
	pv, sealBytes, committing, err := x.checkedStatement(cfg)
	if err != nil {
		return err
	}
	if err := x.verifyContext(tbs); err != nil {
		return err
	}
	_, err = x.verifyStatementSignatures(tbs, pv, sealBytes, committing)
	return err
}

// checkedStatement derives the signed statement of a scheme 2 vote and checks the shape of its signatures.
func (x *VoteMsg) checkedStatement(cfg votesig.Config) (pv, sealBytes []byte, committing bool, err error) {
	pv, sealBytes, committing, err = x.domainBoundStatement(cfg)
	if err != nil {
		return nil, nil, false, fmt.Errorf("vote from '%s': %w", x.Author, err)
	}
	if err := votesig.CheckSignatureShape(x.Signature); err != nil {
		return nil, nil, false, fmt.Errorf("vote from '%s' vote signature: %w", x.Author, err)
	}
	if committing {
		if err := votesig.CheckSignatureShape(x.SealSignature); err != nil {
			return nil, nil, false, fmt.Errorf("vote from '%s' seal signature: %w", x.Author, err)
		}
	}
	return pv, sealBytes, committing, nil
}

// verifyStatementSignatures verifies the vote signature over PV and, for a committing vote, the seal signature, with the voter's key of the
// vote's epoch. It returns that key.
func (x *VoteMsg) verifyStatementSignatures(tbs *trustbase.TrustBaseStore, pv, sealBytes []byte, committing bool) ([]byte, error) {
	voteTrustBase, err := tbs.GetByEpoch(x.VoteInfo.Epoch)
	if err != nil {
		return nil, fmt.Errorf("failed to get trust base for vote verification, epoch %d: %w", x.VoteInfo.Epoch, err)
	}
	if _, err := voteTrustBase.VerifySignature(pv, x.Signature, x.Author); err != nil {
		return nil, fmt.Errorf("vote from '%s' vote signature verification error: %w", x.Author, votesig.BadSignature(err))
	}
	if committing {
		if _, err := voteTrustBase.VerifySignature(sealBytes, x.SealSignature, x.Author); err != nil {
			return nil, fmt.Errorf("vote from '%s' seal signature verification error: %w", x.Author, votesig.BadSignature(err))
		}
	}
	for _, n := range voteTrustBase.GetRootNodes() {
		if n.NodeID == x.Author {
			return bytes.Clone(n.SigKey), nil
		}
	}
	return nil, fmt.Errorf("vote from '%s': no key in the trust base of epoch %d", x.Author, x.VoteInfo.Epoch)
}

// SignedStatement is a scheme 2 vote statement whose signatures were verified: the exact preimage the vote signature covers, for a committing
// vote the native seal bytes the second signature covers, and the voter's key of the vote's epoch.
type SignedStatement struct {
	PV, SealBytes []byte
	Committing    bool
	Key           []byte
}

// VerifyStatement verifies the signed statement of a scheme 2 vote and nothing else: not the high QC or the anchor it carries, not the
// round it was received in, not the envelope. The signatures are over the statement alone, so a vote whose transport context is stale or
// unverifiable still is evidence when its signatures are genuine. It does not admit the vote to anything.
func (x *VoteMsg) VerifyStatement(tbs *trustbase.TrustBaseStore) (*SignedStatement, error) {
	if x.Author == "" || x.VoteInfo == nil || x.LedgerCommitInfo == nil {
		return nil, fmt.Errorf("%w: author, vote info or commit info is missing", votesig.ErrStatement)
	}
	if x.signingScheme() != votesig.SchemeDomainBound {
		return nil, fmt.Errorf("%w: vote is not scheme 2", votesig.ErrScheme)
	}
	cfg, err := tbs.SigningConfig(x.VoteInfo.Epoch)
	if err != nil {
		return nil, err
	}
	if cfg.Scheme != votesig.SchemeDomainBound {
		return nil, fmt.Errorf("%w: epoch %d requires scheme %d", votesig.ErrScheme, x.VoteInfo.Epoch, cfg.Scheme)
	}
	pv, sealBytes, committing, err := x.checkedStatement(cfg)
	if err != nil {
		return nil, err
	}
	key, err := x.verifyStatementSignatures(tbs, pv, sealBytes, committing)
	if err != nil {
		return nil, err
	}
	return &SignedStatement{PV: pv, SealBytes: sealBytes, Committing: committing, Key: key}, nil
}

// SignUTB endorses the unsigned successor entry with the voter's key and puts the vote in the version 3 envelope. It does not touch the vote's own
// signatures, which are over their own statements.
func (x *VoteMsg) SignUTB(signer crypto.Signer, unsigned []byte) error {
	if signer == nil {
		return errSignerIsNil
	}
	sig, err := signer.SignBytes(unsigned)
	if err != nil {
		return fmt.Errorf("failed to sign the trust-base entry: %w", err)
	}
	x.Envelope, x.UTB = votesig.EnvelopeUTB, &drctypes.UTBVote{Unsigned: bytes.Clone(unsigned), Signature: sig}
	return nil
}
