package abdrc

import (
	"bytes"
	gocrypto "crypto"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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

func (x *VoteMsg) Verify(tbs *trustbase.TrustBaseStore) error {
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
	pv, sealBytes, committing, err := x.domainBoundStatement(cfg)
	if err != nil {
		return fmt.Errorf("vote from '%s': %w", x.Author, err)
	}
	if err := votesig.CheckSignatureShape(x.Signature); err != nil {
		return fmt.Errorf("vote from '%s' vote signature: %w", x.Author, err)
	}
	if committing {
		if err := votesig.CheckSignatureShape(x.SealSignature); err != nil {
			return fmt.Errorf("vote from '%s' seal signature: %w", x.Author, err)
		}
	}
	if err := x.verifyContext(tbs); err != nil {
		return err
	}
	voteTrustBase, err := tbs.GetByEpoch(x.VoteInfo.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for vote verification, epoch %d: %w", x.VoteInfo.Epoch, err)
	}
	if _, err := voteTrustBase.VerifySignature(pv, x.Signature, x.Author); err != nil {
		return fmt.Errorf("vote from '%s' vote signature verification error: %w", x.Author, votesig.BadSignature(err))
	}
	if committing {
		if _, err := voteTrustBase.VerifySignature(sealBytes, x.SealSignature, x.Author); err != nil {
			return fmt.Errorf("vote from '%s' seal signature verification error: %w", x.Author, votesig.BadSignature(err))
		}
	}
	return nil
}
