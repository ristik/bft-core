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
)

type VoteMsg struct {
	_                struct{}              `cbor:",toarray"`
	VoteInfo         *drctypes.RoundInfo   `json:"voteInfo"`         // Proposed block hash and resulting state hash
	LedgerCommitInfo *types.UnicitySeal    `json:"ledgerCommitInfo"` // Commit info
	HighQc           *drctypes.QuorumCert  `json:"highQc"`           // Sync with highest QC
	Anchor           *drctypes.EpochAnchor `json:"anchor,omitempty"`
	Author           string                `json:"author"`    // Voter node identifier
	Signature        hex.Bytes             `json:"signature"` // Vote signature on hash of consensus info
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
	if x.Anchor != nil {
		return types.Cbor.Marshal(voteAnchorWire{VoteInfo: x.VoteInfo, LedgerCommitInfo: x.LedgerCommitInfo,
			HighQc: x.HighQc, Author: x.Author, Signature: x.Signature, Anchor: x.Anchor})
	}
	return types.Cbor.Marshal(voteLegacyWire{VoteInfo: x.VoteInfo, LedgerCommitInfo: x.LedgerCommitInfo,
		HighQc: x.HighQc, Author: x.Author, Signature: x.Signature})
}

func (x *VoteMsg) UnmarshalCBOR(data []byte) error {
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

func (x *VoteMsg) Verify(tbs *trustbase.TrustBaseStore) error {
	if x.Author == "" {
		return fmt.Errorf("author is missing")
	}
	if x.VoteInfo == nil {
		return fmt.Errorf("vote from '%s' is missing vote info", x.Author)
	}
	if err := x.VoteInfo.IsValid(); err != nil {
		return fmt.Errorf("vote from '%s' vote info error: %w", x.Author, err)
	}
	if x.LedgerCommitInfo == nil {
		return fmt.Errorf("vote from '%s' ledger commit info (unicity seal) is missing", x.Author)
	}
	// Verify hash of vote info
	hash, err := x.VoteInfo.Hash(gocrypto.SHA256)
	if err != nil {
		return fmt.Errorf("vote from '%s' vote info hash error: %w", x.Author, err)
	}
	if !bytes.Equal(hash, x.LedgerCommitInfo.PreviousHash) {
		return fmt.Errorf("vote from '%s' vote info hash does not match hash in commit info", x.Author)
	}
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
		highQcTrustBase, err := tbs.GetByEpoch(x.HighQc.VoteInfo.Epoch)
		if err != nil {
			return fmt.Errorf("failed to get trust base for high QC verification epoch %d: %w", x.HighQc.VoteInfo.Epoch, err)
		}
		if err := x.HighQc.Verify(highQcTrustBase, tbs.GenesisPin()); err != nil {
			return fmt.Errorf("vote from '%s' high QC error: %w", x.Author, err)
		}
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
		return fmt.Errorf("vote from '%s' signature verification error: %w", x.Author, err)
	}
	return nil
}
