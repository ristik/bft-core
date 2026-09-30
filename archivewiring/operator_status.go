package archivewiring

import (
	"context"
	"errors"
	"fmt"
	"math"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-go-base/types"
)

type JournalUsage struct {
	CandidatesUsed   int   `json:"candidatesUsed"`
	CandidatesCap    int   `json:"candidatesCap"`
	ObservationsUsed int   `json:"observationsUsed"`
	ObservationsCap  int   `json:"observationsCap"`
	BytesUsed        int64 `json:"bytesUsed"`
	BytesCap         int64 `json:"bytesCap"`
}

type BlockPin struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	StateRoot string `json:"stateRoot,omitempty"`
	RootEpoch uint64 `json:"rootEpoch,omitempty"`
	RootRound uint64 `json:"rootRound,omitempty"`
}

type ReplicaReport struct {
	Replica                string `json:"replica"`
	LastAcknowledgedHeight uint64 `json:"lastAcknowledgedHeight"`
	Error                  string `json:"error,omitempty"`
}

type AuthorityReport struct {
	RootEpoch     uint64 `json:"rootEpoch"`
	ShardEpoch    uint64 `json:"shardEpoch"`
	ReservedRound uint64 `json:"reservedRound"`
	Reachable     bool   `json:"reachable"`
	Error         string `json:"error,omitempty"`
}

type OperatorStatus struct {
	CurrentRootEpoch  uint64           `json:"currentRootEpoch"`
	ActivatedHandoffs []uint64         `json:"activatedHandoffs"`
	Journal           JournalUsage     `json:"journal"`
	CertifiedTip      *BlockPin        `json:"certifiedTip,omitempty"`
	PruneFrontier     *BlockPin        `json:"pruneFrontier,omitempty"`
	RestoreBase       *BlockPin        `json:"restoreBase,omitempty"`
	LatestLocalV2     *BlockPin        `json:"latestLocalV2Archive,omitempty"`
	Replicas          []ReplicaReport  `json:"replicas"`
	Authority         *AuthorityReport `json:"authority,omitempty"`
}

// ReadOperatorStatus uses the node's existing authenticated journal and archive
// readers. Replica heights come from durable frontier acknowledgements; errors
// are the publisher's latest process-local transfer diagnostics.
func ReadOperatorStatus(ctx context.Context, journal *configuredprogress.Store, journalContext configuredprogress.Context,
	limits configuredprogress.JournalLimits, local *archive.Store, subject archive.Context,
	replicas [2]peer.ID, currentRootEpoch uint64, activated []uint64,
	progress [2]ReplicaProgress, authority *AuthorityReport) (OperatorStatus, error) {
	var out OperatorStatus
	if journal == nil {
		return out, configuredprogress.ErrSettings
	}
	image, err := journal.LoadJournal(ctx, journalContext, limits)
	if err != nil {
		return out, fmt.Errorf("loading verified journal status: %w", err)
	}
	out.CurrentRootEpoch = currentRootEpoch
	out.ActivatedHandoffs = append([]uint64(nil), activated...)
	out.Journal = JournalUsage{CandidatesUsed: len(image.Candidates), CandidatesCap: limits.Candidates,
		ObservationsUsed: len(image.Observations), ObservationsCap: limits.Observations,
		BytesUsed: image.Bytes, BytesCap: limits.Bytes}
	if image.Frontier != nil && image.Frontier.Anchor != nil {
		a := image.Frontier.Anchor
		out.PruneFrontier = &BlockPin{Height: a.Height, Hash: fmt.Sprintf("0x%x", a.Subject.BlockHash),
			StateRoot: fmt.Sprintf("0x%x", a.StateRoot), RootEpoch: a.Epoch, RootRound: a.Round}
		out.CertifiedTip = cloneHigherPin(out.CertifiedTip, out.PruneFrontier)
	}
	if image.RestoreBase != nil {
		a := image.RestoreBase
		out.RestoreBase = &BlockPin{Height: a.Height, Hash: fmt.Sprintf("0x%x", a.Hash), StateRoot: fmt.Sprintf("0x%x", a.StateRoot), RootRound: a.RootRound}
		out.CertifiedTip = cloneHigherPin(out.CertifiedTip, out.RestoreBase)
	}
	for _, entry := range image.Candidates {
		if !entry.Certified || entry.ResultingUC == nil || len(entry.Candidate.Hash) != 32 || len(entry.Candidate.StateRoot) != 32 {
			continue
		}
		pin := &BlockPin{Height: entry.Candidate.Number, Hash: fmt.Sprintf("0x%x", entry.Candidate.Hash),
			StateRoot: fmt.Sprintf("0x%x", entry.Candidate.StateRoot), RootEpoch: entry.ResultingUC.GetRootEpoch(),
			RootRound: entry.ResultingUC.GetRootRoundNumber()}
		out.CertifiedTip = cloneHigherPin(out.CertifiedTip, pin)
	}
	if local != nil {
		q, rec, latestErr := local.GetLatestReceiptComplete(archive.RoundRequest{Context: subject, Round: math.MaxUint64})
		if latestErr == nil {
			var header gethtypes.Header
			var uc types.UnicityCertificate
			if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil || types.Cbor.Unmarshal(rec.ResultingUC, &uc) != nil ||
				uc.InputRecord == nil || len(uc.InputRecord.BlockHash) != 32 || fmt.Sprintf("0x%x", q.BlockHash) != fmt.Sprintf("0x%x", uc.InputRecord.BlockHash) {
				return out, archive.ErrCorrupt
			}
			out.LatestLocalV2 = &BlockPin{Height: header.Number.Uint64(), Hash: fmt.Sprintf("0x%x", q.BlockHash),
				StateRoot: fmt.Sprintf("0x%x", header.Root), RootEpoch: uc.GetRootEpoch(), RootRound: uc.GetRoundNumber()}
			out.CertifiedTip = cloneHigherPin(out.CertifiedTip, out.LatestLocalV2)
		} else if !errors.Is(latestErr, archive.ErrUnavailable) {
			return out, fmt.Errorf("reading latest local receipt-complete archive record: %w", latestErr)
		}
	}
	out.Replicas = make([]ReplicaReport, 0, len(replicas))
	for i, id := range replicas {
		if id == "" {
			continue
		}
		name := id.String()
		report := ReplicaReport{Replica: name}
		if i < len(progress) {
			report.LastAcknowledgedHeight = progress[i].LastAcknowledgedHeight
			report.Error = progress[i].Error
		}
		if report.Replica == "" && i < len(progress) {
			report.Replica = progress[i].Replica
		}
		if image.Frontier != nil && image.Frontier.Anchor != nil {
			for _, ack := range image.Frontier.Anchor.Acks {
				if ack.Replica == report.Replica && image.Frontier.Anchor.Height > report.LastAcknowledgedHeight {
					report.LastAcknowledgedHeight = image.Frontier.Anchor.Height
				}
			}
		}
		if report.LastAcknowledgedHeight == 0 && report.Error == "" {
			report.Error = "no durable acknowledgement observed"
		}
		out.Replicas = append(out.Replicas, report)
	}
	if authority != nil {
		copy := *authority
		out.Authority = &copy
	}
	return out, nil
}

func cloneHigherPin(current, candidate *BlockPin) *BlockPin {
	if candidate == nil || (current != nil && current.Height >= candidate.Height) {
		return current
	}
	copy := *candidate
	return &copy
}
