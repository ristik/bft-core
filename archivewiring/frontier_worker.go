package archivewiring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// FrontierWorker advances only over contiguous, certified journal entries.
// Publication and certification have their own independent loops.
type FrontierWorker struct {
	Journal         *configuredprogress.Store
	Context         configuredprogress.Context
	Limits          configuredprogress.JournalLimits
	Archive         *archive.Store
	Subject         archive.Context
	Replicas        [2]peer.ID
	Host            shardnode.EvidenceHost
	TransportLimits Limits
	Log             *slog.Logger
	auditCursor     uint64
}

func (w *FrontierWorker) Run(ctx context.Context) error {
	if w.Log == nil {
		w.Log = slog.New(slog.DiscardHandler)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := w.Pass(ctx); err != nil && ctx.Err() == nil {
			w.Log.WarnContext(ctx, "certified frontier waiting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *FrontierWorker) Pass(ctx context.Context) error {
	if w.Journal == nil || w.Archive == nil || w.Replicas[0] == "" || w.Replicas[1] == "" || w.Replicas[0] == w.Replicas[1] {
		return ErrConfig
	}
	if err := w.audit(ctx); err != nil {
		return err
	}
	if err := w.Journal.VerifyFrontierCopies(ctx, w.Context, w.Limits); err != nil {
		return err
	}
	// A crash after the frontier commit but before prune leaves this work for
	// the next pass. Prune itself is idempotent.
	if f, err := w.Journal.LoadFrontier(ctx, w.Context, w.Limits); err != nil {
		return err
	} else if f.Anchor != nil && f.Floor < f.Anchor.Height {
		if err := w.Journal.PruneFrontier(ctx, w.Context, w.Limits); err != nil {
			return err
		}
	}
	image, err := w.Journal.LoadJournal(ctx, w.Context, w.Limits)
	if err != nil {
		return err
	}
	height, sequence, round := uint64(0), uint64(0), uint64(0)
	if image.Frontier != nil && image.Frontier.Anchor != nil {
		height, sequence, round = image.Frontier.Anchor.Height, image.Frontier.Anchor.Sequence, image.Frontier.Anchor.Round
	} else if image.Restored != nil {
		height, round = image.Restored.Height, image.Restored.RootRound
	}
	var covered []frontier.Coverage
	for _, entry := range certifiedEntries(image) {
		if entry.Candidate.Number <= height {
			continue
		}
		if entry.Candidate.Number != height+1 || entry.ResultingUC.GetRootRoundNumber() <= round {
			break
		}
		var hash, state [32]byte
		copy(hash[:], entry.Candidate.Hash)
		copy(state[:], entry.Candidate.StateRoot)
		q := archive.Request{Context: w.Subject, BlockHash: hash}
		rec, err := w.Archive.Get(q)
		if err != nil {
			if errors.Is(err, archive.ErrUnavailable) {
				break
			}
			return err
		}
		_, expected, err := FromJournal(ctx, w.Context, w.Subject, nil, entry)
		if err != nil {
			return err
		}
		digest, err := archive.ManifestDigest(q, rec)
		if err != nil {
			return err
		}
		want, err := archive.ManifestDigest(q, expected)
		if err != nil || digest != want {
			return ErrBinding
		}
		request, err := archive.EncodeRequest(q)
		if err != nil {
			return err
		}
		ack := sha256.Sum256(request)
		sequence++
		covered = append(covered, frontier.Coverage{Anchor: frontier.Record{Sequence: sequence, Height: entry.Candidate.Number, Round: entry.ResultingUC.GetRootRoundNumber(), StateRoot: state, Subject: q, Acks: [2]frontier.Acknowledgment{{Replica: w.Replicas[0].String(), RequestDigest: ack, ManifestDigest: digest}, {Replica: w.Replicas[1].String(), RequestDigest: ack, ManifestDigest: digest}}}, Material: rec})
		height, round = entry.Candidate.Number, entry.ResultingUC.GetRootRoundNumber()
		if len(covered) == 4 {
			break
		}
	}
	if len(covered) == 0 {
		return nil
	}
	if err := w.Journal.AdvanceFrontier(ctx, w.Context, w.Limits, covered); err != nil {
		return fmt.Errorf("frontier advance: %w", err)
	}
	return w.Journal.PruneFrontier(ctx, w.Context, w.Limits)
}

// One bounded page per pass audits every committed promise within minutes at
// the default cadence. A surviving verified copy repairs a missing local or
// replica copy before further frontier advancement.
func (w *FrontierWorker) audit(ctx context.Context) error {
	if w.Host == nil {
		return nil
	} // tests inject the journal's availability adapter
	current, err := w.Journal.LoadFrontier(ctx, w.Context, w.Limits)
	if err != nil {
		return err
	}
	if current.Anchor == nil {
		return nil
	}
	// At a two-second cadence there are 43,200 passes per day. Scale the
	// bounded page count with promised history so a full sweep stays within
	// that interval as the chain grows.
	quota := int((current.Anchor.Height + 43199) / 43200)
	if quota < 4 {
		quota = 4
	}
	availability := ReplicaAvailability{Context: ctx, Host: w.Host, Replicas: w.Replicas, Limits: w.TransportLimits}
	binding := CertifiedBinding{Context: w.Context, Subject: w.Subject}
	for quota > 0 {
		pageLimit := quota
		if pageLimit > 64 {
			pageLimit = 64
		}
		page, err := w.Journal.LoadCoverage(ctx, w.Context, w.Limits, w.auditCursor, pageLimit)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			w.auditCursor = 0
			return nil
		}
		for _, r := range page {
			rec, err := w.Archive.Get(r.Subject)
			if err != nil {
				verified := false
				for _, id := range w.Replicas {
					rec, err = readReplica(ctx, w.Host, id, r.Subject, r.Acks[0].ManifestDigest, w.TransportLimits)
					if err == nil && binding.VerifyCertified(r, rec) == nil {
						verified = true
						break
					}
				}
				if !verified {
					return frontier.ErrUnavailable
				}
				if err := w.Archive.Put(r.Subject, rec); err != nil {
					return err
				}
			}
			digest, err := archive.ManifestDigest(r.Subject, rec)
			if err != nil || digest != r.Acks[0].ManifestDigest || binding.VerifyCertified(r, rec) != nil {
				return frontier.ErrInvalid
			}
			for _, ack := range r.Acks {
				if availability.VerifyAvailable(ack.Replica, r.Subject, ack.ManifestDigest) == nil {
					continue
				}
				var id peer.ID
				for _, configured := range w.Replicas {
					if configured.String() == ack.Replica {
						id = configured
						break
					}
				}
				if id == "" || PutAndReadBack(ctx, w.Host, id, r.Subject, rec, w.TransportLimits) != nil {
					return frontier.ErrUnavailable
				}
			}
			w.auditCursor = r.Height
		}
		quota -= len(page)
	}
	return nil
}

func readReplica(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.Request, want [32]byte, limits Limits) (*archive.Record, error) {
	request, err := archive.EncodeRequest(q)
	if err != nil {
		return nil, err
	}
	answer, err := exchange(ctx, host, id, append([]byte{2}, request...), limits)
	if err != nil {
		return nil, err
	}
	response, err := archive.DecodeFor(q, answer)
	if err != nil || response.Outcome != archive.OK || response.Record == nil {
		return nil, frontier.ErrUnavailable
	}
	digest, err := archive.ManifestDigest(q, response.Record)
	if err != nil || digest != want {
		return nil, frontier.ErrUnavailable
	}
	return response.Record, nil
}
