package configuredadmission

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// JournalProvider serves only certified entries from the locally reverified
// full-history journal. A candidate without a resulting UC is never served.
type JournalProvider struct {
	Store   *configuredprogress.Store
	Context configuredprogress.Context
	Limits  configuredprogress.JournalLimits
}

func (p JournalProvider) FetchJournal(ctx context.Context, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
	if p.Store == nil {
		return nil, fmt.Errorf("journal provider: no store")
	}
	image, err := p.Store.LoadJournal(ctx, p.Context, p.Limits)
	if err != nil {
		return nil, fmt.Errorf("journal provider: verifying store: %w", err)
	}
	entries := make(map[string]configuredprogress.JournalEntry)
	target := req.TargetHash
	if len(target) == 0 {
		for i, o := range image.Observations {
			identity, e := o.UC.InputRecord.Bytes()
			if e != nil {
				return nil, e
			}
			if o.UC.GetRoundNumber() != req.HeldRound || !bytes.Equal(identity, req.HeldIdentity) {
				continue
			}
			if len(o.TargetHash) != 0 {
				return nil, fmt.Errorf("journal provider: held identity is not quiet")
			}
			for j := i - 1; j >= 0; j-- {
				if len(image.Observations[j].TargetHash) == 32 {
					target = image.Observations[j].TargetHash
					break
				}
			}
			break
		}
	}
	if len(target) != 32 {
		return nil, fmt.Errorf("journal provider: no certified source for held quiet interval")
	}
	for _, e := range image.Candidates {
		if e.Certified {
			entries[string(e.Candidate.Hash)] = e
		}
	}
	var reverse []shardnode.JournalFetchEntry
	hash := target
	var total int64
	for !bytes.Equal(hash, req.AfterHash) {
		if len(reverse) >= 256 {
			return nil, fmt.Errorf("journal provider: suffix exceeds 256 blocks")
		}
		e, ok := entries[string(hash)]
		if !ok {
			return nil, fmt.Errorf("journal provider: missing certified entry %x", hash)
		}
		b := e.Candidate
		total += int64(len(b.Raw))
		if total > 64<<20 {
			return nil, fmt.Errorf("journal provider: suffix exceeds 64 MiB")
		}
		reverse = append(reverse, shardnode.JournalFetchEntry{
			Block:       shardnode.Block{Number: b.Number, Hash: b.Hash, ParentHash: b.ParentHash, StateRoot: b.StateRoot, Raw: b.Raw, BlockSize: b.BlockSize, StateSize: b.StateSize},
			ParentState: b.ParentState, Round: b.Round, AuthorizingUC: b.AuthorizingUC, AuthorizingTR: b.AuthorizingTR, ResultingUC: e.ResultingUC, ResultingTR: e.ResultingTR,
		})
		hash = b.ParentHash
	}
	if len(reverse) == 0 {
		return nil, fmt.Errorf("journal provider: target equals ancestor")
	}
	for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = reverse[j], reverse[i]
	}
	return reverse, nil
}

var _ shardnode.JournalFetchProvider = JournalProvider{}
