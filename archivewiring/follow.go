package archivewiring

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"time"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// HeadFollower is the root-free certificate source of a non-active node (phase 1 follower). It asks its sources (archive replicas and
// shard validators, never roots) for their newest certified record, authenticates the record's resulting certificate and its block
// against the node's verified history (the same CertifiedBinding as every archive read), and offers the newest such certificate to the
// node. The node admits it exactly like a root's response: its journal admission authenticates it again, fetches any missing suffix
// from the archive and executes it, and its round commits what is certified and, while non-active, never builds or signs.
//
// A source's head advertisement is only a locator: an unverifiable or older record is ignored, and nothing a source says is trusted. A
// record of an epoch whose activation the node has not installed yet fails verification until the Q3 follower installs it.
type HeadFollower struct {
	Binding CertifiedBinding
	Host    shardnode.EvidenceHost
	Sources func() []peer.ID
	Limits  Limits
	// Active reports whether the node is an active validator; while it is, the follower offers nothing (roots are the fastest path).
	Active func() bool
	// Offer hands a verified certificate to the node (Node.FollowCertificate) and reports whether it was queued.
	Offer func(*types.UnicityCertificate, *certification.TechnicalRecord) bool
	// Interval is the pause between polls; zero is 500 ms.
	Interval time.Duration
	Log      *slog.Logger

	offered *types.UnicityCertificate
}

// ErrFollowConfig is returned for a follower without its sources, host, binding or offer.
var ErrFollowConfig = errors.New("archive follower: incomplete configuration")

// Run polls until ctx ends. It returns nil on cancellation.
func (f *HeadFollower) Run(ctx context.Context) error {
	if f == nil || f.Sources == nil || f.Host == nil || f.Offer == nil || !f.Limits.valid() {
		return ErrFollowConfig
	}
	interval := f.Interval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		if f.Active == nil || !f.Active() {
			f.Poll(ctx)
		}
		timer.Reset(interval)
	}
}

// Poll asks every source once and offers the newest verified certificate that is newer than the last one offered. It reports whether
// one was offered.
func (f *HeadFollower) Poll(ctx context.Context) bool {
	var best *types.UnicityCertificate
	var bestTR *certification.TechnicalRecord
	for _, id := range f.Sources() {
		uc, tr, err := f.head(ctx, id)
		if err != nil {
			if f.Log != nil {
				f.Log.DebugContext(ctx, "follow source head not usable", "source", id.String(), "error", err)
			}
			continue
		}
		if newer(uc, best) {
			best, bestTR = uc, tr
		}
	}
	if best == nil || !newer(best, f.offered) {
		return false
	}
	if !f.Offer(best, bestTR) {
		return false
	}
	f.offered = best
	return true
}

// head is one source's newest certified record, verified.
func (f *HeadFollower) head(ctx context.Context, id peer.ID) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	q, rec, err := FetchLatest(ctx, f.Host, id, archive.RoundRequest{Context: f.Binding.Subject, Round: math.MaxUint64}, f.Limits)
	if err != nil {
		return nil, nil, err
	}
	_, _, result, resultTR, err := decodeRestorePairs(rec)
	if err != nil {
		return nil, nil, err
	}
	var header gethtypes.Header
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil {
		return nil, nil, archive.ErrInvalid
	}
	r := frontier.Record{Height: header.Number.Uint64(), Epoch: result.GetRootEpoch(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
	if err := f.Binding.VerifyCertified(r, rec); err != nil {
		return nil, nil, err
	}
	return result, resultTR, nil
}

// newer orders certificates by root epoch, then root round.
func newer(a, b *types.UnicityCertificate) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	if a.GetRootEpoch() != b.GetRootEpoch() {
		return a.GetRootEpoch() > b.GetRootEpoch()
	}
	return a.GetRootRoundNumber() > b.GetRootRoundNumber()
}
