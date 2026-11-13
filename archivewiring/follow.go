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
	// Accepted reports whether the node durably holds a certificate at or past the given one (Node.Holds). An offered head that is not
	// accepted (its admission failed, say, on a transient missing dependency) is offered again after Retry; nil never re-offers.
	Accepted func(*types.UnicityCertificate) bool
	// NeedsBootstrap reports whether the node's journal still lacks its bootstrap certificate (a fresh journal must begin with it). While it
	// does, the follower first offers the bootstrap certificate taken from its sources' first certified record, instead of asking a root
	// quorum for it (#1050). Nil: the journal is never fresh here.
	NeedsBootstrap func() bool
	// Retry is the wait before re-offering an unaccepted head; zero is five seconds.
	Retry time.Duration
	// Interval is the pause between polls; zero is 500 ms.
	Interval time.Duration
	Log      *slog.Logger

	offered   *types.UnicityCertificate
	offeredAt time.Time
	now       func() time.Time
}

func (f *HeadFollower) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// due reports whether the offered head is unaccepted and its retry wait has passed.
func (f *HeadFollower) due() bool {
	if f.offered == nil || f.Accepted == nil || f.Accepted(f.offered) {
		return false
	}
	retry := f.Retry
	if retry <= 0 {
		retry = 5 * time.Second
	}
	return f.clock().Sub(f.offeredAt) >= retry
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
	if f.NeedsBootstrap != nil && f.NeedsBootstrap() {
		return f.bootstrap(ctx)
	}
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
	if best == nil {
		return false
	}
	if !newer(best, f.offered) && !(sameRound(best, f.offered) && f.due()) {
		return false
	}
	if !f.Offer(best, bestTR) {
		return false
	}
	f.offered, f.offeredAt = best, f.clock()
	if f.Log != nil {
		f.Log.InfoContext(ctx, "archive head offered", "rootEpoch", best.GetRootEpoch(), "rootRound", best.GetRootRoundNumber(), "round", best.GetRoundNumber())
	}
	return true
}

// maxBootstrapRound bounds the search for the first certified record (its first block is certified in one of the first rounds).
const maxBootstrapRound = 16

// bootstrap offers the shard's bootstrap certificate: the authorizing certificate of block 1, taken from a source's first certified
// record and verified with it (CertifiedBinding authenticates both certificates against the node's verified history and binds the block
// to them). The journal then admits it only as the configured bootstrap certificate: a fresh journal refuses anything else. It reports
// whether one was offered.
func (f *HeadFollower) bootstrap(ctx context.Context) bool {
	for _, id := range f.Sources() {
		for round := uint64(1); round <= maxBootstrapRound; round++ {
			q, rec, err := FetchLatest(ctx, f.Host, id, archive.RoundRequest{Context: f.Binding.Subject, Round: round}, f.Limits)
			if err != nil {
				continue
			}
			original, originalTR, result, _, err := decodeRestorePairs(rec)
			if err != nil {
				break
			}
			var header gethtypes.Header
			if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil || header.Number.Uint64() != 1 {
				break // the source's first record is not the first block: it holds no bootstrap evidence for this node
			}
			r := frontier.Record{Height: 1, Epoch: result.GetRootEpoch(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
			if err := f.Binding.VerifyCertified(r, rec); err != nil {
				if f.Log != nil {
					f.Log.WarnContext(ctx, "follow source bootstrap record not verified", "source", id.String(), "error", err)
				}
				break
			}
			if f.Offer(original, originalTR) {
				if f.Log != nil {
					f.Log.InfoContext(ctx, "bootstrap certificate offered from a follow source", "source", id.String(), "rootRound", original.GetRootRoundNumber())
				}
				return true
			}
			return false
		}
	}
	if f.Log != nil {
		f.Log.WarnContext(ctx, "no follow source served a verified first record: the journal still lacks its bootstrap certificate")
	}
	return false
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

func sameRound(a, b *types.UnicityCertificate) bool {
	return a != nil && b != nil && a.GetRootEpoch() == b.GetRootEpoch() && a.GetRootRoundNumber() == b.GetRootRoundNumber()
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
