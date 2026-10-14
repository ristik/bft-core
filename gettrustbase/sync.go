package gettrustbase

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utbstore"
)

// Fetcher retrieves one page from one peer. *Client implements it.
type Fetcher interface {
	Page(ctx context.Context, id peer.ID, req *Request) (*Response, [][]byte, error)
}

// Sink is the store being caught up. *utbstore.Store implements it; Append is the only way in and authenticates each entry from the held tip.
type Sink interface {
	Tip() utbstore.Tip
	Append(b []byte) (bool, error)
}

// SyncOptions bound the catch-up.
type SyncOptions struct {
	Network    types.NetworkID
	To         *uint64       // optional end epoch
	MaxEntries uint32        // requested page entries, default DefaultMaxEntries
	MaxBytes   uint32        // requested page bytes, default DefaultMaxResponse
	Rounds     int           // passes over the peer list before giving up, default 2
	Backoff    time.Duration // pause between passes, default 200 ms
}

// ErrNoPeer: every peer failed or could not serve the range.
var ErrNoPeer = errors.New("gettrustbase: no peer served the range")

// Sync appends the entries after the sink's tip, page by page, authenticating each from the entry before it. The first page freezes (end, EntryID) and
// every later page echoes it, so a peer that is behind or on another history is skipped and the next peer continues from the same cursor. Authenticated
// prefixes are kept even when a later page fails. A peer that is behind, unreachable, on another history or serving an entry the store refuses
// (conflict, invalid signature, gap) is skipped; nothing beyond a refused entry is appended from it. It returns the number of entries appended, with
// nil only when the store reached the end or every peer reported nothing newer.
func Sync(ctx context.Context, f Fetcher, sink Sink, peers []peer.ID, opt SyncOptions) (int, error) {
	if len(peers) == 0 {
		return 0, ErrNoPeer
	}
	if opt.MaxEntries == 0 {
		opt.MaxEntries = DefaultMaxEntries
	}
	if opt.MaxBytes == 0 {
		opt.MaxBytes = DefaultMaxResponse
	}
	if opt.Rounds == 0 {
		opt.Rounds = 2
	}
	if opt.Backoff == 0 {
		opt.Backoff = 200 * time.Millisecond
	}
	from := sink.Tip().Epoch + 1
	var snapEnd *uint64
	var snapID []byte
	appended := 0
	var last error
	for round := 0; round < opt.Rounds; round++ {
		if round > 0 {
			select {
			case <-ctx.Done():
				return appended, ctx.Err()
			case <-time.After(opt.Backoff):
			}
		}
		current := 0 // peers that answered "nothing newer than what we hold"
		for _, id := range peers {
			for {
				if err := ctx.Err(); err != nil {
					return appended, err
				}
				req := &Request{Version: Version, Network: opt.Network, FromEpoch: from, ToEpoch: opt.To, SnapshotEnd: snapEnd, SnapshotEntryID: snapID,
					MaxEntries: opt.MaxEntries, MaxBytes: opt.MaxBytes}
				resp, entries, err := f.Page(ctx, id, req)
				if err != nil {
					last = err
					break
				}
				if resp.Network != opt.Network {
					last = fmt.Errorf("%w: network %d", ErrResponse, resp.Network)
					break
				}
				if resp.Status == StatusNotYetAvailable && snapEnd == nil && resp.EffectiveEnd < from {
					// A peer's tip is unauthenticated metadata: a lagging or hostile peer must not end the catch-up. Only when every peer says there is
					// nothing newer is the store current.
					current++
					break
				}
				if resp.Status != StatusOK {
					last = fmt.Errorf("peer %s: %s", id, resp.Status)
					break
				}
				if resp.FromEpoch != from || (snapEnd != nil && (resp.EffectiveEnd != *snapEnd || !bytes.Equal(resp.EndEntryID, snapID))) {
					last = fmt.Errorf("%w: page does not continue the requested range", ErrResponse)
					break
				}
				refused := false
				for _, raw := range entries {
					if _, err := sink.Append(raw); err != nil {
						// the peer served an entry the store rejects: keep the authenticated prefix, drop its snapshot and try the next peer
						last = fmt.Errorf("peer %s: %w", id, err)
						refused = true
						break
					}
					appended++
				}
				if refused {
					from, snapEnd, snapID = sink.Tip().Epoch+1, nil, nil
					break
				}
				if resp.NextEpoch == nil {
					return appended, nil
				}
				if snapEnd == nil {
					end := resp.EffectiveEnd
					snapEnd, snapID = &end, bytes.Clone(resp.EndEntryID)
				}
				from = *resp.NextEpoch
			}
		}
		if current == len(peers) {
			return appended, nil
		}
	}
	if last == nil {
		last = ErrNoPeer
	}
	return appended, fmt.Errorf("%w: %w", ErrNoPeer, last)
}
