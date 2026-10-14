package rootchain

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// EntryOffers chooses the finalized signed trust-base entries to attach to a certification response. A node with offers answers on the version 2
// certificate protocol; without them it answers exactly as before.
type EntryOffers interface {
	// Offer returns the entries (canonical stored bytes, ascending by epoch, at most certification.MaxTrustBaseUpdates) for a response to recipient whose
	// UC was signed in signerEpoch, and the function to call once the response has been SENT: only then is the recipient considered to have been offered them.
	Offer(recipient peer.ID, signerEpoch uint64) (entries [][]byte, sent func())
	// Reset forgets what the recipient was offered (a reconnect or a handshake), so the next response carries the relevant entries again.
	Reset(recipient peer.ID)
}

// maxOfferHints bounds the per-recipient hints. Eviction only costs a repeated attachment.
const maxOfferHints = 4096

// StoreOffers offers the entries of a utbstore.Store. The hint per recipient is the highest epoch offered to it and was sent successfully; it is
// best-effort and in memory only (a restart resets it), never an acknowledgement or an authority: a missed delivery is repaired by GetTrustBase.
type StoreOffers struct {
	store *utbstore.Store

	mu    sync.Mutex
	hints map[peer.ID]uint64
}

func NewStoreOffers(store *utbstore.Store) *StoreOffers {
	return &StoreOffers{store: store, hints: make(map[peer.ID]uint64)}
}

// Offer attaches the newest entries up to the successor of the UC's signer epoch: an entry is eligible when its epoch is at most signerEpoch+1 (the
// committee that signed the UC endorsed it, or an earlier one did) and it is finalized in the store NOW. The chosen epochs are the (at most two)
// highest eligible ones above the recipient's hint; the genesis is never attached. A repeated old UC therefore never carries an entry newer than its own
// signer epoch's successor, whatever the store has finalized since.
func (o *StoreOffers) Offer(recipient peer.ID, signerEpoch uint64) ([][]byte, func()) {
	if signerEpoch == 0 {
		return nil, nil
	}
	tip := o.store.Tip().Epoch
	hi := min(signerEpoch+1, tip)
	o.mu.Lock()
	hint := o.hints[recipient]
	o.mu.Unlock()
	lo := max(hint+1, o.store.GenesisEpoch()+1)
	if hi+1 > certification.MaxTrustBaseUpdates {
		lo = max(lo, hi+1-certification.MaxTrustBaseUpdates)
	}
	if hi < lo {
		return nil, nil
	}
	var entries [][]byte
	for e := lo; e <= hi; e++ {
		raw, err := o.store.Get(e)
		if err != nil {
			return nil, nil // a hole is not papered over: the client catches up through the range protocol
		}
		entries = append(entries, raw)
	}
	return entries, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if len(o.hints) >= maxOfferHints {
			for k := range o.hints {
				delete(o.hints, k)
				break
			}
		}
		if o.hints[recipient] < hi {
			o.hints[recipient] = hi
		}
	}
}

func (o *StoreOffers) Reset(recipient peer.ID) {
	o.mu.Lock()
	delete(o.hints, recipient)
	o.mu.Unlock()
}
