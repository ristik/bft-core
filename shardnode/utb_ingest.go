package shardnode

import (
	"context"
	"errors"
	"log/slog"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// ingestTrustBaseUpdates turns a version 2 certification response into the legacy response every later stage handles, after its attached entries have
// been authenticated and appended. Any other message is returned unchanged.
//
// The entries are an authority update independent of the response's status and of its certificate: a valid entry is kept even when the certificate or the
// request's outcome is not accepted, and an invalid one never affects the certificate, which is verified afterwards under this client's own epoch rules
// exactly as a legacy response is. A message that is not a well-formed version 2 response (version, bounds) is dropped whole.
func (c *BFTClient) ingestTrustBaseUpdates(ctx context.Context, msg any) any {
	v2, ok := msg.(*certification.CertificationResponseV2)
	if !ok {
		return msg
	}
	if v2 == nil {
		return nil
	}
	if err := v2.IsValid(); err != nil {
		if c.log != nil {
			c.log.WarnContext(ctx, "dropping invalid version 2 certification response", slog.String("err", err.Error()))
		}
		return v2.Response() // its certificate is judged by the legacy checks, which refuse it for the same structural reasons
	}
	c.applyTrustBaseUpdates(ctx, v2.TrustBaseUpdates)
	return v2.Response()
}

func (c *BFTClient) applyTrustBaseUpdates(ctx context.Context, updates []hex.Bytes) {
	store := c.opts.UTBStore
	if store == nil {
		return
	}
	for _, raw := range updates {
		added, err := store.Append(raw)
		switch {
		case err == nil:
			if added && c.opts.OnTrustBaseEntry != nil {
				if entry, entryErr := store.Entry(store.Tip().Epoch); entryErr == nil {
					c.opts.OnTrustBaseEntry(entry)
				}
			}
		case errors.Is(err, utbstore.ErrGap):
			if c.opts.OnTrustBaseGap != nil {
				c.opts.OnTrustBaseGap(store.Tip().Epoch, entryEpoch(raw))
			}
			return // the rest follow the gap
		default:
			if c.log != nil {
				c.log.WarnContext(ctx, "dropping an invalid trust-base update", slog.String("err", err.Error()))
			}
			return // an entry that does not authenticate is not followed by anything the client can use
		}
	}
}

// entryEpoch reads the epoch of an attached entry for diagnostics; 0 when it does not decode.
func entryEpoch(raw []byte) uint64 {
	if e, err := types.DecodeRootTrustBaseV2(raw); err == nil {
		return e.Epoch
	}
	return 0
}
