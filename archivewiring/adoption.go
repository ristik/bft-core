package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ARCHIVE ADOPTION (bft-core#876, arch's design, rev2 approved).
//
// The archive requires the manifests of a block's copies to be byte-identical. Two validators can hold different, individually valid first resulting certificates for the same
// execution block (a repeat of the same input record at a later root round), so a node whose own representation differs from the one its replicas already covered and pruned can
// never obtain two matching copies and its frontier stops. When the oldest uncovered block cannot get two matching copies, the frontier worker probes the configured replicas for
// the representations they hold, and adopts one that
//   - passes the full certified binding under the node's OWN historical trust, with every archive field except the resulting pair byte-equal to the node's record and the resulting
//     certificate certifying the identical input record, and
//   - is read back, by its exact manifest digest, from two distinct configured replicas.
// The adoption is an ARCHIVE choice only: one durable selection record (configuredprogress.SelectArchiveRepresentation), written once while the block is hot and not covered. The
// journal's own association, observations and signing state are untouched, the old representation stays in the archive for promises already made, and manifest equality stays strict.

// adoptionRetry is how long the worker waits before probing again for the same blocked representation.
const adoptionRetry = 10 * time.Second

// fetchDefault reads the representation a replica serves by default for the block (untrusted).
func fetchDefault(ctx context.Context, w *FrontierWorker, id peer.ID, q archive.Request) (*archive.Record, error) {
	return Fetch(ctx, w.Host, id, q, w.TransportLimits)
}

// equivalentRepresentation reports why the offered record is not another proof of the same certified result, or nil: the archive fields other than the resulting pair are
// byte-equal, the resulting certificate certifies the identical input record, and the whole record passes the certified binding under the local trust.
func (w *FrontierWorker) equivalentRepresentation(entry configuredprogress.JournalEntry, q archive.Request, local, offered *archive.Record) error {
	if offered == nil || local == nil {
		return errors.New("no record")
	}
	same := bytes.Equal(local.Header, offered.Header) && bytes.Equal(local.Body, offered.Body) && bytes.Equal(local.CanonicalRootInput, offered.CanonicalRootInput) &&
		bytes.Equal(local.OriginalUC, offered.OriginalUC) && bytes.Equal(local.OriginalTR, offered.OriginalTR) && bytes.Equal(local.Companion, offered.Companion) &&
		bytes.Equal(local.ParentAccounting, offered.ParentAccounting) && len(local.Extensions) == len(offered.Extensions)
	for k, v := range local.Extensions {
		if o, ok := offered.Extensions[k]; !ok || !bytes.Equal(o, v) {
			same = false
		}
	}
	if !same {
		return errors.New("a field other than the resulting pair differs from the local record")
	}
	var mine, theirs types.UnicityCertificate
	if types.Cbor.Unmarshal(local.ResultingUC, &mine) != nil || types.Cbor.Unmarshal(offered.ResultingUC, &theirs) != nil || mine.InputRecord == nil || theirs.InputRecord == nil {
		return errors.New("the resulting certificate does not decode")
	}
	a, errA := types.Cbor.Marshal(mine.InputRecord)
	b, errB := types.Cbor.Marshal(theirs.InputRecord)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return errors.New("the resulting certificate does not certify the identical input record")
	}
	var state [32]byte
	copy(state[:], entry.Candidate.StateRoot)
	r := frontier.Record{Height: entry.Candidate.Number, StateRoot: state, Subject: q, Epoch: theirs.GetRootEpoch(), Round: theirs.GetRootRoundNumber()}
	if err := (CertifiedBinding{Context: w.Context, Subject: w.Subject}).VerifyCertified(r, offered); err != nil {
		return fmt.Errorf("certified binding: %w", err)
	}
	return nil
}

// adoptEquivalent probes the configured replicas for another representation of the blocked block and adopts it when the rules above hold. It reports whether a selection was
// committed (the caller replans on the next pass). It runs inside the frontier worker only, once per blocked block per adoptionRetry, never from a replica goroutine.
func (w *FrontierWorker) adoptEquivalent(ctx context.Context, entry configuredprogress.JournalEntry, q archive.Request, local *archive.Record, localDigest [32]byte) (bool, error) {
	if w.Host == nil || w.Journal == nil || w.Archive == nil || entry.Archive != nil {
		return false, nil
	}
	key := ackKey(entry)
	if at, ok := w.adoptAt[key]; ok && time.Since(at) < adoptionRetry {
		return false, nil
	}
	if w.adoptAt == nil {
		w.adoptAt = make(map[[32]byte]time.Time)
	}
	w.adoptAt[key] = time.Now()
	type offer struct {
		rec      *archive.Record
		replicas []int
	}
	offers := map[[32]byte]*offer{}
	for i, id := range w.Replicas {
		rec, err := fetchDefault(ctx, w, id, q)
		if err != nil {
			continue
		}
		d, err := archive.ManifestDigest(q, rec)
		if err != nil || d == localDigest {
			continue
		}
		o := offers[d]
		if o == nil {
			o = &offer{rec: rec}
			offers[d] = o
		}
		o.replicas = append(o.replicas, i)
	}
	digests := make([][32]byte, 0, len(offers))
	for d := range offers {
		digests = append(digests, d)
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	availability := ReplicaAvailability{Context: ctx, Host: w.Host, Replicas: w.Replicas, Limits: w.TransportLimits}
	for _, d := range digests {
		o := offers[d]
		say := func(msg string, attrs ...any) {
			if w.Log != nil {
				w.Log.WarnContext(ctx, "archive adoption: "+msg, append([]any{"height", entry.Candidate.Number, "block", fmt.Sprintf("%x", q.BlockHash[:8]), "local", fmt.Sprintf("%x", localDigest[:8]), "offered", fmt.Sprintf("%x", d[:8])}, attrs...)...)
			}
		}
		if len(o.replicas) < replicaCopies {
			say("another representation is held by too few replicas", "replicas", len(o.replicas))
			continue
		}
		if err := w.equivalentRepresentation(entry, q, local, o.rec); err != nil {
			say("the offered representation is refused", "err", err)
			continue
		}
		exact := 0
		for _, i := range o.replicas {
			if availability.VerifyAvailable(w.Replicas[i].String(), q, d) == nil {
				exact++
			}
		}
		if exact < replicaCopies {
			say("fewer than two configured replicas return the exact manifest", "exact", exact)
			continue
		}
		// stage the object first; the selection is the single commit. A crash between the two leaves an unused object.
		if err := w.Archive.PutVariant(q, o.rec); err != nil {
			return false, fmt.Errorf("staging the adopted representation: %w", err)
		}
		err := w.Journal.SelectArchiveRepresentation(ctx, w.Context, w.Limits, configuredprogress.ArchiveSelectionRequest{
			BlockHash: q.BlockHash, Prior: configuredprogress.PairID(local.ResultingUC, local.ResultingTR), OldDigest: localDigest, NewDigest: d, UC: o.rec.ResultingUC, TR: o.rec.ResultingTR})
		if err != nil {
			say("the selection was refused", "err", err)
			if errors.Is(err, configuredprogress.ErrStale) || errors.Is(err, configuredprogress.ErrConflict) {
				continue
			}
			return false, err
		}
		if w.Log != nil {
			w.Log.InfoContext(ctx, "archive adoption: adopted the representation the replicas hold", "height", entry.Candidate.Number, "block", fmt.Sprintf("%x", q.BlockHash[:8]),
				"local", fmt.Sprintf("%x", localDigest[:8]), "adopted", fmt.Sprintf("%x", d[:8]), "replicas", len(o.replicas), slog.String("policy", fmt.Sprintf("%x", w.PolicyDigest[:4])))
		}
		return true, nil
	}
	return false, nil
}
