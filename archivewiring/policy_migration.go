package archivewiring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// migrationPage is how many promised positions one pass verifies on the current replicas after a policy switch (bft-core#1030). The
// regular audit sweeps the whole history once a day; a migration releases a retired machine, so it runs as fast as one bounded page
// per pass allows (32 positions a second at the two-second cadence).
const migrationPage = 64

func names(ids []peer.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func decodeNames(list []string) []peer.ID {
	out := make([]peer.ID, 0, len(list))
	for _, n := range list {
		if id, err := peer.Decode(n); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// FrontierPolicy is the frontier policy of a derived archive policy under its durable migration state: the replicas, the lineage
// accepted on historical records, and the retained holders counted for promised copies (and readable through the availability check).
func FrontierPolicy(ctx context.Context, c configuredprogress.Context, subject archive.Context, host shardnode.EvidenceHost, limits Limits,
	replicas []peer.ID, digest [32]byte, m configuredprogress.ArchiveMigration) frontier.Policy {
	readable := slices.Clone(replicas)
	for _, id := range decodeNames(m.Retained) {
		if !slices.Contains(readable, id) {
			readable = append(readable, id)
		}
	}
	// The availability checker outlives the operation that installs it (a catch-up's Advance among them, whose context is canceled when it
	// returns): it keeps the values of ctx but never its cancellation. Each read-back is bounded by the transport limits.
	return frontier.Policy{Context: subject, Eligible: names(replicas), PolicyDigest: digest, Historical: slices.Clone(m.Lineage), Retained: slices.Clone(m.Retained),
		Binding: CertifiedBinding{Context: c, Subject: subject}, Availability: ReplicaAvailability{Context: context.WithoutCancel(ctx), Host: host, Replicas: readable, Limits: limits}}
}

// EnableDerivedFrontier adopts the given snapshot's derived policy durably in the journal and enables (or switches) the journal's frontier
// to it, then publishes the migration state to the policy (ignored there if the policy has switched again meanwhile). Every step uses
// this one snapshot: an activation in between is adopted by the next call, never mixed into this one. It is the startup half of what the
// frontier worker does on a switch; nothing may advance the frontier concurrently. It returns the migration state.
func EnableDerivedFrontier(ctx context.Context, journal *configuredprogress.Store, c configuredprogress.Context, limits configuredprogress.JournalLimits,
	subject archive.Context, host shardnode.EvidenceHost, transport Limits, policy *ReplicaPolicy, snap ReplicaPolicySnapshot) (configuredprogress.ArchiveMigration, error) {
	if snap.Digest == ([32]byte{}) {
		return configuredprogress.ArchiveMigration{}, ErrConfig
	}
	m, err := journal.AdoptArchivePolicy(ctx, c, limits, snap.Encoded, names(snap.Replicas))
	if err != nil {
		return m, fmt.Errorf("adopting the archive policy: %w", err)
	}
	if m.Digest != snap.Digest || !slices.Equal(m.Replicas, names(snap.Replicas)) {
		return m, fmt.Errorf("%w: the adopted archive policy is not the snapshot's", ErrConfig)
	}
	fp := FrontierPolicy(ctx, c, subject, host, transport, snap.Replicas, snap.Digest, m)
	err = journal.ReplaceFrontierPolicy(ctx, c, limits, fp)
	if errors.Is(err, configuredprogress.ErrSettings) {
		err = journal.EnableFrontier(ctx, c, limits, fp)
	}
	if err != nil {
		return m, err
	}
	policy.adopt(snap.Digest, m)
	return m, nil
}

// syncPolicy adopts a switch of Policy before anything is planned under it. Runs under w.advancing.
func (w *FrontierWorker) syncPolicy(ctx context.Context) error {
	if w.Policy == nil {
		return nil
	}
	snap := w.Policy.Snapshot()
	if snap.Digest == ([32]byte{}) {
		w.Replicas, w.PolicyDigest = snap.Replicas, snap.Digest // an explicit pair never switches
		return nil
	}
	if w.applied && w.appliedAt == snap.Digest {
		return nil
	}
	if w.beforeAdopt != nil {
		w.beforeAdopt() // tests: an activation between the snapshot and its adoption
	}
	m, err := EnableDerivedFrontier(ctx, w.Journal, w.Context, w.Limits, w.Subject, w.Host, w.TransportLimits, w.Policy, snap)
	if err != nil {
		return fmt.Errorf("switching the archive policy: %w", err)
	}
	previous := w.Replicas
	w.Replicas, w.PolicyDigest, w.retained, w.migration = snap.Replicas, snap.Digest, decodeNames(m.Retained), &m
	w.applied, w.appliedAt = true, snap.Digest
	if w.Log != nil && !slices.Equal(previous, snap.Replicas) {
		w.Log.InfoContext(ctx, "archive replica policy in force", "replicas", names(snap.Replicas), "previous", names(previous), "shardEpoch", snap.Epoch,
			"retained", m.Retained, "migrationSince", m.Since, "migrationThrough", m.Through, slog.String("policy", fmt.Sprintf("%x", snap.Digest[:4])))
	}
	return nil
}

// migrate verifies one page of the history promised before the switch on the current replicas, rewriting a missing copy from the
// local record (a replica accepts it only if its own journal, coverage or verified history vouches for it), and records the progress
// durably. Retained holders are released only when every promised block position up to the switch AND every retained activation bundle
// has two verified copies on the current replicas; until then they count towards K. The worker's replicas, digest and migration state
// are one adopted snapshot, checked again by the progress commit. It never fails the pass: the regular audit and advance go on. Runs
// under w.advancing.
func (w *FrontierWorker) migrate(ctx context.Context) error {
	if w.Policy == nil || w.migration == nil || w.migration.Complete() || w.Host == nil {
		return nil
	}
	m := *w.migration
	if m.Digest != w.PolicyDigest || !slices.Equal(m.Replicas, names(w.Replicas)) {
		return fmt.Errorf("%w: the migration state is not the adopted policy's", ErrConfig)
	}
	through := m.Through
	var stopped error
	if through < m.Since {
		page, err := w.Journal.LoadCoverage(ctx, w.Context, w.Limits, m.Through, migrationPage)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			through = m.Since // nothing is promised above the verified height (or the coverage base) up to the switch
		}
		binding := CertifiedBinding{Context: w.Context, Subject: w.Subject}
		availability := ReplicaAvailability{Context: ctx, Host: w.Host, Replicas: w.readable(), Limits: w.TransportLimits}
		down := make(map[peer.ID]bool)
		for _, r := range page {
			if r.Height > m.Since {
				through = m.Since
				break
			}
			rec, err := w.promisedMaterial(ctx, binding, r)
			if err != nil {
				stopped = fmt.Errorf("height %d: %w", r.Height, err)
				break
			}
			if n := w.ensureCopies(ctx, availability, down, r, rec, false); n < replicaCopies {
				stopped = fmt.Errorf("%w: height %d: %d of %d current replicas hold a verified copy, two required", frontier.ErrAcknowledgment, r.Height, n, len(w.Replicas))
				break
			}
			through = r.Height
		}
	}
	release := false
	if through >= m.Since && stopped == nil {
		if err := w.ensureBundles(ctx); err != nil {
			stopped = err
		} else {
			release = true
		}
	}
	if through > m.Through || release {
		next, err := w.Journal.AdvanceArchiveMigration(ctx, w.Context, w.Limits, m.Digest, m.Replicas, through, release)
		if err != nil {
			return err
		}
		if err := w.setMigration(ctx, next); err != nil {
			return err
		}
	}
	return stopped
}

// ensureBundles requires every activation bundle this node's archive retains to have two current replicas holding it, read back and
// matching (the same bytes, or the same handoff under BundleVerifier), rewriting it where it is missing. The writer's own copy does not
// count. Runs under w.advancing.
func (w *FrontierWorker) ensureBundles(ctx context.Context) error {
	epochs, err := w.Archive.BundleEpochs(w.Subject)
	if err != nil {
		return err
	}
	for _, epoch := range epochs {
		q := archive.BundleRequest{Context: w.Subject, Epoch: epoch}
		raw, err := w.Archive.GetBundle(q)
		if err != nil {
			return err
		}
		copies := 0
		for _, id := range w.Replicas {
			got, ferr := FetchBundle(ctx, w.Host, id, q, w.TransportLimits)
			if ferr == nil && readBackMatches(ctx, q, w.BundleVerifier, got, raw) || PutBundleAndReadBack(ctx, w.Host, id, q, raw, w.TransportLimits, w.BundleVerifier) == nil {
				copies++
			}
		}
		if copies < replicaCopies {
			return fmt.Errorf("%w: activation bundle of epoch %d: %d of %d current replicas hold it, two required", frontier.ErrAcknowledgment, epoch, copies, len(w.Replicas))
		}
	}
	return nil
}

// setMigration applies a migration state of the policy in force: a release of retained holders switches the journal's frontier policy
// first, so the in-memory set never names fewer holders than the journal counts. Runs under w.advancing.
func (w *FrontierWorker) setMigration(ctx context.Context, m configuredprogress.ArchiveMigration) error {
	if !slices.Equal(names(w.retained), m.Retained) {
		fp := FrontierPolicy(ctx, w.Context, w.Subject, w.Host, w.TransportLimits, w.Replicas, w.PolicyDigest, m)
		if err := w.Journal.ReplaceFrontierPolicy(ctx, w.Context, w.Limits, fp); err != nil {
			return err
		}
		w.retained = decodeNames(m.Retained)
		if w.Log != nil && m.Complete() {
			w.Log.InfoContext(ctx, "archive policy migration complete: every promised position has two verified copies on the current replicas; retained replicas released",
				"replicas", names(w.Replicas), "through", m.Through)
		}
	}
	w.migration = &m
	w.Policy.adopt(w.PolicyDigest, m)
	return nil
}
