package shardnode

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #976, D: what the shard can say about work that has not been certified. The figures are in memory (a restart resets them) and are diagnostics,
// not a delivery deadline.

type pendingWorld struct {
	f    *confBindingFixture
	c    *BFTClient
	net  *swallowingNet
	zero []byte
	pdr  *types.PartitionDescriptionRecord
}

func newPendingWorld(t *testing.T, opts BFTClientOptions) *pendingWorld {
	t.Helper()
	f := newConfBindingFixture(t)
	c, net := resubmitClient(t, f, opts)
	require.NoError(t, c.handleCertificationResponse(context.Background(), f.respond(f.ucMine)))
	return &pendingWorld{f: f, c: c, net: net, zero: make([]byte, 32), pdr: &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}}
}

// uc is a certificate of the fixture's shard: round 4 is the held one; a later root round with the same round is a repeat, the next round is progress.
func (w *pendingWorld) uc(t *testing.T, round, rootRound uint64) *types.UnicityCertificate {
	t.Helper()
	trHash, err := w.f.technical.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: w.zero, Hash: w.zero, SummaryValue: []byte{}, Timestamp: 1}
	return testcertificates.CreateUnicityCertificate(t, w.f.signer, ir, w.pdr, rootRound, w.zero, trHash)
}

func (w *pendingWorld) accept(t *testing.T, uc *types.UnicityCertificate) {
	t.Helper()
	require.NoError(t, w.c.handleCertificationResponse(context.Background(), w.f.respond(uc)))
}

func TestThePendingAgeCountsFromTheFirstSubmissionNotFromAResend(t *testing.T) {
	w := newPendingWorld(t, BFTClientOptions{ResubmitMinInterval: time.Millisecond, MaxResubmits: 3})
	require.NoError(t, w.c.Submit(context.Background(), pendingRequest(w.f)))
	time.Sleep(3 * time.Millisecond)
	w.accept(t, w.f.ucMine) // a duplicate of the held certificate: the request is re-sent
	require.Len(t, w.net.sent(), 2)
	first := w.c.outstanding.firstSent
	require.True(t, w.c.outstanding.lastSent.After(first), "the re-send moved lastSent")

	d := w.c.pendingDiagnostics(first.Add(40 * time.Second))
	require.True(t, d.Pending)
	require.Equal(t, 40*time.Second, d.OutstandingAge, "the age is measured from the first submission")
}

func TestAnAdvancingCertificateRetiresThePendingAgeAndTheCounters(t *testing.T) {
	w := newPendingWorld(t, BFTClientOptions{})
	require.NoError(t, w.c.Submit(context.Background(), pendingRequest(w.f)))
	w.accept(t, w.uc(t, 5, 55))
	d := w.c.pendingDiagnostics(time.Now().Add(time.Hour))
	require.False(t, d.Pending, "the held certificate changed: an old pointer is not pending work")
	require.Zero(t, d.OutstandingAge)
	require.Zero(t, d.ConsecutiveRepeats)
	require.Zero(t, d.NoProgressAge, "no work remains")
}

func TestRepeatsAreCountedAndRebuiltAttemptsDoNotResetTheNoProgressAge(t *testing.T) {
	w := newPendingWorld(t, BFTClientOptions{})
	w.accept(t, w.uc(t, 5, 55)) // progress: the last non-repeat certificate
	progress := w.c.clock().Advanced()
	require.NoError(t, w.c.Submit(context.Background(), pendingRequest(w.f)))

	w.accept(t, w.uc(t, 5, 60)) // a T2 repeat of round 5
	d := w.c.pendingDiagnostics(progress.Add(20 * time.Second))
	require.Equal(t, 1, d.ConsecutiveRepeats)
	require.False(t, d.Pending, "the repeat superseded the request's authorization")
	require.Equal(t, 20*time.Second, d.NoProgressAge, "work remains (a repeat is being rebuilt after) and the clock runs from the last progress")

	require.NoError(t, w.c.Submit(context.Background(), pendingRequest(w.f))) // the rebuilt attempt
	w.accept(t, w.uc(t, 5, 65))                                               // repeated again
	d = w.c.pendingDiagnostics(progress.Add(50 * time.Second))
	require.Equal(t, 2, d.ConsecutiveRepeats)
	require.Equal(t, 50*time.Second, d.NoProgressAge, "a rebuilt attempt does not reset the only alarm")

	require.NoError(t, w.c.Submit(context.Background(), pendingRequest(w.f)))
	d = w.c.pendingDiagnostics(w.c.outstanding.firstSent.Add(5 * time.Second))
	require.True(t, d.Pending)
	require.Equal(t, 5*time.Second, d.OutstandingAge, "the new logical attempt has its own age")

	w.accept(t, w.uc(t, 6, 70)) // a non-repeat certificate: progress
	d = w.c.pendingDiagnostics(time.Now().Add(time.Hour))
	require.Zero(t, d.ConsecutiveRepeats)
	require.Zero(t, d.NoProgressAge)
}

type recordedLog struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordedLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, string(bytes.TrimSpace(p)))
	return len(p), nil
}

func (r *recordedLog) warnings() (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lines {
		if strings.Contains(l, "has not progressed") {
			n++
		}
	}
	return n
}

func TestThePendingWarningIsOperationalAndRateLimited(t *testing.T) {
	w := newPendingWorld(t, BFTClientOptions{PendingWarnAfter: time.Millisecond, RepeatWarnAfter: 2, PendingWarnEvery: time.Hour})
	rec := &recordedLog{}
	w.c.log = slog.New(slog.NewTextHandler(rec, nil))
	ctx := context.Background()

	w.c.reportPending(ctx)
	require.Zero(t, rec.warnings(), "nothing is pending")

	require.NoError(t, w.c.Submit(ctx, pendingRequest(w.f)))
	time.Sleep(5 * time.Millisecond)
	w.c.reportPending(ctx)
	require.Equal(t, 1, rec.warnings(), "a request pending past the threshold warns")
	w.c.reportPending(ctx)
	w.c.reportPending(ctx)
	require.Equal(t, 1, rec.warnings(), "once per PendingWarnEvery")

	w2 := newPendingWorld(t, BFTClientOptions{PendingWarnAfter: -1})
	rec2 := &recordedLog{}
	w2.c.log = slog.New(slog.NewTextHandler(rec2, nil))
	require.NoError(t, w2.c.Submit(ctx, pendingRequest(w2.f)))
	time.Sleep(5 * time.Millisecond)
	w2.c.reportPending(ctx)
	require.Zero(t, rec2.warnings(), "a negative threshold disables the warning (the gauges stay)")

	var nilMetrics *Metrics
	nilMetrics.recordPending(ctx, PendingDiagnostics{})
}

// The production EVM shard adopts certificates through journal admission (deliverConfigured), not through handleCertificationResponse; the figures must
// move there too, and a configured retry of a failed apply (a duplicate, not adopted) must not count (rev3, #995).
func TestThePendingFiguresMoveOnTheConfiguredAdoptionPath(t *testing.T) {
	ctx := context.Background()
	sink := &admissionSink{errors: []error{nil, errors.New("executor unavailable")}}
	c, f := newAdmissionTestClient(t, sink, &admissionTestNet{})
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
	factory.mu.Lock()
	deliver := factory.callbacks.DeliverDurable
	factory.mu.Unlock()
	w := &pendingWorld{f: f, zero: make([]byte, 32), pdr: &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}}
	deliverUC := func(uc *types.UnicityCertificate) error {
		r := f.respond(uc)
		return deliver(ctx, &r.UC, &r.Technical)
	}

	require.NoError(t, deliverUC(f.ucMine)) // the first certificate: progress
	progress := c.clock().Advanced()
	require.False(t, progress.IsZero())
	require.Zero(t, c.pendingDiagnostics(time.Now()).ConsecutiveRepeats)

	repeat := w.uc(t, 4, 60)
	require.Error(t, deliverUC(repeat), "the apply of the repeat fails: the delivery will be retried")
	require.Equal(t, 1, c.pendingDiagnostics(time.Now()).ConsecutiveRepeats, "a repeat adopted through the configured path counts")
	delivered, advanced := c.Progress().Delivered(), c.Progress().Advanced()
	time.Sleep(2 * time.Millisecond)
	require.NoError(t, deliverUC(repeat), "the retry of the failed apply")
	require.Equal(t, delivered, c.Progress().Delivered(), "configured path: the retry is not progress either")
	require.Equal(t, advanced, c.Progress().Advanced())
	d := c.pendingDiagnostics(progress.Add(25 * time.Second))
	require.Equal(t, 1, d.ConsecutiveRepeats, "the retry is a duplicate: not adopted, not counted")
	require.Equal(t, 25*time.Second, d.NoProgressAge, "work remains and the clock runs from the last progress")

	require.NoError(t, deliverUC(w.uc(t, 5, 70)))
	d = c.pendingDiagnostics(time.Now().Add(time.Hour))
	require.Zero(t, d.ConsecutiveRepeats)
	require.Zero(t, d.NoProgressAge)
}

// The progress clock starts with the client, so a node that starts into a run of repeats reports a no-progress age (rev3's nit on #995).
func TestRunSeedsTheProgressClock(t *testing.T) {
	sink := &admissionSink{}
	c, _ := newAdmissionTestClient(t, sink, &admissionTestNet{})
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
	c.mu.Lock()
	seeded := c.clock().Advanced()
	c.consecutiveRepeats = 1 // as if the first certificates seen were repeats
	c.mu.Unlock()
	require.False(t, seeded.IsZero())
	require.Equal(t, 7*time.Second, c.pendingDiagnostics(seeded.Add(7*time.Second)).NoProgressAge)
}

func TestNegativeWarningOptionsAreDefinedNotAccidental(t *testing.T) {
	ctx := context.Background()
	// a negative RepeatWarnAfter: the repeat count alone never warns
	w := newPendingWorld(t, BFTClientOptions{RepeatWarnAfter: -1, PendingWarnAfter: time.Hour, PendingWarnEvery: time.Millisecond})
	rec := &recordedLog{}
	w.c.log = slog.New(slog.NewTextHandler(rec, nil))
	w.accept(t, w.uc(t, 5, 55))
	for i := 0; i < 5; i++ {
		w.accept(t, w.uc(t, 5, 60+uint64(i)))
	}
	w.c.reportPending(ctx)
	require.Zero(t, rec.warnings())
	// a negative PendingWarnEvery does not remove the rate limit: it means the default
	w2 := newPendingWorld(t, BFTClientOptions{PendingWarnAfter: time.Millisecond, PendingWarnEvery: -1})
	rec2 := &recordedLog{}
	w2.c.log = slog.New(slog.NewTextHandler(rec2, nil))
	require.NoError(t, w2.c.Submit(ctx, pendingRequest(w2.f)))
	time.Sleep(5 * time.Millisecond)
	for i := 0; i < 5; i++ {
		w2.c.reportPending(ctx)
	}
	require.Equal(t, 1, rec2.warnings())
}
