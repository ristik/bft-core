package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/shardnode"
	"go.opentelemetry.io/otel/metric"
)

var ErrConfig = errors.New("archive wiring: invalid replica configuration")

type Publisher struct {
	Journal        *configuredprogress.Store
	Context        configuredprogress.Context
	JournalLimits  configuredprogress.JournalLimits
	Archive        *archive.Store
	Subject        archive.Context
	Host           shardnode.EvidenceHost
	Replicas       [2]peer.ID
	Limits         Limits
	Log            *slog.Logger
	Metrics        *Metrics
	BundleVerifier BundleVerifier
	ReceiptSource  ReceiptSource

	mu              sync.Mutex
	ack             map[[32]byte]uint8
	bundleAck       map[uint64]uint8
	cursor          int
	replicaCursor   [2]int
	status          Status
	replicaProgress [2]ReplicaProgress
}

// ReceiptSource is the execution RPC boundary used only while capturing an
// archive record. Extraction and verification never depend on it.
type ReceiptSource interface {
	GetBlockReceipts(context.Context, [32]byte) ([][]byte, error)
}

func (p *Publisher) fromJournal(ctx context.Context, e configuredprogress.JournalEntry) (archive.Request, *archive.Record, error) {
	q, rec, err := FromJournal(ctx, p.Context, p.Subject, nil, e)
	if err != nil {
		return q, nil, err
	}
	var envelopes [][]byte
	if p.ReceiptSource != nil {
		envelopes, err = captureBlockReceipts(ctx, p.ReceiptSource, q.BlockHash)
	} else {
		var body gethtypes.Body
		if rlp.DecodeBytes(rec.Body, &body) != nil || len(body.Transactions) != 0 {
			return q, nil, archive.ErrUnavailable
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return q, nil, ctx.Err()
		}
		return q, nil, fmt.Errorf("%w: capturing certified block receipts: %w", archive.ErrUnavailable, err)
	}
	rec, err = WithReceiptList(rec, envelopes)
	return q, rec, err
}

// Receipt RPC visibility can lag certification briefly while the execution
// client commits the canonical block. Retry only explicitly temporary null
// responses, with a bound so malformed receipts or a stuck node stay loud.
func captureBlockReceipts(ctx context.Context, source ReceiptSource, hash [32]byte) ([][]byte, error) {
	const retryBound = 5 * time.Second
	const retryInterval = 100 * time.Millisecond
	retryCtx, cancel := context.WithTimeout(ctx, retryBound)
	defer cancel()
	var lastRetryable error
	for {
		envelopes, err := source.GetBlockReceipts(retryCtx, hash)
		if err == nil {
			return envelopes, nil
		}
		if retryCtx.Err() != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if lastRetryable != nil {
				return nil, lastRetryable
			}
			return nil, err
		}
		var retryable interface{ Temporary() bool }
		if !errors.As(err, &retryable) || !retryable.Temporary() {
			return nil, err
		}
		lastRetryable = err
		ticker := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil, ctx.Err()
		case <-retryCtx.Done():
			ticker.Stop()
			return nil, lastRetryable
		case <-ticker.C:
		}
	}
}

type Status struct{ Pending, Acknowledged, Lagging int64 }

// ReplicaProgress is process-local transfer diagnostics. Durable acknowledgements
// are read from the journal frontier and remain the authority for pruning.
type ReplicaProgress struct {
	Replica                string `json:"replica"`
	LastAcknowledgedHeight uint64 `json:"lastAcknowledgedHeight"`
	Error                  string `json:"error,omitempty"`
}

// Snapshot is diagnostic only. Durable availability is re-established through
// verified read-back after restart; this in-memory count never licenses prune.
func (p *Publisher) Snapshot() Status { p.mu.Lock(); defer p.mu.Unlock(); return p.status }

// ReplicaProgress returns a copy of the latest per-peer transfer diagnostics.
func (p *Publisher) ReplicaProgress() [2]ReplicaProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.replicaProgress
}

// Validate checks the complete static policy before the node starts.
func (p *Publisher) Validate() error {
	if p.Journal == nil || p.Archive == nil || p.Host == nil || p.Replicas[0] == "" || p.Replicas[1] == "" || p.Replicas[0] == p.Replicas[1] || !p.Limits.valid() {
		return ErrConfig
	}
	var q archive.Request
	q.Context = p.Subject
	q.BlockHash[0] = 1
	if _, err := archive.EncodeRequest(q); err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return nil
}

// Run uses the journal as its durable pending queue. Scans and transfers run
// outside the certification path. One pass processes at most four records and
// rotates its starting point so a failed replica cannot starve later records.
func (p *Publisher) Run(ctx context.Context) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Log == nil {
		p.Log = slog.New(slog.DiscardHandler)
	}
	p.mu.Lock()
	if p.ack == nil {
		p.ack = make(map[[32]byte]uint8)
	}
	if p.bundleAck == nil {
		p.bundleAck = make(map[uint64]uint8)
	}
	p.mu.Unlock()
	var workers sync.WaitGroup
	for i := range p.Replicas {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			p.replicaLoop(ctx, index)
		}(i)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			if err := p.publishBundles(ctx); err != nil && ctx.Err() == nil {
				p.Log.WarnContext(ctx, "handoff bundle replication waiting", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer workers.Wait()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := p.pass(ctx); err != nil && ctx.Err() == nil {
			p.Log.WarnContext(ctx, "archive publication waiting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *Publisher) publishBundles(ctx context.Context) error {
	epochs, err := p.Archive.BundleEpochs(p.Subject)
	if err != nil {
		return err
	}
	var waiting error
	for _, epoch := range epochs {
		q := archive.BundleRequest{Context: p.Subject, Epoch: epoch}
		raw, err := p.Archive.GetBundle(q)
		if err != nil {
			return err
		}
		if p.BundleVerifier == nil {
			return ErrConfig
		}
		if err := p.BundleVerifier(ctx, q, raw); err != nil {
			return err
		}
		p.mu.Lock()
		bits := p.bundleAck[epoch]
		p.mu.Unlock()
		for i, id := range p.Replicas {
			if bits&(1<<i) != 0 {
				continue
			}
			if err := PutBundleAndReadBack(ctx, p.Host, id, q, raw, p.Limits, p.BundleVerifier); err != nil {
				waiting = errors.Join(waiting, fmt.Errorf("epoch %d replica %s: %w", epoch, id, err))
				continue
			}
			p.mu.Lock()
			p.bundleAck[epoch] |= 1 << i
			p.mu.Unlock()
		}
	}
	return waiting
}

func (p *Publisher) pass(ctx context.Context) error {
	image, err := p.Journal.LoadJournal(ctx, p.Context, p.JournalLimits)
	if err != nil {
		return err
	}
	entries := make([]configuredprogress.JournalEntry, 0, len(image.Candidates))
	for _, e := range image.Candidates {
		if e.Certified {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Candidate.Number < entries[j].Candidate.Number })
	processed := 0
	var first error
	p.mu.Lock()
	start := p.cursor
	p.mu.Unlock()
	for i := 0; i < len(entries); i++ {
		index := (start + i) % len(entries)
		e := entries[index]
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var hash [32]byte
		copy(hash[:], e.Candidate.Hash)
		p.mu.Lock()
		bits := p.ack[hash]
		p.mu.Unlock()
		if bits == 3 {
			continue
		}
		if processed >= 4 {
			break
		}
		processed++
		p.mu.Lock()
		p.cursor = (index + 1) % len(entries)
		p.mu.Unlock()
		q := archive.Request{Context: p.Subject, BlockHash: hash}
		rec, eerr := p.Archive.GetReceiptComplete(q)
		if errors.Is(eerr, archive.ErrUnavailable) {
			q, rec, eerr = p.fromJournal(ctx, e)
			if eerr == nil {
				eerr = p.Archive.Put(q, rec)
			}
		} else if eerr == nil {
			_, expected, verifyErr := p.fromJournal(ctx, e)
			if verifyErr != nil {
				eerr = verifyErr
			} else {
				gotDigest, gotErr := archive.ManifestDigest(q, rec)
				wantDigest, wantErr := archive.ManifestDigest(q, expected)
				if gotErr != nil || wantErr != nil || gotDigest != wantDigest {
					eerr = ErrBinding
				}
			}
		}
		if eerr != nil {
			if first == nil {
				first = eerr
			}
			continue
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	live := make(map[[32]byte]struct{}, len(entries))
	var status Status
	for _, e := range entries {
		var h [32]byte
		copy(h[:], e.Candidate.Hash)
		live[h] = struct{}{}
		switch p.ack[h] {
		case 3:
			status.Acknowledged++
		case 0:
			status.Pending++
		default:
			status.Lagging++
		}
	}
	for h := range p.ack {
		if _, ok := live[h]; !ok {
			delete(p.ack, h)
		}
	}
	p.status = status
	if p.Metrics != nil {
		p.Metrics.set(status)
	}
	return first
}

func certifiedEntries(image configuredprogress.JournalSnapshot) []configuredprogress.JournalEntry {
	entries := make([]configuredprogress.JournalEntry, 0, len(image.Candidates))
	for _, e := range image.Candidates {
		if e.Certified {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Candidate.Number < entries[j].Candidate.Number })
	return entries
}

// Each replica owns an independent bounded retry loop. A lost peer cannot
// consume the healthy peer's deadline or cursor.
func (p *Publisher) replicaLoop(ctx context.Context, index int) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := p.replicaPass(ctx, index); err != nil && ctx.Err() == nil {
			p.Log.WarnContext(ctx, "archive replica waiting", "replica", p.Replicas[index], "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Publisher) replicaPass(ctx context.Context, index int) error {
	image, err := p.Journal.LoadJournal(ctx, p.Context, p.JournalLimits)
	if err != nil {
		return err
	}
	entries := certifiedEntries(image)
	if len(entries) == 0 {
		return nil
	}
	mask := uint8(1 << index)
	p.mu.Lock()
	start := p.replicaCursor[index]
	p.mu.Unlock()
	var first error
	processed := 0
	for j := 0; j < len(entries); j++ {
		position := (start + j) % len(entries)
		e := entries[position]
		var hash [32]byte
		copy(hash[:], e.Candidate.Hash)
		p.mu.Lock()
		bits := p.ack[hash]
		p.mu.Unlock()
		if bits&mask != 0 {
			continue
		}
		if processed == 4 {
			break
		}
		processed++
		p.mu.Lock()
		p.replicaCursor[index] = (position + 1) % len(entries)
		p.mu.Unlock()
		q := archive.Request{Context: p.Subject, BlockHash: hash}
		rec, err := p.Archive.GetReceiptComplete(q)
		if errors.Is(err, archive.ErrUnavailable) {
			p.setReplicaError(index, "local receipt-complete archive record unavailable")
			continue // The local publisher will reconstruct this record.
		}
		if err == nil {
			_, expected, checkErr := p.fromJournal(ctx, e)
			if checkErr != nil {
				err = checkErr
			} else {
				got, gotErr := archive.ManifestDigest(q, rec)
				want, wantErr := archive.ManifestDigest(q, expected)
				if gotErr != nil || wantErr != nil || got != want {
					err = ErrBinding
				}
			}
		}
		if err == nil {
			err = PutAndReadBack(ctx, p.Host, p.Replicas[index], q, rec, p.Limits)
		}
		if err != nil {
			p.setReplicaError(index, err.Error())
			if first == nil {
				first = fmt.Errorf("replica %s: %w", p.Replicas[index], err)
			}
			continue
		}
		p.mu.Lock()
		p.ack[hash] |= mask
		if e.Candidate.Number > p.replicaProgress[index].LastAcknowledgedHeight {
			p.replicaProgress[index].LastAcknowledgedHeight = e.Candidate.Number
		}
		p.replicaProgress[index].Replica = p.Replicas[index].String()
		p.replicaProgress[index].Error = ""
		p.mu.Unlock()
		if p.Log != nil {
			p.Log.InfoContext(ctx, "archive replica ack catch-up", "replica", p.Replicas[index].String(), "block", fmt.Sprintf("%x", hash[:]))
		}
	}
	return first
}

func (p *Publisher) setReplicaError(index int, message string) {
	p.mu.Lock()
	p.replicaProgress[index].Replica = p.Replicas[index].String()
	p.replicaProgress[index].Error = message
	p.mu.Unlock()
}

// JournalVerifier accepts a remote publication only when this replica's own
// independently checked journal names the same certified association and bytes.
// A lagging replica refuses and can accept the retry after catch-up.
func JournalVerifier(store *configuredprogress.Store, c configuredprogress.Context, limits configuredprogress.JournalLimits, subject archive.Context, receiptSources ...ReceiptSource) Verifier {
	return func(ctx context.Context, q archive.Request, rec *archive.Record) error {
		if store == nil || rec == nil {
			return ErrBinding
		}
		image, err := store.LoadJournal(ctx, c, limits)
		if err != nil {
			return err
		}
		for _, entry := range image.Candidates {
			if !entry.Certified || !bytes.Equal(entry.Candidate.Hash, q.BlockHash[:]) {
				continue
			}
			wantQ, wantRec, err := FromJournal(ctx, c, subject, nil, entry)
			if err != nil {
				return err
			}
			var envelopes [][]byte
			if len(receiptSources) != 0 && receiptSources[0] != nil {
				envelopes, err = receiptSources[0].GetBlockReceipts(ctx, wantQ.BlockHash)
			} else {
				var body gethtypes.Body
				if rlp.DecodeBytes(wantRec.Body, &body) != nil || len(body.Transactions) != 0 {
					return archive.ErrUnavailable
				}
			}
			if err != nil {
				return err
			}
			wantRec, err = WithReceiptList(wantRec, envelopes)
			if err != nil {
				return err
			}
			got, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
			if err != nil {
				return err
			}
			want, err := archive.EncodeResponse(archive.Response{Request: wantQ, Outcome: archive.OK, Record: wantRec})
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return ErrBinding
			}
			return nil
		}
		if err := store.VerifyCoveredArchive(ctx, c, limits, q, rec); err == nil {
			return nil
		}
		return ErrUncertified
	}
}

type Metrics struct {
	mu           sync.Mutex
	status       Status
	registration metric.Registration
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	if meter == nil {
		return nil, ErrConfig
	}
	m := &Metrics{}
	pending, err := meter.Int64ObservableGauge("archive.pending_records")
	if err != nil {
		return nil, err
	}
	acknowledged, err := meter.Int64ObservableGauge("archive.acknowledged_records")
	if err != nil {
		return nil, err
	}
	lagging, err := meter.Int64ObservableGauge("archive.lagging_records")
	if err != nil {
		return nil, err
	}
	m.registration, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		m.mu.Lock()
		s := m.status
		m.mu.Unlock()
		observer.ObserveInt64(pending, s.Pending)
		observer.ObserveInt64(acknowledged, s.Acknowledged)
		observer.ObserveInt64(lagging, s.Lagging)
		return nil
	}, pending, acknowledged, lagging)
	return m, err
}

func (m *Metrics) set(s Status) { m.mu.Lock(); m.status = s; m.mu.Unlock() }
func (m *Metrics) Close() error {
	if m == nil || m.registration == nil {
		return nil
	}
	return m.registration.Unregister()
}
