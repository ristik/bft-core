package recordwiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/shardnode"
)

var (
	ErrReadinessUnavailable = errors.New("recordwiring: child readiness is unavailable")
	ErrContinuity           = errors.New("recordwiring: authenticated continuity is not established")
	ErrObservationBound     = errors.New("recordwiring: observation history exceeds its bound")
	ErrGenesisCertificate   = errors.New("recordwiring: no configuration-bound genesis certificate is available")
)

// ObservationLimits are the accepted continuity bounds: the complete certificate/TR bundle is
// bounded before signature verification.
type ObservationLimits struct {
	MaxCertificates int
	MaxBytes        int
}

var DefaultObservationLimits = ObservationLimits{MaxCertificates: 512, MaxBytes: 1 << 20}

type observedPair struct {
	uc   *types.UnicityCertificate
	tr   *certification.TechnicalRecord
	raw  []byte
	size int
}

// Observations retains authenticated UC/TR pairs observed by this process. Observe verifies the
// TR binding and copies both values; certificate authentication remains the caller's precondition
// and is repeated by Prepare before the history grants readiness.
type Observations struct {
	mu      sync.Mutex
	limits  ObservationLimits
	pairs   []observedPair
	bytes   int
	version uint64
}

func NewObservations(l ObservationLimits) (*Observations, error) {
	if l.MaxCertificates <= 0 || l.MaxBytes <= 0 {
		return nil, fmt.Errorf("%w: MaxCertificates=%d MaxBytes=%d", ErrObservationBound, l.MaxCertificates, l.MaxBytes)
	}
	return &Observations{limits: l}, nil
}

func (o *Observations) Observe(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if uc == nil || uc.InputRecord == nil || tr == nil {
		return fmt.Errorf("%w: incomplete certificate/TR", ErrContinuity)
	}
	th, err := tr.Hash()
	if err != nil || !bytes.Equal(th, uc.TRHash) {
		return fmt.Errorf("%w: technical record is not certificate-bound", ErrContinuity)
	}
	ucRaw, err := types.Cbor.Marshal(uc)
	if err != nil {
		return fmt.Errorf("%w: encoding certificate: %v", ErrContinuity, err)
	}
	trRaw, err := types.Cbor.Marshal(tr)
	if err != nil {
		return fmt.Errorf("%w: encoding technical record: %v", ErrContinuity, err)
	}
	if len(ucRaw)+len(trRaw) > o.limits.MaxBytes {
		return fmt.Errorf("%w: one observation is %d bytes", ErrObservationBound, len(ucRaw)+len(trRaw))
	}
	var ucCopy types.UnicityCertificate
	var trCopy certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(ucRaw, &ucCopy); err != nil {
		return err
	}
	if err := types.Cbor.Unmarshal(trRaw, &trCopy); err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if n := len(o.pairs); n != 0 && bytes.Equal(o.pairs[n-1].raw, ucRaw) {
		return nil
	}
	o.version++
	o.pairs = append(o.pairs, observedPair{uc: &ucCopy, tr: &trCopy, raw: ucRaw, size: len(ucRaw) + len(trRaw)})
	o.bytes += len(ucRaw) + len(trRaw)
	for len(o.pairs) > o.limits.MaxCertificates || o.bytes > o.limits.MaxBytes {
		o.bytes -= o.pairs[0].size
		o.pairs[0] = observedPair{}
		o.pairs = o.pairs[1:]
	}
	return nil
}

func (o *Observations) evidence(source, held *types.UnicityCertificate) (shardnode.AnchorEvidence, uint64, error) {
	sourceRaw, err := types.Cbor.Marshal(source)
	if err != nil {
		return shardnode.AnchorEvidence{}, 0, err
	}
	heldRaw, err := types.Cbor.Marshal(held)
	if err != nil {
		return shardnode.AnchorEvidence{}, 0, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	start, end := -1, -1
	for i := range o.pairs {
		if start < 0 && bytes.Equal(o.pairs[i].raw, sourceRaw) {
			start = i
		}
		if start >= 0 && bytes.Equal(o.pairs[i].raw, heldRaw) {
			end = i
		}
	}
	if start < 0 || end < start {
		return shardnode.AnchorEvidence{}, o.version, fmt.Errorf("%w: source or held certificate was not observed in this process", ErrContinuity)
	}
	ev := shardnode.AnchorEvidence{Source: o.pairs[start].uc, SourceTechnical: o.pairs[start].tr}
	for _, p := range o.pairs[start+1 : end+1] {
		ev.Tail = append(ev.Tail, shardnode.EvidenceLink{UC: p.uc, Technical: p.tr})
	}
	// Marshal/unmarshal once so verification owns a snapshot after the lock is released.
	raw, err := types.Cbor.Marshal(ev)
	if err != nil {
		return shardnode.AnchorEvidence{}, o.version, err
	}
	var snap shardnode.AnchorEvidence
	if err := types.Cbor.Unmarshal(raw, &snap); err != nil {
		return shardnode.AnchorEvidence{}, o.version, err
	}
	return snap, o.version, nil
}

// PreparedReadiness is an opaque, owner-produced result. W3b may revalidate it immediately before
// Build/sign; its unexported representation prevents callers from fabricating ready state.
type PreparedReadiness struct{ p *preparedReadiness }

type preparedReadiness struct {
	owner              *Readiness
	observationVersion uint64
	headToken          certifiedstore.HeadToken
	blockNumber        uint64
	blockHash          []byte
	stateRoot          []byte
	held               []byte
}

func (p PreparedReadiness) Valid() bool { return p.p != nil }

type Readiness struct {
	deployment Deployment
	store      *certifiedstore.Store
	executor   shardnode.Executor
	observed   *Observations
	limits     shardnode.AnchorEvidenceLimits
}

func NewReadiness(d Deployment, store *certifiedstore.Store, executor shardnode.Executor, observed *Observations) (*Readiness, error) {
	if !d.Valid() || store == nil || executor == nil || observed == nil {
		return nil, fmt.Errorf("%w: checked deployment, store, executor and observations are required", ErrReadinessUnavailable)
	}
	return &Readiness{deployment: d, store: store, executor: executor, observed: observed,
		limits: shardnode.DefaultAnchorEvidenceLimits}, nil
}

// Prepare performs all expensive store, witness, trust and continuity verification. It takes no
// Round or finality lock. W3b must still revalidate the held/version, executor and durable head.
func (r *Readiness) Prepare(ctx context.Context, held *types.UnicityCertificate) (PreparedReadiness, error) {
	// Own the caller's held certificate before any trust/store lookup. A mutable pointer must not
	// name one certificate for continuity verification and another for the returned authority.
	heldRaw, err := types.Cbor.Marshal(held)
	if err != nil {
		return PreparedReadiness{}, fmt.Errorf("%w: held certificate: %v", ErrContinuity, err)
	}
	var heldSnapshot types.UnicityCertificate
	if err := types.Cbor.Unmarshal(heldRaw, &heldSnapshot); err != nil {
		return PreparedReadiness{}, fmt.Errorf("%w: held certificate: %v", ErrContinuity, err)
	}
	held = &heldSnapshot
	loaded, headToken, err := r.store.LoadWithToken(ctx, r.deployment.StoreContext())
	if err != nil {
		return PreparedReadiness{}, fmt.Errorf("%w: loading durable head: %w", ErrReadinessUnavailable, err)
	}
	head, err := r.executor.Head(ctx)
	if err != nil || head.Number != loaded.BlockNumber() || !bytes.Equal(head.Hash, loaded.BlockHash().Bytes()) || !bytes.Equal(head.StateRoot, loaded.StateRoot().Bytes()) {
		return PreparedReadiness{}, fmt.Errorf("%w: executor is not exactly at the durable head", ErrReadinessUnavailable)
	}
	source, err := loaded.Certificate()
	if err != nil {
		return PreparedReadiness{}, err
	}
	ev, version, err := r.observed.evidence(source, held)
	if err != nil {
		return PreparedReadiness{}, err
	}
	c := r.deployment.StoreContext()
	vc := shardnode.AnchorEvidenceContext{PartitionID: c.PartitionID, ShardID: c.ShardID,
		ShardConfHash: c.FullShardConfHash, TrustBases: c.TrustBases, Held: held}
	if loaded.BlockNumber() == 0 {
		err = shardnode.VerifyGenesisContinuity(ctx, ev, vc, r.limits, r.deployment.GenesisState().Bytes())
		if err == nil {
			heldTR := ev.SourceTechnical
			if len(ev.Tail) != 0 {
				heldTR = ev.Tail[len(ev.Tail)-1].Technical
			}
			// #153 E1-E4: authorized round > 0 and > held history; exact configured block 0;
			// the already verified snapshot proves the registry is still at genesis.
			err = registryproof.GenesisParentEligible(heldTR.Round, held.InputRecord,
				r.deployment.GenesisState().Bytes(), loaded.Snapshot())
		}
	} else {
		anchor, verr := shardnode.VerifyAnchorEvidence(ctx, ev, vc, r.limits)
		err = verr
		if err == nil && (!bytes.Equal(anchor.BlockHash, loaded.BlockHash().Bytes()) || !bytes.Equal(anchor.StateRoot, loaded.StateRoot().Bytes()) || anchor.Round != loaded.PartitionRound()) {
			err = fmt.Errorf("%w: verified source is not the durable record", ErrContinuity)
		}
	}
	if err != nil {
		return PreparedReadiness{}, fmt.Errorf("%w: %w", ErrContinuity, err)
	}
	// VerifyAnchorEvidence authenticates every certificate first. The registry profile is narrower
	// than #92's general predicate: all links must then name the one root epoch pinned by deployment.
	// The deployment pins the genesis root epoch and shard epoch: nothing may precede them. Later ones are
	// the verified history of installed handoffs, so an upper root epoch bound is the installed epoch.
	current := c.Registry.RootEpoch
	if c.EpochAuthority != nil {
		var ready bool
		if current, ready = c.EpochAuthority.CurrentRootEpoch(); !ready || current < c.Registry.RootEpoch {
			return PreparedReadiness{}, fmt.Errorf("%w: installed root epoch is unavailable", ErrContinuity)
		}
	}
	for i, uc := range continuityCertificates(ev, held) {
		if got := uc.GetRootEpoch(); got < c.Registry.RootEpoch || got > current {
			return PreparedReadiness{}, fmt.Errorf("%w: authenticated continuity certificate %d names root epoch %d, deployment history is %d..%d",
				ErrContinuity, i, got, c.Registry.RootEpoch, current)
		}
	}
	// A technical record is the authorization its certificate's configuration names: the genesis shard epoch
	// under the genesis configuration, the installed assignment's own epoch under that assignment's.
	ucs := continuityCertificates(ev, held)
	for i, tr := range continuityTechnicalRecords(ev) {
		want := c.Registry.ShardEpoch
		if conf := ucs[i].ShardConfHash; !bytes.Equal(conf, c.FullShardConfHash) {
			pdr, err := r.deployment.RecordConfig(conf)
			if err != nil || pdr == nil {
				return PreparedReadiness{}, fmt.Errorf("%w: continuity certificate %d is of an assignment this node has not installed: %w", ErrContinuity, i, err)
			}
			want = pdr.Epoch
		}
		if tr.Epoch != want {
			return PreparedReadiness{}, fmt.Errorf("%w: authenticated continuity technical record %d names shard epoch %d, its configuration pins %d",
				ErrContinuity, i, tr.Epoch, want)
		}
	}
	return PreparedReadiness{p: &preparedReadiness{owner: r, observationVersion: version, headToken: headToken, blockNumber: loaded.BlockNumber(),
		blockHash: loaded.BlockHash().Bytes(), stateRoot: loaded.StateRoot().Bytes(), held: heldRaw}}, nil
}

func continuityTechnicalRecords(ev shardnode.AnchorEvidence) []*certification.TechnicalRecord {
	out := make([]*certification.TechnicalRecord, 0, len(ev.Tail)+1)
	out = append(out, ev.SourceTechnical)
	for _, link := range ev.Tail {
		out = append(out, link.Technical)
	}
	return out
}

func continuityCertificates(ev shardnode.AnchorEvidence, held *types.UnicityCertificate) []*types.UnicityCertificate {
	out := make([]*types.UnicityCertificate, 0, len(ev.Tail)+2)
	out = append(out, ev.Source)
	for _, link := range ev.Tail {
		out = append(out, link.UC)
	}
	return append(out, held)
}

// Revalidate performs only decisive mutable-state checks: exact held bytes, unchanged observation
// version, byte-identical durable head, and exact executor identity. It does no trust, signature or
// proof verification and is suitable for W3b's short finality decision boundary.
func (r *Readiness) Revalidate(ctx context.Context, prepared PreparedReadiness, held *types.UnicityCertificate) error {
	if prepared.p == nil || prepared.p.owner != r {
		return ErrReadinessUnavailable
	}
	heldRaw, err := types.Cbor.Marshal(held)
	if err != nil || !bytes.Equal(heldRaw, prepared.p.held) {
		return fmt.Errorf("%w: held certificate changed", ErrReadinessUnavailable)
	}
	r.observed.mu.Lock()
	version := r.observed.version
	r.observed.mu.Unlock()
	if version != prepared.p.observationVersion {
		return fmt.Errorf("%w: observed certificate history changed", ErrReadinessUnavailable)
	}
	if !r.store.HeadUnchanged(prepared.p.headToken) {
		return fmt.Errorf("%w: durable head changed", ErrReadinessUnavailable)
	}
	head, err := r.executor.Head(ctx)
	if err != nil || head.Number != prepared.p.blockNumber || !bytes.Equal(head.Hash, prepared.p.blockHash) || !bytes.Equal(head.StateRoot, prepared.p.stateRoot) {
		return fmt.Errorf("%w: executor moved", ErrReadinessUnavailable)
	}
	return nil
}

// PublishGenesis publishes the configuration-derived genesis identity/witness only when supplied a
// genuine authenticated no-block UC/TR. Store verification rejects nil root history and all other
// attempts; this function never repairs or synthesizes certification.
func PublishGenesis(ctx context.Context, store *certifiedstore.Store, d Deployment, executor shardnode.Executor,
	finality FinalityLock, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if store == nil || !d.Valid() || executor == nil || finality == nil || uc == nil || uc.InputRecord == nil || tr == nil {
		return ErrGenesisCertificate
	}
	if len(uc.InputRecord.BlockHash) != 0 || !bytes.Equal(uc.InputRecord.Hash, d.GenesisState().Bytes()) ||
		!bytes.Equal(uc.InputRecord.PreviousHash, d.GenesisState().Bytes()) {
		return fmt.Errorf("%w: certificate is not no-block history at configured genesis", ErrGenesisCertificate)
	}
	c := d.StoreContext()
	prepared, err := store.Prepare(ctx, c, certifiedstore.Record{BlockHash: c.Registry.EVMGenesisHash, BlockNumber: 0,
		StateRoot: d.GenesisState(), PartitionRound: uc.InputRecord.RoundNumber, Certificate: uc,
		Technical: tr, Witness: d.GenesisEvidence()})
	if err != nil {
		return err
	}
	release, err := finality.Hold(ctx, "certified-genesis-publication")
	if err != nil {
		return err
	}
	defer release()
	head, err := executor.Head(ctx)
	if err != nil || head.Number != 0 || !bytes.Equal(head.Hash, c.Registry.EVMGenesisHash.Bytes()) || !bytes.Equal(head.StateRoot, d.GenesisState().Bytes()) {
		return fmt.Errorf("%w: executor is not exactly at configured genesis", ErrReadinessUnavailable)
	}
	return store.Commit(prepared)
}
