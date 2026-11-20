package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The root side of the validator-registry (VR) handoff protocol (VT-05b, ristik/bft-core#1159; design section 5.3). The roots observe
// VR's outputs at the EVM blocks their committed chain certifies (stage 0) and derive the intent the executor judges against
// (vrschedule.Intents). Every root runs the staged protocol over the committed state (vrschedule.Service behind its verification queue
// and the /unicity/vr-handoff/1.0.0 peer protocol): it keeps the successors' sticky possession proofs, assembles as its committed view's
// assembler, verifies the successors' readiness and retains the first complete certificate (I-RET). A leader then orders, in this order of
// priority, the Prepare of a complete verified certificate whose gates hold, the Freeze v5 and H; and otherwise, once the view's replay
// floor and its own residence wait are met, the next HandoffView.

// ErrVRHandoff reports a VR handoff operation this root refuses.
var ErrVRHandoff = errors.New("VR handoff")

// VRHandoffConfig wires the VR handoff root side: the intent provider (with its sources and output cache), the VR reader the observer
// fetches through, the designated EVM shard, the Freeze v5 witness builder at the frozen parent, this root's root key (its assemblies),
// the peer protocol's opener, and the verification cap.
type VRHandoffConfig struct {
	Intents *vrschedule.Intents
	Reader  vrschedule.Reader
	EVM     types.PartitionShardID
	// Witness builds the Freeze v5 witness over VR at a certified EVM block (the frozen parent P) for result.
	Witness func(ctx context.Context, blockHash, stateRoot [32]byte, result vrschema.Word) ([]byte, error)
	Signer  abcrypto.Signer
	Opener  vrschedule.Opener // nil: the protocol's messages are not sent (a test, or a single root)
	PiMax   time.Duration
	Log     *slog.Logger
	// ShardStaged tells the paired shard node the EVM node ids of the derived intent's successor (nil: none given; an empty list when the
	// intent died): the shard node then serves them as staged peers so a joiner can catch its EVM chain up (VT-09b). Retried until it succeeds.
	ShardStaged func(ctx context.Context, shardEpoch, stamp uint64, ids []string) error
	// ShardStampPath persists the generation stamp counter: stamps stay monotonic across restarts and backward clock adjustments (empty: in memory)
	ShardStampPath string
	// Member, when set, makes this node do every successor-member step itself (VT-09, design 5.3.3): its sticky possession proof, its
	// readiness over a verified assembly with the support commitments, the staging and the pre-connection; no host-side drive.
	Member *VRMemberConfig
}

// VRMemberConfig is this node's member participation: its EVM key (the possession proof), the file its signed state persists in and the
// rules it supports (nil: every rule of the committed schedule).
type VRMemberConfig struct {
	EVMSigner abcrypto.Signer
	// EVMPoP, when set, is the possession-proof provider (the authority's): it takes the place of EVMSigner
	EVMPoP    vrschedule.PoPProvider
	EVMNodeID string // the node id of EVMSigner: checked against the EVM node the intent names for this node
	Path      string
	Supports  func(vrschema.Activation) bool
	Hold      func() bool // development test hook: true holds the readiness back (see vrschedule.MemberConfig.Hold)
}

type vrHandoff struct {
	cfg      VRHandoffConfig
	observer *vrschedule.Observer
	svc      *vrschedule.Service
	queue    *vrschedule.Queue
	obsWake  chan struct{} // a commit happened: the durable observation queue has new entries (a wakeup only; nothing is carried)
	// obsq is the durable observation queue of the CURRENT block store (the manager replaces its block store on recovery and on an epoch switch)
	obsq     func() observationQueue
	resumed  bool // the observer resumed from the queue's cursor
	peers    func() []peer.ID
	update   func() (vrschedule.Committed, error)
	prefetch chan vrschedule.CertifiedEVM
	wmu      sync.Mutex
	witness  struct {
		at      [32]byte
		intent  [32]byte
		payload []byte
	}
	fetching bool

	member *vrschedule.Member
	// source sync (VT-09b): a root that never observed a result's publication asks the incumbents for its committed source
	srcMu      sync.Mutex
	srcFetched map[[32]byte]time.Time
	srcBusy    bool
	// the successor's EVM node ids as the paired shard node should hold them: desired is set under stageMu with the active intent, version bumped
	// on each change; the worker delivers the latest and records what it delivered
	shardDesired   []string
	shardEpoch     uint64 // the shard epoch the desired assignment would install (installed + 1)
	shardStamp     uint64 // the generation stamp: later changes carry larger ones, so the shard orders them and ignores a delayed older one
	shardLast      time.Time
	shardPersisted uint64 // the stamp the counter file holds: a generation is sent only once its stamp is durable
	shardVer       uint64
	shardDone      uint64
	shardKick      chan struct{}
	statMu         sync.Mutex
	deriveErr      string // the last derivation's refusal (an input this root lacks), empty once an intent derives
	observeErr     int    // certified EVM blocks the observer gave up on since the last one it read
	// incumbents is the installed committee's weighted roots without this one and its total weight (this root included), from ONE trust-base snapshot
	incumbents func() ([]vrschedule.WeightedPeer, uint64)
	// stageIntent keeps the members the derived intent names (its successors' EVM validators and roots) as the staged successor, from the
	// intent's derivation on; nil clears it
	stageIntent  func(epoch uint64, ids []evmassign.Identity, roots []evmroot.Member) error
	intentStaged bool
	stagedFor    [32]byte // the intent digest the staged members were stored for
	// stageMu serializes every write of the staged successor with the refresh worker's view of the active intent: a staging write (the intent's
	// members, a verified candidate, a prepared certificate's) is made only for the intent that is active under this lock, so a callback that
	// outlives its intent can neither restore a cleared set nor replace another intent's
	stageMu sync.Mutex
	// installCandidate writes a verified candidate's staging (nil: the manager's own); replaced in tests
	installCandidate func(vrschedule.Staged) error
	activeIntent     [32]byte
	haveActive       bool
	kick             chan struct{}

	// the stage pull (GetStage): a (re)started root rebuilds its view state from its peers until one answers; while the current intent
	// holds no complete certificate it pulls again from one peer at a time every PullInterval, the re-send path for messages its queue or
	// buffer dropped
	pmu      sync.Mutex
	restored bool
	pulling  bool
	lastPull time.Time
	pullNext int
	now      func() time.Time

	// the committed state and leader inputs the manager's VR paths read (the block store's, the executor's intents; replaced in tests)
	opening func() (storage.VROpening, bool, error)
	queryAt func(*storage.ExecutedBlock) (storage.VRIntentQuery, bool, error)
	derive  func(storage.VRIntentQuery) (vrschedule.Derived, bool, error)
	leader  func(vrschedule.PreparePlan, *storage.ExecutedBlock, uint64, types.PartitionShardID, func(p, root [32]byte) ([]byte, error), crypto.Hash) (vrschedule.LeaderStep, error)
	reject  func(ctx context.Context, parentRound, round uint64, qc *rctypes.QuorumCert) bool
	// recoveryEligible judges a held exact-recovery candidate at the parent block (the manager's own when nil; replaced in tests)
	recoveryEligible func(*storage.ExecutedBlock, evmassign.Candidate) error
	// retained is the retained candidate of a body (the block store's when nil; replaced in tests)
	retained func(bodyID []byte) ([]byte, error)
	// resolved says whether the branch ending at the round has resolved (closed or acknowledged) the result (the block store's when nil; replaced in tests)
	resolved func(parentRound uint64, result [32]byte) bool
}

// vrOperator is the sender identity of the loopback operator endpoints.
const vrOperator = "operator"

// PullInterval is how often a root whose current intent holds no complete certificate pulls a peer's stage set.
const PullInterval = 5 * time.Second

// EnableVRHandoff installs the VR handoff root side on a VR-mode manager: the intent provider into the executor's VR services, the commit
// observer, the protocol service with its verification queue, and their workers (stopped with ctx). It must be called before the manager
// starts.
func (x *ConsensusManager) EnableVRHandoff(ctx context.Context, cfg VRHandoffConfig) error {
	svc := x.blockStore().PosServices()
	if svc == nil || svc.Registry == nil || cfg.Intents == nil || cfg.Reader == nil || cfg.Witness == nil {
		return fmt.Errorf("%w: the VR services, the intent provider, the VR reader and the witness builder are required", ErrVRHandoff)
	}
	if x.q3 == nil {
		return fmt.Errorf("%w: a VR handoff needs the verified Q3 history", ErrVRHandoff)
	}
	if cfg.Intents.Outputs == nil {
		cfg.Intents.Outputs = vrschedule.NewOutputs()
	}
	if cfg.Log == nil {
		cfg.Log = x.log
	}
	cfg.Intents.Config = x.q3.ProtocolConfig
	svc.Registry.Intents = cfg.Intents
	v := &vrHandoff{cfg: cfg, obsWake: make(chan struct{}, 1), obsq: func() observationQueue { return x.blockStore() }, prefetch: make(chan vrschedule.CertifiedEVM, 64),
		observer: &vrschedule.Observer{Reader: cfg.Reader, Sources: cfg.Intents.Sources, Outputs: cfg.Intents.Outputs, Log: cfg.Log,
			OnPending: func(a []vrschema.Activation) { x.notePending(a, x.InstalledRootEpoch()) }}}
	v.svc = vrschedule.NewService(vrschedule.ServiceConfig{Self: x.id.String(), Signer: cfg.Signer, Log: cfg.Log, Send: func(m vrschedule.Message) { v.send(ctx, m) }})
	v.queue = vrschedule.NewQueue(v.svc, cfg.PiMax)
	v.kick = make(chan struct{}, 1)
	v.queue.Delivered = func(o vrschedule.Outcome, _ []vrschedule.Message, err error) {
		if err != nil && o != vrschedule.Duplicate {
			cfg.Log.Debug("VR handoff: a message is not retained", "outcome", o.String(), "error", err)
		}
		if o == vrschedule.Retained {
			v.wake() // an assembly may be the member's cue
		}
	}
	if cfg.Member != nil {
		m, err := vrschedule.NewMember(v.svc, vrschedule.MemberConfig{Self: x.id.String(), RootSigner: cfg.Signer, EVMSigner: cfg.Member.EVMSigner, EVMPoP: cfg.Member.EVMPoP,
			Path: cfg.Member.Path, Send: func(m vrschedule.Message) { v.send(ctx, m) }, Supports: cfg.Member.Supports, Hold: cfg.Member.Hold, EVMNodeID: cfg.Member.EVMNodeID, Stage: x.stageVRCandidate, Log: cfg.Log})
		if err != nil {
			return err
		}
		v.member = m
	}
	// a service round serves only the senders of one membership snapshot: the service's members of its last committed update (the installed
	// committee, K and the current intent's successors) and the local operator
	v.queue.Admission = func() map[string]bool {
		m, ok := v.svc.Membership()
		if !ok {
			return nil // no committed membership yet (the queue starts before the first commit): nothing is pruned
		}
		m[vrOperator] = true
		return m
	}
	v.peers = func() []peer.ID { return x.vrPeers(v) }
	v.stageIntent = x.stageVRIntentMembers
	v.incumbents = func() ([]vrschedule.WeightedPeer, uint64) {
		tb := x.trustBase.Load() // one snapshot: the peers and the total weight must come from the same committee
		var out []vrschedule.WeightedPeer
		var total uint64
		for _, n := range tb.RootNodes {
			if n == nil {
				continue
			}
			total += n.Stake
			id, err := peer.Decode(n.NodeID)
			if err != nil || id == x.id {
				continue
			}
			out = append(out, vrschedule.WeightedPeer{ID: id, Weight: n.Stake})
		}
		return out, total
	}
	cfg.Intents.MissingSource = func(r vrschema.Word) { v.fetchSource(ctx, [32]byte(r)) }
	v.update = x.vrCommitted
	v.now = time.Now
	// through the accessor at each call: the manager replaces its block store (recovery, an epoch switch)
	v.opening = func() (storage.VROpening, bool, error) { return x.blockStore().CommittedVROpening() }
	v.queryAt = func(b *storage.ExecutedBlock) (storage.VRIntentQuery, bool, error) {
		return x.blockStore().VRQueryAt(b)
	}
	v.derive = cfg.Intents.DeriveCached // the leader's checks never wait on the execution client (review #1188 B9)
	v.leader = vrschedule.LeaderRecords
	v.reject = x.preferRejection
	// a HandoffView is judged over its parent, normally executed but not yet committed: VR's output there is prefetched when the parent is
	// executed, and read on demand (bounded) when the judgment comes first
	reader := cfg.Reader
	cfg.Intents.Fetch = func(blockHash, stateRoot [32]byte) (*vrhandoff.Output, error) {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return reader.OpenOutput(c, blockHash, stateRoot)
	}
	x.vr = v
	v.attach(x.blockStore())
	go v.run(ctx)
	go v.prefetchRun(ctx)
	go v.queue.Run(ctx)
	if cfg.ShardStaged != nil {
		if stamp, ok := initShardStaging(cfg); ok {
			v.shardKick = make(chan struct{}, 1)
			v.shardStamp, v.shardPersisted = stamp, stamp // continue above every stamp an earlier run issued
			v.setShardStaged(0, nil)                      // reconcile at start: the desired state is nothing staged until an intent derives
			go v.shardStagedRun(ctx)
		}
	}
	if v.member != nil {
		go v.memberRun(ctx)
	}
	return nil
}

func (v *vrHandoff) wake() {
	select {
	case v.kick <- struct{}{}:
	default:
	}
}

// memberRun does the node's member steps whenever the committed state or a retained message gives a cue, and every second (the re-sends).
func (v *vrHandoff) memberRun(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-v.kick:
		}
		if err := v.member.Step(); err != nil {
			if e := err.Error(); e != last {
				last = e
				v.cfg.Log.Warn("VR handoff member: a step failed (retried)", "error", err)
			}
		} else {
			last = ""
		}
	}
}

// onExecuted queues VR's output at an executed block's certified EVM state for prefetching (never blocking consensus).
func (v *vrHandoff) onExecuted(b *storage.ExecutedBlock) {
	if b == nil || b.BlockData == nil {
		return
	}
	si := b.ShardState.States[v.cfg.EVM]
	if si == nil || si.IR == nil || len(si.IR.BlockHash) != 32 || len(si.IR.Hash) != 32 {
		return
	}
	if _, ok := v.cfg.Intents.Outputs.At([32]byte(si.IR.Hash)); ok {
		return
	}
	select {
	case v.prefetch <- vrschedule.CertifiedEVM{BlockHash: [32]byte(si.IR.BlockHash), StateRoot: [32]byte(si.IR.Hash)}:
	default:
	}
}

func (v *vrHandoff) prefetchRun(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-v.prefetch:
			if _, ok := v.cfg.Intents.Outputs.At(c.StateRoot); ok {
				continue
			}
			rc, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, err := v.cfg.Reader.OpenOutput(rc, c.BlockHash, c.StateRoot)
			cancel()
			if err == nil {
				v.cfg.Intents.Outputs.Put(c.StateRoot, out)
			}
		}
	}
}

// VRServices are the VR-mode collaborators installed into the control executor (nil on a root that is not in VR mode).
func (x *ConsensusManager) VRServices() *storage.VRServices {
	if svc := x.blockStore().PosServices(); svc != nil {
		return svc.Registry
	}
	return nil
}

// VRService is the protocol service, for the peer protocol's server.
func (x *ConsensusManager) VRService() (*vrschedule.Service, *vrschedule.Queue) {
	if x.vr == nil {
		return nil, nil
	}
	return x.vr.svc, x.vr.queue
}

// vrPeers are the peers this root's messages go to: the incumbents and the current intent's successor and K roots, without itself.
func (x *ConsensusManager) vrPeers(v *vrHandoff) []peer.ID {
	seen := map[string]bool{x.id.String(): true}
	var out []peer.ID
	add := func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		if p, err := peer.Decode(id); err == nil {
			out = append(out, p)
		}
	}
	for _, n := range x.trustBase.Load().RootNodes {
		add(n.NodeID)
	}
	for id := range v.svc.Members() {
		add(id)
	}
	return out
}

func (v *vrHandoff) send(ctx context.Context, m vrschedule.Message) {
	if v.cfg.Opener == nil {
		return
	}
	peers := v.peers()
	go func() {
		if err := vrschedule.Push(ctx, v.cfg.Opener, peers, m); err != nil {
			v.cfg.Log.Debug("VR handoff: a message did not reach every peer", "error", err)
		}
	}()
}

// observationQueue is the durable queue of certified EVM observations the block store writes in the commit transaction.
type observationQueue interface {
	PendingObservations(max int) ([]storage.ObservationInput, storage.ObservationCursor, error)
	AckObservation(round uint64, cursor storage.ObservationCursor) error
}

// attach connects a block store to the handoff: it queues the designated EVM shard's certified blocks at every commit, in the commit
// transaction, and wakes the worker; the execution observer prefetches.
func (v *vrHandoff) attach(bs *storage.BlockStore) {
	bs.SetObservedShard(v.cfg.EVM)
	bs.SetCommitObserver(v.onCommit)
	bs.SetExecutionObserver(v.onExecuted)
}

// onCommit wakes the worker (never blocking consensus). It carries nothing: the committed blocks' observations are already durable in the
// queue, so a dropped wakeup loses nothing (the worker also polls).
func (v *vrHandoff) onCommit(_ []*storage.ExecutedBlock) { v.obsWakeup() }

func (v *vrHandoff) obsWakeup() {
	select {
	case v.obsWake <- struct{}{}:
	default:
	}
}

// ObservePoll is how often the worker looks at the queue without a wakeup, and the bounds of its backoff after a failed read.
const (
	ObservePoll       = 3 * time.Second
	observeBackoffMin = 500 * time.Millisecond
	observeBackoffMax = 10 * time.Second
)

// run consumes the durable observation queue in order (stage 0), then updates the protocol over the committed state; after its first update
// a (re)started root rebuilds its view state from its peers (GetStage).
func (v *vrHandoff) run(ctx context.Context) {
	backoff := observeBackoffMin
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-v.obsWake:
		case <-timer.C:
		}
		ok := v.drain(ctx)
		v.refresh(ctx)
		wait := ObservePoll
		if !ok {
			wait = backoff
			if backoff *= 2; backoff > observeBackoffMax {
				backoff = observeBackoffMax
			}
		} else {
			backoff = observeBackoffMin
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// drain observes every queued entry in commit order. An entry is acknowledged only after its outcome (a recorded source, an awaiting item,
// or nothing to record) is durable; a failed read leaves it queued, and the next pass (after a backoff, never giving up) replays from it. It
// reports whether the queue was fully drained.
func (v *vrHandoff) drain(ctx context.Context) bool {
	q := v.obsq()
	if q == nil {
		return true
	}
	for {
		entries, cursor, err := q.PendingObservations(64)
		if err != nil {
			v.cfg.Log.Debug("VR handoff: the observation queue is not readable", "error", err)
			return true // a store without a queue (tests): nothing to drain
		}
		if !v.resumed {
			if cursor.Set {
				v.observer.Resume(cursor.Round, vrschema.Word(cursor.Prev))
			}
			v.resumed = true
		}
		if len(entries) == 0 {
			v.statMu.Lock()
			v.observeErr = 0
			v.statMu.Unlock()
			return true
		}
		for _, e := range entries {
			c := vrschedule.CertifiedEVM{RootRound: e.RootRound, ParentRound: e.ParentRound, RootUCTime: e.RootUCTime, BlockHash: e.BlockHash, StateRoot: e.StateRoot, ShardRound: e.ShardRound}
			if err := v.observer.Observe(ctx, c); err != nil {
				v.statMu.Lock()
				v.observeErr++
				v.statMu.Unlock()
				v.cfg.Log.Warn("VR handoff: observing a certified EVM block failed; it stays queued and is retried", "shardRound", c.ShardRound, "rootRound", c.RootRound, "error", err)
				return false
			}
			round, prev := v.observer.Cursor()
			if err := q.AckObservation(e.RootRound, storage.ObservationCursor{Set: true, Round: round, Prev: [32]byte(prev)}); err != nil {
				v.cfg.Log.Warn("VR handoff: acknowledging an observation failed; it stays queued", "rootRound", c.RootRound, "error", err)
				return false
			}
		}
		v.statMu.Lock()
		v.observeErr = 0
		v.statMu.Unlock()
	}
}

func (v *vrHandoff) refresh(ctx context.Context) {
	c, err := v.update()
	if err != nil {
		v.cfg.Log.Debug("VR handoff: the committed intent is not derivable here yet", "error", err)
		return
	}
	v.svc.Update(c)
	v.stagedMembers(c)
	v.wake()
	if c.Prepared && c.FrozenParent != ([32]byte{}) {
		if p, ok := v.svc.Prepared(); ok {
			// in the background: the commit worker never waits on the execution client (review #1188 B8); fetchWitness de-duplicates
			go v.fetchWitness(ctx, c.FrozenParent, c.FrozenRoot, p)
		}
	}
	v.pull(ctx)
}

// pull starts a stage pull when one is due (never more than one at a time, never on the commit worker): after a (re)start from every peer
// until one answers, then while the current intent holds no complete certificate from one peer at a time every PullInterval.
func (v *vrHandoff) pull(ctx context.Context) {
	intent, view, complete, ok := v.svc.Current()
	complete = !v.svc.ExchangeOpen() // open while no certificate is held, or while the plan still waits for K support; a prepared root pulls only to recover the certificate
	if !ok || v.cfg.Opener == nil {
		return
	}
	v.pmu.Lock()
	now := v.now()
	due := !v.pulling && (!v.restored || (!complete && now.Sub(v.lastPull) >= PullInterval))
	if !due {
		v.pmu.Unlock()
		return
	}
	v.pulling, v.lastPull = true, now
	restoring := !v.restored
	peers := v.peers()
	slices.Sort(peers) // a stable order: the periodic pull goes round the peers
	if !restoring && len(peers) > 0 {
		peers = []peer.ID{peers[v.pullNext%len(peers)]}
		v.pullNext++
	}
	v.pmu.Unlock()
	from := uint64(0)
	if view >= vrschedule.RetainedViews {
		from = view - vrschedule.RetainedViews + 1
	}
	go func() {
		answered := v.pullFrom(ctx, peers, intent, from)
		v.pmu.Lock()
		defer v.pmu.Unlock()
		v.pulling = false
		if answered {
			v.restored = true
		}
	}()
}

// PullFanOut is how many peers a restore pull asks at once.
const PullFanOut = 4

// pullFrom asks the peers, PullFanOut at a time, for their stage sets of intent until a complete certificate is held, and offers each set's
// messages in order (proofs, assemblies, readiness) as that peer's; a set is abandoned at its first refused message. A peer that stalls
// holds one slot for at most the stream deadline. It reports whether any peer answered. The verifications of a pulled set run here, outside
// the verification queue; the per-sender allowances bound them.
func (v *vrHandoff) pullFrom(ctx context.Context, peers []peer.ID, intent [32]byte, from uint64) bool {
	var answered atomic.Bool
	sem := make(chan struct{}, PullFanOut)
	var wg sync.WaitGroup
	for _, p := range peers {
		if !v.svc.ExchangeOpen() {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p peer.ID) {
			defer func() { <-sem; wg.Done() }()
			set, err := vrschedule.GetStage(ctx, v.cfg.Opener, p, intent, from)
			if err != nil {
				return
			}
			answered.Store(true)
			for _, m := range set.Offers() {
				if o, _, _ := v.svc.Offer(p.String(), m); o == vrschedule.Refused {
					v.cfg.Log.Debug("VR handoff: a peer's stage set holds a refused message", "peer", p.String())
					return
				}
			}
		}(p)
	}
	wg.Wait()
	return answered.Load()
}

// vrCommitted is what the protocol learns from the committed root block: the derived intent, its committed view, a committed Prepare of its
// attempt, the incumbents, K, the committed support table and schedule.
func (x *ConsensusManager) vrCommitted() (vrschedule.Committed, error) {
	var c vrschedule.Committed
	q, on, err := x.blockStore().CommittedVRQuery()
	if err != nil || !on {
		return c, errors.Join(ErrVRHandoff, errors.New("no committed VR state"), err)
	}
	s, err := vradmit.DecodeRootState(q.Control.VR)
	if err != nil {
		return c, err
	}
	d, ok, err := x.vr.cfg.Intents.Derive(q)
	x.vr.noteDerive(err)
	if err != nil {
		return c, err
	}
	// the membership the protocol admits is of this one committed state, derivable or not: the committee of its epoch and K. Without both,
	// complete and of the state's epoch, nothing is published, and the service keeps its last good membership (astra review of #1188, r5)
	var facts storage.VRRootFacts
	var store trustBasesByEpoch
	if x.trustBaseStore != nil {
		store = x.trustBaseStore
	}
	c.Incumbents, facts, err = vrMembership(q, x.trustBase.Load(), store)
	if err != nil {
		return c, err
	}
	c.K, c.Schedule = facts.Lifecycle.Incumbent, facts.Fold.Schedule
	x.noteSchedule(c.Schedule, q.Epoch) // the warning and the gauge, from the moment the committed schedule holds an entry this binary lacks
	c.Table = s.Support
	c.Derived, c.Derivable = d, ok
	if !ok {
		return c, nil
	}
	if bytes.Equal(s.Backoff.Intent, d.Digest[:]) {
		c.CommittedView = s.Backoff.LastView
	}
	c.Prepared = s.Backoff.Prepared
	if c.Prepared && len(q.Control.FrozenParent) == 32 && q.LatestEVMOK && bytes.Equal(q.LatestEVMBlock, q.Control.FrozenParent) {
		c.FrozenParent, c.FrozenRoot = [32]byte(q.Control.FrozenParent), q.LatestEVMRoot
	}
	return c, nil
}

// trustBasesByEpoch is the trust-base store's lookup.
type trustBasesByEpoch interface {
	GetByEpoch(epoch uint64) (*types.RootTrustBaseV1, error)
}

// vrMembership is the membership a committed VR state names: the root committee of its epoch (from the store, or the live trust base only
// when it is of that epoch) and its root facts (K, the schedule). It fails rather than guess a committee of another epoch or an empty K.
func vrMembership(q storage.VRIntentQuery, live *types.RootTrustBaseV1, store trustBasesByEpoch) (map[string][]byte, storage.VRRootFacts, error) {
	var tb *types.RootTrustBaseV1
	if store != nil {
		if byEpoch, err := store.GetByEpoch(q.Epoch); err == nil && byEpoch != nil {
			tb = byEpoch
		}
	}
	if tb == nil && live != nil && live.Epoch == q.Epoch {
		tb = live
	}
	if tb == nil || tb.Epoch != q.Epoch {
		return nil, storage.VRRootFacts{}, fmt.Errorf("%w: no root committee of epoch %d", ErrVRHandoff, q.Epoch)
	}
	if q.Root == nil {
		return nil, storage.VRRootFacts{}, fmt.Errorf("%w: no root facts of the committed state", ErrVRHandoff)
	}
	facts, err := q.Root()
	if err != nil {
		return nil, storage.VRRootFacts{}, errors.Join(ErrVRHandoff, err)
	}
	incumbents := map[string][]byte{}
	for _, n := range tb.RootNodes {
		incumbents[n.NodeID] = bytes.Clone(n.SigKey)
	}
	return incumbents, facts, nil
}

// VRIntentView is the intent this root derives over its committed state, for the operator: the intent, its digest, the root epoch it
// succeeds, the incumbents in assembler order and the assembler of the committed current view.
type VRIntentView struct {
	Intent     vrhandoff.Intent
	Digest     [32]byte
	RootEpoch  uint64
	View       uint64
	Incumbents []string
	Assembler  string
}

func (x *ConsensusManager) vrDerived() (vrschedule.Derived, map[string][]byte, error) {
	if x.vr == nil {
		return vrschedule.Derived{}, nil, fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	q, on, err := x.blockStore().CommittedVRQuery()
	if err != nil || !on {
		return vrschedule.Derived{}, nil, errors.Join(ErrVRHandoff, errors.New("no committed VR state"), err)
	}
	d, ok, err := x.vr.cfg.Intents.Derive(q)
	if err != nil {
		return d, nil, errors.Join(ErrVRHandoff, err)
	}
	if !ok {
		return d, nil, fmt.Errorf("%w: no intent is derivable over the committed state", ErrVRHandoff)
	}
	keys := map[string][]byte{}
	for _, n := range x.trustBase.Load().RootNodes {
		keys[n.NodeID] = bytes.Clone(n.SigKey)
	}
	return d, keys, nil
}

// VRIntent is the current intent over the committed state.
func (x *ConsensusManager) VRIntent() (VRIntentView, error) {
	d, keys, err := x.vrDerived()
	if err != nil {
		return VRIntentView{}, err
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	view := uint64(0)
	if s, ok, _ := x.blockStore().CommittedVRState(); ok && bytes.Equal(s.Backoff.Intent, d.Digest[:]) {
		view = s.Backoff.LastView
	}
	order := vrhandoff.AssemblerOrder(d.Digest, ids)
	return VRIntentView{Intent: d.Intent, Digest: d.Digest, RootEpoch: d.RootEpoch, View: view, Incumbents: order, Assembler: vrschema.Assembler(order, view)}, nil
}

// VRBody is the successor body and the successor trust base an assembled candidate of the current intent determines (what each member's
// readiness signs). The candidate must be the intent's unsigned candidate with valid possession proofs.
func (x *ConsensusManager) VRBody(candidate []byte) (q3format.BodyV3, []byte, error) {
	d, _, err := x.vrDerived()
	if err != nil {
		return q3format.BodyV3{}, nil, err
	}
	if _, err := vrhandoff.VerifyAssembly(d.Intent, vrhandoff.Assembly{IntentDigest: d.Digest[:], Candidate: candidate}); err != nil {
		return q3format.BodyV3{}, nil, errors.Join(ErrVRHandoff, err)
	}
	body, err := vrhandoff.DeriveBody(d.Intent, d.RootEpoch, sha256.Sum256(candidate), d.Body)
	if err != nil {
		return body, nil, errors.Join(ErrVRHandoff, err)
	}
	_, tb, err := vrhandoff.TrustBase(d.Intent, d.RootEpoch)
	return body, tb, errors.Join(err)
}

// OfferVRMessage submits one protocol message as a member (or the operator on its behalf) would send it: verified in the queue like any
// peer's.
func (x *ConsensusManager) OfferVRMessage(m vrschedule.Message) error {
	if x.vr == nil {
		return fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	if !x.vr.queue.Submit(vrOperator, m) {
		return fmt.Errorf("%w: the verification queue is full", ErrVRHandoff)
	}
	return nil
}

// VRStage is this root's retained stage set of the current intent from a view on.
func (x *ConsensusManager) VRStage(fromView uint64) (vrschedule.StageSet, [32]byte, error) {
	if x.vr == nil {
		return vrschedule.StageSet{}, [32]byte{}, fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	intent, _, _, ok := x.vr.svc.Current()
	if !ok {
		return vrschedule.StageSet{}, intent, fmt.Errorf("%w: no current intent", ErrVRHandoff)
	}
	set, _ := x.vr.svc.Stage(intent, fromView)
	return set, intent, nil
}

// SubmitVRCertificate offers a complete view certificate's assembly and readiness to the protocol (an operator path): each is verified
// as any peer's; the first complete certificate of the intent is retained.
func (x *ConsensusManager) SubmitVRCertificate(c vrschema.ViewCertificate) error {
	if x.vr == nil {
		return fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	a := c.Assembly
	if o, _, err := x.vr.svc.Offer(vrOperator, vrschedule.Message{Assembly: &a}); o != vrschedule.Retained && o != vrschedule.Duplicate {
		return errors.Join(fmt.Errorf("%w: the assembly is %s", ErrVRHandoff, o.String()), err)
	}
	for i := range c.Readiness {
		r := c.Readiness[i]
		if o, _, err := x.vr.svc.Offer(vrOperator, vrschedule.Message{Readiness: &r}); o != vrschedule.Retained && o != vrschedule.Duplicate {
			return errors.Join(fmt.Errorf("%w: readiness %d is %s", ErrVRHandoff, i, o.String()), err)
		}
	}
	if _, _, complete, _ := x.vr.svc.Current(); !complete {
		return fmt.Errorf("%w: the certificate does not complete the view", ErrVRHandoff)
	}
	return nil
}

// vrRecordsForRound is the leader's handoff record of a VR chain for the round (vrschedule.LeaderRecords): the Prepare of the planned
// certificate (proposer priority: a due rejection first), its Freeze v5 once the Prepare bound the frozen parent, then H. A Prepare is
// ordered only for a plan whose intent is still the one derivable at this parent and whose activation time gate holds; the Freeze reads
// the witness from the cache the commit of the Prepare filled (the proposal path never waits on the execution client).
func (x *ConsensusManager) vrRecordsForRound(round uint64, parent *storage.ExecutedBlock, parentQC *rctypes.QuorumCert) ([][]byte, error) {
	control := parent.ShardState.Control
	v := x.vr
	if control == nil {
		return nil, nil
	}
	plan, ok := v.svc.Plan()
	if control.Phase == "prepared" || control.Phase == "endorsed" {
		plan, ok = v.svc.Prepared()
	}
	if !ok {
		return nil, nil
	}
	step, err := v.leader(plan, parent, round, v.cfg.EVM, func(p, root [32]byte) ([]byte, error) { return v.witnessAt(p, root, plan) }, x.params.HashAlgorithm)
	if err != nil {
		x.log.Warn("VR handoff: no handoff record ordered", "round", round, "attempt", plan.Attempt, "error", err)
		return nil, nil
	}
	if step.Kind == "" {
		if step.Reason == vrschedule.ReasonOtherBody {
			// review #1188 B13: this root's I-RET certificate is of another view's body than the committed Prepare's; only roots holding
			// the prepared body order its Freeze
			x.log.Info("VR handoff: the prepared body is not this root's certificate; another leader orders its Freeze", "round", round,
				"attempt", plan.Attempt)
			return nil, nil
		}
		x.log.Debug("VR handoff: no handoff record ordered", "round", round, "reason", step.Reason)
		return nil, nil
	}
	if step.Kind == "prepare" {
		// the planned certificate's intent must still be the one derivable at this parent (it may have died for a reason the epoch and
		// attempt do not show: R no longer open, another fold or schedule); judged from the cache only (a miss: not this round)
		q, on, qerr := v.queryAt(parent)
		if qerr != nil || !on {
			return nil, nil
		}
		d, derivable, derr := v.derive(q)
		if derr != nil || !derivable || d.Digest != plan.Intent {
			x.log.Debug("VR handoff: the planned intent is not the one derivable at this parent", "round", round, "error", derr)
			return nil, nil
		}
		// A result the branch already resolved (a recovery superseded it, or it was acknowledged) is never prepared again, though VR's output on the
		// EVM may still read Published until the EVM imports the record that resolved it: a Prepare freezes that very EVM, so it would keep the
		// record from ever arriving, and its Freeze is refused (#1221 live run).
		if rid := d.Intent.Source.ResultID; len(rid) == 32 {
			resolved := func(r uint64, id [32]byte) bool { return x.blockStore().RejectionResolved(r, id) }
			if v.resolved != nil {
				resolved = v.resolved
			}
			if resolved(parentQC.GetRound(), [32]byte(rid)) {
				x.log.Info("VR handoff: the planned result is already resolved at this parent; no Prepare", "round", round, "attempt", plan.Attempt)
				return nil, nil
			}
		}
		// the activation time gate (design 7.1): the Prepare's UC time is at least T of every effective schedule with E <= e_J + 1
		if q.Root != nil {
			if facts, ferr := q.Root(); ferr == nil &&
				vrschema.PrepareTimeGate(control.Epoch+1, uint64(types.NewTimestamp()), vrschema.Effective(facts.Fold.Schedule)) != nil {
				return nil, nil
			}
		}
		if v.reject(context.Background(), parentQC.GetRound(), round, parentQC) {
			return nil, nil
		}
	}
	x.log.Info("VR handoff: ordering the "+step.Kind, "round", round, "attempt", plan.Attempt, "view", plan.Certificate.Assembly.Slot)
	return step.Records, nil
}

// witnessAt is the Freeze witness at the frozen parent, from the cache only: the proposal path never waits on the execution client. A miss
// starts the fetch in the background (normally it is already done: refresh fetches it once the Prepare commits).
func (v *vrHandoff) witnessAt(p, root [32]byte, h vrschedule.PreparePlan) ([]byte, error) {
	v.wmu.Lock()
	if v.witness.payload != nil && v.witness.at == p && v.witness.intent == h.Intent {
		w := v.witness.payload
		v.wmu.Unlock()
		return w, nil
	}
	v.wmu.Unlock()
	go v.fetchWitness(context.Background(), p, root, h)
	return nil, errors.New("the Freeze witness is being fetched")
}

// fetchWitness reads the Freeze witness at the frozen parent once (concurrent calls do not repeat it) and caches it.
func (v *vrHandoff) fetchWitness(ctx context.Context, p, root [32]byte, h vrschedule.PreparePlan) {
	v.wmu.Lock()
	if v.fetching || (v.witness.payload != nil && v.witness.at == p && v.witness.intent == h.Intent) {
		v.wmu.Unlock()
		return
	}
	v.fetching = true
	v.wmu.Unlock()
	defer func() {
		v.wmu.Lock()
		v.fetching = false
		v.wmu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	w, err := v.cfg.Witness(ctx, p, root, h.Result)
	if err != nil {
		v.cfg.Log.Warn("VR handoff: the Freeze witness at the frozen parent is unavailable", "error", err)
		return
	}
	v.wmu.Lock()
	v.witness.at, v.witness.intent, v.witness.payload = p, h.Intent, w
	v.wmu.Unlock()
}

// orderHandoffView adds the next HandoffView to a proposal that orders no handoff record (proposer priority: a Prepare is preferred), once
// the leader's own residence wait for the committed opening has passed and the trial execution over the parent (the replay rule) admits
// it. The voters apply the same residence rule before voting.
func (x *ConsensusManager) orderHandoffView(ctx context.Context, block *rctypes.BlockData) {
	x.orderHandoffViewWith(ctx, block, func(b *rctypes.BlockData) error { return x.blockStore().TrialExecute(b, x.irReqVerifier) })
}

func (x *ConsensusManager) orderHandoffViewWith(ctx context.Context, block *rctypes.BlockData, trialExecute func(*rctypes.BlockData) error) {
	if x.vr == nil || block == nil || block.Payload == nil || len(block.Payload.HandoffRecords) != 0 || len(block.Payload.PosControls) >= rctypes.MaxPosControls {
		return
	}
	if _, ok := x.vr.svc.Plan(); ok {
		return // a complete verified certificate: the Prepare comes first, never another view
	}
	o, on, err := x.vr.opening()
	if err != nil || !on {
		return
	}
	b := o.State.Backoff
	if b.Prepared || b.Settled {
		return
	}
	var intent [32]byte
	switch {
	case b.LastView != 0:
		copy(intent[:], b.Intent)
	case o.IntentOK:
		intent = o.Intent.Digest
	default:
		return
	}
	view := b.LastView + 1
	now := x.residenceNow()
	if x.residence == nil {
		x.residence = newVRResidence(now)
	}
	if wait, held, ok := x.residence.wait(o, intent, view, now); !ok || !held || wait != 0 {
		return
	}
	d := x.vr.cfg.Intents.Deployment
	c := rctypes.PosControl{Registry: true, Network: d.RootNetwork, ChainID: d.ChainID, Custody: d.Registry, OrderingEpoch: block.Epoch, OrderingRound: block.Round,
		Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: intent, View: view}}
	trial := *block
	payload := *block.Payload
	payload.PosControls = append(append([]rctypes.PosControl(nil), payload.PosControls...), c)
	trial.Payload = &payload
	if err := trialExecute(&trial); err != nil {
		x.log.DebugContext(ctx, "VR handoff: the next view is not due at this parent", "view", view, "error", err)
		return
	}
	block.Payload = trial.Payload
	x.log.InfoContext(ctx, "VR handoff: proposing HandoffView", "intent", fmt.Sprintf("%x", intent[:8]), "view", view)
}

// stageVRCandidate stages the candidate of a verified assembly of the current intent on this node (VT-09): the successor body, its candidate
// digest and attempt, and the successor's EVM validators and roots, so that a joiner keeps the successor committee connected before the
// commit (#1133, #1086) and the node reports what it has staged. The service has verified the assembly in full and derived the body from the
// intent; here only what this chain's epoch makes of it is checked: the next epoch of this chain, its protocol configuration, and this node
// among the successors. Staging never signs and never activates.
func (x *ConsensusManager) stageVRCandidate(s vrschedule.Staged) error {
	v := x.vr
	if v == nil {
		return fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	v.stageMu.Lock()
	defer v.stageMu.Unlock()
	if !v.haveActive || v.activeIntent != s.Intent {
		return fmt.Errorf("%w: the intent this candidate belongs to is no longer the active one", ErrVRHandoff)
	}
	install := v.installCandidate
	if install == nil {
		install = x.installVRCandidate
	}
	if err := install(s); err != nil {
		return err
	}
	// this write is owned like the intent-level one: it is recorded so that the intent's end clears it, whichever writer installed the set
	v.intentStaged, v.stagedFor = true, s.Intent
	return nil
}

// installVRCandidate writes the staged members and candidate digest of a verified candidate (under the operator barrier).
func (x *ConsensusManager) installVRCandidate(s vrschedule.Staged) error {
	return x.operator(func() error {
		if x.q3 == nil {
			return fmt.Errorf("%w: no Q3 history to stage into", ErrVRHandoff)
		}
		cfg, err := x.q3.ProtocolConfig()
		if err != nil {
			return errors.Join(ErrVRHandoff, err)
		}
		old := x.trustBase.Load()
		b := s.Body
		if old == nil || b.Config != cfg || b.Network != uint64(old.NetworkID) || b.Epoch != old.Epoch+1 {
			return fmt.Errorf("%w: the candidate is not the next epoch of this chain", ErrVRHandoff)
		}
		self := false
		for _, m := range b.Members {
			self = self || m.NodeID == x.id.String()
		}
		if !self {
			return fmt.Errorf("%w: this node is not a member of the successor committee", ErrVRHandoff)
		}
		ids, roots := devStagedExtras(s.Identities, b.Members)
		x.storeStagedEVM(b.Epoch, evmassign.Candidate{Identities: ids}, roots)
		x.q3Staged.Store(&Q3Staged{CandidateDigest: s.CandidateDigest, BodyID: b.Identity(), Attempt: s.Attempt, Config: b.Config.Identity()})
		return nil
	})
}

// stagedMembers keeps the successor the committed intent names staged on this node from the intent's derivation on (VT-09, #1133, #1086): the
// incumbents then admit a joiner's root and EVM node (the proposal gate, the frontier and records services, the acquisition) before any
// assembly exists, which a joiner needs to follow the committed chain and derive the intent itself, and every member keeps the successor
// committee connected. An intent that is no longer derivable clears what it staged. The assembly's verified candidate replaces it with its
// digest and body (stageVRCandidate); the members are the same.
func (v *vrHandoff) stagedMembers(c vrschedule.Committed) {
	if v.stageIntent == nil {
		return
	}
	v.stageMu.Lock()
	defer v.stageMu.Unlock()
	if !c.Derivable {
		v.haveActive = false
		// nothing, but in the vrdev build the development hook's extras (for the first assignment: the dev lanes' shard epoch is 0)
		extras := devShardExtras(nil)
		var extraEpoch uint64
		if len(extras) > 0 {
			extraEpoch = 1
		}
		v.setShardStaged(extraEpoch, extras)
		if v.intentStaged {
			// cleared once the clearing is installed: a refused call is tried again at the next refresh
			if v.stageIntent(0, nil, nil) == nil {
				v.intentStaged = false
			}
		}
		return
	}
	v.activeIntent, v.haveActive = c.Derived.Digest, true
	if v.intentStaged && v.stagedFor == c.Derived.Digest {
		return
	}
	cand, err := vrhandoff.CandidateOf(c.Derived.Intent)
	if err != nil {
		return
	}
	evm := make([]string, 0, len(cand.Identities))
	for _, m := range cand.Identities {
		evm = append(evm, m.EVMNodeID)
	}
	v.setShardStaged(cand.OldShardEpoch+1, devShardExtras(evm))
	roots := make([]evmroot.Member, 0, len(cand.RootMembers))
	for _, m := range cand.RootMembers {
		roots = append(roots, evmroot.Member{NodeID: m.NodeID, StakingID: m.NodeID, ConsensusKey: m.Key, Weight: m.Weight})
	}
	// cached only once installed: an epoch mismatch or a refused operator call is tried again at the next refresh
	if err := v.stageIntent(c.Derived.RootEpoch+1, cand.Identities, roots); err == nil {
		v.intentStaged, v.stagedFor = true, c.Derived.Digest
	}
}

// stageVRIntentMembers stores the staged successor's members for the root epoch (nothing, with epoch 0, clears them). It never touches the
// digest a verified candidate staged (Q3Staged).
func (x *ConsensusManager) stageVRIntentMembers(epoch uint64, ids []evmassign.Identity, roots []evmroot.Member) error {
	return x.operator(func() error {
		if epoch == 0 {
			x.q3StagedEVM.Store(nil)
			x.q3Staged.Store(nil)
			return nil
		}
		if old := x.trustBase.Load(); old == nil || epoch != old.Epoch+1 {
			return fmt.Errorf("%w: the intent's successor is not the next epoch of this chain", ErrVRHandoff)
		}
		ids, roots = devStagedExtras(ids, roots)
		x.storeStagedEVM(epoch, evmassign.Candidate{Identities: ids}, roots)
		return nil
	})
}

// SourceRetry is how often a root asks for a source it still lacks.
const SourceRetry = 5 * time.Second

// fetchSource asks the incumbents for the committed source of r (once at a time, retried every SourceRetry) and records it when
// identical answers of incumbents carry weight above the faulty bound (vrschedule.SourceFaulty). It never blocks the derivation that found the source missing.
func (v *vrHandoff) fetchSource(ctx context.Context, r [32]byte) {
	if v.cfg.Opener == nil {
		return
	}
	v.srcMu.Lock()
	if v.srcBusy || time.Since(v.srcFetched[r]) < SourceRetry {
		v.srcMu.Unlock()
		return
	}
	if v.srcFetched == nil {
		v.srcFetched = map[[32]byte]time.Time{}
	}
	v.srcFetched[r], v.srcBusy = time.Now(), true
	v.srcMu.Unlock()
	peers, total := v.incumbents()
	go func() {
		defer func() { v.srcMu.Lock(); v.srcBusy = false; v.srcMu.Unlock() }()
		e, err := vrschedule.FetchSource(ctx, v.cfg.Opener, peers, r, total)
		if err != nil {
			v.cfg.Log.Debug("VR handoff: the source of a result is not available from the incumbents yet", "result", fmt.Sprintf("%x", r[:8]), "error", err)
			return
		}
		// a fetched height is never trusted (incumbents of an earlier build report the shard round): it is re-derived from the certified
		// block's header, and a source whose header cannot be resolved yet stays unrecorded and is fetched again
		hr, _ := v.cfg.Reader.(vrschedule.HeaderReader)
		if e, err = vrschedule.ResolveFetched(ctx, hr, e); err != nil {
			v.cfg.Log.Debug("VR handoff: a fetched source is not recorded: its height is not verified yet", "result", fmt.Sprintf("%x", r[:8]), "error", err)
			return
		}
		if _, err := v.cfg.Intents.Sources.Record(e); err != nil {
			v.cfg.Log.Warn("VR handoff: recording a fetched source failed", "error", err)
			return
		}
		v.cfg.Log.Info("VR handoff: the committed source of a result was fetched from the incumbents", "result", fmt.Sprintf("%x", r[:8]), "evmBlockNumber", e.EVMBlockNumber, "certRootRound", e.CertRootRound)
		v.wake()
	}()
}

func (v *vrHandoff) noteDerive(err error) {
	v.statMu.Lock()
	defer v.statMu.Unlock()
	if err != nil && errors.Is(err, vrschedule.ErrUnavailable) {
		v.deriveErr = err.Error()
		return
	}
	v.deriveErr = ""
}

// VRMemberStatus is what a node reports of its readiness to take part in a handoff: "catching up" while an input it needs is missing (it
// derives no intent and signs nothing), "ready" once it derives the intent from its own committed state and its own VR reads, and "idle" when
// there is no intent to derive.
type VRMemberStatus struct {
	State      string   `json:"state"` // "off", "idle", "catching up" or "ready"
	Reasons    []string `json:"reasons,omitempty"`
	Intent     string   `json:"intent,omitempty"`
	Successor  bool     `json:"successor,omitempty"`
	CommitView uint64   `json:"view,omitempty"`
}

// VRMemberStatus reports the member's state: catching up when this root is recovering the root chain, cannot read VR at the certified EVM blocks
// through its own execution client (it has not synced the EVM chain), or lacks the committed source of the open result.
func (x *ConsensusManager) VRMemberStatus() VRMemberStatus {
	v := x.vr
	if v == nil {
		return VRMemberStatus{State: "off"}
	}
	return v.memberStatus(x.recovery.InRecovery(), x.id.String())
}

func (v *vrHandoff) memberStatus(recovering bool, self string) VRMemberStatus {
	var reasons []string
	if recovering {
		reasons = append(reasons, "the root chain is being recovered from peers")
	}
	v.statMu.Lock()
	if v.observeErr > 0 {
		reasons = append(reasons, fmt.Sprintf("VR cannot be read at %d certified EVM blocks through this node's execution client: its EVM chain is not synced", v.observeErr))
	}
	if v.deriveErr != "" {
		reasons = append(reasons, v.deriveErr)
	}
	v.statMu.Unlock()
	intent, view, successor, ok := v.svc.SuccessorState(self)
	if ok && len(reasons) == 0 {
		return VRMemberStatus{State: "ready", Intent: fmt.Sprintf("%x", intent[:]), CommitView: view, Successor: successor}
	}
	if len(reasons) > 0 {
		return VRMemberStatus{State: "catching up", Reasons: reasons}
	}
	return VRMemberStatus{State: "idle"}
}

// setShardStaged records the successor's EVM node ids the paired shard node should hold, for the shard epoch that assignment would install
// (empty clears), under stageMu with the active intent. Each change gets a larger generation stamp.
func (v *vrHandoff) setShardStaged(shardEpoch uint64, ids []string) {
	if v.shardKick == nil {
		return
	}
	if slices.Equal(v.shardDesired, ids) && v.shardEpoch == shardEpoch && v.shardVer > 0 {
		return
	}
	v.shardDesired, v.shardEpoch = slices.Clone(ids), shardEpoch
	v.shardVer++
	v.shardStamp = max(uint64(time.Now().UnixNano()), v.shardStamp+1)
	select {
	case v.shardKick <- struct{}{}:
	default:
	}
}

// shardStagedResend is how often the desired set is delivered again although it was accepted: a shard node that restarted since holds nothing
// until it is told again, and a root that restarted reconciles at its first tick (its desired state at start is "nothing staged").
const shardStagedResend = 30 * time.Second

// shardStagedRun delivers the desired staged set to the paired shard node, retrying every few seconds until it is accepted and again every
// shardStagedResend (both sides reconcile after a restart: the root's first delivery is its desired state at start, a clear until an intent
// derives). Delivery is in order and latest-wins by generation: a set an intent replaced or cleared meanwhile is never installed after its
// replacement, even by a delayed request, because the shard checks the stamp.
func (v *vrHandoff) shardStagedRun(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-v.shardKick:
		}
		v.stageMu.Lock()
		ids, epoch, stamp, ver, done, last := slices.Clone(v.shardDesired), v.shardEpoch, v.shardStamp, v.shardVer, v.shardDone, v.shardLast
		persisted := v.shardPersisted
		v.stageMu.Unlock()
		if ver == done && time.Since(last) < shardStagedResend {
			continue
		}
		// the generation is durable before it is sent: a restart never issues a stamp at or below one the shard accepted. A failed write sends
		// nothing and is retried at the next tick (an unchanged set does not skip it: persisted lags the stamp until a write succeeds).
		if v.cfg.ShardStampPath != "" && persisted < stamp {
			if err := writeStamp(v.cfg.ShardStampPath, stamp); err != nil {
				v.cfg.Log.Warn("VR handoff: the staging generation counter could not be persisted; nothing is sent until it is (retried)", "error", err)
				continue
			}
			v.stageMu.Lock()
			v.shardPersisted = max(v.shardPersisted, stamp)
			v.stageMu.Unlock()
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := v.cfg.ShardStaged(c, epoch, stamp, ids)
		cancel()
		if err != nil {
			v.cfg.Log.Debug("VR handoff: the paired shard node did not take the staged successor (retried)", "error", err)
			continue
		}
		v.stageMu.Lock()
		if v.shardDone < ver {
			v.shardDone = ver
		}
		v.shardLast = time.Now()
		v.stageMu.Unlock()
		if ver != done {
			v.cfg.Log.Info("VR handoff: the paired shard node holds the staged successor", "evmNodes", len(ids))
		}
	}
}

// readStamp is the persisted generation counter. A missing file is a fresh install (zero, no error); a file that exists but cannot be read or
// does not hold a counter is an error: the counter's history is unknown, so the wall clock is no substitute (after a backward clock jump it
// would issue stamps the shard rejects forever).
func readStamp(path string) (uint64, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the node's own state file
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the staging generation counter %s is corrupt: %w", path, err)
	}
	return n, nil
}

// initShardStaging is the staging delivery's start: it reads the persisted counter and reports whether delivery may run. With an unreadable or
// corrupt counter delivery does not start (a loud error): the counter is written only after a successful read, and staging is left to the shard
// node's own cleanup (the next installed assignment clears its staged set).
func initShardStaging(cfg VRHandoffConfig) (stamp uint64, ok bool) {
	if cfg.ShardStampPath == "" {
		return 0, true
	}
	n, err := readStamp(cfg.ShardStampPath)
	if err != nil {
		cfg.Log.Error("VR handoff: the staging generation counter is unreadable or corrupt; the staged successor is NOT told to the paired shard node until an operator repairs or removes the file", "path", cfg.ShardStampPath, "error", err)
		return 0, false
	}
	return n, true
}

// writeStamp persists the counter atomically (write, sync, rename).
func writeStamp(path string, n uint64) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- the node's own state file
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.FormatUint(n, 10) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path)) // #nosec G304 -- the node's own home
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
