package shardnode

import (
	"sync"
	"time"
)

// Health is a thread-safe, continuously-updated snapshot of this node's
// state — what docs/engine-api-adapter-plan.md C3.4 calls making "a
// lagging validator visible without reading logs." Like Metrics, it is
// optional throughout: every update method is nil-safe.
type Health struct {
	mu sync.RWMutex

	executorOK  bool
	executorErr string

	lastUCRound        uint64
	lastUCRootRound    uint64
	lastSubmittedRound uint64
	currentLeader      string
	isLeader           bool

	// voting is false while this node deliberately withholds certification requests — today only
	// the restored-process gate (Round.MarkRestored, design §6.1). It is a status an operator must
	// be able to see without reading logs: such a node looks healthy in every other field, follows
	// the shard, and reconciles its executor, while contributing nothing to quorum.
	voting          bool
	nonVotingReason string

	// certifiedRecord is what the last reload of the certified-block record established (#14), empty when
	// the node runs without a record store. It is a status, not an authorization: it changes no vote.
	certifiedRecord       string
	certifiedRecordDetail string

	// certifiedRecordReadiness is the record gate's verdict (#14 W3b-1): "ready", or the refusal, set
	// on every round the gate evaluates. Both fields are empty without the gate, and like
	// certifiedRecord they are a status, not an authorization.
	certifiedRecordReadiness       string
	certifiedRecordReadinessDetail string
	executionRecovery              string
	executionRecoveryDetail        string
	role                           string
	roleEpoch                      uint64
	binding                        *Binding
	// roleSource and bindingSource, when set, are read at every snapshot: the report is the live role lease and the current binding, not
	// the value of the last notification (bft-core#1061: a restart's replay published the role before the runtime completed the epoch,
	// and nothing notified it afterwards)
	roleSource    func() (epoch uint64, active bool)
	bindingSource func() Binding

	updatedAt time.Time
}

// Binding is what this node's health report is evidence OF (bft-core#1057): which node, of which network and shard, under which installed
// shard configuration and which verified activation history. Orchestration compares it with what it expects and with an incumbent's; it
// authorizes nothing here, and the node's role (RoleLease) and its signing authority stay the only signing decisions.
type Binding struct {
	NodeID string `json:"nodeId"`
	// SigKey is the key the installed configuration names for this node (hex), empty while it does not name it (Member false).
	SigKey      string `json:"sigKey,omitempty"`
	NetworkID   uint64 `json:"networkId"`
	PartitionID uint64 `json:"partitionId"`
	ShardID     string `json:"shardId"`
	// ShardEpoch and ShardConfHash (hex) are the installed (verified) shard configuration's.
	ShardEpoch    uint64 `json:"shardEpoch"`
	ShardConfHash string `json:"shardConfHash,omitempty"`
	Member        bool   `json:"member"`
	// History is the verified activation history (root epoch and V3 body id, hex) from the pinned genesis to the tip: the authenticated
	// ancestry a later epoch is checked against. Empty without a Q3 runtime.
	History []HistoryEntry `json:"history,omitempty"`
}

// HistoryEntry is one epoch of the verified activation history.
type HistoryEntry struct {
	Epoch  uint64 `json:"epoch"`
	BodyID string `json:"bodyId"`
}

// UpdateBinding replaces the binding evidence (a copy is kept).
func (h *Health) UpdateBinding(b Binding) {
	if h == nil {
		return
	}
	b.History = append([]HistoryEntry(nil), b.History...)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.binding = &b
	h.updatedAt = time.Now()
}

func NewHealth() *Health {
	// Voting until something says otherwise: the default is the ordinary validator, and every
	// refusal to vote is recorded by the code that decides it.
	return &Health{voting: true}
}

// Snapshot is Health's JSON-marshalable value form — a copy, so it can be
// read (and encoded into an HTTP response) without holding Health's lock.
type Snapshot struct {
	ExecutorOK         bool   `json:"executorOk"`
	ExecutorError      string `json:"executorError,omitempty"`
	LastUCRound        uint64 `json:"lastUCRound"`
	LastUCRootRound    uint64 `json:"lastUCRootRound"`
	LastSubmittedRound uint64 `json:"lastSubmittedRound"`
	CurrentLeader      string `json:"currentLeader"`
	IsLeader           bool   `json:"isLeader"`
	Voting             bool   `json:"voting"`
	NonVotingReason    string `json:"nonVotingReason,omitempty"`
	// CertifiedRecord names the outcome of the last certified-record reload, and is empty without a
	// record store.
	CertifiedRecord       string `json:"certifiedRecord,omitempty"`
	CertifiedRecordDetail string `json:"certifiedRecordDetail,omitempty"`
	// CertifiedRecordReadiness names the record gate's verdict for the last round it evaluated, and
	// is empty without the gate.
	CertifiedRecordReadiness       string `json:"certifiedRecordReadiness,omitempty"`
	CertifiedRecordReadinessDetail string `json:"certifiedRecordReadinessDetail,omitempty"`
	ExecutionRecovery              string `json:"executionRecovery,omitempty"`
	ExecutionRecoveryDetail        string `json:"executionRecoveryDetail,omitempty"`
	// Role is the published role ("active" or "follower") and RoleEpoch the completed activation epoch it was published at; empty without
	// a role (a node that is not a root-free follower).
	Role      string `json:"role,omitempty"`
	RoleEpoch uint64 `json:"roleEpoch,omitempty"`
	// Binding names the node, network, shard, installed configuration and verified history the report is about; nil until set.
	Binding   *Binding  `json:"binding,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`

	// SecondsSinceUpdate is computed at snapshot time, not stored — see
	// (*Health).Snapshot. It's the field worth alerting on: a healthy
	// validator's UpdatedAt moves roughly every T3 (root block rate); a
	// large value here is the single clearest "this node stalled" signal,
	// clearer than reading round numbers and doing the arithmetic by hand.
	SecondsSinceUpdate float64 `json:"secondsSinceUpdate"`
}

func (h *Health) updateExecutorStatus(ok bool, errMsg string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.executorOK = ok
	h.executorErr = errMsg
	h.updatedAt = time.Now()
}

func (h *Health) updateCertificate(ucRound, ucRootRound uint64, leader string, selfID string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastUCRound = ucRound
	h.lastUCRootRound = ucRootRound
	h.currentLeader = leader
	h.isLeader = leader == selfID
	h.updatedAt = time.Now()
}

// updateVoting records whether this node is contributing certification requests, and why not when
// it is not. Idempotent: the round loop calls it every round, so it must not churn updatedAt or the
// reason for an unchanged state.
func (h *Health) updateVoting(voting bool, reason string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.voting == voting && h.nonVotingReason == reason {
		return
	}
	h.voting = voting
	h.nonVotingReason = reason
	h.updatedAt = time.Now()
}

func (h *Health) updateCertifiedRecord(outcome, detail string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certifiedRecord = outcome
	h.certifiedRecordDetail = detail
	h.updatedAt = time.Now()
}

// updateCertifiedRecordReadiness records the record gate's verdict for a round. It is idempotent so a
// steady ready state does not churn updatedAt on every round, but a verdict that changes is always
// visible.
func (h *Health) updateCertifiedRecordReadiness(outcome, detail string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.certifiedRecordReadiness == outcome && h.certifiedRecordReadinessDetail == detail {
		return
	}
	h.certifiedRecordReadiness = outcome
	h.certifiedRecordReadinessDetail = detail
	h.updatedAt = time.Now()
}

func (h *Health) updateExecutionRecovery(outcome, detail string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// A terminal journal or recovery error is an operator stop. Periodic
	// readiness checks must not erase it while the process keeps running.
	if h.executionRecovery == "stopped" && outcome != "stopped" {
		return
	}
	if h.executionRecovery == outcome && h.executionRecoveryDetail == detail {
		return
	}
	h.executionRecovery, h.executionRecoveryDetail = outcome, detail
	h.updatedAt = time.Now()
}

// SetRoleSource makes every snapshot report the role the source gives at that moment (the live role lease, see RoleLease). It takes
// precedence over UpdateRole.
func (h *Health) SetRoleSource(f func() (epoch uint64, active bool)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.roleSource = f
}

// SetBindingSource makes every snapshot report the binding the source gives at that moment. It takes precedence over UpdateBinding.
func (h *Health) SetBindingSource(f func() Binding) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bindingSource = f
}

// UpdateRole records the published role (see RoleLease) for operators and orchestration.
func (h *Health) UpdateRole(active bool, epoch uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.role, h.roleEpoch = "follower", epoch
	if active {
		h.role = "active"
	}
	h.updatedAt = time.Now()
}

func (h *Health) updateSubmitted(round uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSubmittedRound = round
	h.updatedAt = time.Now()
}

// Snapshot returns the current state. Safe to call from an HTTP handler
// goroutine concurrently with the round loop updating it.
func (h *Health) Snapshot() Snapshot {
	if h == nil {
		return Snapshot{}
	}
	h.mu.RLock()
	roleSource, bindingSource := h.roleSource, h.bindingSource
	h.mu.RUnlock()
	// the sources are read outside the lock: they take the role's and the installed set's own locks
	var live *Binding
	if bindingSource != nil {
		b := bindingSource()
		live = &b
	}
	var liveEpoch uint64
	var liveActive bool
	if roleSource != nil {
		liveEpoch, liveActive = roleSource()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := Snapshot{
		ExecutorOK:                     h.executorOK,
		ExecutorError:                  h.executorErr,
		LastUCRound:                    h.lastUCRound,
		LastUCRootRound:                h.lastUCRootRound,
		LastSubmittedRound:             h.lastSubmittedRound,
		CurrentLeader:                  h.currentLeader,
		IsLeader:                       h.isLeader,
		Voting:                         h.voting,
		NonVotingReason:                h.nonVotingReason,
		CertifiedRecord:                h.certifiedRecord,
		CertifiedRecordDetail:          h.certifiedRecordDetail,
		CertifiedRecordReadiness:       h.certifiedRecordReadiness,
		CertifiedRecordReadinessDetail: h.certifiedRecordReadinessDetail,
		ExecutionRecovery:              h.executionRecovery,
		ExecutionRecoveryDetail:        h.executionRecoveryDetail,
		Role:                           h.role,
		RoleEpoch:                      h.roleEpoch,
		UpdatedAt:                      h.updatedAt,
	}
	if h.binding != nil {
		b := *h.binding
		b.History = append([]HistoryEntry(nil), b.History...)
		s.Binding = &b
	}
	if live != nil {
		live.History = append([]HistoryEntry(nil), live.History...)
		s.Binding = live
	}
	if roleSource != nil {
		s.Role, s.RoleEpoch = "follower", liveEpoch
		if liveActive {
			s.Role = "active"
		}
	}
	if !h.updatedAt.IsZero() {
		s.SecondsSinceUpdate = time.Since(h.updatedAt).Seconds()
	}
	return s
}
