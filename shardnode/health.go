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

	updatedAt time.Time
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
	CertifiedRecord       string    `json:"certifiedRecord,omitempty"`
	CertifiedRecordDetail string    `json:"certifiedRecordDetail,omitempty"`
	UpdatedAt             time.Time `json:"updatedAt"`

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
	defer h.mu.RUnlock()
	s := Snapshot{
		ExecutorOK:            h.executorOK,
		ExecutorError:         h.executorErr,
		LastUCRound:           h.lastUCRound,
		LastUCRootRound:       h.lastUCRootRound,
		LastSubmittedRound:    h.lastSubmittedRound,
		CurrentLeader:         h.currentLeader,
		IsLeader:              h.isLeader,
		Voting:                h.voting,
		NonVotingReason:       h.nonVotingReason,
		CertifiedRecord:       h.certifiedRecord,
		CertifiedRecordDetail: h.certifiedRecordDetail,
		UpdatedAt:             h.updatedAt,
	}
	if !h.updatedAt.IsZero() {
		s.SecondsSinceUpdate = time.Since(h.updatedAt).Seconds()
	}
	return s
}
