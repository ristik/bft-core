package vrschema

import "sort"

// ViewTrace is a scripted single view transition v -> v+1 under the reference timing model of the view vectors. Times are real
// milliseconds; UC times are integer seconds. Roots have weight 1. A root's seen time is when it first held the opening commit of v
// (a restart replaces it with the re-learning time). The model is exact for validity (the replay floor) and is the frozen judgment
// model for the liveness-side quantities (residence, earliest commit of v+1, the assembler's window, completion). The residence wait
// is the live voting RULE every honest root applies (it is not a premise); only its drift bound rho and the adequacy of T are premises.
type ViewTrace struct {
	N          int            `json:"n"`
	Byzantine  []int          `json:"byzantine"` // vote for anything replay-valid, at once
	Silent     []int          `json:"silent"`    // non-cooperating: never vote
	TOverride  uint64         `json:"tOverride"` // premise vectors only: a T off the 10*2^k ladder (0: T(level, view))
	Level      uint8          `json:"level"`
	View       uint64         `json:"view"`                // v
	Assemblers uint32         `json:"assemblers"`          // n of the attempt (for T)
	OpenUCTime uint64         `json:"openUcTime"`          // openTime(v)
	SeenMs     []uint64       `json:"seenMs"`              // per root
	RestartMs  map[int]uint64 `json:"restartMs,omitempty"` // root -> re-learning time
	ProposalMs uint64         `json:"proposalMs"`          // the v+1 proposal is made at
	ProposalUC uint64         `json:"proposalUc"`          // its block UC time
	Assembler  int            `json:"assembler"`
	DMs        uint64         `json:"dMs"` // the signing path D = Lambda + delta + pi_a + pi_m, measured from c_v
}

// ViewJudgment is the frozen outcome of a trace.
type ViewJudgment struct {
	TSeconds         uint64 `json:"tSeconds"`
	Never            bool   `json:"never"`
	ReplayValid      bool   `json:"replayValid"`
	ResidenceWaitMs  uint64 `json:"residenceWaitMs"`
	EarliestCommitMs uint64 `json:"earliestCommitMs"`
	AssemblerWindow  int64  `json:"assemblerWindowMs"`
	CvMs             uint64 `json:"cvMs"` // c_v
	Completes        bool   `json:"completes"`
}

// Quorum is the smallest count strictly above 2/3 of n.
func Quorum(n int) int { return 2*n/3 + 1 }

// Judge evaluates the trace.
func (t ViewTrace) Judge() ViewJudgment {
	var j ViewJudgment
	j.TSeconds, j.Never = ViewTimeoutSeconds(t.Level, t.View, t.Assemblers)
	at, never := Deadline(t.OpenUCTime, t.Level, t.View, t.Assemblers)
	if t.TOverride != 0 {
		j.TSeconds, j.Never, at, never = t.TOverride, false, t.OpenUCTime+t.TOverride, false
	}
	j.ReplayValid = !never && t.ProposalUC >= at
	if j.Never {
		return j
	}
	j.ResidenceWaitMs = ResidenceWaitMillis(j.TSeconds)
	byz := map[int]bool{}
	for _, b := range t.Byzantine {
		byz[b] = true
	}
	silent := map[int]bool{}
	for _, b := range t.Silent {
		silent[b] = true
	}
	var elig []uint64
	for i := 0; i < t.N; i++ {
		if byz[i] || silent[i] {
			continue
		}
		s := t.SeenMs[i]
		if r, ok := t.RestartMs[i]; ok {
			s = r
		}
		elig = append(elig, s+j.ResidenceWaitMs)
	}
	sort.Slice(elig, func(a, b int) bool { return elig[a] < elig[b] })
	need := Quorum(t.N) - len(byz)
	commit := t.ProposalMs
	if need > len(elig) {
		commit = ^uint64(0) // never commits
	} else if need > 0 && elig[need-1] > commit {
		commit = elig[need-1]
	}
	j.EarliestCommitMs = commit
	if !j.ReplayValid {
		j.EarliestCommitMs = ^uint64(0)
	}
	a := t.SeenMs[t.Assembler]
	if r, ok := t.RestartMs[t.Assembler]; ok {
		a = r
	}
	if j.EarliestCommitMs != ^uint64(0) {
		j.AssemblerWindow = int64(j.EarliestCommitMs) - int64(a)
	} else {
		j.AssemblerWindow = -1
	}
	// c_v is when the first honest root holds the opening commit; D already contains the learning spread Lambda, so the view's
	// certificate is complete at c_v + D (design section 8.3), provided its assembler is honest and cooperating
	cv := ^uint64(0)
	for i := 0; i < t.N; i++ {
		if !byz[i] && !silent[i] {
			cv = min(cv, t.SeenMs[i])
		}
	}
	j.CvMs = cv
	j.Completes = !byz[t.Assembler] && !silent[t.Assembler] && cv != ^uint64(0) &&
		(j.EarliestCommitMs == ^uint64(0) || (cv <= ^uint64(0)-t.DMs && cv+t.DMs <= j.EarliestCommitMs))
	return j
}

// LeaderChoice is the proposer-priority policy of an honest leader: a complete verified certificate (and the gates) wins over a due
// HandoffView; a due rejection wins over a fresh Prepare. Byzantine leaders are unconstrained (the vectors give their choice).
func LeaderChoice(certComplete, gatesHold, viewDue, rejectionDue, quietForPrepare bool) string {
	switch {
	case rejectionDue && quietForPrepare:
		return "RejectResult"
	case certComplete && gatesHold:
		return "Prepare"
	case viewDue:
		return "HandoffView"
	}
	return "none"
}

// CertificateAdmissible is the Freeze-side view rule: a certificate of view w is valid iff w <= the committed current view (a late
// certificate of an earlier retained view included) and no Freeze is committed yet.
func CertificateAdmissible(certView, committedView uint64, freezeCommitted bool) bool {
	return certView <= committedView && !freezeCommitted
}
