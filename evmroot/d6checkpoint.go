package evmroot

// D6 part 1: the trusted checkpoint, its freshness policy (derived, not
// asserted), and the separation of live certificate admission (measured
// against the current authenticated origin) from retirement-related key
// retention.
//
// Normative source: docs/design/d6-historical-trust-proof-custody.md §2,
// docs/pos/specification/evm-partition.tex §"Execution Evidence and
// Historical Trust", governance.tex §"Economic Invariants".

// Checkpoint is what a new or long-offline client starts from. It is trust
// initialisation, not a complete history.
type Checkpoint struct {
	NetworkID        uint64
	RootCommitment   []byte
	ConfigCommitment []byte
	EVMHeadNumber    uint64
	EVMHeadHash      []byte
	EVMHeadStateRoot []byte
	RootRound        uint64 // certified root round this checkpoint attests
}

// Complete reports whether every field a client needs is present.
func (c Checkpoint) Complete() bool {
	return c.NetworkID != 0 && len(c.RootCommitment) > 0 && len(c.ConfigCommitment) > 0 &&
		len(c.EVMHeadHash) == 32 && len(c.EVMHeadStateRoot) == 32
}

// LiveCertAdmission is the round-denominated live certificate check result.
type LiveCertAdmission struct {
	Admitted bool
	Reason   string
}

// AdmitLiveCertificate applies the live certificate admission rule
// (governance.tex §"Economic Invariants" clause 3) against the CURRENT
// AUTHENTICATED ORIGIN, not a checkpoint:
//
//   - the certificate round is not ahead of the imported certified origin;
//   - the certificate is within W_cert certified root rounds of that origin;
//   - the signer epoch was active at the claimed root round.
//
// A certificate outside the W_cert window is NOT admitted as live — it must
// be authenticated through the historical checkpoint/ancestry path
// (d6proof.go), never by expired-key signatures alone. Checkpoints belong
// to that separate path and are not an input here.
func AdmitLiveCertificate(certRound, importedOriginRound, wCert uint64, signerEpochActiveAtClaimedRound bool) LiveCertAdmission {
	if certRound > importedOriginRound {
		return LiveCertAdmission{false, "certificate round is ahead of the imported certified origin — retry after root progress"}
	}
	if importedOriginRound-certRound > wCert {
		return LiveCertAdmission{false, "certificate is older than W_cert relative to the current authenticated origin — use the historical checkpoint/ancestry path"}
	}
	if !signerEpochActiveAtClaimedRound {
		return LiveCertAdmission{false, "signer epoch was not active at the claimed root round"}
	}
	return LiveCertAdmission{Admitted: true}
}

// NestingValid checks the mandatory window nesting: W_cert <= Δ_ev < Δ_hold.
func NestingValid(wCert, deltaEv, deltaHold uint64) bool {
	return wCert <= deltaEv && deltaEv < deltaHold
}

// KeyRetentionRequired reports whether an evidence-verification key must be
// retained even after it leaves the ordinary certificate-admission cache.
func KeyRetentionRequired(hasOutstandingEvidenceObligation, hasOutstandingRetirementObligation bool) bool {
	return hasOutstandingEvidenceObligation || hasOutstandingRetirementObligation
}

// ConsensusMinRoundPeriodSeconds and MaxObservedRoundPeriodSeconds bracket
// a *plausible* real time for one certified root round, in whole seconds.
// They are NOT an enforced pacing guarantee: the root
// Pacemaker.AdvanceRoundQC advances immediately on a QC, so consensus does
// not guarantee any minimum duration of a SUCCESSFUL round, and the
// observed profile runs rounds well under a second. They exist only to
// keep the round-based ADVISORY number (RoundBasedAdvisorySeconds) from
// being nonsensical:
//
//   - ConsensusMinRoundPeriodSeconds: the unit of the estimate, one whole
//     second. It is not a physical or protocol minimum (sub-second rounds
//     occur, so a one-second estimate may already exceed a real round and
//     the advisory number can overstate the window; it asserts nothing).
//     A zero estimate is rejected.
//   - MaxObservedRoundPeriodSeconds: it also may not be set arbitrarily
//     *large* — a huge MinRoundPeriodSeconds would inflate the advisory
//     protection window without any stronger guarantee. A value over this
//     is rejected.
//
// The actual safety limit does NOT come from these. It comes from
// FreshnessPolicy.EnforcedRealTimeFloorSeconds — a real wall-clock
// retirement-protection guarantee supplied from an enforced mechanism. A
// policy without one is Unsupported.
const (
	ConsensusMinRoundPeriodSeconds uint64 = 1
	MaxObservedRoundPeriodSeconds  uint64 = 120
)

// FreshnessPolicy is a checkpoint acquisition/age policy, in elapsed
// seconds.
type FreshnessPolicy struct {
	DeltaHoldRounds       uint64 // Δ_hold in certified root rounds
	DeltaEvRounds         uint64 // Δ_ev in certified root rounds
	MinRoundPeriodSeconds uint64 // advisory-only per-round estimate; must be in [ConsensusMin, MaxObserved]
	ChurnMarginSeconds    uint64 // slack for validator-set churn faster than the nominal pacing
	AcquireLatencySeconds uint64 // worst-case time to fetch and verify a fresh checkpoint

	// EnforcedRealTimeFloorSeconds is the ONLY input the safety limit is
	// derived from: a real wall-clock lower bound on how long retirement
	// protection lasts, guaranteed by an enforced mechanism (a wall-clock
	// hold on withdrawals / real-time attestation), supplied as an
	// authenticated value. Zero ⇒ the policy is Unsupported and Valid() is
	// false.
	EnforcedRealTimeFloorSeconds uint64
}

// RoundBasedAdvisorySeconds is the Δ_hold-rounds-times-a-period estimate.
// It is ADVISORY ONLY — consensus does not guarantee a minimum successful
// round duration, so this is not a safety bound. Kept for operator
// intuition and comparison against the enforced floor.
func (p FreshnessPolicy) RoundBasedAdvisorySeconds() uint64 {
	hold := p.DeltaHoldRounds * p.MinRoundPeriodSeconds
	ev := p.DeltaEvRounds * p.MinRoundPeriodSeconds
	if hold <= ev+p.ChurnMarginSeconds {
		return 0
	}
	return hold - ev - p.ChurnMarginSeconds
}

// Supported reports whether the policy rests on an enforced real-time
// protection guarantee. Without one, no checkpoint-staleness safety claim
// can be made from this policy — it should be reported unsupported, not
// asserted safe.
func (p FreshnessPolicy) Supported() bool { return p.EnforcedRealTimeFloorSeconds > 0 }

// MinRealTimeProtectionSeconds is the enforced floor (0 when Unsupported).
func (p FreshnessPolicy) MinRealTimeProtectionSeconds() uint64 {
	if !p.Supported() {
		return 0
	}
	return p.EnforcedRealTimeFloorSeconds
}

// MaxCheckpointStalenessSeconds is the strict freshness limit, derived from
// the ENFORCED floor (never from round counts): the floor minus the
// acquisition latency, and strictly less than the floor. Zero when
// Unsupported or when the latency leaves no headroom.
func (p FreshnessPolicy) MaxCheckpointStalenessSeconds() uint64 {
	prot := p.MinRealTimeProtectionSeconds()
	if prot == 0 || prot <= p.AcquireLatencySeconds {
		return 0
	}
	limit := prot - p.AcquireLatencySeconds
	if limit >= prot {
		return prot - 1
	}
	return limit
}

// Valid reports whether the policy admits a positive, strictly-safe
// staleness limit. It requires: an enforced real-time floor (Supported);
// the advisory per-round estimate inside [ConsensusMin, MaxObserved] — a
// conservative floor must be a lower bound, not an arbitrarily large
// number; and a positive staleness limit strictly below the enforced
// protection.
func (p FreshnessPolicy) Valid() bool {
	if !p.Supported() {
		return false
	}
	if p.MinRoundPeriodSeconds < ConsensusMinRoundPeriodSeconds ||
		p.MinRoundPeriodSeconds > MaxObservedRoundPeriodSeconds {
		return false
	}
	return p.MaxCheckpointStalenessSeconds() > 0 &&
		p.MaxCheckpointStalenessSeconds() < p.MinRealTimeProtectionSeconds()
}
