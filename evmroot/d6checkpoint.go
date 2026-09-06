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

// ConsensusMinRoundPeriodSeconds is the protocol-enforced lower bound on
// how little real time one certified root round can take. It is NOT a
// deployment tuning knob: the root chain's own round machine cannot
// finalise a round faster than one network propagation delay plus the two
// BFT voting phases (propose→vote→commit) at the minimum permitted round
// timeout. A FreshnessPolicy whose MinRoundPeriodSeconds sits below this
// bound is not "aggressive" — it is unsound, because it would let a client
// treat a checkpoint as fresh past the point where the keys backing it
// could already be withdrawable. This constant is the justified floor the
// re-review asked for; a deployment may raise MinRoundPeriodSeconds above
// it (slower observed pacing) but Valid() rejects anything below it.
const ConsensusMinRoundPeriodSeconds uint64 = 2

// FreshnessPolicy is a checkpoint acquisition/age policy, in elapsed
// seconds. It is a CLIENT policy derived from real-time protection, round
// pacing, churn margin and acquisition latency — not simply Δ_hold rounds
// times a period. The per-round floor it uses must be at least the
// protocol-enforced ConsensusMinRoundPeriodSeconds (checked by Valid).
type FreshnessPolicy struct {
	DeltaHoldRounds       uint64 // Δ_hold in certified root rounds
	DeltaEvRounds         uint64 // Δ_ev in certified root rounds
	MinRoundPeriodSeconds uint64 // conservative floor on the real time one certified root round takes; >= ConsensusMinRoundPeriodSeconds
	ChurnMarginSeconds    uint64 // slack for validator-set churn faster than the nominal pacing
	AcquireLatencySeconds uint64 // worst-case time to fetch and verify a fresh checkpoint
}

// MinRealTimeProtectionSeconds is the least real time retirement protection
// can be relied on to last: Δ_hold rounds at the conservative per-round
// floor, minus the evidence window (which must still fit inside protection),
// minus churn slack.
func (p FreshnessPolicy) MinRealTimeProtectionSeconds() uint64 {
	hold := p.DeltaHoldRounds * p.MinRoundPeriodSeconds
	ev := p.DeltaEvRounds * p.MinRoundPeriodSeconds
	if hold <= ev+p.ChurnMarginSeconds {
		return 0
	}
	return hold - ev - p.ChurnMarginSeconds
}

// MaxCheckpointStalenessSeconds is the strict freshness limit: a client's
// trusted checkpoint may be at most this old. It leaves the acquisition
// latency as headroom so that, even if a client refreshes at the last
// permitted moment, keys backing the anchor cannot have become withdrawable
// before the refresh completes. Zero (or the Valid check failing) means the
// configured pacing/protection cannot support a safe checkpoint policy.
func (p FreshnessPolicy) MaxCheckpointStalenessSeconds() uint64 {
	prot := p.MinRealTimeProtectionSeconds()
	if prot <= p.AcquireLatencySeconds {
		return 0
	}
	limit := prot - p.AcquireLatencySeconds
	if limit >= prot {
		return prot - 1 // strictly less than the protection itself
	}
	return limit
}

// Valid reports whether the policy admits a positive, strictly-safe
// staleness limit AND rests on a per-round floor the protocol actually
// enforces (>= ConsensusMinRoundPeriodSeconds) — an illustrative period
// below the enforced minimum is not a guarantee and is rejected.
func (p FreshnessPolicy) Valid() bool {
	return p.MinRoundPeriodSeconds >= ConsensusMinRoundPeriodSeconds &&
		p.MaxCheckpointStalenessSeconds() > 0 &&
		p.MaxCheckpointStalenessSeconds() < p.MinRealTimeProtectionSeconds()
}
