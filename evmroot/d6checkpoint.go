package evmroot

// D6 part 1: the trusted checkpoint, its freshness policy, and the
// separation of live certificate admission from retirement-related key
// retention.
//
// Normative source: docs/design/d6-historical-trust-proof-custody.md §2,
// docs/pos/specification/evm-partition.tex §"Execution Evidence and
// Historical Trust", governance.tex §"Economic Invariants". Issue:
// https://github.com/ristik/bft-core/issues/8

// Checkpoint is what a new or long-offline client starts from. It is trust
// initialisation, not a complete history: the client verifies subsequent
// transitions, not an arbitrary chain signed by retired keys.
type Checkpoint struct {
	NetworkID        uint64
	RootCommitment   []byte // committed root/configuration commitment
	ConfigCommitment []byte
	EVMHeadNumber    uint64
	EVMHeadHash      []byte
	EVMHeadStateRoot []byte
	RootRound        uint64 // certified root round of this checkpoint
}

// Complete reports whether every field a client needs is present.
func (c Checkpoint) Complete() bool {
	return c.NetworkID != 0 && len(c.RootCommitment) > 0 && len(c.ConfigCommitment) > 0 &&
		len(c.EVMHeadHash) == 32 && len(c.EVMHeadStateRoot) == 32
}

// CheckpointFreshnessLimitSeconds is the weak-subjectivity checkpoint
// freshness limit — a CLIENT policy measured in elapsed time, derived from
// the minimum real-time protection implied by round pacing and collateral
// retention:
//
//	limit = Δ_hold (retirement protection, in rounds) × minRoundPeriodSeconds
//
// It is DISTINCT from W_cert (a round-denominated admission window) and from
// the number of keys cached in EVM state. Changing pacing, churn or
// protection requires re-deriving it.
func CheckpointFreshnessLimitSeconds(deltaHoldRounds, minRoundPeriodSeconds uint64) uint64 {
	return deltaHoldRounds * minRoundPeriodSeconds
}

// LiveCertAdmission is the result of the round-denominated live certificate
// check.
type LiveCertAdmission struct {
	Admitted bool
	Reason   string
}

// AdmitLiveCertificate applies the live certificate admission rule
// (governance.tex §"Economic Invariants" clause 3): the round is within the
// W_cert window of the checkpoint, the signer epoch was active at the
// claimed root round, and the round is not ahead of the imported origin. A
// certificate outside this window is not rejected outright — it needs the
// checkpoint/ancestry path instead (see d6proof.go), never expired-key
// signatures alone.
func AdmitLiveCertificate(certRound, checkpointRound, importedOriginRound, wCert uint64, signerEpochActiveAtClaimedRound bool) LiveCertAdmission {
	if certRound > importedOriginRound {
		return LiveCertAdmission{false, "certificate round is ahead of the imported root origin — retry after root progress"}
	}
	if !signerEpochActiveAtClaimedRound {
		return LiveCertAdmission{false, "signer epoch was not active at the claimed root round"}
	}
	if checkpointRound > certRound && checkpointRound-certRound > wCert {
		return LiveCertAdmission{false, "certificate is older than W_cert — authenticate via the checkpoint/ancestry path, not expired keys"}
	}
	return LiveCertAdmission{Admitted: true}
}

// NestingValid checks the mandatory nesting of the three round windows:
// live certificate age fits inside the evidence window, which fits inside
// retirement protection.
//
//	W_cert ≤ Δ_ev < Δ_hold
func NestingValid(wCert, deltaEv, deltaHold uint64) bool {
	return wCert <= deltaEv && deltaEv < deltaHold
}

// KeyRetentionRequired reports whether an evidence-verification key must be
// retained even though it has left the ordinary certificate-admission
// cache. Retention is bounded by governed validator/transition/evidence
// limits and must NOT be curtailed to permit a withdrawal.
func KeyRetentionRequired(hasOutstandingEvidenceObligation, hasOutstandingRetirementObligation bool) bool {
	return hasOutstandingEvidenceObligation || hasOutstandingRetirementObligation
}

// MinRealTimeProtectionSeconds is what an offline client must assume as the
// real-time value of retirement protection, given round pacing. It is the
// floor the checkpoint freshness limit is derived from.
func MinRealTimeProtectionSeconds(deltaHoldRounds, minRoundPeriodSeconds uint64) uint64 {
	return deltaHoldRounds * minRoundPeriodSeconds
}
