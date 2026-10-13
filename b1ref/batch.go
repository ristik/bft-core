package b1ref

import (
	"bytes"
	"fmt"
)

// evalBatch is the staged evaluator of a scanned and decoded CERT_BATCH_V2 request (briefs/b1-any-age-contract.md section 3). It
// returns the batch's false reason (nil when valid) or an infrastructure error, in the contract's precedence:
//
//  1. the common words (Registry/Host first); then phase 1 or no usable origin yet is false, with no epoch read;
//  2. every requested epoch in [g, U], in first-use order, read and validated once with its keys parsed (Registry/Host first);
//  3. every distinct claim, in first-use order: binding and folds, and conflict with an earlier different claim for the same
//     (partition, shard) under the same seal;
//  4. every distinct complete seal, in first-use order: network, epoch admissibility, start <= r, r < end when closed, r <= O, then
//     every supplied signature and the weighted quorum.
//
// All of 3 and 4 is evaluated, so the work done depends on the request and state, not on which check fails first; the reason is
// the first failing claim, else the first failing seal. Only successes would ever be reused, and nothing outlives the call.
func evalBatch(pl *plan, claims []claim, st State, pins Pins) (error, error) {
	c, err := readCommon(st, pins)
	if err != nil {
		return nil, err
	}
	if c.phase == 1 {
		return ErrPhase, nil
	}
	if !c.ready {
		return ErrOriginNotReady, nil
	}
	epochs := make(map[uint64]*epochAuth, pl.e)
	for i := uint64(0); i < pl.k; i++ {
		e := pl.occ[i].epoch
		if _, seen := epochs[e]; seen || e < c.g || e > c.origin {
			continue
		}
		auth, err := loadEpoch(st, c, e)
		if err != nil {
			return nil, err
		}
		epochs[e] = auth
	}

	var claimWhy error
	for i := uint64(0); i < pl.k; i++ {
		o := &pl.occ[i]
		if !o.newClaim {
			continue
		}
		why := claimRelation(claims, pl, i)
		if why != nil && claimWhy == nil {
			claimWhy = fmt.Errorf("claim %d: %w", i, why)
		}
	}
	var sealWhy error
	for i := uint64(0); i < pl.k; i++ {
		if !pl.occ[i].newSeal {
			continue
		}
		why := sealRelation(&claims[i], c, epochs)
		if why != nil && sealWhy == nil {
			sealWhy = fmt.Errorf("seal of claim %d: %w", i, why)
		}
	}
	if claimWhy != nil {
		return claimWhy, nil
	}
	return sealWhy, nil
}

// claimRelation checks distinct claim i: its binding and folds, and that no earlier different claim names the same partition and
// shard under the same seal (exact repeats were folded away by the grouping).
func claimRelation(claims []claim, pl *plan, i uint64) error {
	work("claim")
	c := &claims[i]
	var conflict error
	for j := uint64(0); j < i; j++ {
		p := &pl.occ[j]
		if p.newClaim && p.sealGroup == pl.occ[i].sealGroup && claims[j].partition == c.partition && bytes.Equal(claims[j].shardBytes, c.shardBytes) {
			conflict = ErrClaimConflict
			break
		}
	}
	if err := ucFolds(c); err != nil {
		return err
	}
	return conflict
}

// sealRelation checks one complete seal against its epoch's authority. There is no certificate-age window: a seal of an admitted
// epoch is valid while start_e <= r <= O and, for a closed epoch, r < end_e.
func sealRelation(c *claim, cm *common, epochs map[uint64]*epochAuth) error {
	seal := c.uc.UnicitySeal
	if uint64(seal.NetworkID) != uint64(cm.network) {
		return ErrNetwork
	}
	if seal.Epoch < cm.g {
		return ErrEpochBeforeGenesis
	}
	if seal.Epoch > cm.origin {
		return ErrEpochNotUsable
	}
	auth := epochs[seal.Epoch]
	r := seal.RootChainRoundNumber
	if r < auth.entry.Start {
		return ErrBeforeStart
	}
	if auth.entry.End != nil && r >= *auth.entry.End {
		return ErrAfterEnd
	}
	if r > cm.o {
		return ErrFuture
	}
	return verifySignatures(c, auth)
}

// verifySignatures checks every supplied signature over SHA256(Seal.SigBytes()) and then the weighted quorum. Any unknown signer
// or bad signature fails the seal even when the rest reach quorum; the loop does not stop early.
func verifySignatures(c *claim, auth *epochAuth) error {
	sigBytes, err := c.uc.UnicitySeal.SigBytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	work("quorum")
	var first error
	good := uint64(0)
	for _, kv := range c.sigs.pairs() {
		m, ok := auth.members[string(kv[0])]
		if !ok {
			first = firstErr(first, ErrUnknownSigner)
			continue
		}
		if err := checkSignature(&m, kv[1], sigBytes); err != nil {
			first = firstErr(first, err)
			continue
		}
		good += m.weight
	}
	if first != nil {
		return first
	}
	if good < auth.threshold {
		return ErrQuorum
	}
	return nil
}
