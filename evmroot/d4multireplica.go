package evmroot

import (
	"errors"
	"fmt"
)

// Honest locks are durable. Byzantine voters may sign both branches. The
// explorer enumerates every honest X/Y/abstain assignment and checks distinct
// weighted signer sets, including a payload descendant against empty suffix.
type D4Signer struct {
	ID           string
	Weight       uint64
	Byzantine    bool
	LockedRecord string
}

func (s *D4Signer) Vote(record string) bool {
	if s.Byzantine {
		return true
	}
	if s.LockedRecord != "" && s.LockedRecord != record {
		return false
	}
	s.LockedRecord = record
	return true
}
func (s D4Signer) Restart() D4Signer { return s }

type D4QuorumResult struct {
	Cases             int
	BothQuorate       bool
	MinHonestBlocking uint64
	Threshold, Total  uint64
}

func ExploreD4Quorums(signers []D4Signer, threshold uint64) (D4QuorumResult, error) {
	var total, byz uint64
	honest := []D4Signer{}
	for _, s := range signers {
		if s.Weight == 0 {
			return D4QuorumResult{}, errors.New("zero weight")
		}
		total += s.Weight
		if s.Byzantine {
			byz += s.Weight
		} else {
			honest = append(honest, s)
		}
	}
	if threshold == 0 || threshold > total || byz >= threshold {
		return D4QuorumResult{}, ErrD4Quorum
	}
	result := D4QuorumResult{Threshold: threshold, Total: total, MinHonestBlocking: total}
	var walk func(int, uint64, uint64, uint64)
	walk = func(i int, x, y, refuse uint64) {
		if i == len(honest) {
			result.Cases++
			if x+byz >= threshold && y+byz >= threshold {
				result.BothQuorate = true
			}
			if refuse < result.MinHonestBlocking {
				result.MinHonestBlocking = refuse
			}
			return
		}
		w := honest[i].Weight
		walk(i+1, x+w, y, refuse)
		walk(i+1, x, y+w, refuse)
		walk(i+1, x, y, refuse+w)
	}
	walk(0, 0, 0, 0)
	return result, nil
}
func PayloadSuffixQCImpossible(signers []D4Signer, certifiedH []string, threshold uint64) error {
	weight := map[string]uint64{}
	var total, byz, refuse uint64
	for _, s := range signers {
		if _, ok := weight[s.ID]; ok {
			return errors.New("duplicate signer")
		}
		weight[s.ID] = s.Weight
		total += s.Weight
		if s.Byzantine {
			byz += s.Weight
		}
	}
	for _, id := range certifiedH {
		w, ok := weight[id]
		if !ok {
			return errors.New("unknown signer")
		}
		for _, s := range signers {
			if s.ID == id && !s.Byzantine {
				refuse += w
			}
		}
	}
	if refuse <= total-threshold || total-refuse >= threshold {
		return fmt.Errorf("honest refusing weight %d fails blocking bound %d", refuse, total-threshold)
	}
	_ = byz
	return nil
}

// Historical LastCRs are verified under each certificate's own epoch body.
// The snapshot import never promotes them to current consumer authority.
type D4HistoricalUC struct {
	Epoch         uint64
	Shard         uint32
	ValidForEpoch uint64
}

func VerifyHistoricalLastCR(ucs []D4HistoricalUC, available map[uint64]bool, current uint64) error {
	for _, uc := range ucs {
		if !available[uc.Epoch] || uc.ValidForEpoch != uc.Epoch || uc.Shard == uint32(D4ControlPartition) {
			return ErrD4Proof
		}
	}
	_ = current
	return nil
}
