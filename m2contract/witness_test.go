package m2contract

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// Two genuinely different signature maps authenticate one canonical body.
// The D4 old-quorum commitment remains a separate activation-verifier input.
func TestSignedQuorumSubsetsHaveOneBodyID(t *testing.T) {
	var members evmroot.WeightSet
	signers := make(map[string]abcrypto.Signer)
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.Verifier()
		if err != nil {
			t.Fatal(err)
		}
		key, err := v.MarshalPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("member-%d", i)
		members = append(members, evmroot.Member{StakingID: "stake-" + name, NodeID: name, ConsensusKey: key, Weight: 1})
		signers[name] = s
	}
	b := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 3, Epoch: 5, EarliestActivation: 70, Members: members, RootThreshold: 3, StateSummary: bytes.Repeat([]byte{3}, 32), ChangeRecordHash: bytes.Repeat([]byte{4}, 32), PredecessorHash: bytes.Repeat([]byte{5}, 32)}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	subsets := [][]string{{"member-0", "member-1", "member-2"}, {"member-1", "member-2", "member-3"}}
	var ids [2][32]byte
	var witnesses [2]map[string][]byte
	for index, subset := range subsets {
		candidate := b
		candidate.Members = append(evmroot.WeightSet(nil), b.Members...)
		for i := range candidate.Members {
			candidate.Members[i].ConsensusKey = bytes.Clone(b.Members[i].ConsensusKey)
		}
		id := candidate.Identity()
		witness := make(map[string][]byte)
		for _, name := range subset {
			sig, err := signers[name].SignBytes(id[:])
			if err != nil {
				t.Fatal(err)
			}
			witness[name] = sig
			for _, m := range candidate.Members {
				if m.NodeID == name {
					v, err := abcrypto.NewVerifierSecp256k1(m.ConsensusKey)
					if err != nil {
						t.Fatal(err)
					}
					if err := v.VerifyBytes(sig, id[:]); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		reached, valid := candidate.Members.QuorumReached(subset, candidate.RootThreshold)
		if !valid || !reached {
			t.Fatal("signed subset lacked quorum")
		}
		ids[index] = candidate.Identity()
		witnesses[index] = witness
	}
	if ids[0] != ids[1] {
		t.Fatal("verified quorum subsets produced different body IDs")
	}
	if len(witnesses[0]) != 3 || len(witnesses[1]) != 3 || witnesses[0]["member-0"] == nil || witnesses[1]["member-3"] == nil {
		t.Fatal("witness maps were not distinct quorum subsets")
	}
	changed := b
	changed.Members = append(evmroot.WeightSet(nil), b.Members...)
	changed.Members[0].ConsensusKey = bytes.Repeat([]byte{9}, 33)
	if changed.Identity() == ids[0] {
		t.Fatal("member key did not change the production body ID")
	}
}
