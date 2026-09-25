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
	id := b.Identity()
	subsets := [][]string{{"member-0", "member-1", "member-2"}, {"member-1", "member-2", "member-3"}}
	var prior map[string][]byte
	for _, subset := range subsets {
		witness := make(map[string][]byte)
		for _, name := range subset {
			sig, err := signers[name].SignBytes(id[:])
			if err != nil {
				t.Fatal(err)
			}
			witness[name] = sig
			for _, m := range members {
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
		reached, valid := members.QuorumReached(subset, b.RootThreshold)
		if !valid || !reached {
			t.Fatal("signed subset lacked quorum")
		}
		if b.Identity() != id {
			t.Fatal("witness changed body identity")
		}
		if prior != nil {
			same := true
			for name, sig := range prior {
				if !bytes.Equal(witness[name], sig) {
					same = false
					break
				}
			}
			if same {
				t.Fatal("witness maps did not differ")
			}
		}
		prior = witness
	}
}
