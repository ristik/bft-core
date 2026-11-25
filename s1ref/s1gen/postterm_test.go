package s1gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

var update = flag.Bool("update", false, "rewrite the committed corpus files")

const (
	postTermSeed       = "p85-post-term-seal"
	postTermCorpusPath = "testdata/post-term-corpus-go-v1.json"
)

// The committed corpus is the generator's output (go test ./s1ref/s1gen -update rewrites it).
func TestPostTermCorpusIsCurrent(t *testing.T) {
	got, err := BuildPostTermCorpus(postTermSeed).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(postTermCorpusPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(postTermCorpusPath)
	if err != nil {
		t.Fatalf("read %s (go test ./s1ref/s1gen -update): %v", postTermCorpusPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("committed %s is stale: regenerate with go test ./s1ref/s1gen -update", postTermCorpusPath)
	}
	again, _ := BuildPostTermCorpus(postTermSeed).JSON()
	if !bytes.Equal(got, again) {
		t.Fatal("the generator is not deterministic")
	}
}

func ptHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func ptNum(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad number %q: %v", s, err)
	}
	return n
}

// independent reconstruction with the generator's own CBOR writer (not votesig or types.UnicitySeal): the seal bytes from the typed statement with
// its opaque previousHash, and VI when the statement carries its (informational) opening, which must then hash to previousHash.
func ptRebuild(t *testing.T, s PTStatement, net uint64, g []byte) (vi, sb []byte) {
	t.Helper()
	if s.VotingEpoch != "" {
		var gg [32]byte
		copy(gg[:], g)
		items := [][]byte{cUint(net), cText(dv(gg)), cUint(ptNum(t, s.VotingEpoch)), cUint(ptNum(t, s.VotingRound)), cUint(ptNum(t, s.Parent)), cBytes(ptHex(t, s.Exec))}
		if ts := ptNum(t, s.VoteTimestamp); ts != 0 {
			items = append(items, cUint(ts))
		}
		vi = cArr(items...)
		if h := sha256.Sum256(vi); hx(h[:]) != s.PreviousHash {
			t.Fatalf("the statement's opening does not hash to its previousHash")
		}
	}
	sb = cTag(tagSeal, cArr(cUint(1), cUint(net), cUint(ptNum(t, s.CommitRound)), cUint(ptNum(t, s.CommitEpoch)), cUint(ptNum(t, s.CommitTimestamp)),
		cBytes(ptHex(t, s.PreviousHash)), cBytes(ptHex(t, s.Hash)), cNull))
	return vi, sb
}

// independent P85 signature rule with dcrd: 65 bytes, v in {0,1}, 1 <= r < n, 1 <= s <= n/2, one recovery with that parity.
func ptValid(sig, digest, key []byte) bool {
	if len(sig) != 65 || sig[64] > 1 {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || r.IsZero() || s.SetByteSlice(sig[32:64]) || s.IsZero() || s.IsOverHalfOrder() {
		return false
	}
	compact := append([]byte{27 + 4 + sig[64]}, sig[:64]...)
	pub, _, err := ecdsa.RecoverCompact(compact, digest)
	return err == nil && bytes.Equal(pub.SerializeCompressed(), key)
}

// Every byte and verdict of the corpus re-derived independently of the generator's native code paths: VI and the seal bytes with this package's
// CBOR writer, signatures with dcrd, the trust-base chain with the strict decoder, the classification and the submission verdicts from the rule.
func TestPostTermCorpusIndependentReplay(t *testing.T) {
	raw, err := os.ReadFile(postTermCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var c PostTermCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	n, _ := new(big.Int).SetString(c.Curve["n"], 16)
	if n.Cmp(secp256k1.S256().N) != 0 || c.MaxSubset != 16 {
		t.Fatal("curve or bound")
	}
	accepted, rejected, sigs, openTips := 0, 0, 0, 0
	reasons := map[string]bool{}
	for _, sc := range c.Scenarios {
		g := ptHex(t, sc.Genesis)
		aStar := ptNum(t, sc.ActivationRound)
		rH := sc.Closure.TerminalRoot

		// trust-base chain: the successor extends the predecessor, the registry facts are the entries' members in node-id order
		pred, err := types.DecodeRootTrustBaseV2(ptHex(t, sc.Predecessor.UTB))
		if err != nil {
			t.Fatal(err)
		}
		succ, err := types.DecodeRootTrustBaseV2(ptHex(t, sc.Successor.UTB))
		if err != nil {
			t.Fatal(err)
		}
		if err := succ.VerifySuccessor(pred); err != nil {
			t.Fatalf("%s: successor: %v", sc.ID, err)
		}
		for _, x := range []struct {
			tb *types.RootTrustBaseV2
			c  PTCommittee
		}{{pred, sc.Predecessor}, {succ, sc.Successor}} {
			id, _ := x.tb.EntryID()
			if hx(id[:]) != x.c.EntryID || hx(x.tb.PreviousEntryID) != x.c.PreviousEntryID || dec(x.tb.Epoch) != x.c.Epoch || dec(x.tb.EpochStart) != x.c.Start ||
				dec(x.tb.QuorumThreshold) != x.c.Threshold || len(x.tb.RootNodes) != len(x.c.Members) {
				t.Fatalf("%s epoch %s: committee facts differ from the entry", sc.ID, x.c.Epoch)
			}
			var total uint64
			for i, m := range x.c.Members {
				nd := x.tb.RootNodes[i]
				if m.Index != i || m.NodeID != nd.NodeID || m.Key != hx(nd.SigKey) || m.Weight != dec(nd.Stake) {
					t.Fatalf("%s: member %d", sc.ID, i)
				}
				pk, err := secp256k1.ParsePubKey(nd.SigKey)
				if err != nil {
					t.Fatal(err)
				}
				// address = keccak256(X||Y)[12:], checked against go-ethereum's derivation in the generator by its own hash below
				if len(m.Address) != 40 || pk == nil {
					t.Fatalf("%s: member %d address", sc.ID, i)
				}
				total += nd.Stake
			}
			if x.c.TotalWeight != dec(total) || x.c.Threshold != dec(total*2/3+1) || x.c.Threshold != dec(total-(total-1)/3) {
				t.Fatalf("%s: weights", sc.ID)
			}
		}
		if sc.Predecessor.End == nil || *sc.Predecessor.End != sc.Successor.Start || sc.Successor.Start != sc.ActivationRound || sc.Successor.End != nil {
			t.Fatalf("%s: end[e] = start[e+1] = A*", sc.ID)
		}
		if ptNum(t, sc.Closure.HRound) >= aStar || sc.Closure.ClosedEpoch != sc.Predecessor.Epoch {
			t.Fatalf("%s: closure", sc.ID)
		}
		keyOf := func(i int) []byte {
			if i < 0 || i >= len(sc.Predecessor.Members) {
				return nil
			}
			return ptHex(t, sc.Predecessor.Members[i].Key)
		}

		seals := map[string]PTSeal{}
		for _, s := range sc.Seals {
			seals[s.ID] = s
			vi, sb := ptRebuild(t, s.Statement, s.SignedNetwork, ptHex(t, s.SignedGenesis))
			d := sha256.Sum256(sb)
			if hx(vi) != s.VoteInfo || s.Statement.PreviousHash != s.PreviousHash || hx(sb) != s.SigBytes || hx(d[:]) != s.SealDigest {
				t.Fatalf("%s/%s: VI, VH or seal bytes differ from the independent encoding", sc.ID, s.ID)
			}
			cr := ptNum(t, s.Statement.CommitRound)
			want := "offence"
			if cr < aStar {
				want = "in-term"
			} else if s.Statement.Hash == rH {
				want = "exempt"
			}
			if s.Class != want {
				t.Fatalf("%s/%s: class %s, rule says %s", sc.ID, s.ID, s.Class, want)
			}
			if len(s.Signatures) != len(sc.Predecessor.Members) {
				t.Fatalf("%s/%s: every member signs", sc.ID, s.ID)
			}
			for _, v := range s.Signatures {
				sigs++
				if !v.Valid || !v.Native || !ptValid(ptHex(t, v.Signature), d[:], keyOf(v.Index)) {
					t.Fatalf("%s/%s: %s's native signature", sc.ID, s.ID, v.NodeID)
				}
			}
			if ot := s.OpenTip; ot != nil {
				openTips++
				// the open-tip consumer (b1ref, epoch e the installed open tip) accepts the certificate, and the certificate carries these signatures
				st, pins := openTipState(b1gen.PreState{Storage: ot.Storage, PinnedGenesisCommitment: ot.PinnedGenesisCommitment, PinnedProfileHash: ot.PinnedProfileHash})
				req := ptHex(t, ot.Request)
				v, err := b1ref.Cert(req, st, pins)
				if err != nil || !v.Valid || !ot.Accepted {
					t.Fatalf("%s/%s: the open-tip consumer refuses the seal: %v %v", sc.ID, s.ID, err, v.Why)
				}
				for _, x := range s.Signatures {
					if !bytes.Contains(req, ptHex(t, x.Signature)) {
						t.Fatalf("%s/%s: the certificate does not carry %s's signature", sc.ID, s.ID, x.NodeID)
					}
				}
				if !bytes.Contains(req, ptHex(t, s.Statement.PreviousHash)) || !bytes.Contains(req, ptHex(t, s.Statement.Hash)) {
					t.Fatalf("%s/%s: the certificate's seal is another seal", sc.ID, s.ID)
				}
			}
		}

		offences := map[string]string{} // label -> digest|charged key
		for _, sub := range sc.Submissions {
			st := sub.Statement
			e := ptNum(t, sc.Predecessor.Epoch)
			cr := ptNum(t, st.CommitRound)
			shape := cr > 0 && ptNum(t, st.CommitEpoch) == e
			var fail []string
			var digest []byte
			if !shape {
				fail = append(fail, ptStatement)
				if sub.Digest != "" {
					t.Fatalf("%s/%s: a refused statement has no rebuilt bytes", sc.ID, sub.ID)
				}
				digest = ptHex(t, seals[sub.Seal].SealDigest)
			} else {
				vi, sb := ptRebuild(t, st, sc.Network, g)
				d := sha256.Sum256(sb)
				digest = d[:]
				if hx(vi) != sub.VoteInfo || st.PreviousHash != sub.PreviousHash || hx(sb) != sub.SigBytes || hx(d[:]) != sub.Digest {
					t.Fatalf("%s/%s: rebuilt bytes", sc.ID, sub.ID)
				}
			}
			idx := sub.Indices
			idxOK := len(idx) > 0 && len(idx) <= c.MaxSubset && len(sub.Signatures) == len(idx)
			for i, x := range idx {
				if x < 0 || x >= len(sc.Predecessor.Members) || (i > 0 && idx[i-1] >= x) || (i < len(sub.Signatures) && sub.Signatures[i].Index != x) {
					idxOK = false
				}
			}
			if !idxOK {
				fail = append(fail, ptIndices)
			}
			var weight uint64
			if len(sub.Signatures) == len(idx) {
				sigOK, seen := true, map[int]bool{}
				for _, v := range sub.Signatures {
					sigs++
					key := keyOf(v.Index)
					if key == nil {
						continue
					}
					ok := ptValid(ptHex(t, v.Signature), digest, key)
					if ok != v.Valid {
						t.Fatalf("%s/%s: signature of index %d (%s): valid=%t, dcrd says %t", sc.ID, sub.ID, v.Index, v.Mutation, v.Valid, ok)
					}
					if !ok {
						sigOK = false
					} else if !seen[v.Index] {
						seen[v.Index] = true
						weight += ptNum(t, sc.Predecessor.Members[v.Index].Weight)
					}
				}
				if !sigOK && shape {
					fail = append(fail, ptSignature)
				}
				if weight < ptNum(t, sc.Predecessor.Threshold) && shape {
					fail = append(fail, ptWeight)
				}
			}
			if !slices.Contains(idx, sub.Charged) {
				fail = append(fail, ptCharged)
			}
			if cr < aStar {
				fail = append(fail, ptPostTerm)
			}
			if st.Hash == rH {
				fail = append(fail, ptExempt)
			}
			if fail == nil {
				fail = []string{}
			}
			if !slices.Equal(fail, sub.Failures) || sub.Accept != (len(fail) == 0) || sub.SignedWeight != dec(weight) {
				t.Fatalf("%s/%s: failures %v accept %t, rule says %v", sc.ID, sub.ID, sub.Failures, sub.Accept, fail)
			}
			if sub.Accept {
				accepted++
				id := sub.Digest + "|" + sc.Predecessor.Members[sub.Charged].Key
				if prev, ok := offences[sub.Offence]; ok && prev != id {
					t.Fatalf("%s/%s: offence label %s names two statements", sc.ID, sub.ID, sub.Offence)
				}
				for l, x := range offences {
					if x == id && l != sub.Offence {
						t.Fatalf("%s/%s: one statement and signer under two labels", sc.ID, sub.ID)
					}
				}
				offences[sub.Offence] = id
			} else {
				rejected++
				if !slices.Contains(fail, sub.Reason) {
					t.Fatalf("%s/%s: declared reason %s not among %v", sc.ID, sub.ID, sub.Reason, fail)
				}
			}
			reasons[sub.Reason] = true
		}
	}
	for _, r := range []string{"ok", ptStatement, ptIndices, ptSignature, ptWeight, ptCharged, ptPostTerm, ptExempt} {
		if !reasons[r] {
			t.Fatalf("no case for %s", r)
		}
	}
	if openTips < 4 {
		t.Fatalf("%d open-tip seals", openTips)
	}
	if accepted < 8 || rejected < 35 || sigs < 200 {
		t.Fatalf("corpus too small: %d accepted, %d rejected, %d signatures", accepted, rejected, sigs)
	}
}

// The signature edge cases (on r1, an extra beyond the quorum) say what each layer does with them, so a Solidity port can see why each check is explicit.
func TestPostTermSignatureEdgeCases(t *testing.T) {
	c := BuildPostTermCorpus(postTermSeed)
	byID := map[string]PTSubmission{}
	for _, s := range c.Scenarios[0].Submissions {
		byID[s.ID] = s
	}
	charged := func(id string) PTSignature { return byID[id].Signatures[0] }
	signer := c.Scenarios[0].Predecessor.Members[0]
	// the parity-flipped high-s twin recovers the signer through ecrecover: low s must be checked explicitly
	if hs := charged("no.sig.high-s"); hs.Ecrecover == nil || *hs.Ecrecover != signer.Address || hs.RecoveredKey == nil || *hs.RecoveredKey != signer.Key || hs.Reason != "s-range" {
		t.Fatalf("high-s twin: %+v", hs)
	}
	// the wrong parity recovers another key (or none)
	if wp := charged("no.sig.wrong-parity"); wp.Reason != "key" || (wp.Ecrecover != nil && *wp.Ecrecover == signer.Address) {
		t.Fatalf("wrong parity: %+v", wp)
	}
	for id, reason := range map[string]string{"no.sig.compact-64": "length", "no.sig.length-66": "length", "no.sig.v2": "recovery-id", "no.sig.v3": "recovery-id",
		"no.sig.v27": "recovery-id", "no.sig.r-zero": "r-range", "no.sig.r-n": "r-range", "no.sig.s-zero": "s-range", "no.sig.s-n": "s-range", "no.sig.byte-flip": "key"} {
		if v := charged(id); v.Reason != reason || v.Valid || v.Native {
			t.Fatalf("%s: %+v", id, v)
		}
	}
	// member addresses are keccak addresses of the keys
	for _, m := range c.Scenarios[0].Predecessor.Members {
		k := newPTKey(c.Seed+"/weighted", map[string]string{"r1": "r1", "r2": "r2", "r3": "r3", "r4": "r4", "r5": "r5"}[m.NodeID])
		if hx(k.pub) != m.Key || hx(k.addr[:]) != m.Address {
			t.Fatalf("member %s key/address", m.NodeID)
		}
	}
}
