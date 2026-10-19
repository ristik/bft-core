package s1ref_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/s1ref/s1gen"
)

const digestCorpusPath = "testdata/evidence-digest-corpus-v1.json"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func num(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad number %q: %v", s, err)
	}
	return n
}

// The committed corpus is the generator's output.
func TestDigestCorpusIsCurrent(t *testing.T) {
	c := s1gen.BuildDigestCorpus("s1-evidence-digest")
	got, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(digestCorpusPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(digestCorpusPath)
	if err != nil {
		t.Fatalf("read %s (go test ./s1ref -update): %v", digestCorpusPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("committed %s is stale: regenerate with go test ./s1ref -update", digestCorpusPath)
	}
}

// Every figure of the corpus is what the production encoder and verifier produce: the generator's independent CBOR writer, the votesig encoders and the
// secp256k1 verifier agree, so a second implementation matching the corpus matches the live protocol.
func TestDigestCorpusMatchesTheProductionEncoderAndVerifier(t *testing.T) {
	c := s1gen.BuildDigestCorpus("s1-evidence-digest")
	n := new(big.Int)
	n.SetString(c.Curve["n"], 16)
	half := new(big.Int)
	half.SetString(c.Curve["halfN"], 16)
	votes, timeouts := 0, 0
	for _, ctx := range c.Contexts {
		cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: ctx.Network}
		copy(cfg.Genesis[:], unhex(t, ctx.Genesis))
		if cfg.VoteDomain() != ctx.VoteDomain || cfg.TimeoutDomain() != ctx.TimeoutDomain {
			t.Fatalf("N=%d: domains differ", ctx.Network)
		}
		byID := map[string]s1gen.DigestVote{}
		for _, v := range ctx.Votes {
			votes++
			byID[v.ID] = v
			vi := votesig.VoteInfo{Epoch: num(t, v.Epoch), Round: num(t, v.Round), Parent: num(t, v.Parent), Timestamp: num(t, v.Timestamp)}
			copy(vi.Exec[:], unhex(t, v.Exec))
			commit := votesig.Commit{Round: num(t, v.CommitRound)}
			if v.CommitHash != nil {
				commit.Hash = unhex(t, *v.CommitHash)
			}
			viBytes, err := cfg.VoteInfoBytes(vi)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			vh, _ := cfg.VoteInfoHash(vi)
			pv, err := cfg.VotePreimage(vi, commit)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			if hex.EncodeToString(viBytes) != v.VoteInfo || hex.EncodeToString(vh[:]) != v.VoteInfoHash || hex.EncodeToString(pv) != v.Preimage {
				t.Fatalf("N=%d %s: VI/VH/PV differ from votesig", ctx.Network, v.ID)
			}
			d := sha256.Sum256(pv)
			if hex.EncodeToString(d[:]) != v.Digest {
				t.Fatalf("%s: digest", v.ID)
			}
			if (vi.Timestamp == 0) != (len(viBytes) > 0 && viBytes[0] == 0x86) {
				t.Fatalf("%s: VI arity does not follow the timestamp rule", v.ID)
			}
			ver, err := crypto.NewVerifierSecp256k1(unhex(t, v.Key))
			if err != nil {
				t.Fatal(err)
			}
			for name, sig := range map[string]string{"sig64": v.Sig64, "sig65": v.Sig65} {
				if err := votesig.CheckSignatureShape(unhex(t, sig)); err != nil {
					t.Fatalf("%s %s: %v", v.ID, name, err)
				}
				if err := ver.VerifyBytes(unhex(t, sig), pv); err != nil {
					t.Fatalf("%s %s does not verify: %v", v.ID, name, err)
				}
			}
			s := new(big.Int).SetBytes(unhex(t, v.Sig64)[32:64])
			hs := new(big.Int).SetBytes(unhex(t, v.SigHighS)[32:64])
			if s.Cmp(half) > 0 || hs.Cmp(half) <= 0 || new(big.Int).Add(s, hs).Cmp(n) != 0 {
				t.Fatalf("%s: low/high s forms", v.ID)
			}
			if v.Seal != nil {
				seal := types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(num(t, v.Seal.Network)), RootChainRoundNumber: num(t, v.Seal.Round),
					Epoch: num(t, v.Seal.Epoch), Timestamp: num(t, v.Seal.Timestamp), PreviousHash: unhex(t, v.Seal.PreviousHash), Hash: unhex(t, v.Seal.Hash)}
				sb, err := seal.SigBytes()
				if err != nil || hex.EncodeToString(sb) != v.Seal.SigBytes {
					t.Fatalf("%s: seal bytes differ from UnicitySeal.SigBytes (%v)", v.ID, err)
				}
				if v.Seal.PreviousHash != v.VoteInfoHash {
					t.Fatalf("%s: the seal's previous hash is VH", v.ID)
				}
				if err := ver.VerifyBytes(unhex(t, v.Seal.Signature), sb); err != nil {
					t.Fatalf("%s: seal signature: %v", v.ID, err)
				}
				// a seal signature never stands in for the vote signature, nor the reverse
				if ver.VerifyBytes(unhex(t, v.Seal.Signature), pv) == nil || ver.VerifyBytes(unhex(t, v.Sig64), sb) == nil {
					t.Fatalf("%s: seal and vote signatures are interchangeable", v.ID)
				}
			}
		}
		for _, p := range ctx.Pairs {
			a, b := byID[p.A], byID[p.B]
			same := a.Preimage == b.Preimage
			offence := a.Signer == b.Signer && a.Epoch == b.Epoch && a.Round == b.Round && !same
			if offence != p.Equivocation {
				t.Fatalf("pair %s: equivocation=%t, the votes say %t", p.ID, p.Equivocation, offence)
			}
		}
		for _, to := range ctx.Timeouts {
			timeouts++
			tt := votesig.Timeout{Epoch: num(t, to.Epoch), Round: num(t, to.Round), HighQcRound: num(t, to.HighQcRound), Author: to.Author}
			if to.Anchor != nil {
				a := votesig.Anchor{Epoch: num(t, to.Anchor.Epoch), Slot: num(t, to.Anchor.Slot)}
				copy(a.GenesisID[:], unhex(t, to.Anchor.GenesisID))
				tt.Anchor = &a
			}
			pt, err := cfg.TimeoutPreimage(tt)
			if err != nil {
				t.Fatalf("%s: %v", to.ID, err)
			}
			if hex.EncodeToString(pt) != to.Preimage {
				t.Fatalf("N=%d timeout %s: PT differs from votesig", ctx.Network, to.ID)
			}
			d := sha256.Sum256(pt)
			if hex.EncodeToString(d[:]) != to.Digest {
				t.Fatalf("timeout %s: digest", to.ID)
			}
			ver, _ := crypto.NewVerifierSecp256k1(unhex(t, to.Key))
			if err := ver.VerifyBytes(unhex(t, to.Sig64), pt); err != nil {
				t.Fatalf("timeout %s: %v", to.ID, err)
			}
		}
	}
	if votes < 80 || timeouts < 10 {
		t.Fatalf("corpus too small: %d votes, %d timeouts", votes, timeouts)
	}
}
