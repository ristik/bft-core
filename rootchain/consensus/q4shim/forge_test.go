package q4shim

import (
	"context"
	"crypto"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// epoch 1 signs legacy, epoch 2 (the fixtures' epoch) domain-bound, nothing else is installed
func forgeSigning(epoch uint64) (votesig.Config, error) {
	switch epoch {
	case 1:
		return votesig.Config{Scheme: votesig.SchemeLegacy}, nil
	case 2:
		return testCfg, nil
	}
	return votesig.Config{}, votesig.ErrConfig
}

func forgeFixture(t *testing.T) *fixture {
	return newFixture(t, func(c *Config) { c.Signing = forgeSigning })
}

// forged returns the single forged message the fixture's network received after the honest one.
func forged(t *testing.T, f *fixture, honest any) any {
	t.Helper()
	f.send(honest, f.b)
	got := f.inner.got()
	require.Len(t, got, 2, "the honest message, then one forgery to a")
	require.Equal(t, f.a, got[1].to)
	return got[1].msg
}

func timeoutStatement(t *testing.T, m *abdrc.TimeoutMsg, cfg votesig.Config) []byte {
	t.Helper()
	if cfg.Scheme == votesig.SchemeDomainBound {
		pt, err := m.Preimage(cfg)
		require.NoError(t, err)
		return pt
	}
	return m.Bytes()
}

func TestForgery(t *testing.T) {
	forge := func(f *fixture, variant, impersonate string) {
		require.NoError(f.t, f.net.SetForgeries([]Forgery{{Name: variant, Recipients: []string{f.a.String()}, Variant: variant, Impersonate: impersonate, Require: true}}))
	}
	t.Run("impersonate: re-signed by this node's key under a member's identity", func(t *testing.T) {
		f := forgeFixture(t)
		victim := newSigner(t)
		victimID, err := peerOf(victim)
		require.NoError(t, err)
		forge(f, "impersonate", victimID)
		m := forged(t, f, boundTimeout(t, f.s, f.self.String(), 5)).(*abdrc.TimeoutMsg)
		require.Equal(t, victimID, m.Author)
		pt := timeoutStatement(t, m, testCfg)
		require.NoError(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, pt), "signed by the forger")
		require.Error(t, mustVerifier(t, victim).VerifyBytes(m.Signature, pt), "not by the claimed author")
		require.NoError(t, f.net.Finish())
	})
	t.Run("unknown-signer: a fresh key under its own identity", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "unknown-signer", "")
		m := forged(t, f, boundTimeout(t, f.s, f.self.String(), 5)).(*abdrc.TimeoutMsg)
		id, err := peer.Decode(m.Author)
		require.NoError(t, err)
		require.NotContains(t, []peer.ID{f.self, f.a, f.b}, id)
		require.Error(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, timeoutStatement(t, m, testCfg)))
	})
	t.Run("bad-signature: the honest statement with a corrupted signature", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "bad-signature", "")
		honest := boundTimeout(t, f.s, f.self.String(), 5)
		m := forged(t, f, honest).(*abdrc.TimeoutMsg)
		require.Equal(t, f.self.String(), m.Author)
		require.NotEqual(t, honest.Signature, m.Signature)
		require.Error(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, timeoutStatement(t, m, testCfg)))
	})
	t.Run("wrong-domain: valid only over another genesis", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "wrong-domain", "")
		m := forged(t, f, boundTimeout(t, f.s, f.self.String(), 5)).(*abdrc.TimeoutMsg)
		other := testCfg
		other.Genesis[0] ^= 0xff
		require.Error(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, timeoutStatement(t, m, testCfg)))
		require.NoError(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, timeoutStatement(t, m, other)))
	})
	t.Run("old-form: a legacy signature in the scheme 2 epoch", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "old-form", "")
		m := forged(t, f, boundVote(t, f.s, f.self.String(), 5)).(*abdrc.VoteMsg)
		require.Equal(t, uint64(votesig.SchemeLegacy), schemeOf(m.Scheme))
		require.EqualValues(t, 2, m.VoteInfo.Epoch)
		bs, err := m.LedgerCommitInfo.SigBytes()
		require.NoError(t, err)
		require.NoError(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, bs), "a valid legacy signature")
		h, err := m.VoteInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, h, []byte(m.LedgerCommitInfo.PreviousHash))
	})
	t.Run("old-epoch: the previous epoch's rule, validly signed", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "old-epoch", "")
		m := forged(t, f, boundTimeout(t, f.s, f.self.String(), 5)).(*abdrc.TimeoutMsg)
		require.EqualValues(t, 1, m.Timeout.Epoch)
		require.Equal(t, uint64(votesig.SchemeLegacy), schemeOf(m.Scheme))
		require.NoError(t, mustVerifier(t, f.s).VerifyBytes(m.Signature, m.Bytes()))
	})
	t.Run("future-epoch: an epoch with no configuration", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "future-epoch", "")
		m := forged(t, f, boundTimeout(t, f.s, f.self.String(), 5)).(*abdrc.TimeoutMsg)
		require.EqualValues(t, 3, m.Timeout.Epoch)
		var forgeEv *Event
		for _, e := range f.net.Trace() {
			if e.Kind == "forge" {
				forgeEv = &e
			}
		}
		require.NotNil(t, forgeEv, "the forgery is traced although its epoch has no configuration")
		require.EqualValues(t, 3, forgeEv.Epoch)
		require.NotEmpty(t, forgeEv.RawSHA256)
	})
	t.Run("stale: this node's own message of an earlier round, unchanged", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "stale", "")
		first := boundTimeout(t, f.s, f.self.String(), 5)
		f.send(first, f.b)
		require.Len(t, f.inner.got(), 1, "nothing older than the first round: no stale forgery yet")
		f.send(boundTimeout(t, f.s, f.self.String(), 6), f.b)
		got := f.inner.got()
		require.Len(t, got, 3)
		m := got[2].msg.(*abdrc.TimeoutMsg)
		require.EqualValues(t, 5, m.Timeout.Round)
		require.Equal(t, first.Signature, m.Signature)
		require.Equal(t, 1, f.net.Forged("stale"))
	})
	t.Run("once per class and round; only own messages; the class filter applies", func(t *testing.T) {
		f := forgeFixture(t)
		require.NoError(t, f.net.SetForgeries([]Forgery{{Name: "v", Recipients: []string{f.a.String()}, Variant: "bad-signature", Class: Vote}}))
		f.send(boundTimeout(t, f.s, f.self.String(), 5), f.b)
		require.Len(t, f.inner.got(), 1, "a vote forgery ignores timeouts")
		f.send(boundVote(t, f.s, f.self.String(), 5), f.b)
		f.send(boundVote(t, f.s, f.self.String(), 5), f.a)
		require.Len(t, f.inner.got(), 4, "two honest votes and one forgery for the round")
		f.send(boundVote(t, f.s, "someone-else", 6), f.b)
		require.Len(t, f.inner.got(), 5)
		require.Equal(t, 1, f.net.Forged("v"))
	})
	t.Run("the trace records a forgery as forge, not as an equivocation, and the status counts it", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "bad-signature", "")
		f.send(boundTimeout(t, f.s, f.self.String(), 5), f.b)
		require.Equal(t, []string{"attempt", "deliver", "forge"}, kinds(f.net.Trace()))
		require.Equal(t, 1, f.net.Status().Forged["bad-signature"])
		require.Empty(t, f.net.Status().Byzantine)
	})
	t.Run("invalid instructions are refused", func(t *testing.T) {
		f := forgeFixture(t)
		a := f.a.String()
		for name, fs := range map[string]Forgery{
			"unknown variant":            {Name: "x", Recipients: []string{a}, Variant: "state"},
			"no recipients":              {Name: "x", Variant: "stale"},
			"impersonate without a peer": {Name: "x", Recipients: []string{a}, Variant: "impersonate"},
			"a peer for another variant": {Name: "x", Recipients: []string{a}, Variant: "stale", Impersonate: a},
			"a proposal class":           {Name: "x", Recipients: []string{a}, Variant: "stale", Class: Proposal},
			"a bad recipient":            {Name: "x", Recipients: []string{"nope"}, Variant: "stale"},
		} {
			require.ErrorIs(t, f.net.SetForgeries([]Forgery{fs}), ErrBadControl, name)
		}
		require.ErrorIs(t, f.net.Apply(context.Background(), Control{Forgery: []Forgery{{Name: "x", Variant: "stale"}}}), ErrBadControl)
	})
	t.Run("a required forgery that never happened fails the scenario", func(t *testing.T) {
		f := forgeFixture(t)
		forge(f, "stale", "")
		require.ErrorIs(t, f.net.Finish(), ErrRuleNotHit)
	})
	t.Run("a scheme-bound variant in a legacy epoch is a fault, not a silent honest copy", func(t *testing.T) {
		f := newFixture(t, func(c *Config) {
			c.Signing = func(uint64) (votesig.Config, error) { return votesig.Config{Scheme: votesig.SchemeLegacy}, nil }
		})
		forge(f, "wrong-domain", "")
		err := f.net.Send(context.Background(), legacyVote(t, f.s, f.self.String(), 5), f.b)
		require.ErrorIs(t, err, ErrBadControl)
		require.NotEmpty(t, f.net.Faults())
	})
}

// The offline checker accepts a duplicated delivery (same send, same bytes) and counts it, counts a release that reorders held sends, and
// keeps a forgery out of the statement sets (an impersonation must not make its claimed author an equivocator); a duplicate with other bytes fails.
func TestTraceCheckerCountsDuplicatesReordersAndForgeries(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	write := func(t *testing.T, tamperDuplicate bool) (string, *fixture, string) {
		dir := t.TempDir()
		var lines [][]byte
		f := newFixture(t, func(c *Config) {
			c.Signing = forgeSigning
			c.Trace = func(ev Event) { b, _ := json.Marshal(ev); lines = append(lines, b) }
		})
		victim, err := peerOf(newSigner(t))
		require.NoError(t, err)
		f.apply(Control{Rules: []Rule{{Name: "dup", To: []string{f.a.String()}, Action: Duplicate}, {Name: "hold", To: []string{f.b.String()}, Action: Hold}},
			Forgery: []Forgery{{Name: "imp", Recipients: []string{f.a.String()}, Variant: "impersonate", Impersonate: victim}}})
		for r := uint64(3); r < 6; r++ {
			f.send(boundTimeout(t, f.s, f.self.String(), r), f.a, f.b)
		}
		f.apply(Control{Rules: []Rule{{Name: "dup", To: []string{f.a.String()}, Action: Duplicate}, {Name: "hold", To: []string{f.b.String()}, Action: Hold}},
			Releases: []Release{{ID: "x", Rule: "hold", Order: LIFO}}})
		root := filepath.Join(dir, "root1")
		require.NoError(t, os.MkdirAll(root, 0o755))
		var out []byte
		seen := map[float64]bool{}
		for _, l := range lines {
			if tamperDuplicate {
				var ev map[string]any
				require.NoError(t, json.Unmarshal(l, &ev))
				if ev["kind"] == "deliver" && ev["rule"] == "dup" {
					id := ev["sendId"].(float64)
					if seen[id] {
						ev["rawSha256"] = "00"
						l, _ = json.Marshal(ev)
						tamperDuplicate = false
					}
					seen[id] = true
				}
			}
			out = append(out, l...)
			out = append(out, '\n')
		}
		require.NoError(t, os.WriteFile(filepath.Join(root, "trace.jsonl"), out, 0o600))
		st, err := json.Marshal(f.net.Status())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, "status.json"), st, 0o600))
		return dir, f, victim
	}
	run := func(dir string, args ...string) (map[string]any, string, error) {
		out, err := exec.Command(py, append([]string{"../../../scripts/q4-trace-check.py", dir, "--roots", "1"}, args...)...).CombinedOutput()
		var rep map[string]any
		_ = json.Unmarshal(out, &rep)
		return rep, string(out), err
	}
	t.Run("counted, and no equivocator", func(t *testing.T) {
		dir, f, _ := write(t, false)
		rep, out, err := run(dir, "--peer", "1="+f.self.String())
		require.NoError(t, err, out)
		require.Equal(t, "PASS", rep["verdict"], out)
		require.EqualValues(t, 3, rep["duplicates_delivered"], out)
		require.EqualValues(t, 2, rep["reordered_releases"], "three held sends released last-in-first-out: two inversions")
		require.EqualValues(t, 3, rep["forged"], out)
		require.Empty(t, rep["equivocators"], "the impersonated author is not an equivocator")
	})
	t.Run("a duplicate with other bytes fails", func(t *testing.T) {
		dir, f, _ := write(t, true)
		_, out, err := run(dir, "--peer", "1="+f.self.String())
		require.Error(t, err)
		require.Contains(t, out, "duplicate of send")
	})
}
