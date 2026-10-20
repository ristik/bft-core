package b1ref_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmroot"
)

func entryOf(t *testing.T, w b1gen.EpochWords) b1state.Entry {
	t.Helper()
	e := b1state.Entry{Epoch: w.Epoch, BodyKind: w.BodyKind, Start: w.Start, SigningScheme: w.SigningScheme}
	e.BodyID, e.ActivationCommitID, e.SigningConfigHash = word32(t, w.BodyID), word32(t, w.ActivationCommitID), word32(t, w.SigningConfigHash)
	for _, m := range w.Members {
		k, err := hex.DecodeString(m.Key)
		require.NoError(t, err)
		mem := b1state.Member{NodeID: m.NodeID, Weight: m.Weight}
		copy(mem.Key[:], k)
		e.Members = append(e.Members, mem)
	}
	return e
}

// TestRegistryWriterMatchesReader: the corpus's multi-epoch history (b1gen.History, epochs 0..8) installed through the system writer
// (b1state.GenesisWords, then b1state.Registry.Apply with B = 2: two appends and the origin advance per update, the write-side guards
// on) yields exactly the registry words the corpus vectors carry, and b1ref verifies UCs of old, scheme 1, scheme 2 and current
// epochs against the writer's words. The writer (b1state) and the reader (b1ref) derive the layout independently.
func TestRegistryWriterMatchesReader(t *testing.T) {
	h := b1gen.NewHistory("b1-any-age-v1", 0)
	pre := h.Rendered()
	var entries []b1state.Entry
	for _, w := range pre.Epochs {
		entries = append(entries, entryOf(t, w))
	}
	p := b1state.Profile{Network: pre.Network, RootGenesisID: entries[0].BodyID, ExecutionChainID: 2, RuntimeHash: [32]byte{3}, CompilerHash: [32]byte{4},
		MaxEpochsPerUpdate: 2, DeltaEV: 1, DeltaHold: 2, RestGas: 100, CompanionBytes: 1000000, OtherCompanionBytes: 1024, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
	p.SystemGas, _ = p.RequiredSystemGas()
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	profileHash, err := p.Hash()
	require.NoError(t, err)
	// the genesis commitment is an operational word registrygenesis allocates; the corpus fixture carries its own value
	gc := word32(t, pre.GenesisCommitment)
	words, err := b1state.GenesisWords(p, entries[0], gc)
	require.NoError(t, err)
	reg, err := b1state.NewRegistry(entries[0], b1state.Deployment{GenesisCommitment: gc, ProfileHash: profileHash})
	require.NoError(t, err)

	// first usable origin in the genesis epoch, then two epochs per update with the origin moving to the new tip; O stays below the
	// next start (the append guard), and ends at the corpus clock
	apply := func(newEntries []b1state.Entry, epoch, round uint64) {
		var err error
		var ch *b1state.Changes
		reg, ch, err = reg.Apply(b1state.Update{PriorTipEpoch: reg.Tip, NewEntries: newEntries, OriginEpoch: epoch, OriginRound: round}, p.MaxEpochsPerUpdate)
		require.NoError(t, err)
		for s, v := range ch.Final {
			words[s] = v
		}
	}
	apply(nil, 0, 500)
	for e := uint64(1); e+1 <= b1gen.HistoryOrigin; e += 2 {
		round := b1gen.HistoryStart(e+1) + 500
		if e+1 == b1gen.HistoryOrigin {
			round = b1gen.HistoryClock
		}
		apply(entries[e:e+2], e+1, round)
	}
	require.Equal(t, uint64(b1gen.HistoryOrigin), reg.Tip)
	require.True(t, reg.Ready)

	words[b1state.FixedSlot("genesisCommitment")] = gc

	// every word the corpus registry carries is the writer's word; the writer's other words are operational slots outside B1
	compared := 0
	for _, sw := range pre.Storage {
		slot, want := word32(t, sw.Slot), word32(t, sw.Value)
		if slot == b1state.FixedSlot("b1.profileHash") {
			continue // the corpus pins a fixture profile hash; this registry carries the writer's profile hash
		}
		require.Equal(t, want, words[slot], "slot %s", sw.Slot)
		compared++
	}
	require.Greater(t, compared, 250)
	// every entry and member slot of the nine epochs, zero words included, is the same in the writer's state and the corpus's
	corpus := map[[32]byte][32]byte{}
	for _, sw := range pre.Storage {
		corpus[word32(t, sw.Slot)] = word32(t, sw.Value)
	}
	slots := 0
	for _, e := range pre.Epochs {
		for f := uint64(0); f < 11; f++ {
			s := b1ref.EntrySlot(e.Epoch, f)
			require.Equal(t, corpus[s], words[s], "epoch %d field %d", e.Epoch, f)
			slots++
		}
		for j := range e.Members {
			for f := uint64(0); f < 8; f++ {
				s := b1ref.MemberSlot(e.Epoch, uint64(j), f)
				require.Equal(t, corpus[s], words[s], "epoch %d member %d field %d", e.Epoch, j, f)
				slots++
			}
		}
	}
	require.Equal(t, 9*(11+4*8), slots)
	// the writer also caches C_e at field 11 of every entry (B7 trust cache); the reader corpus does not carry it, since no reader reads it
	deployment := b1state.Deployment{GenesisCommitment: gc, ProfileHash: profileHash}
	for _, e := range entries {
		want, err := deployment.EpochCommitment(e)
		require.NoError(t, err)
		require.Equal(t, want, words[b1state.EntrySlot(e.Epoch, b1state.CommitmentField)], "epoch %d C_e", e.Epoch)
		require.NotContains(t, corpus, b1state.EntrySlot(e.Epoch, b1state.CommitmentField))
	}
	// and nothing the reader reads is missing: every nonzero B1 word the writer wrote for entries and the common state is in the corpus
	for _, name := range b1ref.CommonSlots {
		if name != "b1.profileHash" {
			require.Equal(t, words[b1state.FixedSlot(name)], words[b1ref.FixedSlot(name)], name)
		}
	}

	st := b1ref.Words(words)
	pins := b1ref.Pins{GenesisCommitment: gc, ProfileHash: profileHash}
	req := func(claims ...[]byte) []byte { return b1gen.Request(claims...) }
	for name, claims := range map[string][][]byte{
		"genesis epoch":       {h.Claim(b1gen.Seal{Epoch: 0, Round: 700, Variant: "w", Signers: b1gen.DefaultSigners(0)}, 1, "")},
		"old scheme 1 epoch":  {h.Claim(b1gen.Seal{Epoch: 2, Round: 2500, Variant: "w", Signers: b1gen.DefaultSigners(2)}, 1, "")},
		"scheme 2 epoch":      {h.Claim(b1gen.Seal{Epoch: 6, Round: 6500, Variant: "w", Signers: b1gen.DefaultSigners(6)}, 1, "")},
		"usable epoch at O":   {h.Claim(b1gen.Seal{Epoch: 8, Round: b1gen.HistoryClock, Variant: "w", Signers: b1gen.DefaultSigners(8)}, 1, "")},
		"three epochs, mixed": {h.Claim(b1gen.Seal{Epoch: 1, Round: 1500, Variant: "w", Signers: b1gen.DefaultSigners(1)}, 1, ""), h.Claim(b1gen.Seal{Epoch: 5, Round: 5500, Variant: "w", Signers: b1gen.DefaultSigners(5)}, 2, "0"), h.Claim(b1gen.Seal{Epoch: 8, Round: 9000, Variant: "w", Signers: b1gen.DefaultSigners(8)}, 3, "")},
	} {
		v, err := b1ref.Cert(req(claims...), st, pins)
		require.NoError(t, err, name)
		require.True(t, v.Valid, "%s: %v", name, v.Why)
	}
	v, err := b1ref.Cert(req(h.Claim(b1gen.Seal{Epoch: 8, Round: b1gen.HistoryClock + 1, Variant: "w", Signers: b1gen.DefaultSigners(8)}, 1, "")), st, pins)
	require.NoError(t, err)
	require.False(t, v.Valid, "a round above the writer's O is future")
}

// TestD6AdmissionParity: the D6 any-age admission model (evmroot.AdmitCertificate, contract section 7b) and the b1ref relation give the
// same verdict for every epoch and round of a grid over the writer-built registry, and each D6 golden admission case has a corpus vector
// with the same verdict. The model checks only round and interval; b1ref also verifies the signatures, which are valid here.
func TestD6AdmissionParity(t *testing.T) {
	h := b1gen.NewHistory("b1-any-age-v1", 0)
	pre := h.Rendered()
	st, pins := state(t, &pre)
	ends := map[uint64]*uint64{}
	for _, e := range pre.Epochs {
		if e.HasEnd {
			end := e.End
			ends[e.Epoch] = &end
		}
	}
	checked := 0
	for _, e := range []uint64{0, 2, 5, 8, 9, 40} {
		start := b1gen.HistoryStart(e)
		if e > b1gen.HistoryOrigin {
			start = b1gen.HistoryClock / 2
		}
		rounds := []uint64{start, start + 1, b1gen.HistoryClock, b1gen.HistoryClock + 1}
		if start > 0 {
			rounds = append(rounds, start-1)
		}
		if end := ends[e]; end != nil {
			rounds = append(rounds, *end-1, *end)
		}
		for _, r := range rounds {
			if r == 0 {
				continue
			}
			ce := evmroot.CertEpoch{Start: start, End: ends[e], Admitted: e <= b1gen.HistoryOrigin}
			model := evmroot.AdmitCertificate(r, b1gen.HistoryClock, true, ce)
			v, err := b1ref.Cert(b1gen.Request(h.Claim(b1gen.Seal{Epoch: e, Round: r, Variant: "p", Signers: b1gen.DefaultSigners(e)}, 1, "")), st, pins)
			require.NoError(t, err)
			require.Equal(t, model.Admitted, v.Valid, "epoch %d round %d: model %q, b1ref %v", e, r, model.Reason, v.Why)
			checked++
		}
	}
	require.Greater(t, checked, 30)
	// not ready: the model refuses (b1ref's not-ready verdict is the corpus vector reg.origin-not-ready, mapped below)
	require.False(t, evmroot.AdmitCertificate(1500, 0, false, evmroot.CertEpoch{Start: 1000, Admitted: true}).Admitted)

	// each D6 golden admission case and the corpus vector that exercises the same rule (very old open epoch: epoch 8 at round 9,000 against
	// O = 1,000,000; very old closed epoch: the genesis epoch about 10^6 rounds back)
	m, _ := loadGolden(t)
	verdict := map[string]bool{}
	for _, v := range m.Vectors {
		if v.Expected.Valid != nil {
			verdict[v.ID] = *v.Expected.Valid
		}
	}
	for d6, vector := range map[string]string{
		"very_old_current_epoch": "reuse.one-epoch.two-seals", "very_old_closed_epoch": "time.genesis-epoch.ok", "round_equals_start": "time.closed.start.ok",
		"round_is_end_minus_one": "time.closed.last.ok", "round_equals_end": "time.closed.at-end", "round_equals_origin_open_epoch": "time.origin.at-O.ok",
		"round_ahead_of_origin": "time.origin.future", "round_before_epoch_start": "time.closed.before-start", "no_usable_origin": "reg.origin-not-ready",
		"epoch_not_admitted": "time.past-tip",
	} {
		var want *bool
		for _, c := range evmroot.BuildD6Vectors().CertAdmission {
			if c.Name == d6 {
				w := c.Admitted
				want = &w
			}
		}
		require.NotNil(t, want, "D6 case %s", d6)
		got, ok := verdict[vector]
		require.True(t, ok, "corpus vector %s", vector)
		require.Equal(t, *want, got, "D6 %s vs corpus %s", d6, vector)
	}
}
