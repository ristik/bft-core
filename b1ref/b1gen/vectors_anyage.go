package b1gen

import (
	"encoding/hex"
	"fmt"
)

// anyAge: the acceptance relation without a certificate-age window (contract section 3; vectors plan family A and B).
func (g *gen) anyAge(seed string) {
	const fam = "Time/history"
	h := NewHistory(seed, 0)
	const O = HistoryClock
	one := func(s Seal) []byte { return req(claimOf(h.uc(s, 1, ""))) }
	run := func(id, desc string, s Seal, pre PreState, want string) {
		g.ok(id, fam, desc, one(s), pre, want, nil, nil)
	}
	pre, preloaded := h.Pre(), h.Preloaded()

	run("time.genesis-epoch.ok", "genesis epoch 0, about 10^6 rounds old", hseal(0, 500, "a"), pre, "")
	run("time.closed.start.ok", "closed epoch, r = start", hseal(1, 1000, "a"), pre, "")
	run("time.closed.last.ok", "closed epoch, r = end-1", hseal(1, 1999, "a"), pre, "")
	run("time.closed.before-start", "r inside the predecessor's interval", hseal(2, 1999, "a"), pre, "ErrBeforeStart")
	run("time.closed.at-end", "r = end of a closed epoch", hseal(2, 3000, "a"), pre, "ErrAfterEnd")
	run("time.same-members.predecessor-round", "same members as the predecessor, r in the predecessor's interval", hseal(5, 4500, "a"), pre, "ErrBeforeStart")
	run("time.origin.at-O.ok", "usable epoch, r = O", hseal(8, O, "a"), pre, "")
	run("time.origin.future", "usable epoch, r = O+1", hseal(8, O+1, "a"), pre, "ErrFuture")
	run("time.preloaded.not-usable", "imported epoch above the usable origin", hseal(9, O+600, "a"), preloaded, "ErrEpochNotUsable")
	run("time.preloaded.origin-closed.ok", "usable epoch closed by a preloaded successor above O, r = O", hseal(8, O, "a"), preloaded, "")
	run("time.preloaded.origin-closed.future", "usable epoch closed above O, O < r < end", hseal(8, O+100, "a"), preloaded, "ErrFuture")
	run("time.past-tip", "epoch above the imported tip: false, no entry read", hseal(1<<40, O, "a"), pre, "ErrEpochNotUsable")
	run("time.wrong-set", "seal of epoch 3 signed by the next set (node04 is not a member of epoch 3)",
		Seal{Epoch: 3, Round: 3500, Variant: "a", Signers: []int{1, 2, 4}}, pre, "ErrUnknownSigner")
	run("time.quorum-short", "two of four signatures", Seal{Epoch: 6, Round: 6500, Variant: "a", Signers: []int{1, 2}}, pre, "ErrQuorum")

	g3 := NewHistory(seed, 3)
	pre3 := g3.Pre()
	g.ok("time.genesis-3.ok", fam, "nonzero genesis epoch 3, r = start", req(claimOf(g3.uc(hseal(3, 3000, "a"), 1, ""))), pre3, "", nil, nil)
	g.ok("time.genesis-3.before", fam, "epoch 2 below the genesis epoch 3: false, no entry read", req(claimOf(g3.uc(hseal(2, 2500, "a"), 1, ""))), pre3, "ErrEpochBeforeGenesis", nil, nil)
}

// registryFamily: phase and readiness verdicts, and the infrastructure failures of impossible admitted state (contract sections
// 1 to 3).
func (g *gen) registryFamily(seed string) {
	const fam = "Registry"
	h := NewHistory(seed, 0)
	c3 := claimOf(h.uc(hseal(3, 3500, "a"), 1, ""))
	r3 := req(c3)
	verdict := func(id, desc string, mod func(*PreState), want string) {
		p := h.Pre()
		mod(&p)
		g.ok(id, fam, desc, r3, p, want, nil, nil)
	}
	infra := func(id, desc string, request []byte, mod func(*PreState), want string) {
		p := h.Pre()
		mod(&p)
		g.registry(id, fam, desc, request, p, want)
	}
	common := func(id, desc string, mod func(*PreState)) { infra(id, desc, r3, mod, "ErrRegistryCommon") }
	entry := func(id, desc string, mod func(*PreState)) { infra(id, desc, r3, mod, "ErrRegistryInvalidEpoch") }
	set := func(p *PreState, name string, v [32]byte) { p.override(fixedSlot(name), v) }
	e3 := func(p *PreState) *EpochWords { return &p.Epochs[3] }

	verdict("reg.phase-1", "phase 1: false before any epoch read", func(p *PreState) { p.Phase = 1 }, "ErrPhase")
	verdict("reg.origin-not-ready", "initialized, no usable origin yet (U = O = 0): false", func(p *PreState) { p.OriginReady, p.Origin, p.ClockRound = false, 0, 0 }, "ErrOriginNotReady")
	verdict("reg.unrequested-corruption.ok", "an unrequested epoch is corrupt: no whole-history scan, the batch is valid",
		func(p *PreState) { p.override(entrySlot(5, 0), w64(2)) }, "")

	common("reg.common.genesis-commitment", "genesisCommitment zero", func(p *PreState) { p.GenesisCommitment = hex32([32]byte{}) })
	common("reg.common.phase-3", "phase 3", func(p *PreState) { p.Phase = 3 })
	common("reg.common.uninitialized", "b1.initialized 0", func(p *PreState) { set(p, "b1.initialized", w64(0)) })
	common("reg.common.network-zero", "network 0", func(p *PreState) { p.Network = 0 })
	common("reg.common.network-wide", "network word above u16", func(p *PreState) { set(p, "b1.network", w64(0x10003)) })
	common("reg.common.profile-pin", "profile hash differs from the verifier's pin", func(p *PreState) { p.ProfileHash = hex32(flip32(h32(p.ProfileHash))) })
	common("reg.common.format-1", "b1.format 1", func(p *PreState) { set(p, "b1.format", w64(1)) })
	common("reg.common.ready-2", "b1.originReady 2", func(p *PreState) { set(p, "b1.originReady", w64(2)) })
	common("reg.common.genesis-above-tip", "g > I", func(p *PreState) { p.GenesisEpoch = 9 })
	common("reg.common.origin-above-tip", "U > I", func(p *PreState) { p.Origin, p.ImportedTip = 9, 8 })
	common("reg.common.not-ready-origin", "not ready but U != 0", func(p *PreState) { p.OriginReady, p.ClockRound = false, 0 })
	common("reg.common.clock-high-bytes", "clock.rootRound with a nonzero high byte", func(p *PreState) {
		w := w64(HistoryClock)
		w[0] = 1
		set(p, "clock.rootRound", w)
	})

	infra("reg.epoch.missing", "no installed entry for epoch 3 in [g, U]", r3, func(p *PreState) { p.Epochs = append(p.Epochs[:3], p.Epochs[4:]...) }, "ErrRegistryMissingEpoch")
	infra("reg.epoch.missing-mixed", "a false claim (epoch above the tip) and a claim of a missing epoch: the registry failure wins",
		req(claimOf(h.uc(hseal(1<<40, 900, "a"), 1, "")), c3), func(p *PreState) { p.Epochs = append(p.Epochs[:3], p.Epochs[4:]...) }, "ErrRegistryMissingEpoch")
	// a corrupt requested entry and a failing claim: Registry before any semantic false, in both occurrence orders
	falseClaim := claimOf(h.uc(hseal(5, 5500, "a"), 1, ""))
	falseClaim.stateRoot = flip32(falseClaim.stateRoot)
	corrupt := func(p *PreState) { p.override(entrySlot(3, 0), w64(2)) }
	infra("reg.corrupt-before-false.corrupt-first", "a corrupt requested entry, then a claim with a wrong state root", req(c3, falseClaim), corrupt, "ErrRegistryInvalidEpoch")
	infra("reg.corrupt-before-false.false-first", "the false claim first: still Registry", req(falseClaim, c3), corrupt, "ErrRegistryInvalidEpoch")
	entry("reg.entry.present-2", "present word 2", func(p *PreState) { p.override(entrySlot(3, 0), w64(2)) })
	entry("reg.entry.has-end-2", "hasEnd word 2", func(p *PreState) { p.override(entrySlot(3, 6), w64(2)) })
	entry("reg.entry.open-with-end", "hasEnd 0 with a nonzero end", func(p *PreState) { e3(p).HasEnd = false; p.override(entrySlot(3, 5), w64(4000)) })
	entry("reg.entry.count-0", "member count 0", func(p *PreState) { p.override(entrySlot(3, 9), w64(0)) })
	entry("reg.entry.count-17", "member count 17", func(p *PreState) { p.override(entrySlot(3, 9), w64(17)) })
	entry("reg.entry.total-weight", "stored total weight differs from the members' sum", func(p *PreState) { p.override(entrySlot(3, 10), w64(5)) })
	entry("reg.entry.body-kind-4", "body kind 4", func(p *PreState) { e3(p).BodyKind = 4 })
	entry("reg.entry.body-zero", "body identity zero", func(p *PreState) { e3(p).BodyID = hex32([32]byte{}) })
	entry("reg.entry.scheme-3", "unsupported signing scheme 3", func(p *PreState) { e3(p).SigningScheme = 3 })
	entry("reg.entry.config-zero", "signing configuration hash zero", func(p *PreState) { e3(p).SigningConfigHash = hex32([32]byte{}) })
	entry("reg.member.id-length-0", "member ID length 0", func(p *PreState) { p.override(memberSlot(3, 0, 0), w64(0)) })
	entry("reg.member.id-padding", "nonzero byte after the member ID", func(p *PreState) {
		var w [32]byte
		copy(w[:], e3(p).Members[0].NodeID)
		w[31] = 'x'
		p.override(memberSlot(3, 0, 1), w)
	})
	entry("reg.member.key-padding", "nonzero byte after the 33-byte key", func(p *PreState) {
		var w [32]byte
		w[0], w[1] = keyBytes(e3(p).Members[0].Key)[32], 1
		p.override(memberSlot(3, 0, 6), w)
	})
	entry("reg.member.key-off-curve", "member key not on the curve", func(p *PreState) { e3(p).Members[0].Key = "02" + hex32([32]byte{}) })
	entry("reg.member.duplicate-key", "two members with one key", func(p *PreState) { e3(p).Members[1].Key = e3(p).Members[0].Key })
	entry("reg.member.unsorted", "member IDs out of order", func(p *PreState) { m := e3(p).Members; m[0], m[1] = m[1], m[0] })
	entry("reg.member.weight-0", "member weight 0", func(p *PreState) { e3(p).Members[0].Weight = 0 })
	entry("reg.interval.past-open", "an epoch below U left open", func(p *PreState) { e3(p).HasEnd, e3(p).End = false, 0 })
	infra("reg.interval.start-above-O", "the usable epoch starting above O (without the check its seal would be a false ErrBeforeStart)",
		req(claimOf(h.uc(hseal(8, 9000, "a"), 1, ""))), func(p *PreState) { p.Epochs[8].Start = HistoryClock + 1 }, "ErrRegistryInvalidEpoch")
	entry("reg.interval.past-end-above-O", "a closed epoch below U ending above O", func(p *PreState) { e3(p).End = HistoryClock + 1 })
	infra("reg.interval.usable-ended", "the usable epoch closed at or below O", req(claimOf(h.uc(hseal(8, 9000, "a"), 1, ""))),
		func(p *PreState) { p.Epochs[8].HasEnd, p.Epochs[8].End = true, HistoryClock }, "ErrRegistryInvalidEpoch")
}

func keyBytes(s string) []byte { b, _ := hex.DecodeString(s); return b }

// reuse: canonical grouping and verification-local reuse (contract section 3; vectors plan family D). Valid vectors carry the
// counters: one entry load per distinct epoch, one signature loop per distinct complete seal, one fold per distinct claim.
func (g *gen) reuse(seed string) {
	const fam = "Reuse"
	h := NewHistory(seed, 0)
	pre := h.Pre()
	a := hseal(8, 9000, "a")
	c := func(s Seal, part uint32, shard string) claimSpec { return claimOf(h.uc(s, part, shard)) }
	ok := func(id, desc string, cs ...claimSpec) { g.ok(id, fam, desc, req(cs...), pre, "", nil, nil) }

	ok("reuse.one-seal.three-claims", "three claims under one seal: E=1, S=1, A=3", c(a, 1, ""), c(a, 2, "0"), c(a, 2, "1"))
	ok("reuse.one-epoch.two-seals", "two seals of one epoch: one entry load, two quorum checks", c(a, 1, ""), c(hseal(8, 9100, "b"), 1, ""))
	ok("reuse.three-epochs", "seals of epochs 1, 4 and 8", c(hseal(1, 1500, "a"), 1, ""), c(hseal(4, 4500, "a"), 1, ""), c(a, 1, ""))
	ok("reuse.duplicate-claim", "an exact duplicate claim: A=1, the bytes still charged", c(a, 1, ""), c(a, 1, ""))
	ok("reuse.one-shard.two-rounds", "one shard under two seals of one epoch", c(a, 3, ""), c(hseal(8, 9200, "a"), 3, ""))
	ok("reuse.one-shard.two-epochs", "one shard under seals of epochs 2 and 8", c(hseal(2, 2500, "a"), 3, ""), c(a, 3, ""))
	ok("reuse.epochs.first-use-order", "epochs requested in descending order: grouping is first use, not sorted", c(a, 1, ""), c(hseal(4, 4500, "a"), 1, ""), c(hseal(1, 1500, "a"), 1, ""))

	bad := a
	bad.BadLast = true
	extra := a
	extra.Signers = []int{1, 2, 3, 4}
	g.ok("reuse.witness.verified-first", fam, "a verified seal, then the same unsigned seal with one bad signature: a separate group, false",
		req(c(a, 1, ""), c(bad, 3, "")), pre, "ErrSigInvalid", nil, nil)
	g.ok("reuse.witness.altered-first", fam, "the altered seal first, then the verified one: same verdict and gas",
		req(c(bad, 3, ""), c(a, 1, "")), pre, "ErrSigInvalid", nil, nil)
	ok("reuse.witness.extra-signature", "the same unsigned seal with an extra valid signature: two groups, both valid", c(a, 1, ""), c(extra, 3, ""))

	good := c(a, 1, "")
	for _, f := range []struct {
		name, want string
		mod        func(*claimSpec)
	}{
		{"config", "ErrShardConf", func(x *claimSpec) { x.conf = flip32(x.conf) }},
		{"state", "ErrStateRoot", func(x *claimSpec) { x.stateRoot = flip32(x.stateRoot) }},
		{"ir", "ErrIRHash", func(x *claimSpec) { x.irHash = flip32(x.irHash) }},
	} {
		wrong := good
		f.mod(&wrong)
		g.ok(fmt.Sprintf("reuse.seal-hit.%s.verified-first", f.name), fam, "a claim under an already verified seal still has its binding checked",
			req(good, wrong), pre, f.want, nil, nil)
		g.ok(fmt.Sprintf("reuse.seal-hit.%s.wrong-first", f.name), fam, "the wrong claim first", req(wrong, good), pre, f.want, nil, nil)
	}

	// sixteen claims, sixteen seals of sixteen epochs would need sixteen installed epochs; the maximal duplicate case is one
	// maximal seal (sixteen signatures from a sixteen-member epoch) repeated in every occurrence.
	big := newFixture(seed+"/16", 16)
	bp := big.pre()
	cs := big.build("a", big.round, big.vals, false)
	var all []claimSpec
	for _, k := range [][2]interface{}{{uint32(1), ""}, {uint32(2), "0"}, {uint32(2), "1"}, {uint32(3), ""}, {uint32(4), ""}, {uint32(5), ""}, {uint32(6), ""}, {uint32(7), ""}} {
		all = append(all, claimOf(cs.get(k[0].(uint32), k[1].(string))))
	}
	all = append(all, all...)
	g.ok("reuse.maximal-seal.sixteen-occurrences", fam, "a sixteen-signature seal in sixteen occurrences (eight distinct claims, each twice)", req(all...), bp, "", nil, nil)
}
