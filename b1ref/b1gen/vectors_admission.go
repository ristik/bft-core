package b1gen

func (g *gen) timeAdmission(seed string) {
	const fam = "Time/history"
	f := newFixture(seed, 4)
	cs := f.build("a", f.round, f.vals[:3], false)
	u := cs.get(1, "")
	req := newRequest(claimOf(u)).wire()
	sh := shapeOf(u)
	// r is the seal root round, 990; the default pre-state is epoch 7 open
	// from round 900, W_cert 50, O 1000, origin epoch 7.
	run := func(id, desc, want string, mod func(*PreState)) {
		p := f.pre()
		p.Epochs = append([]EpochWords{}, p.Epochs...)
		mod(&p)
		g.ok(id, fam, opUC, desc, req, p, sh, want, nil, nil)
	}
	closed := func(p *PreState, end uint64) { p.Origin = 8; p.Epochs[0].End = end }
	run("time.start.eq.ok", "r = start", "", func(p *PreState) { p.Epochs[0].Start = 990 })
	run("time.start.before", "r = start-1", "ErrBeforeStart", func(p *PreState) { p.Epochs[0].Start = 991 })
	run("time.end.last.ok", "r = end-1 (closed interval)", "", func(p *PreState) { closed(p, 991) })
	run("time.end.eq", "r = end", "ErrAfterEnd", func(p *PreState) { closed(p, 990) })
	run("time.open.not-origin", "open interval of an epoch that is not the origin epoch", "ErrOpenInterval", func(p *PreState) { p.Origin = 8 })
	run("time.age.wcert.ok", "age = W_cert", "", func(p *PreState) { p.ClockRound = 990 + p.WCert })
	run("time.age.wcert+1", "age = W_cert+1", "ErrStale", func(p *PreState) { p.ClockRound = 990 + p.WCert + 1 })
	run("time.future", "r = O+1", "ErrFuture", func(p *PreState) { p.ClockRound = 989 })
	run("time.wcert-zero.current.ok", "W_cert = 0 admits the current round only", "", func(p *PreState) { p.WCert = 0; p.ClockRound = 990 })
	run("time.wcert-zero.old", "W_cert = 0 with the certificate one round old", "ErrStale", func(p *PreState) { p.WCert = 0; p.ClockRound = 991 })
	run("time.seal-epoch.after-origin", "seal epoch above the origin epoch", "ErrSealEpoch", func(p *PreState) { p.Origin = 6 })
	run("time.epoch.missing", "no registry entry for the epoch", "ErrUnknownEpoch", func(p *PreState) { p.Epochs = nil })
	run("time.network.registry", "registry network differs from the seal", "ErrNetwork", func(p *PreState) { p.Network = 4 })
}
