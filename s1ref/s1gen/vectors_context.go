package s1gen

// context covers the injected authenticated context: view commitment, body,
// network, signing history and the actual activation intervals.
func (g *gen) context() {
	w := g.w
	v1, v2 := w.view1(), w.view2()
	c := w.ctx()
	const fam = "Context"
	e2 := w.sign(w.nc("v1", 150, 0x11))
	l1 := w.sign(w.leg("v1", 50, 0x31))

	g.no("ctx.none", fam, "no context at all: authenticated absence is false", nil, v2, "ErrUnknownEpoch", e2)
	g.no("ctx.unknown-epoch", fam, "the history has no record of epoch 2", &ContextJSON{Network: uint16(w.net), OpenEpoch: 1, Epochs: c.Epochs[:1]}, v2, "ErrUnknownEpoch", e2)
	g.no("ctx.unknown-epoch.zero-view-hash", fam, "an epoch record with a zero view hash is unknown", c.mut(2, func(e *EpochJSON) { e.ViewHash = hx32([32]byte{}) }), v2, "ErrUnknownEpoch", e2)
	g.no("ctx.view-hash", fam, "carried view does not match the authenticated view hash", c.mut(2, func(e *EpochJSON) { e.ViewHash = hx32(flipHash(v2.hash())) }), v2, "ErrViewHash", e2)
	g.no("ctx.body-id", fam, "authenticated body identity differs", c.mut(2, func(e *EpochJSON) { e.BodyID = hx32(flipHash(w.body[2])) }), v2, "ErrBodyID", e2)
	g.no("ctx.source-kind", fam, "authenticated source kind differs", c.mut(2, func(e *EpochJSON) { e.SourceKind = 1 }), v2, "ErrSourceKind", e2)
	g.no("ctx.network", fam, "context network differs from the carried view network", func() *ContextJSON { d := c.clone(); d.Network = uint16(w.net + 1); return d }(), v2, "ErrNetwork", e2)

	// A forged view: the attacker's key under the honest member's name, same body and epoch.
	forged := v2.with(func(v *viewSpec) { v.members[0].key = w.vals["x1"].pub })
	fe := w.sign(w.nc("v1", 150, 0x11))
	fe.voteSig = w.vals["x1"].sign(fe.pv)
	g.no("ctx.view-substituted", fam, "attacker view carrying the honest body identity and an attacker key for the author", c, forged, "ErrViewHash", fe)

	// Signing history.
	g.no("ctx.config.unknown-scheme", fam, "signing configuration with an unknown scheme", c.mut(2, func(e *EpochJSON) { e.Scheme = 3 }), v2, "ErrSigningConfig", e2)
	g.no("ctx.config.scheme0", fam, "missing signing record is never a default", c.mut(2, func(e *EpochJSON) { e.Scheme = 0 }), v2, "ErrSigningConfig", e2)
	g.no("ctx.config.zero-genesis", fam, "scheme 2 needs a root genesis identity", c.mut(2, func(e *EpochJSON) { e.Genesis = hx32([32]byte{}) }), v2, "ErrSigningConfig", e2)
	g.no("ctx.config.network", fam, "signing configuration network differs from N", c.mut(2, func(e *EpochJSON) { e.SigNetwork = w.net + 1 }), v2, "ErrSigningConfig", e2)
	g.no("ctx.history.default-legacy", fam, "forged history that defaults epoch 2 to scheme 1", c.mut(2, func(e *EpochJSON) { e.Scheme, e.Genesis = 1, hx32([32]byte{}) }), v2, "ErrSchemeEpoch", e2)
	g.no("ctx.history.legacy-in-activated", fam, "a legacy vote where the history says epoch 1 is scheme 2", c.mut(1, func(e *EpochJSON) { e.Scheme, e.Genesis = 2, hx32(w.genesis) }), v1, "ErrSchemeEpoch", l1)
	g.no("ctx.history.scheme2-in-legacy", fam, "a scheme 2 vote claiming epoch 1", c, v1, "ErrSchemeEpoch", func() *ev { e := w.sign(w.nc("v1", 50, 0x11)); e.epoch = 1; return e }())
	g.no("ctx.voting-epoch", fam, "voting epoch 1 under the epoch 2 view", c, v2, "ErrEpochMismatch", func() *ev { e := w.nc("v1", 150, 0x11); e.epoch = 1; return w.sign(e) }())

	// Both sides of the scheme activation and the actual interval boundaries (epoch 1 is [1,100), epoch 2 is [100,open)).
	g.yes("ctx.activation.last-legacy-round.ok", fam, "round end-1 of the legacy epoch", c, v1, w.sign(w.leg("v1", 99, 0x31)))
	g.no("ctx.activation.legacy-at-end", fam, "round equal to the legacy interval end", c, v1, "ErrAfterEnd", w.sign(w.leg("v1", 100, 0x31)))
	g.yes("ctx.activation.first-domain-round.ok", fam, "round equal to the interval start of the scheme 2 epoch", c, v2, w.sign(w.nc("v1", 100, 0x11)))
	g.no("ctx.activation.domain-before-start", fam, "round start-1 of the scheme 2 epoch", c, v2, "ErrBeforeStart", w.sign(w.nc("v1", 99, 0x11)))
	g.no("ctx.interval.earliest-eligible-start", fam, "a round between an earlier eligible activation and the actual start: actual boundaries only", c, v2, "ErrBeforeStart", w.sign(w.nc("v1", 95, 0x11)))
	g.no("ctx.interval.open-epoch", fam, "an open interval must name the authenticated current open epoch", func() *ContextJSON { d := c.clone(); d.OpenEpoch = 3; return d }(), v2, "ErrOpenInterval", e2)
	g.yes("ctx.interval.closed-epoch-while-newer-open.ok", fam, "a closed interval needs no open-epoch indication of its own", c, v1, l1)
	g.yes("ctx.interval.uncommitted-round.ok", fam, "no committed-frontier ceiling: a far-future uncommitted voting round is admissible", c, v2, w.sign(w.nc("v1", 1_000_000, 0x11)))
	g.yes("ctx.interval.old-round.ok", fam, "no W_cert age gate: an old round of a closed epoch verifies", c, v1, w.sign(w.leg("v1", 2, 0x31)))

	// Authors.
	g.no("ctx.author.retired-key-in-epoch2", fam, "a key retired before epoch 2 signing a vote of epoch 2", c, v2, "ErrUnknownAuthor", w.sign(w.nc("v4", 150, 0x11)))
	g.no("ctx.author.unknown", fam, "author not in the view", c, v2, "ErrUnknownAuthor", func() *ev { e := w.nc("zz", 150, 0x11); e.author = "v1"; s := w.sign(e); s.author = "zz"; return s }())
	g.no("ctx.author.substituted", fam, "author spelling of another member over this member's signature", c, v2, "ErrSigInvalid", func() *ev { e := w.sign(w.nc("v1", 150, 0x11)); e.author = "v2"; return e }())
	g.no("ctx.author.case", fam, "author spelling differing in case is another identity", c, v2, "ErrUnknownAuthor", func() *ev { e := w.sign(w.nc("v1", 150, 0x11)); e.author = "V1"; return e }())
	g.no("ctx.author.empty", fam, "empty author", c, v2, "ErrUnknownAuthor", func() *ev { e := w.sign(w.nc("v1", 150, 0x11)); e.author = ""; return e }())
}

func flipHash(h [32]byte) [32]byte { h[0] ^= 1; return h }
