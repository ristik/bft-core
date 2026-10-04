package s1gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

type q1Vector struct {
	Name           string            `json:"name"`
	Scheme         uint64            `json:"scheme"`
	Kind           string            `json:"kind"`
	SignedBytesHex string            `json:"signedBytesHex"`
	DigestHex      string            `json:"digestHex"`
	PublicKeyHex   string            `json:"publicKeyHex"`
	SignaturesHex  map[string]string `json:"signaturesHex"`
	WireHex        string            `json:"wireHex"`
	DerivedHex     map[string]string `json:"derivedHex"`
}

type q1Doc struct {
	Network        uint64     `json:"network"`
	RootGenesisHex string     `json:"rootGenesisHex"`
	Vectors        []q1Vector `json:"vectors"`
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// evidenceOf extracts the S1 evidence of a published wire vote without
// re-signing: the node's own decoder reads the wire, and only the fields S1
// carries are kept. The published signed bytes, digests and derived values are
// re-derived here and must match.
func evidenceOf(v q1Vector, net uint64, genesis [32]byte) (*ev, error) {
	var vm abdrc.VoteMsg
	if err := vm.UnmarshalCBOR(unhex(v.WireHex)); err != nil {
		return nil, fmt.Errorf("%s: %w", v.Name, err)
	}
	e := &ev{scheme: 1, author: vm.Author, epoch: vm.VoteInfo.Epoch, round: vm.VoteInfo.RoundNumber,
		parent: vm.VoteInfo.ParentRoundNumber, ts: vm.VoteInfo.Timestamp,
		net: uint64(vm.LedgerCommitInfo.NetworkID), sealRound: vm.LedgerCommitInfo.RootChainRoundNumber,
		sealEpoch: vm.LedgerCommitInfo.Epoch, sealTS: vm.LedgerCommitInfo.Timestamp,
		prev: vm.LedgerCommitInfo.PreviousHash, hash: vm.LedgerCommitInfo.Hash, voteSig: vm.Signature,
		signNet: net}
	if vm.Scheme == 2 {
		e.scheme, e.genesis = 2, genesis
	}
	if len(vm.VoteInfo.CurrentRootHash) != 32 {
		return nil, fmt.Errorf("%s: exec hash width", v.Name)
	}
	copy(e.exec[:], vm.VoteInfo.CurrentRootHash)
	if len(vm.SealSignature) != 0 {
		e.sealSig = vm.SealSignature
	}
	// Re-derive every published signed byte string.
	if e.scheme == 1 {
		e.pv = e.sealBytes()
	} else {
		vi := e.vi(net, genesis)
		vh := sum(vi)
		if hx(vi) != v.DerivedHex["voteInfo"] || hx(vh[:]) != v.DerivedHex["voteInfoHash"] || !bytes.Equal(vh[:], e.prev) {
			return nil, fmt.Errorf("%s: VI/VH differ from the published derivation", v.Name)
		}
		e.pv = e.preimage(net, genesis, vh[:])
		if e.committing() && hx(e.sealBytes()) != v.DerivedHex["nativeSealSigBytes"] {
			return nil, fmt.Errorf("%s: native seal bytes differ from the published ones", v.Name)
		}
	}
	d := sha256.Sum256(e.pv)
	if hx(e.pv) != v.SignedBytesHex || hx(d[:]) != v.DigestHex {
		return nil, fmt.Errorf("%s: signed bytes or digest differ from the published ones", v.Name)
	}
	e.content = d
	return e, nil
}

// q1 reuses the published Q1 vectors: three votes (legacy, committing,
// non-committing), the timeout signatures used as substitutions, and a pair.
func (g *gen) q1(seed string, file []byte) error {
	var doc q1Doc
	if err := json.Unmarshal(file, &doc); err != nil {
		return err
	}
	by := map[string]q1Vector{}
	for _, v := range doc.Vectors {
		by[v.Name] = v
	}
	var G [32]byte
	copy(G[:], unhex(doc.RootGenesisHex))
	net := doc.Network
	legacy, err := evidenceOf(by["legacy vote"], net, G)
	if err != nil {
		return err
	}
	cmv, err := evidenceOf(by["domain-bound committing vote"], net, G)
	if err != nil {
		return err
	}
	ncv, err := evidenceOf(by["domain-bound non-committing vote"], net, G)
	if err != nil {
		return err
	}

	// World A: the published keys of authors 1 and 2; 3 and 4 are seeded. Epoch 1 is
	// the legacy epoch [1,12) and epoch 2 the domain-bound one from round 12.
	wa := newWorld(seed+"/q1", net)
	wa.genesis, wa.boundary = G, 12
	members := func(ids ...string) []memberSpec {
		pub := map[string][]byte{"1": unhex(by["legacy vote"].PublicKeyHex), "2": unhex(by["legacy timeout"].PublicKeyHex),
			"3": wa.vals["v3"].pub, "4": wa.vals["v4"].pub}
		var ms []memberSpec
		for _, id := range ids {
			ms = append(ms, memberSpec{id: id, key: pub[id], weight: 1})
		}
		return ms
	}
	view1 := viewSpec{network: net, epoch: 1, kind: 1, body: wa.body[1], members: members("1", "2", "3", "4")}
	view2 := viewSpec{network: net, epoch: 2, kind: 2, body: wa.body[2], members: members("1", "2", "3", "4")}
	ctx := &ContextJSON{Network: uint16(net), OpenEpoch: 2, Epochs: []EpochJSON{
		wa.entry(view1, 1, 12, 1, [32]byte{}), wa.entry(view2, 12, 0, 2, G)}}
	const fam = "Q1 published vectors"

	g.yes("q1.legacy-vote.ok", fam, "published legacy vote (epoch 1, round 11), scheme 1: signature verified, no domain or conflict identity", ctx, view1, legacy)
	g.yes("q1.committing-vote.ok", fam, "published domain-bound committing vote: voting epoch 2 round 12, not commit round 11", ctx, view2, cmv)
	g.yes("q1.noncommitting-vote.ok", fam, "published domain-bound non-committing vote: voting epoch 2 round 12", ctx, view2, ncv)
	g.yes("q1.pair.committing-vs-noncommitting.ok", fam, "the two published scheme 2 votes of author 1 for one slot are an equivocation pair", ctx, view2, cmv, ncv)
	g.yes("q1.pair.noncommitting-vs-committing.ok", fam, "the same pair in the other order: identical output", ctx, view2, ncv, cmv)

	// Replay under another genesis or network: the binding computed from the context fails.
	otherG := newDRBG(seed, "q1/other-genesis").hash()
	g.no("q1.committing-vote.other-genesis", fam, "domain replay under another root genesis fails the vote info binding", ctx.mut(2, func(e *EpochJSON) { e.Genesis = hx32(otherG) }), view2, "ErrBinding", cmv)
	g.no("q1.noncommitting-vote.other-genesis", fam, "domain replay fails even for a non-committing vote", ctx.mut(2, func(e *EpochJSON) { e.Genesis = hx32(otherG) }), view2, "ErrBinding", ncv)
	view2n := view2.with(func(v *viewSpec) { v.network = net + 1 })
	ctxN := &ContextJSON{Network: uint16(net + 1), OpenEpoch: 2, Epochs: []EpochJSON{wa.entry(view2n, 12, 0, 2, G)}}
	ctxN.Epochs[0].SigNetwork = net + 1
	g.no("q1.committing-vote.other-network", fam, "domain replay on another network fails the binding", ctxN, view2n, "ErrBinding", cmv)

	// The context's signing history disagrees with the evidence scheme.
	g.no("q1.legacy-vote.context-scheme2", fam, "a legacy vote where the authenticated epoch signs with scheme 2", ctx.mut(1, func(e *EpochJSON) { e.Scheme, e.Genesis = 2, hx32(G) }), view1, "ErrSchemeEpoch", legacy)
	g.no("q1.committing-vote.context-scheme1", fam, "a scheme 2 vote where the authenticated epoch is legacy: never reinterpreted", ctx.mut(2, func(e *EpochJSON) { e.Scheme, e.Genesis = 1, hx32([32]byte{}) }), view2, "ErrSchemeEpoch", cmv)

	// Timeout and timeout-certificate signatures presented as vote signatures.
	timeoutSig := unhex(by["domain-bound timeout"].SignaturesHex["timeout"])
	anchorSig := unhex(by["domain-bound anchor timeout"].SignaturesHex["timeout"])
	tcSig := unhex(by["domain-bound timeout certificate with different signer high QC rounds"].SignaturesHex["1"])
	legTimeoutSig := unhex(by["legacy timeout"].SignaturesHex["timeout"])
	sub := func(base *ev, author string, sig []byte) *ev {
		c := base.cp()
		c.author, c.voteSig = author, sig
		return c
	}
	g.no("q1.substitution.timeout-sig-as-vote", fam, "the published domain-bound timeout signature of author 2 as a vote signature", ctx, view2, "ErrSigInvalid", sub(ncv, "2", timeoutSig))
	g.no("q1.substitution.anchor-timeout-sig-as-vote", fam, "the published anchor timeout signature as a vote signature", ctx, view2, "ErrSigInvalid", sub(ncv, "2", anchorSig))
	g.no("q1.substitution.tc-sig-as-vote", fam, "a published timeout-certificate signature of author 1 as a vote signature", ctx, view2, "ErrSigInvalid", sub(ncv, "1", tcSig))
	g.no("q1.substitution.legacy-timeout-sig-as-vote", fam, "the published legacy timeout signature as a legacy vote signature", ctx, view1, "ErrSigInvalid", sub(legacy, "2", legTimeoutSig))

	// Mutations of the published votes without re-signing.
	mutate := func(base *ev, f func(*ev)) *ev { c := base.cp(); f(c); return c }
	g.no("q1.legacy-vote.exec-altered", fam, "legacy vote info exec altered: RoundInfo hash no longer equals the previous hash", ctx, view1, "ErrBinding", mutate(legacy, func(e *ev) { e.exec[0] ^= 1 }))
	g.no("q1.legacy-vote.timestamp-altered", fam, "legacy vote info timestamp altered: the native hash covers it", ctx, view1, "ErrBinding", mutate(legacy, func(e *ev) { e.ts++ }))
	g.no("q1.legacy-vote.previous-hash-altered", fam, "legacy previous hash altered", ctx, view1, "ErrBinding", mutate(legacy, func(e *ev) { e.prev = flip(e.prev, 0) }))
	g.no("q1.legacy-vote.signature-altered", fam, "legacy signature altered", ctx, view1, "ErrSigInvalid", mutate(legacy, func(e *ev) { e.voteSig = flip(e.voteSig, 10) }))
	g.no("q1.legacy-vote.seal-signature-present", fam, "scheme 1 requires a null seal signature", ctx, view1, "ErrSealSigForbidden", mutate(legacy, func(e *ev) { e.sealSig = cmv.sealSig }))
	g.no("q1.legacy-vote.wrong-author", fam, "legacy vote carried under another member's identity", ctx, view1, "ErrSigInvalid", mutate(legacy, func(e *ev) { e.author = "2" }))
	g.no("q1.committing-vote.commit-hash-altered", fam, "commit hash altered: the vote info hash still holds, the preimage no longer matches the signature", ctx, view2, "ErrSigInvalid", mutate(cmv, func(e *ev) { e.hash = flip(e.hash, 0) }))
	g.no("q1.committing-vote.commit-round-altered", fam, "commit round altered", ctx, view2, "ErrSigInvalid", mutate(cmv, func(e *ev) { e.sealRound-- }))
	g.no("q1.committing-vote.seal-timestamp-altered", fam, "seal timestamp altered: the vote signature holds, the seal signature does not", ctx, view2, "ErrSigInvalid", mutate(cmv, func(e *ev) { e.sealTS++ }))
	g.no("q1.committing-vote.seal-signature-missing", fam, "committing vote without its seal signature", ctx, view2, "ErrSealSigMissing", mutate(cmv, func(e *ev) { e.sealSig = nil }))
	g.no("q1.committing-vote.signatures-swapped", fam, "vote and seal signatures swapped", ctx, view2, "ErrSigInvalid", mutate(cmv, func(e *ev) { e.voteSig, e.sealSig = e.sealSig, e.voteSig }))
	g.no("q1.committing-vote.round-altered", fam, "voting round altered: vote info binding fails", ctx, view2, "ErrBinding", mutate(cmv, func(e *ev) { e.round++ }))
	g.no("q1.committing-vote.epoch-altered", fam, "voting epoch altered to the legacy epoch under the epoch 2 view", ctx, view2, "ErrEpochMismatch", mutate(cmv, func(e *ev) { e.epoch = 1 }))
	g.no("q1.noncommitting-vote.seal-signature-present", fam, "non-committing vote carrying a seal signature", ctx, view2, "ErrSealSigForbidden", mutate(ncv, func(e *ev) { e.sealSig = cmv.sealSig }))
	g.no("q1.noncommitting-vote.commit-data", fam, "non-committing vote with a non-zero seal epoch", ctx, view2, "ErrStatement", mutate(ncv, func(e *ev) { e.sealEpoch = 2 }))
	return nil
}
