package vrschema

import "fmt"

// The certified handoff-PoP miss vectors (#1319): the request digest, the miss statement's signed bytes, and certificate verdicts over a
// five-member committee of unit weights (quorum 4).

func fxMissCommittee() ([]CommitteeMember, []string) {
	var out []CommitteeMember
	var ids []string
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("root-%d", i)
		out = append(out, CommitteeMember{NodeID: id, Key: pubOf(genKey(100 + i)), Weight: 1})
		ids = append(ids, id)
	}
	return out, ids
}

func fxMissRequest(rid Word) PoPRequest {
	return PoPRequest{Epoch: 3, Network: fxRootNetwork, Predecessor: wb("pred-body"), ResultID: rid[:], Attempt: 0, Roster: []uint64{1, 2, 3, 4, 5},
		Deadline: 14_096, Intent: wb("intent")}
}

// fxMissCert is the certificate of stakingID signed by the committee members at the given 1-based positions.
func fxMissCert(r PoPRequest, stakingID uint64, signers ...int) MissCertificate {
	d, err := r.Digest()
	if err != nil {
		panic(err)
	}
	msg, err := MissStatementBytes(d, stakingID)
	if err != nil {
		panic(err)
	}
	c := MissCertificate{StakingID: stakingID}
	for _, i := range signers {
		sig, err := signerOf(genKey(100 + i)).SignBytes(msg)
		if err != nil {
			panic(err)
		}
		c.Sigs = append(c.Sigs, MissSig{NodeID: fmt.Sprintf("root-%d", i), Sig: sig})
	}
	return c
}

// fxMisses is a two-certificate list for the control encoding vectors.
func fxMisses() []MissCertificate {
	r := fxMissRequest(w("result"))
	return []MissCertificate{fxMissCert(r, 4, 1, 2, 3, 5), fxMissCert(r, 5, 1, 2, 3, 4)}
}

func genPoPMissEncodings(b *vb, rid Word) {
	r := fxMissRequest(rid)
	d, err := r.Digest()
	if err != nil {
		b.fail("pop request: %v", err)
		return
	}
	b.add("PoP request digest", "digest.popRequest", map[string]any{"network": fxRootNetwork, "predecessor": Hexb(r.Predecessor), "resultId": Hexb(r.ResultID),
		"attempt": r.Attempt, "roster": r.Roster, "deadline": Dec(r.Deadline), "intent": Hexb(r.Intent)}, map[string]any{"digest": Hexb(d[:])})
	msg, _ := MissStatementBytes(d, 5)
	b.add("PoP miss statement", "handoff.popMissStatement", map[string]any{"request": Hexb(d[:]), "stakingId": 5}, map[string]any{"bytes": Hexb(msg)})

	committee, _ := fxMissCommittee()
	var members []any
	for _, m := range committee {
		members = append(members, map[string]any{"nodeId": m.NodeID, "key": Hexb(m.Key), "weight": m.Weight})
	}
	cases := []struct {
		name  string
		certs []MissCertificate
		want  uint16
	}{
		{"one member certified by four of five", []MissCertificate{fxMissCert(r, 5, 1, 2, 3, 4)}, 0b10000},
		{"two members certified independently", []MissCertificate{fxMissCert(r, 2, 1, 3, 4, 5), fxMissCert(r, 5, 1, 2, 3, 4)}, 0b10010},
		{"three of five is below the quorum", []MissCertificate{fxMissCert(r, 5, 1, 2, 3)}, 0},
		{"a member outside the roster", []MissCertificate{fxMissCert(r, 6, 1, 2, 3, 4)}, 0},
	}
	other := r
	other.Roster = []uint64{1, 2, 3, 4, 5, 6}
	cases = append(cases, struct {
		name  string
		certs []MissCertificate
		want  uint16
	}{"statements of another roster", []MissCertificate{fxMissCert(other, 5, 1, 2, 3, 4)}, 0})
	wrongDomain := fxMissCert(r, 5, 1, 2, 3, 4)
	for i := range wrongDomain.Sigs {
		sig, _ := signerOf(genKey(100 + i + 1)).SignBytes(append([]byte("UNICITY_VR_POP_MISS?"), d[:]...))
		wrongDomain.Sigs[i].Sig = sig
	}
	cases = append(cases, struct {
		name  string
		certs []MissCertificate
		want  uint16
	}{"signatures over another domain", []MissCertificate{wrongDomain}, 0})
	for _, c := range cases {
		got, err := VerifyMissCertificates(r, c.certs, committee, 4)
		enc, _ := EncodeMissCertificates(c.certs)
		exp := map[string]any{"ok": err == nil}
		if err == nil {
			exp["missedBitmap"] = got
		} else {
			exp["error"] = err.Error()
		}
		if (err == nil) != (c.want != 0) || got != c.want {
			b.fail("miss certificates %s: %d %v", c.name, got, err)
		}
		b.add(c.name, "handoff.missCertificates", map[string]any{"request": Hexb(d[:]), "roster": r.Roster, "committee": members,
			"certificates": Hexb(enc), "threshold": 4}, exp)
	}
}
