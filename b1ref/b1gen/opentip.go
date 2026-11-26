package b1gen

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// OpenTipMember is a committee member keyed from outside this generator (the P85 post-term corpus, s1ref/s1gen).
type OpenTipMember struct {
	ID     string
	Priv   [32]byte
	Weight uint64
}

// OpenTipCase is what an open-tip consumer (a wallet or B1 caller that has not installed the successor) sees: a CERT_BATCH_V2 request certifying
// partition 1 under one native seal of `epoch` with the given previous hash (an opaque word: no VoteInfo opening is needed or checked), and the
// registry in which that epoch is the installed, usable and open tip from `start`.
type OpenTipCase struct {
	Request    []byte
	Pre        PreState // rendered: Storage holds every word
	Root       [32]byte // the seal's Hash: the unicity tree root of the variant's input records
	Timestamp  uint64   // the seal's timestamp
	SigBytes   []byte   // the native seal bytes with null signatures
	Signatures map[string][]byte
}

// OpenTip builds an OpenTipCase: the seal at root round `round`, signed with 65-byte native signatures by `signers` (member ids), over the tree
// of `variant`'s input records.
func OpenTip(seed string, network uint16, epoch, start, round uint64, prev [32]byte, variant string, members []OpenTipMember, signers []string) OpenTipCase {
	f := newFixture(seed, 0)
	f.network, f.epoch, f.origin, f.clock = network, epoch, epoch, round+100
	f.sealPrev = &prev
	byID := map[string]validator{}
	var vals []validator
	for _, m := range members {
		k := secp256k1.PrivKeyFromBytes(m.Priv[:])
		v := validator{id: m.ID, key: k, pub: k.PubKey().SerializeCompressed()}
		byID[m.ID] = v
		vals = append(vals, v)
	}
	auth := authorityOf(network, epoch, 2, f.body, vals)
	weight := map[string]uint64{}
	for _, m := range members {
		weight[m.ID] = m.Weight
	}
	for i := range auth.members {
		auth.members[i].weight = weight[auth.members[i].id]
	}
	p := f.registryBase()
	p.GenesisEpoch, p.ImportedTip, p.Origin = epoch, epoch, epoch
	w := f.epochWords(auth, epoch, start, 0, true)
	w.SigningScheme = 2
	p.Epochs = []EpochWords{w}
	var sv []validator
	for _, id := range signers {
		sv = append(sv, byID[id])
	}
	cs := f.build(variant, round, sv, true)
	u := cs.get(1, "")
	p.render()
	out := OpenTipCase{Request: Request(claimOf(u).wire()), Pre: p, Root: cs.treeRoot, Timestamp: u.seal.timestamp, SigBytes: u.seal.sigBytes(),
		Signatures: map[string][]byte{}}
	for _, e := range u.seal.sigs {
		out.Signatures[e.key] = e.val
	}
	return out
}
