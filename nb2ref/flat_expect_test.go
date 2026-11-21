package nb2ref

// A producer for signed fixture expectations, separate from the verifier and
// wallet. It consumes the typed fixture recipe, not verifier states or logs.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"golang.org/x/crypto/sha3"
)

func expectedKeccak(parts ...[]byte) (out [32]byte) {
	h := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		h.Write(part)
	}
	h.Sum(out[:0])
	return out
}

func expectedCommit(label string, fields ...[]byte) [32]byte {
	tag := expectedKeccak([]byte("UNICITY/NB2/CONT/1.1/" + label))
	return expectedKeccak(append([][]byte{tag[:]}, fields...)...)
}

func expectedCBOR(t *testing.T, value any) []byte {
	t.Helper()
	b, err := cbor.Marshal(value)
	require.NoError(t, err)
	return b
}

func expectedSID(t *testing.T, cd Certification) [32]byte {
	p := cbor.Tag{Number: 39032, Content: []any{uint64(1), []byte{byte(cd.Source.Type)}, cd.Source.Params}}
	return sha256.Sum256(expectedCBOR(t, []any{p, cd.SourceHash[:]}))
}

func expectedClaim(t *testing.T, raw []byte) flatClaim {
	t.Helper()
	var uc types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &uc))
	ir, err := uc.InputRecord.Bytes()
	require.NoError(t, err)
	seal, err := types.Cbor.Marshal(uc.UnicitySeal)
	require.NoError(t, err)
	shard := uc.ShardTreeCertificate.Shard.Bytes()
	prefix := binary.BigEndian.AppendUint32(nil, uint32(uc.UnicityTreeCertificate.Partition))
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(shard)))
	prefix = append(prefix, shard...)
	wire := bytes.Clone(prefix)
	wire = append(wire, uc.ShardConfHash...)
	wire = append(wire, uc.InputRecord.Hash...)
	irHash := sha256.Sum256(ir)
	wire = append(wire, irHash[:]...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(raw)))
	wire = append(wire, raw...)
	sealHash, claimHash := sha256.Sum256(seal), sha256.Sum256(wire)
	return flatClaim{key: expectedCommit("CLAIM_KEY", sealHash[:], prefix),
		value: expectedCommit("CLAIM_VALUE", claimHash[:]), wire: wire}
}

func expectedPageRoot(evidence []byte) [32]byte {
	var leaves [][32]byte
	n := binary.BigEndian.AppendUint64(nil, uint64(len(evidence)))
	for start := 0; start < len(evidence); start += 4096 {
		page := evidence[start:min(start+4096, len(evidence))]
		i := binary.BigEndian.AppendUint64(nil, uint64(len(leaves)))
		size := binary.BigEndian.AppendUint16(nil, uint16(len(page)))
		leaves = append(leaves, expectedCommit("PAGE", n, i, size, page))
	}
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, expectedCommit("PAD"))
	}
	for len(leaves) > 1 {
		for i := range len(leaves) / 2 {
			leaves[i] = expectedCommit("PAGE_NODE", leaves[2*i][:], leaves[2*i+1][:])
		}
		leaves = leaves[:len(leaves)/2]
	}
	return leaves[0]
}

type expectedLeaf struct{ key, hash [32]byte }

type expectedSparse struct {
	label string
	// The recursive builder walks MSB-first; defaults here are indexed by
	// the number of remaining bits, so missing subtrees need no traversal.
	defaults [257][32]byte
	leaves   map[[32]byte][32]byte
}

func newExpectedSparse(label string) expectedSparse {
	tree := expectedSparse{label: label, leaves: make(map[[32]byte][32]byte)}
	for i := range 256 {
		prev := tree.defaults[i]
		tree.defaults[i+1] = expectedCommit(label, prev[:], prev[:])
	}
	return tree
}

func (tree *expectedSparse) root() [32]byte {
	leaves := make([]expectedLeaf, 0, len(tree.leaves))
	for key, hash := range tree.leaves {
		leaves = append(leaves, expectedLeaf{key, hash})
	}
	slices.SortFunc(leaves, func(a, b expectedLeaf) int { return bytes.Compare(a.key[:], b.key[:]) })
	return tree.subtree(leaves, 0)
}

func (tree *expectedSparse) subtree(leaves []expectedLeaf, bit int) [32]byte {
	if len(leaves) == 0 {
		return tree.defaults[256-bit]
	}
	if bit == 256 {
		return leaves[0].hash
	}
	i := 0
	for i < len(leaves) && leaves[i].key[bit/8]&(0x80>>uint(bit%8)) == 0 {
		i++
	}
	l, r := tree.subtree(leaves[:i], bit+1), tree.subtree(leaves[i:], bit+1)
	return expectedCommit(tree.label, l[:], r[:])
}

type expectedLineage struct {
	domain, session, pageRoot [32]byte
	runtimeAddress            [20]byte
	state                     FlatState // fields only; this producer serializes them independently
	sids, claims              expectedSparse
}

func newExpectedLineage(t *testing.T, v *FlatVerifier, evidence []byte) *expectedLineage {
	p := expectedPageRoot(evidence)
	d := sha256.Sum256(flatGolden(t, "gamma"))
	g := expectedCommit("GEN", v.deployment.Salt[:], d[:])
	n := binary.BigEndian.AppendUint64(nil, uint64(len(evidence)))
	s := expectedCommit("SESSION", []byte{1, 1}, g[:], d[:], v.cfg.Vault[:], v.deployment.Recovery[:],
		v.deployment.Runtime[:], v.deployment.Pins[:], n, p[:])
	return &expectedLineage{domain: d, session: s, pageRoot: p, runtimeAddress: v.deployment.Recovery,
		state: FlatState{Phase: 1, LevelsLeft: binary.BigEndian.Uint64(evidence[6:14])},
		sids:  newExpectedSparse("SID_NODE"), claims: newExpectedSparse("CLAIM_NODE")}
}

func expectedAmount(t *testing.T, raw []byte) (amount [32]byte) {
	t.Helper()
	var data cbor.RawTag
	require.NoError(t, cbor.Unmarshal(raw, &data))
	require.Equal(t, uint64(39050), data.Number)
	var fields []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(data.Content, &fields))
	var outputs [][][]byte
	require.NoError(t, cbor.Unmarshal(fields[1], &outputs))
	copy(amount[32-len(outputs[0][1]):], outputs[0][1])
	return amount
}

func expectedResult(t *testing.T, source [32]byte, mask [32]byte) [32]byte {
	imprint := append([]byte{0, 0}, source[:]...)
	return sha256.Sum256(expectedCBOR(t, [][]byte{imprint, mask[:]}))
}

func expectedStateWire(s FlatState) []byte {
	b := []byte{byte(s.Phase)}
	for _, n := range []uint64{s.Seq, s.Pos, s.LevelsLeft, s.TransfersLeft} {
		b = binary.BigEndian.AppendUint64(b, n)
	}
	return bytes.Join([][]byte{b, s.SeenRoot[:], s.ClaimRoot[:], s.Owner[:], s.State[:],
		s.TokenID[:], s.Amount[:], s.ParentLink[:], s.ParentManifest[:]}, nil)
}

func expectedVerdictWire(v *Verdict) []byte {
	b := make([]byte, 192)
	copy(b[:32], v.Domain[:])
	copy(b[32:64], v.Eta[:])
	binary.BigEndian.PutUint64(b[88:96], v.MinSegment)
	copy(b[96:128], v.Asset[:])
	copy(b[140:160], v.Recipient[:])
	v.Amount.FillBytes(b[160:192])
	return b
}

func expectedLog(e FlatEvent, emitter [20]byte) RawLog {
	data := make([]byte, 32)
	binary.BigEndian.PutUint64(data[24:], e.Seq)
	var signature string
	switch e.Kind {
	case FlatProgressEvent:
		signature = "NB2Progress11(bytes32,uint64,bytes32)"
		data = append(data, e.StateDigest[:]...)
	case FlatCompleteEvent, FlatGapEvent:
		signature = "NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)"
		data = append(data, expectedVerdictWire(e.Verdict)...)
		if e.Kind == FlatGapEvent {
			signature = "NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)"
			word := make([]byte, 32)
			binary.BigEndian.PutUint64(word[24:], e.NextSegment)
			data = append(data, word...)
			data = append(data, e.Head[:]...)
		}
	}
	return RawLog{Address: emitter, Topics: [][32]byte{expectedKeccak([]byte(signature)), e.Session}, Data: data}
}

func (p *expectedLineage) packet(t *testing.T, records []flatSourceFixture) (*FlatState, FlatEvent) {
	t.Helper()
	s := &p.state
	out := FlatEvent{Kind: FlatProgressEvent, Session: p.session, Seq: s.Seq + 1}
	for _, op := range records {
		p.sids.leaves[op.sid] = expectedCommit("SID", op.sid[:])
		for _, c := range op.claims {
			p.claims.leaves[c.key] = expectedCommit("CLAIM", c.key[:], c.value[:])
		}
		s.Pos = op.end
		tok := op.token
		if op.code != FlatTransfer {
			id := sha256.Sum256(expectedCBOR(t, []any{tok.Mint.Salt[:], tok.Mint.Network}))
			suffix := sha256.Sum256([]byte("TOKENID"))
			source := sha256.Sum256(expectedCBOR(t, [][]byte{id[:], suffix[:]}))
			s.TokenID = id
			s.State = expectedResult(t, source, id)
			s.Amount = expectedAmount(t, tok.Mint.Data)
			s.Owner = [33]byte(tok.Mint.Recipient.Params)
			s.ParentLink, s.ParentManifest = [32]byte{}, [32]byte{}
			s.Phase, s.TransfersLeft = 3, uint64(len(tok.Transfers))
			continue
		}
		tx := tok.Transfers[op.transfer]
		s.TransfersLeft--
		if s.TransfersLeft != 0 {
			s.State = expectedResult(t, s.State, tx.Mask)
			s.Owner = [33]byte(tx.Recipient.Params)
			continue
		}
		txHash := sha256.Sum256(tok.transfersRaw[op.transfer])
		if s.LevelsLeft > 1 {
			var manifest cbor.RawTag
			require.NoError(t, cbor.Unmarshal(tx.Data, &manifest))
			require.Equal(t, uint64(39046), manifest.Number)
			var roots [][]byte
			require.NoError(t, cbor.Unmarshal(manifest.Content, &roots))
			s.ParentManifest = [32]byte(roots[0])
			s.ParentLink = sha256.Sum256(bytes.Join([][]byte{[]byte("UNICITY/NB2/1.1/PARENT"),
				p.domain[:], s.TokenID[:], op.sid[:], txHash[:], s.ParentManifest[:], s.Amount[:]}, nil))
			s.Owner, s.State = [33]byte{}, [32]byte{}
			s.Phase = 2
			s.LevelsLeft--
			continue
		}
		var ret cbor.RawTag
		require.NoError(t, cbor.Unmarshal(tx.Data, &ret))
		require.Equal(t, uint64(39052), ret.Number)
		var fields struct {
			_                                struct{} `cbor:",toarray"`
			Version                          uint64
			Domain, Asset, Recipient, Amount []byte
			Start                            uint64
		}
		require.NoError(t, cbor.Unmarshal(ret.Content, &fields))
		btid := sha256.Sum256(expectedCBOR(t, [][]byte{[]byte("UNICITY_NB2_BURN"), op.sid[:], txHash[:]}))
		eta := sha256.Sum256(expectedCBOR(t, [][]byte{[]byte("UNICITY_NB2_REDEMPTION"), p.domain[:], btid[:]}))
		out.Kind = FlatCompleteEvent
		out.Verdict = &Verdict{Domain: [32]byte(fields.Domain), Eta: eta, MinSegment: fields.Start, Asset: [32]byte(fields.Asset),
			Recipient: [20]byte(fields.Recipient), Amount: new(big.Int).SetBytes(fields.Amount)}
		return nil, out
	}
	s.Seq = out.Seq
	s.SeenRoot, s.ClaimRoot = p.sids.root(), p.claims.root()
	out.StateDigest = expectedCommit("STATE", p.session[:], expectedStateWire(*s))
	next := *s
	return &next, out
}

func expectedArchiveStep(d [32]byte, index uint64, before, root [32]byte) [32]byte {
	tag := expectedKeccak([]byte("UNICITY_NB2_ARCHIVE_STEP"))
	return expectedKeccak(tag[:], d[:], binary.BigEndian.AppendUint64(nil, index), before[:], root[:])
}

func expectedGapRoot(ids [][32]byte) [32]byte {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	nodes := make([][32]byte, len(ids))
	for i := range ids {
		r := ids[(i+1)%len(ids)]
		nodes[i] = expectedKeccak([]byte{0}, ids[i][:], r[:])
	}
	for len(nodes) > 1 {
		for i := range len(nodes) / 2 {
			nodes[i] = expectedKeccak([]byte{1}, nodes[i*2][:], nodes[i*2+1][:])
		}
		nodes = nodes[:len(nodes)/2]
	}
	return nodes[0]
}

func expectedSettlement(before flatCustodyFixture, v *Verdict, segmentSize int) flatCustodyFixture {
	after := before
	after.Current = append(slices.Clone(before.Current), hex.EncodeToString(v.Eta[:]))
	after.Population++
	delta := func(balance string, amount *big.Int) string {
		n, _ := new(big.Int).SetString(balance, 10)
		return n.Add(n, amount).String()
	}
	debit := new(big.Int).Neg(v.Amount)
	after.Liability = delta(before.Liability, debit)
	after.VaultBalance = delta(before.VaultBalance, debit)
	after.RecipientBalance = delta(before.RecipientBalance, v.Amount)
	after.Events = append(slices.Clone(before.Events), Event{Name: "Paid", Eta: v.Eta, Recipient: v.Recipient, Amount: v.Amount})
	if len(after.Current) == segmentSize {
		ids := make([][32]byte, len(after.Current))
		ordered := slices.Clone(after.Current)
		slices.Sort(ordered)
		for i, id := range ordered {
			ids[i] = [32]byte(mustHex(id))
		}
		old := [32]byte(mustHex(before.Head))
		next := expectedArchiveStep(v.Domain, before.Segment, old, expectedGapRoot(ids))
		after.Events = append(after.Events, Event{Name: "SegmentSealed", Segment: before.Segment, Before: old, After: next, IDs: ids})
		after.Head, after.PreviousHead = hex.EncodeToString(next[:]), before.Head
		after.Current, after.Previous = []string{}, after.Current
		after.Segment++
		after.Population = 0
	}
	return after
}

func expectedGenesisHead(d [32]byte, k uint64) [32]byte {
	tag := expectedKeccak([]byte("UNICITY_NB2_ARCHIVE_GENESIS"))
	return expectedKeccak(tag[:], d[:], binary.BigEndian.AppendUint16(nil, uint16(k)))
}
