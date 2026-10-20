package b7rel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/b1state"
)

// testdata/b7-relation-vectors-v1.json is produced here (B7REL_UPDATE=1 go test ./b7rel) and replayed by the Solidity adapter
// and the Rust guest. Every value is derived; nothing is edited by hand.
const vectorsPath = "testdata/b7-relation-vectors-v1.json"

type commitmentVector struct {
	Name              string     `json:"name"`
	GenesisCommitment string     `json:"genesisCommitment"`
	ProfileHash       string     `json:"profileHash"`
	Epoch             uint64     `json:"epoch"`
	Metadata          []string   `json:"metadata"` // the 11 stored words, closure words included
	Members           [][]string `json:"members"`  // 8 stored words per member
	Commitment        string     `json:"commitment"`
}

type journalVector struct {
	Name    string `json:"name"`
	Journal string `json:"journal"`
	Valid   bool   `json:"valid"`
	Digest  string `json:"digest,omitempty"`
}

type vectors struct {
	Format           string             `json:"format"`
	Note             string             `json:"note"`
	RelationDomain   string             `json:"relationDomain"`
	Limits           map[string]uint64  `json:"limits"`
	RelationID       string             `json:"relationId"`
	CommitmentDomain string             `json:"commitmentDomain"`
	JournalDomain    string             `json:"journalDomain"`
	Commitments      []commitmentVector `json:"commitments"`
	Journals         []journalVector    `json:"journals"`
}

func h(b []byte) string { return "0x" + hex.EncodeToString(b) }

func label(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func member(i int, idLen int) b1state.Member {
	id := strings.Repeat(string(rune('a'+i%26)), idLen)
	k := label(fmt.Sprint("b7rel/key/", i))
	priv, err := ethcrypto.ToECDSA(k[:])
	if err != nil {
		panic(err)
	}
	var key [33]byte
	copy(key[:], ethcrypto.CompressPubkey(&priv.PublicKey))
	return b1state.Member{NodeID: id, Key: key, Weight: uint64(i + 1)}
}

func entry(epoch, bodyKind uint64, n, idLen int) b1state.Entry {
	e := b1state.Entry{Epoch: epoch, BodyKind: bodyKind, BodyID: label(fmt.Sprint("b7rel/body/", epoch)), Start: 100 * epoch,
		SigningScheme: 2, SigningConfigHash: label(fmt.Sprint("b7rel/signing/", epoch))}
	if bodyKind != 1 {
		e.ActivationCommitID = label(fmt.Sprint("b7rel/activation/", epoch))
	}
	for i := 0; i < n; i++ {
		e.Members = append(e.Members, member(i, idLen))
	}
	return e
}

func commitmentCase(t *testing.T, name string, g, p [32]byte, e b1state.Entry) commitmentVector {
	t.Helper()
	c, err := EpochCommitment(g, p, e)
	require.NoError(t, err)
	meta, members := e.StoredWords()
	v := commitmentVector{Name: name, GenesisCommitment: h(g[:]), ProfileHash: h(p[:]), Epoch: e.Epoch, Commitment: h(c[:])}
	for _, w := range meta {
		v.Metadata = append(v.Metadata, h(w[:]))
	}
	for _, m := range members {
		var ws []string
		for _, w := range m {
			ws = append(ws, h(w[:]))
		}
		v.Members = append(v.Members, ws)
	}
	return v
}

func baseJournal(epochs int) Journal {
	j := Journal{RelationID: RelationID(), ChainID: big.NewInt(31337), GenesisCommitment: label("b7rel/genesis"), ProfileHash: label("b7rel/profile"),
		WitnessCommitment: label("b7rel/witness"),
		Release: Release{Cfg: label("b7rel/cfg"), Nonce: big.NewInt(5), Amount: big.NewInt(1_000_000_007), TokenID: label("b7rel/token"),
			Salt: label("b7rel/salt"), FirstPredicateHash: label("b7rel/p0"), LockDigest: label("b7rel/lock"), Nullifier: label("b7rel/nullifier")}}
	j.Release.ReleaseTo[0], j.Release.ReleaseTo[19] = 0xAA, 0x01
	for i := 0; i < epochs; i++ {
		e := uint64(i + 1)
		j.Epochs = append(j.Epochs, EpochUse{Epoch: e, Commitment: label(fmt.Sprint("b7rel/C/", e)), MinRound: 100*e + 1, MaxRound: 100*e + 50})
	}
	return j
}

func build(t *testing.T) vectors {
	t.Helper()
	g, p := label("b7rel/genesis"), label("b7rel/profile")
	v := vectors{Format: "UNICITY_B7_RELATION_VECTORS/v1",
		Note: "Produced by bft-core (B7REL_UPDATE=1 go test ./b7rel). Candidate limits and relation ID, the per-epoch registry commitment C_e " +
			"over the stored entry words (closure words 5 and 6 excluded), and the canonical journal with one isolated refusal per rule. Do not edit by hand.",
		RelationDomain: h(RelationDomain[:]), RelationID: func() string { r := RelationID(); return h(r[:]) }(),
		CommitmentDomain: h(CommitmentDomain[:]), JournalDomain: h(JournalDomain[:]),
		Limits: map[string]uint64{"maxLeaves": MaxLeaves, "maxTransfers": MaxTransfers, "maxEpochs": MaxEpochs, "maxAnchors": MaxAnchors,
			"maxSemanticBytes": MaxSemanticBytes, "maxWitnessBytes": MaxWitnessBytes, "maxMembersPerEpoch": MaxMembersPerEpoch, "maxRSMTSiblings": MaxRSMTSiblings}}

	open := entry(7, 2, 4, 12)
	closed := open
	end := uint64(799)
	closed.End = &end
	co, cc := commitmentCase(t, "successor, open", g, p, open), commitmentCase(t, "the same successor, closed", g, p, closed)
	require.Equal(t, co.Commitment, cc.Commitment, "closing an epoch does not change C_e")
	require.NotEqual(t, co.Metadata[5], cc.Metadata[5])
	v.Commitments = append(v.Commitments,
		commitmentCase(t, "genesis, one member", g, p, entry(1, 1, 1, 1)),
		co, cc,
		commitmentCase(t, "sixteen members, 128-byte node IDs", g, p, entry(9, 3, b1state.MaxMembers, 128)),
		commitmentCase(t, "the successor under another genesis commitment", label("b7rel/other-genesis"), p, open),
		commitmentCase(t, "the successor under another profile", g, label("b7rel/other-profile"), open))

	ok := func(name string, j Journal) {
		b, err := j.Encode()
		require.NoError(t, err)
		d := Digest(b)
		v.Journals = append(v.Journals, journalVector{Name: name, Journal: h(b), Valid: true, Digest: h(d[:])})
	}
	ok("one epoch", baseJournal(1))
	ok("three epochs", baseJournal(3))
	ok("MaxEpochs epochs", baseJournal(MaxEpochs))
	z := baseJournal(1)
	z.Epochs[0].MinRound = z.Epochs[0].MaxRound
	ok("one round", z)

	valid, err := baseJournal(3).Encode()
	require.NoError(t, err)
	bad := func(name string, mut func(b []byte) []byte) {
		b := mut(bytes.Clone(valid))
		_, err := Decode(b)
		require.ErrorIs(t, err, ErrJournal, name)
		v.Journals = append(v.Journals, journalVector{Name: name, Journal: h(b), Valid: false})
	}
	at := func(word, byteIdx int) func(b []byte) []byte {
		return func(b []byte) []byte { b[32*word+byteIdx] ^= 0x01; return b }
	}
	setCount := func(n uint64) func(b []byte) []byte {
		return func(b []byte) []byte { w := word(n); copy(b[32*15:], w[:]); return b }
	}
	bad("another domain", at(0, 31))
	bad("empty", func([]byte) []byte { return nil })
	bad("one trailing byte", func(b []byte) []byte { return append(b, 0) })
	bad("one trailing word", func(b []byte) []byte { return append(b, make([]byte, 32)...) })
	bad("one word short", func(b []byte) []byte { return b[:len(b)-32] })
	bad("epoch count zero, three epochs of length", setCount(0))
	bad("epoch count above the length", setCount(4))
	bad("epoch count above MaxEpochs, three epochs of length", setCount(MaxEpochs+1))
	// the count rules alone: the length is the one the count implies, so only the 1..MaxEpochs bound refuses
	bad("epoch count zero, header only (512 bytes)", func(b []byte) []byte { b = b[:32*headerWords]; w := word(0); copy(b[32*15:], w[:]); return b })
	bad("MaxEpochs+1 epochs, length-consistent", func([]byte) []byte {
		b, err := baseJournal(MaxEpochs).Encode()
		require.NoError(t, err)
		w := word(MaxEpochs + 1)
		copy(b[32*15:], w[:])
		for _, x := range [][32]byte{word(MaxEpochs + 1), label("b7rel/C/65"), word(100*(MaxEpochs+1) + 1), word(100*(MaxEpochs+1) + 50)} {
			b = append(b, x[:]...)
		}
		require.Len(t, b, 32*(headerWords+epochUseWords*(MaxEpochs+1)))
		return b
	})
	bad("epoch count with a high byte", at(15, 0))
	bad("releaseTo with a high byte", at(13, 0))
	bad("epoch with a high byte", at(16, 0))
	bad("minRound with a high byte", at(18, 0))
	bad("maxRound with a high byte", at(19, 0))
	bad("minRound above maxRound", func(b []byte) []byte { w := word(1 << 40); copy(b[32*18:], w[:]); return b })
	bad("epochs descending", func(b []byte) []byte {
		x := bytes.Clone(b[32*16 : 32*20])
		copy(b[32*16:32*20], b[32*20:32*24])
		copy(b[32*20:32*24], x)
		return b
	})
	bad("duplicate epoch", func(b []byte) []byte { copy(b[32*20:32*21], b[32*16:32*17]); return b })
	return v
}

func TestB7RelationVectorsAreTheCommittedFile(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", " ")
	require.NoError(t, enc.Encode(build(t)))
	if os.Getenv("B7REL_UPDATE") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(vectorsPath, buf.Bytes(), 0o644))
	}
	want, err := os.ReadFile(vectorsPath)
	require.NoError(t, err)
	require.Equal(t, string(want), buf.String(), "regenerate with B7REL_UPDATE=1 and replay in the consumers")
}

// The decoder round-trips every valid vector and the encoder refuses what the decoder refuses.
func TestJournalRoundTripAndEncoderRefusals(t *testing.T) {
	for _, n := range []int{1, 2, MaxEpochs} {
		b, err := baseJournal(n).Encode()
		require.NoError(t, err)
		j, err := Decode(b)
		require.NoError(t, err)
		again, err := j.Encode()
		require.NoError(t, err)
		require.Equal(t, b, again)
	}
	for name, mut := range map[string]func(*Journal){
		"no epochs":       func(j *Journal) { j.Epochs = nil },
		"too many epochs": func(j *Journal) { *j = baseJournal(MaxEpochs + 1) },
		"duplicate epoch": func(j *Journal) { j.Epochs[1].Epoch = j.Epochs[0].Epoch },
		"min above max":   func(j *Journal) { j.Epochs[0].MinRound = j.Epochs[0].MaxRound + 1 },
		"negative amount": func(j *Journal) { j.Release.Amount = big.NewInt(-1) },
		"nil chain":       func(j *Journal) { j.ChainID = nil },
	} {
		j := baseJournal(2)
		mut(&j)
		_, err := j.Encode()
		require.ErrorIs(t, err, ErrJournal, name)
	}
}

// C_e changes with every committed word and with the genesis, profile and epoch, but not with the closure words.
func TestEpochCommitmentBindsEveryStoredWordButClosure(t *testing.T) {
	g, p := label("g"), label("p")
	base := entry(5, 2, 3, 10)
	c0, err := EpochCommitment(g, p, base)
	require.NoError(t, err)
	diff := func(name string, e b1state.Entry, g2, p2 [32]byte) {
		c, err := EpochCommitment(g2, p2, e)
		require.NoError(t, err)
		require.NotEqual(t, c0, c, name)
	}
	mut := func(f func(e *b1state.Entry)) b1state.Entry {
		e := base
		e.Members = append([]b1state.Member(nil), base.Members...)
		f(&e)
		return e
	}
	diff("genesis", base, label("g2"), p)
	diff("profile", base, g, label("p2"))
	diff("epoch", mut(func(e *b1state.Entry) { e.Epoch = 6 }), g, p)
	diff("bodyKind", mut(func(e *b1state.Entry) { e.BodyKind = 3 }), g, p)
	diff("bodyID", mut(func(e *b1state.Entry) { e.BodyID[0] ^= 1 }), g, p)
	diff("activation", mut(func(e *b1state.Entry) { e.ActivationCommitID[0] ^= 1 }), g, p)
	diff("start", mut(func(e *b1state.Entry) { e.Start++ }), g, p)
	diff("signing scheme", mut(func(e *b1state.Entry) { e.SigningScheme = 1 }), g, p)
	diff("signing config", mut(func(e *b1state.Entry) { e.SigningConfigHash[0] ^= 1 }), g, p)
	diff("member weight", mut(func(e *b1state.Entry) { e.Members[1].Weight++ }), g, p)
	diff("member key", mut(func(e *b1state.Entry) { e.Members[1].Key[5] ^= 1 }), g, p)
	diff("member node ID", mut(func(e *b1state.Entry) { e.Members[1].NodeID += "x" }), g, p)
	diff("one member fewer", mut(func(e *b1state.Entry) { e.Members = e.Members[:2] }), g, p)
	end := uint64(9_999)
	c, err := EpochCommitment(g, p, mut(func(e *b1state.Entry) { e.End = &end }))
	require.NoError(t, err)
	require.Equal(t, c0, c, "closure words are excluded")
}

// The registry serves exactly the epochs one journal can name.
func TestTheRegistryViewBoundIsMaxEpochs(t *testing.T) {
	require.EqualValues(t, MaxEpochs, b1state.MaxCommitmentView)
}
