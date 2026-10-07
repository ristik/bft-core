package rootrecords

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// The vectors are the authenticated replacement of the custody contracts' local MockRootRecords fixtures (unicity-pos-contracts
// test/p85): the projection itself produces the records, and the contracts replay them verbatim, recompute every identifier with
// their own keccak and decode every payload. Set ROOTRECORDS_UPDATE=1 to regenerate.

const vectorsPath = "testdata/records-vectors.json"

type vectorRecord struct {
	Index       uint64 `json:"index"`
	ID          string `json:"recordId"`
	Predecessor string `json:"predecessor"`
	Kind        uint8  `json:"kind"`
	Progress    uint64 `json:"progress"`
	UCTime      uint64 `json:"ucTime"`
	Data        string `json:"data"`
}

type vectorScenario struct {
	Name    string         `json:"name"`
	Records []vectorRecord `json:"records"`
}

type vectorFile struct {
	Format    string           `json:"format"`
	Scenarios []vectorScenario `json:"scenarios"`
}

func label(s string) [32]byte {
	var a [32]byte
	copy(a[:], ethcrypto.Keccak256([]byte(s)))
	return a
}

func toVector(name string, recs []Record) vectorScenario {
	s := vectorScenario{Name: name}
	for _, r := range recs {
		s.Records = append(s.Records, vectorRecord{r.Index, "0x" + hex.EncodeToString(r.ID[:]), "0x" + hex.EncodeToString(r.Predecessor[:]), uint8(r.Kind), r.Progress, r.UCTime, "0x" + hex.EncodeToString(r.Data)})
	}
	return s
}

func fromVector(t *testing.T, s vectorScenario) []Record {
	t.Helper()
	dec := func(h string) []byte {
		b, err := hex.DecodeString(h[2:])
		require.NoError(t, err)
		return b
	}
	var out []Record
	for _, v := range s.Records {
		r := Record{Index: v.Index, Kind: Kind(v.Kind), Progress: v.Progress, UCTime: v.UCTime, Data: dec(v.Data)}
		copy(r.ID[:], dec(v.ID))
		copy(r.Predecessor[:], dec(v.Predecessor))
		out = append(out, r)
	}
	return out
}

// buildVectors projects the two scenarios the custody tests need. Round and progress numbers follow the custody fixtures: the genesis
// epoch is epoch 1 from round 1, the incumbent's H is ordered at round 100 (p = 99), the successor starts at offset 100 on round 101.
func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	resJ, resJ2, asgK := label("result/J"), label("result/J2"), label("assignment/K")

	h := NewProjector(1, 1)
	require.NoError(t, h.Import(origin(1, 10, 1_000)))
	require.NoError(t, h.Tracker.Observe(1, 50))
	_, err := h.SessionClosed(resJ2)
	require.NoError(t, err)
	_, err = h.Ack(resJ, 100, 2, 101)
	require.NoError(t, err)
	require.NoError(t, h.Tracker.Observe(2, 151))
	require.NoError(t, h.Import(origin(1, 20, 1_200)))
	_, _, err = h.Close(ClosureKey{1, label("record/H"), 100}, Closure{label("assignment/genesis"), label("terminal-root"), label("exposure-digest"), label("key-history-digest")})
	require.NoError(t, err)
	_, err = h.Retire(1, 1, label("ref-digest"))
	require.NoError(t, err)

	r := NewProjector(1, 1)
	require.NoError(t, r.Import(origin(1, 10, 1_000)))
	require.NoError(t, r.Tracker.Observe(1, 50))
	_, err = r.RecoveryAck(resJ, asgK, 100, 2, 101, 130, 3, 131, 3)
	require.NoError(t, err)

	return vectorFile{Format: "UNICITY_P85_ROOT_RECORDS/v1", Scenarios: []vectorScenario{toVector("handoff-closure-retirement", h.Log.Records()), toVector("recovery", r.Log.Records())}}
}

func TestVectorsAreTheProjection(t *testing.T) {
	want, err := json.MarshalIndent(buildVectors(t), "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	if os.Getenv("ROOTRECORDS_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(vectorsPath, want, 0o644))
	}
	got, err := os.ReadFile(vectorsPath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run with ROOTRECORDS_UPDATE=1 to regenerate")
}

func TestVectorsVerifyAndCarryTheAnchors(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	require.NoError(t, err)
	var f vectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	for _, s := range f.Scenarios {
		require.NoError(t, Verify(fromVector(t, s)), s.Name)
	}
	hs := fromVector(t, f.Scenarios[0])
	require.Len(t, hs, 4)
	require.Equal(t, []Anchor{{49, 1_000}, {99, 1_000}, {150, 1_200}, {150, 1_200}}, anchors(hs))
	require.Equal(t, []Kind{KindSessionClosed, KindAck, KindClosure, KindRetirement}, kinds(hs))
	rs := fromVector(t, f.Scenarios[1])
	require.Len(t, rs, 1)
	require.Equal(t, uint64(129+1), payloadWord(rs[0], 5)) // K offset = p(J,130)+1 = (100+29)+1
}

func anchors(rs []Record) (out []Anchor) {
	for _, r := range rs {
		out = append(out, Anchor{r.Progress, r.UCTime})
	}
	return
}

func kinds(rs []Record) (out []Kind) {
	for _, r := range rs {
		out = append(out, r.Kind)
	}
	return
}
