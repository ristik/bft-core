package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

func evidenceObservation(exec byte) *rootevidence.Observation {
	return &rootevidence.Observation{Author: "1", Key: bytes.Repeat([]byte{2}, 33), Epoch: 2, Round: 12, S: rootevidence.Statement{
		Parent: 11, Exec: bytes.Repeat([]byte{exec}, 32), Signature: []byte{exec}, PV: []byte{0xaa, exec}}}
}

// `evidence scan` merges the journals of separate roots: one half in each is an offence that neither root alone could show.
func TestEvidenceScanMergesTheHalvesOfSeparateRoots(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for i, exec := range []byte{1, 2} {
		p := filepath.Join(dir, "j"+string(rune('a'+i))+".db")
		db, err := boltdb.New(p)
		require.NoError(t, err)
		j, err := rootevidence.NewJournal(db, 0)
		require.NoError(t, err)
		_, err = j.Record(evidenceObservation(exec))
		require.NoError(t, err)
		require.NoError(t, db.Close())
		files = append(files, p)
	}
	scan := func(paths ...string) (out struct {
		Pairs []struct {
			Author       string
			Epoch, Round uint64
		}
		Slots int
	}) {
		cmd := newEvidenceCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		args := []string{"scan"}
		for _, p := range paths {
			args = append(args, "--journal", p)
		}
		cmd.SetArgs(args)
		require.NoError(t, cmd.Execute())
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		return out
	}
	require.Empty(t, scan(files[0]).Pairs)
	require.Empty(t, scan(files[1]).Pairs)
	both := scan(files...)
	require.Len(t, both.Pairs, 1)
	require.Equal(t, "1", both.Pairs[0].Author)
	require.EqualValues(t, 12, both.Pairs[0].Round)
}

// The submitter reads the case and the settlement cursor after its own transactions: the reader must not be pinned to a block taken before them.
func TestEvidenceReaderReadsTheHead(t *testing.T) {
	require.Empty(t, evidenceReader(nil).Block)
}

// A lane with two offenders in the same journals submits for the one it names (X4 B4's second offence); a key which matches nothing is an error.
func TestPairsOfOffender(t *testing.T) {
	a := &rootevidence.SlotRecord{Key: bytes.Repeat([]byte{2}, 33), Round: 541}
	b := &rootevidence.SlotRecord{Key: bytes.Repeat([]byte{3}, 33), Round: 543}
	both := []*rootevidence.SlotRecord{a, b}
	got, err := pairsOfOffender(both, "")
	require.NoError(t, err)
	require.Equal(t, both, got)
	got, err = pairsOfOffender(both, hex.EncodeToString(b.Key))
	require.NoError(t, err)
	require.Equal(t, []*rootevidence.SlotRecord{b}, got)
	got, err = pairsOfOffender(both, "0x"+hex.EncodeToString(a.Key))
	require.NoError(t, err)
	require.Equal(t, []*rootevidence.SlotRecord{a}, got)
	_, err = pairsOfOffender(both, hex.EncodeToString(bytes.Repeat([]byte{4}, 33)))
	require.ErrorIs(t, err, ErrEvidence)
	_, err = pairsOfOffender(both, "zz")
	require.ErrorIs(t, err, ErrEvidence)
}
