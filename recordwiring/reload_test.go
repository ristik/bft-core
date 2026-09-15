package recordwiring_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/recordwiring"
)

func publish(t *testing.T, path string, d recordwiring.Deployment, c *certifiedchain.Chain, blocks ...int) {
	s, err := recordwiring.OpenStore(path, 8)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	for _, i := range blocks {
		uc, tr := c.Certificate(i)
		b := c.Blocks[i]
		require.NoError(t, s.Publish(context.Background(), d.StoreContext(), certifiedstore.Record{
			BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round,
			Certificate: uc, Technical: tr, Witness: b.Evidence,
		}), "block %d", i)
	}
}

// dump reads every key and value of the store file read-only, with no store handle open.
func dump(t *testing.T, path string) map[string][]byte {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	out := map[string][]byte{}
	require.NoError(t, db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return b.ForEach(func(k, v []byte) error {
				out[string(name)+"/"+string(k)] = bytes.Clone(v)
				return nil
			})
		})
	}))
	return out
}

// reload reopens the store at path in a fresh handle, as a restarted process does, and reloads it. It
// requires that reloading changed no stored key or value.
func reload(t *testing.T, path string, d recordwiring.Deployment, ex *stubExecutor) recordwiring.ReloadResult {
	before := dump(t, path)
	s, err := recordwiring.OpenStore(path, 8)
	require.NoError(t, err)
	res := recordwiring.Reload(context.Background(), s, d, ex)
	require.NoError(t, s.Close())
	require.Equal(t, before, dump(t, path), "reloading writes nothing")
	return res
}

func TestReloadOutcomes(t *testing.T) {
	c := certifiedchain.New(t, 3, 3)
	d := mustDeployment(t, c)
	another := c.ExecutedWith(c.Blocks[1], 2, 6, []byte("another block at height 2"))
	require.NotEqual(t, c.Blocks[2].Hash, another.Hash)

	cases := map[string]struct {
		published []int
		head      func(ex *stubExecutor)
		want      recordwiring.Outcome
		wantErr   error
		hasRecord bool
	}{
		"the executor is at the recorded block":                   {[]int{0, 1, 2}, func(ex *stubExecutor) { ex.head = ref(c.Blocks[2]) }, recordwiring.OutcomeDurableReady, nil, true},
		"the executor is at the recorded genesis":                 {[]int{0}, func(ex *stubExecutor) { ex.head = ref(c.Blocks[0]) }, recordwiring.OutcomeDurableReady, nil, true},
		"the executor is behind the record":                       {[]int{0, 1, 2}, func(ex *stubExecutor) { ex.head = ref(c.Blocks[1]) }, recordwiring.OutcomeExecutorBehind, recordwiring.ErrExecutorBehind, true},
		"the executor is ahead of the record":                     {[]int{0, 1, 2}, func(ex *stubExecutor) { ex.head = ref(c.Blocks[3]) }, recordwiring.OutcomeExecutorAhead, recordwiring.ErrExecutorAhead, true},
		"the executor holds another block at the recorded height": {[]int{0, 1, 2}, func(ex *stubExecutor) { ex.head = ref(another) }, recordwiring.OutcomeExecutorDiverged, recordwiring.ErrExecutorDiverged, true},
		"the executor names the recorded hash at another state": {[]int{0, 1, 2}, func(ex *stubExecutor) {
			ex.head = ref(c.Blocks[2])
			ex.head.StateRoot = c.Blocks[1].StateRoot.Bytes()
		}, recordwiring.OutcomeExecutorDiverged, recordwiring.ErrExecutorDiverged, true},
		"the executor's head cannot be read": {[]int{0, 1, 2}, func(ex *stubExecutor) { ex.headErr = errors.New("connection refused") }, recordwiring.OutcomeExecutorUnavailable, recordwiring.ErrExecutorUnavailable, true},
		"an empty store":                     {nil, func(ex *stubExecutor) { ex.head = ref(c.Blocks[2]) }, recordwiring.OutcomeNoRecord, certifiedstore.ErrNoRecord, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "certified.db")
			publish(t, path, d, c, tc.published...)
			ex := &stubExecutor{genesis: ref(c.Blocks[0])}
			tc.head(ex)
			res := reload(t, path, d, ex)
			require.Equal(t, tc.want, res.Outcome, "%v", res.Err)
			require.Equal(t, tc.hasRecord, res.HasRecord)
			if tc.wantErr == nil {
				require.NoError(t, res.Err)
			} else {
				require.ErrorIs(t, res.Err, tc.wantErr)
			}
			if tc.hasRecord {
				last := c.Blocks[tc.published[len(tc.published)-1]]
				require.Equal(t, last.Hash, res.Record.BlockHash())
				require.Equal(t, last.Number, res.Record.BlockNumber())
			}
		})
	}
}

func TestReloadRefusesUntrustedRecordsWithoutFallback(t *testing.T) {
	c := certifiedchain.New(t, 3, 2)
	d := mustDeployment(t, c)

	t.Run("a damaged head record with an older record present and the executor at that older block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "certified.db")
		publish(t, path, d, c, 0, 1, 2)
		db, err := bolt.Open(path, 0o600, nil)
		require.NoError(t, err)
		require.NoError(t, db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("certified-record/v1"))
			head := bytes.Clone(b.Get([]byte("head")))
			v := bytes.Clone(b.Get(head))
			v[len(v)/2] ^= 0x01
			return b.Put(head, v)
		}))
		require.NoError(t, db.Close())

		ex := &stubExecutor{genesis: ref(c.Blocks[0]), head: ref(c.Blocks[1])}
		res := reload(t, path, d, ex)
		require.Equal(t, recordwiring.OutcomeRecordUntrusted, res.Outcome)
		require.ErrorIs(t, res.Err, certifiedstore.ErrRecordUntrusted)
		require.False(t, res.HasRecord, "the older record for the executor's block is not used")
	})

	t.Run("a record published under another deployment", func(t *testing.T) {
		foreign := certifiedchain.New(t, 4, 2)
		path := filepath.Join(t.TempDir(), "certified.db")
		publish(t, path, mustDeployment(t, foreign), foreign, 0, 1, 2)

		ex := &stubExecutor{genesis: ref(c.Blocks[0]), head: ref(foreign.Blocks[2])}
		res := reload(t, path, d, ex)
		require.Equal(t, recordwiring.OutcomeRecordUntrusted, res.Outcome)
		require.ErrorIs(t, res.Err, certifiedstore.ErrWrongContext)
		require.False(t, res.HasRecord)
	})
}
