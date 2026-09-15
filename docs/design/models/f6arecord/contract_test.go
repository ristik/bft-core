package f6arecord

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

/*
The crash contract, executable. A node model moves one certified block B through the pipeline

	observed -> executor-applied -> witness-verified -> durable-ready

and a crash can end the process after any step. Reload is a new model instance over the same store and
executor. It decides readiness only from the store, configuration, the executor's head and, for readiness
for B's child, the live certificate; memory from before the crash is gone.

  - observed: a certificate for B authenticated under configuration. Memory only.
  - executor-applied: the executor's head is B. The executor's state, not this node's.
  - witness-verified: witness(B) acquired by hash and accepted by registryproof.Verify. Memory only.
  - durable-ready: the record for B, with certificate, technical record and witness(B), committed in one
    transaction with the head pointer, AND re-verified on reload, AND the executor's head is B.

Durable-ready is necessary for building, validating or signing for B's child, not sufficient: a durable
record replays perfectly after a whole-store rollback, so readyForChild also requires the live certificate
to be the one recorded (errStale). Nothing here reads, writes, resets or implies signing state.
*/

const (
	headKey      = "head"
	recordPrefix = "record/"
	genesisKey   = "record/genesis"
)

func recordKey(b block) string {
	if b.Number == 0 {
		return genesisKey
	}
	return fmt.Sprintf("%s%020d/%x", recordPrefix, b.PartitionRound, b.Hash)
}

type harness struct {
	t        *testing.T
	d        *deployment
	chain    []block
	cfg      config
	store    *faultStore
	executor *fakeExecutor
	rpc      *fakeRPC
	signed   map[[32]byte]bool // the modelled trust base: digests of certificates the root chain issued
	certs    map[common.Hash]certificate
	trs      map[common.Hash]technicalRecord
	retain   int
	// trByDigest finds the technical record a certificate commits to.
	trByDigest map[string]technicalRecord
}

var modelShard = []byte{0x80}

func newHarness(t *testing.T, blocks int) *harness {
	d := newDeployment(t, 3)
	chain := d.chain(t, blocks)
	h := &harness{
		t: t, d: d, chain: chain, store: newFaultStore(), rpc: newFakeRPC(chain...),
		executor: newFakeExecutor(chain[0], chain[1:]...), signed: map[[32]byte]bool{},
		certs: map[common.Hash]certificate{}, trs: map[common.Hash]technicalRecord{}, retain: 2,
	}
	h.cfg = config{context: contextFor(d, 3, 8, modelShard), proofContext: d.ctx, authenticate: h.authenticate}
	for i, b := range chain {
		prev := b.StateRoot
		if i > 0 {
			prev = chain[i-1].StateRoot
		}
		tr := technicalRecord{Round: b.PartitionRound + 1, Epoch: 0}
		c := certificate{
			NetworkID: 3, PartitionID: 8, ShardID: modelShard, ShardConfHash: d.ctx.FullShardConfHash.Bytes(),
			PartitionRound: b.PartitionRound, PreviousHash: prev.Bytes(), StateHash: b.StateRoot.Bytes(),
			BlockHash: b.Hash.Bytes(), TRHash: tr.digest(), RootRound: 4 + b.PartitionRound,
			Timestamp: 1_700_000_000 + b.PartitionRound,
		}
		if b.Number == 0 {
			// Genesis history names no block (#153 §7.3 E2); the genesis identity comes from configuration.
			c.BlockHash = nil
		}
		h.certs[b.Hash], h.trs[b.Hash] = c, tr
		h.issue(c, tr)
	}
	return h
}

func (h *harness) authenticate(c certificate) error {
	if !h.signed[c.digest()] {
		return errors.New("not issued by the modelled root chain")
	}
	return nil
}

// node is one process lifetime.
type node struct {
	h        *harness
	observed *block
	witness  registrywitness.Witness
}

func (h *harness) start() *node { return &node{h: h} }

func (n *node) observe(b block) error {
	c := n.h.certs[b.Hash]
	if err := n.h.authenticate(c); err != nil {
		return err
	}
	n.observed = &b
	return nil
}

func (n *node) apply() error {
	if n.observed == nil {
		return errors.New("pipeline: nothing observed")
	}
	return n.h.executor.commit(n.observed.Hash)
}

func (n *node) capture() error {
	if n.observed == nil {
		return errors.New("pipeline: nothing observed")
	}
	w, err := registrywitness.Acquire(context.Background(), n.h.rpc, n.h.cfg.proofContext, n.observed.Hash)
	if err != nil {
		return err
	}
	n.witness = w
	return nil
}

func (n *node) recordFor(b block, ev registryproof.Evidence) certifiedRecord {
	return certifiedRecord{
		Version: recordVersion, Context: n.h.cfg.context, BlockHash: b.Hash.Bytes(), BlockNumber: b.Number,
		StateRoot: b.StateRoot.Bytes(), PartitionRound: b.PartitionRound, Certificate: n.h.certs[b.Hash],
		Technical: n.h.trs[b.Hash], WitnessHeader: ev.Header, WitnessAccount: ev.AccountProof, WitnessStorage: ev.StorageProofs,
	}
}

/*
persist is the atomic write boundary. One transaction writes the record for B, points the head at it, and
applies retention. It refuses to write without a verified witness for exactly the observed block, and
without the executor being at B, so a durable record never claims more than the node established.
*/
func (n *node) persist(crashBeforeCommit bool) error {
	b := n.observed
	if b == nil || !n.witness.Valid() || n.witness.Parent() != b.Hash {
		return errNoWitness
	}
	if n.h.executor.head.Hash != b.Hash {
		return errExecutorBehind
	}
	enc, err := encodeRecord(n.recordFor(*b, n.witness.Evidence()))
	if err != nil {
		return err
	}
	tx := n.h.store.begin()
	key := recordKey(*b)
	tx.put(key, enc)
	tx.put(headKey, []byte(key))
	// Retention: keep the genesis record and the newest `retain` non-genesis records, in this transaction.
	existing := n.h.store.keys(recordPrefix)
	var nonGenesis []string
	for _, k := range existing {
		if k != genesisKey && k != key {
			nonGenesis = append(nonGenesis, k)
		}
	}
	if b.Number != 0 {
		nonGenesis = append(nonGenesis, key)
	}
	for len(nonGenesis) > n.h.retain {
		tx.del(nonGenesis[0])
		nonGenesis = nonGenesis[1:]
	}
	return tx.commit(crashBeforeCommit)
}

// readiness is the outcome of a reload.
type readiness struct {
	block    *block
	snapshot registryproof.Snapshot
	err      error
}

/*
reload decides durable readiness for a new process. The head pointer names exactly one record; if it is
missing, damaged, for another context, or its witness does not verify, the node is not ready. It never
falls back to an older retained record: that would present an older state as the current one, and the
executor, not the record, decides where the node is. Then the executor's head is compared with the record.
*/
func (h *harness) reload() readiness {
	keyBytes, ok := h.store.get(headKey)
	if !ok {
		return readiness{err: errNoRecord}
	}
	raw, ok := h.store.get(string(keyBytes))
	if !ok {
		return readiness{err: fmt.Errorf("%w: head names a missing record", errRecordUntrusted)}
	}
	r, err := decodeRecord(raw)
	if err != nil {
		return readiness{err: err}
	}
	s, err := verifyRecord(h.cfg, r)
	if err != nil {
		return readiness{err: err}
	}
	b := block{Hash: common.BytesToHash(r.BlockHash), Number: r.BlockNumber, StateRoot: common.BytesToHash(r.StateRoot), PartitionRound: r.PartitionRound}
	head := h.executor.head
	switch {
	case head.Hash == b.Hash:
		return readiness{block: &b, snapshot: s}
	case head.Number < b.Number:
		return readiness{block: &b, err: errExecutorBehind}
	case head.Number > b.Number:
		return readiness{block: &b, err: errExecutorAhead}
	default:
		return readiness{block: &b, err: errExecutorDiverged}
	}
}

// readyForChild is readiness when the held certificate is reached from the record's certificate with no
// intervening links: it is the record's own certificate, or a repeat of it. See readyWith (continuity_test.go).
func (h *harness) readyForChild(held certificate) (registryproof.Snapshot, error) {
	return h.readyWith(nil, link{cert: held, tr: h.trByDigest[string(held.TRHash)]})
}

// certify runs the whole pipeline for b without faults.
func (h *harness) certify(b block) {
	n := h.start()
	require.NoError(h.t, n.observe(b))
	require.NoError(h.t, n.apply())
	require.NoError(h.t, n.capture())
	require.NoError(h.t, n.persist(false))
}

func TestHappyPathEndsDurableReady(t *testing.T) {
	h := newHarness(t, 3)
	for _, b := range h.chain {
		h.certify(b)
		r := h.reload()
		require.NoError(t, r.err)
		require.Equal(t, b.Hash, r.block.Hash)
		s, err := h.readyForChild(h.certs[b.Hash])
		require.NoError(t, err)
		require.Equal(t, b.PartitionRound, s.Fields().RoundAuthorized)
	}
}

/*
TestCrashBetweenPipelineSteps: record(P) is durable and the executor is at P; the node then processes B,
P's child, and crashes at each boundary. Reload never reports durable-ready for B unless its record
committed, and never reports readiness for P while the executor has moved past it.
*/
func TestCrashBetweenPipelineSteps(t *testing.T) {
	for name, tc := range map[string]struct {
		run     func(h *harness, n *node, b block)
		wantErr error  // reload outcome
		ready   string // "P", "B" or ""
	}{
		"after observing, before executor commit": {func(h *harness, n *node, b block) {
			require.NoError(t, n.observe(b))
		}, nil, "P"},
		"after executor commit, before witness acquisition": {func(h *harness, n *node, b block) {
			require.NoError(t, n.observe(b))
			require.NoError(t, n.apply())
		}, errExecutorAhead, ""},
		"after witness verification, before the durable write": {func(h *harness, n *node, b block) {
			require.NoError(t, n.observe(b))
			require.NoError(t, n.apply())
			require.NoError(t, n.capture())
		}, errExecutorAhead, ""},
		"inside the durable write, before commit": {func(h *harness, n *node, b block) {
			require.NoError(t, n.observe(b))
			require.NoError(t, n.apply())
			require.NoError(t, n.capture())
			require.ErrorIs(t, n.persist(true), errCrashed)
		}, errExecutorAhead, ""},
		"after the durable write commits": {func(h *harness, n *node, b block) {
			require.NoError(t, n.observe(b))
			require.NoError(t, n.apply())
			require.NoError(t, n.capture())
			require.NoError(t, n.persist(false))
		}, nil, "B"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, 2)
			p, b := h.chain[1], h.chain[2]
			h.certify(h.chain[0])
			h.certify(p)
			tc.run(h, h.start(), b)

			r := h.reload() // a new process
			if tc.wantErr != nil {
				require.ErrorIs(t, r.err, tc.wantErr)
				_, err := h.readyForChild(h.certs[b.Hash])
				require.Error(t, err, "not ready for B's child")
				_, err = h.readyForChild(h.certs[p.Hash])
				require.Error(t, err, "not ready for P's child either: the executor is past P")
				return
			}
			require.NoError(t, r.err)
			switch tc.ready {
			case "P":
				require.Equal(t, p.Hash, r.block.Hash)
				_, err := h.readyForChild(h.certs[b.Hash])
				require.ErrorIs(t, err, errStale, "the live certificate for B makes P's readiness stale")
			case "B":
				require.Equal(t, b.Hash, r.block.Hash)
				_, err := h.readyForChild(h.certs[b.Hash])
				require.NoError(t, err)
			}
		})
	}
}

func TestProofExpiryBeforeCaptureStaysUnavailable(t *testing.T) {
	h := newHarness(t, 2)
	p, b := h.chain[1], h.chain[2]
	h.certify(h.chain[0])
	h.certify(p)
	h.rpc.expire(b.Hash)

	n := h.start()
	require.NoError(t, n.observe(b))
	require.NoError(t, n.apply())
	err := n.capture()
	require.ErrorIs(t, err, registrywitness.ErrUnavailable, "expired proof is unavailable, never invalid")
	require.ErrorIs(t, n.persist(false), errNoWitness, "no record is written without a verified witness")

	r := h.reload()
	require.ErrorIs(t, r.err, errExecutorAhead, "the node is not ready; obtaining witness(B) now belongs to #15")
}

func TestInterruptedAndDamagedRecordsAreRefused(t *testing.T) {
	cases := map[string]func(h *harness, key string){
		"a bit flipped in the stored record": func(h *harness, key string) {
			require.True(t, h.store.corrupt(key, 40))
		},
		"a truncated record": func(h *harness, key string) {
			raw, _ := h.store.get(key)
			require.True(t, h.store.truncate(key, len(raw)/2))
		},
		"the head names a record that is not there": func(h *harness, key string) {
			tx := h.store.begin()
			tx.del(key)
			require.NoError(t, tx.commit(false))
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, 2)
			h.certify(h.chain[0])
			h.certify(h.chain[1])
			h.certify(h.chain[2])
			key := recordKey(h.chain[2])
			damage(h, key)

			r := h.reload()
			require.ErrorIs(t, r.err, errRecordUntrusted)
			require.Nil(t, r.block, "no older retained record is substituted")
			_, olderStillThere := h.store.get(recordKey(h.chain[1]))
			require.True(t, olderStillThere, "premise: an older record was available to substitute")
		})
	}
}

// storedWith rewrites the head record through a change and re-encodes it with a valid digest, as a writer
// bug or a record from elsewhere would present: internally consistent, and wrong.
func storedWith(t *testing.T, h *harness, b block, change func(r *certifiedRecord)) {
	raw, ok := h.store.get(recordKey(b))
	require.True(t, ok)
	r, err := decodeRecord(raw)
	require.NoError(t, err)
	change(&r)
	enc, err := encodeRecord(r)
	require.NoError(t, err)
	tx := h.store.begin()
	tx.put(recordKey(b), enc)
	require.NoError(t, tx.commit(false))
}

func TestInconsistentRecordsAreRefusedOnReload(t *testing.T) {
	other := newDeployment(t, 4)
	for name, tc := range map[string]struct {
		change func(h *harness, r *certifiedRecord)
		want   error
	}{
		"a missing witness": {func(h *harness, r *certifiedRecord) {
			r.WitnessHeader, r.WitnessAccount, r.WitnessStorage = nil, nil, nil
		}, errWitness},
		"the witness of another block in the same deployment": {func(h *harness, r *certifiedRecord) {
			ev := h.chain[1].Evidence
			r.WitnessHeader, r.WitnessAccount, r.WitnessStorage = ev.Header, ev.AccountProof, ev.StorageProofs
		}, errWitness},
		"a witness for another deployment": {func(h *harness, r *certifiedRecord) {
			ev := other.genesisBlock().Evidence
			r.WitnessHeader, r.WitnessAccount, r.WitnessStorage = ev.Header, ev.AccountProof, ev.StorageProofs
		}, errWitness},
		"a record for another context": {func(h *harness, r *certifiedRecord) {
			r.Context = contextFor(other, 4, 8, modelShard)
		}, errWrongContext},
		"another block's certificate": {func(h *harness, r *certifiedRecord) {
			r.Certificate = h.certs[h.chain[1].Hash]
			r.Technical = h.trs[h.chain[1].Hash]
		}, errWrongBlock},
		"a certificate the root chain did not issue": {func(h *harness, r *certifiedRecord) {
			r.Certificate.RootRound++
		}, errCertificate},
		"a technical record the certificate does not commit to": {func(h *harness, r *certifiedRecord) {
			r.Technical.Round++
		}, errTechnicalRecord},
		"a record claiming another height": {func(h *harness, r *certifiedRecord) {
			r.BlockNumber++
		}, errWrongBlock},
		"an unknown record version": {func(h *harness, r *certifiedRecord) {
			r.Version = recordVersion + 1
		}, errRecordUntrusted},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, 2)
			h.certify(h.chain[0])
			h.certify(h.chain[1])
			h.certify(h.chain[2])
			storedWith(t, h, h.chain[2], func(r *certifiedRecord) { tc.change(h, r) })
			r := h.reload()
			require.ErrorIs(t, r.err, tc.want)
			_, err := h.readyForChild(h.certs[h.chain[2].Hash])
			require.Error(t, err)
		})
	}
}

func TestExecutorAheadOrBehindTheRecord(t *testing.T) {
	t.Run("behind: not ready until the executor commits the recorded block", func(t *testing.T) {
		h := newHarness(t, 2)
		for _, b := range h.chain {
			h.certify(b)
		}
		h.executor.head = h.chain[1] // e.g. the execution client lost its last commit
		require.ErrorIs(t, h.reload().err, errExecutorBehind)

		require.NoError(t, h.executor.commit(h.chain[2].Hash), "recovery re-commits the recorded, certified block")
		require.NoError(t, h.reload().err)
	})
	t.Run("behind without the payload: not ready, and nothing to commit", func(t *testing.T) {
		h := newHarness(t, 2)
		for _, b := range h.chain {
			h.certify(b)
		}
		delete(h.executor.payloads, h.chain[2].Hash)
		h.executor.head = h.chain[1]
		require.ErrorIs(t, h.executor.commit(h.chain[2].Hash), errPayloadUnavailable)
		require.ErrorIs(t, h.reload().err, errExecutorBehind)
	})
	t.Run("ahead: the association for the newer block was lost", func(t *testing.T) {
		h := newHarness(t, 3)
		for _, b := range h.chain[:3] {
			h.certify(b)
		}
		require.NoError(t, h.executor.commit(h.chain[3].Hash))
		r := h.reload()
		require.ErrorIs(t, r.err, errExecutorAhead)
		_, err := h.readyForChild(h.certs[h.chain[3].Hash])
		require.Error(t, err, "readiness for the newer block needs its own record")
	})
	t.Run("diverged: another block at the recorded height", func(t *testing.T) {
		h := newHarness(t, 2)
		for _, b := range h.chain {
			h.certify(b)
		}
		fork := h.d.executed(t, h.chain[1], 7, 42)
		require.NotEqual(t, h.chain[2].Hash, fork.Hash)
		h.executor.payloads[fork.Hash] = fork
		require.NoError(t, h.executor.commit(fork.Hash))
		require.ErrorIs(t, h.reload().err, errExecutorDiverged)
	})
}

func TestWholeStoreRollbackCannotTestifyToCurrency(t *testing.T) {
	h := newHarness(t, 3)
	for _, b := range h.chain {
		h.certify(b)
	}
	// Restore the store as it was after record(block 1) committed: internally perfect, and stale.
	require.True(t, h.store.rollbackTo(1))

	t.Run("with the executor at the newer block, the node is not ready", func(t *testing.T) {
		require.ErrorIs(t, h.reload().err, errExecutorAhead)
	})
	t.Run("with the executor also restored, the stale record reloads but is not ready for the live round", func(t *testing.T) {
		h.executor.head = h.chain[1]
		r := h.reload()
		require.NoError(t, r.err, "a rolled-back store and executor are locally consistent")
		_, err := h.readyForChild(h.certs[h.chain[3].Hash])
		require.ErrorIs(t, err, errStale, "only the live certificate exposes the rollback")
	})
}

func TestReplacementDiskAndMigration(t *testing.T) {
	t.Run("an empty replacement disk has no record", func(t *testing.T) {
		h := newHarness(t, 2)
		for _, b := range h.chain {
			h.certify(b)
		}
		h.store.wipe()
		require.ErrorIs(t, h.reload().err, errNoRecord)
	})
	t.Run("genesis readiness is re-established from configuration, only at genesis and only with genesis history", func(t *testing.T) {
		h := newHarness(t, 1)
		h.store.wipe()
		// The genesis witness is derived from configuration (registrygenesis), then treated like any other
		// captured witness: verified, persisted with the genesis certificate, and re-verified on reload.
		n := h.start()
		require.NoError(t, n.observe(h.chain[0]))
		require.NoError(t, n.capture())
		require.NoError(t, n.persist(false))
		s, err := h.readyForChild(h.certs[h.chain[0].Hash])
		require.NoError(t, err)
		genesisState := h.chain[0].StateRoot.Bytes()
		ir := &bfttypes.InputRecord{RoundNumber: 0, PreviousHash: genesisState, Hash: genesisState}
		require.NoError(t, registryproof.GenesisParentEligible(2, ir, genesisState, s), "the §9.2a initial-timeout rule still applies")
	})
	t.Run("a legacy certificate file creates no readiness", func(t *testing.T) {
		h := newHarness(t, 2)
		// The old FileStore holds the latest certificate only. Migration may use it as an observed
		// certificate, re-authenticated; it supplies no witness, so readiness still needs witness(B).
		n := h.start()
		require.NoError(t, n.observe(h.chain[2]), "the legacy certificate authenticates")
		require.NoError(t, h.executor.commit(h.chain[2].Hash))
		require.ErrorIs(t, n.persist(false), errNoWitness)
		require.ErrorIs(t, h.reload().err, errNoRecord)
	})
}

func TestRetentionIsPartOfTheWrite(t *testing.T) {
	h := newHarness(t, 5)
	for _, b := range h.chain[:5] {
		h.certify(b)
	}
	require.Equal(t, []string{recordKey(h.chain[3]), recordKey(h.chain[4]), genesisKey}, h.store.keys(recordPrefix),
		"genesis and the newest two records are retained (keys in sorted order)")

	n := h.start()
	b := h.chain[5]
	require.NoError(t, n.observe(b))
	require.NoError(t, n.apply())
	require.NoError(t, n.capture())
	require.ErrorIs(t, n.persist(true), errCrashed)
	require.Equal(t, []string{recordKey(h.chain[3]), recordKey(h.chain[4]), genesisKey}, h.store.keys(recordPrefix),
		"a crash inside the write deletes nothing")

	require.NoError(t, n.persist(false))
	require.Equal(t, []string{recordKey(h.chain[4]), recordKey(h.chain[5]), genesisKey}, h.store.keys(recordPrefix))
}

func TestPersistRefusesToClaimMoreThanItEstablished(t *testing.T) {
	h := newHarness(t, 2)
	h.certify(h.chain[0])
	h.certify(h.chain[1])
	b := h.chain[2]

	t.Run("no witness", func(t *testing.T) {
		n := h.start()
		require.NoError(t, n.observe(b))
		require.NoError(t, n.apply())
		require.ErrorIs(t, n.persist(false), errNoWitness)
	})
	t.Run("a witness for another block", func(t *testing.T) {
		n := h.start()
		require.NoError(t, n.observe(h.chain[1]))
		require.NoError(t, n.capture())
		n.observed = &b
		require.ErrorIs(t, n.persist(false), errNoWitness)
	})
	t.Run("the executor is not at the block", func(t *testing.T) {
		h.executor.head = h.chain[1]
		n := h.start()
		require.NoError(t, n.observe(b))
		require.NoError(t, n.capture())
		require.ErrorIs(t, n.persist(false), errExecutorBehind)
	})
	t.Run("a certificate the root chain did not issue is never observed", func(t *testing.T) {
		n := h.start()
		forged := b
		forged.PartitionRound = 99
		h.certs[forged.Hash] = certificate{PartitionRound: 99}
		require.Error(t, n.observe(forged))
	})
}

// TestTheRecordHoldsNoSigningState: the signing record stays in the authority's memory (ADR 0009, F6c
// contract). The stored record and the store's keys have nowhere to put it.
func TestTheRecordHoldsNoSigningState(t *testing.T) {
	forbidden := []string{"sign", "key", "generation", "reserv", "session", "journal", "vote", "cursor"}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Slice || rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			lower := strings.ToLower(f.Name)
			for _, word := range forbidden {
				require.NotContains(t, lower, word, "%s.%s", path, f.Name)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	walk(reflect.TypeOf(certifiedRecord{}), "certifiedRecord")

	h := newHarness(t, 2)
	for _, b := range h.chain {
		h.certify(b)
	}
	for _, k := range h.store.keys("") {
		require.True(t, k == headKey || strings.HasPrefix(k, recordPrefix), "unexpected key %q", k)
	}
}

// TestChecksNoOtherRuleCovers isolates reload and readiness rules that an earlier check would otherwise
// refuse first. Each case changes only what the named rule inspects.
func TestChecksNoOtherRuleCovers(t *testing.T) {
	certified := func(t *testing.T) *harness {
		h := newHarness(t, 2)
		for _, b := range h.chain {
			h.certify(b)
		}
		return h
	}
	head := func(h *harness) block { return h.chain[2] }

	t.Run("a live certificate for the recorded block that the root chain did not issue", func(t *testing.T) {
		h := certified(t)
		live := h.certs[head(h).Hash]
		live.RootRound += 100 // same block and round, not issued
		_, err := h.readyForChild(live)
		require.ErrorIs(t, err, errCertificate)
	})
	t.Run("a future envelope version is refused by version, before its payload is decoded", func(t *testing.T) {
		h := certified(t)
		enc, err := envelopeFor(recordVersion+1, []byte{0xff, 0x00, 0x13})
		require.NoError(t, err)
		tx := h.store.begin()
		tx.put(recordKey(head(h)), enc)
		require.NoError(t, tx.commit(false))
		require.ErrorIs(t, h.reload().err, errRecordVersion)
	})
	t.Run("an oversized stored value is refused before decoding", func(t *testing.T) {
		h := certified(t)
		tx := h.store.begin()
		tx.put(recordKey(head(h)), make([]byte, maxRecordBytes+1))
		require.NoError(t, tx.commit(false))
		r := h.reload()
		require.ErrorIs(t, r.err, errRecordUntrusted)
		require.ErrorContains(t, r.err, "exceeds")
	})
	t.Run("an issued certificate for another network naming the recorded block", func(t *testing.T) {
		h := certified(t)
		storedWith(t, h, head(h), func(r *certifiedRecord) {
			r.Certificate.NetworkID = 4 // the record's own context stays the configured one
			h.signed[r.Certificate.digest()] = true
		})
		require.ErrorIs(t, h.reload().err, errWrongContext)
	})
	t.Run("a record and certificate naming a block hash of the wrong width", func(t *testing.T) {
		h := certified(t)
		storedWith(t, h, head(h), func(r *certifiedRecord) {
			r.BlockHash = r.BlockHash[1:]
			r.Certificate.BlockHash = r.BlockHash
			h.signed[r.Certificate.digest()] = true
		})
		r := h.reload()
		require.ErrorIs(t, r.err, errWrongBlock)
		require.ErrorContains(t, r.err, "bytes")
	})
}
