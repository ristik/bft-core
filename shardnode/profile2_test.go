package shardnode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

func profile2Proof(t *testing.T, terminal *types.UnicityCertificate) (evmroot.HandoffProof, evmroot.D4TrustBase) {
	t.Helper()
	old, keys := evmroot.D4FixtureTrustBase(7, map[string]uint64{"a": 1, "b": 1, "c": 1, "d": 1})
	r := evmroot.OrderedHandoffRecord{Network: 3, Epoch: 7, Attempt: 1, OrderedRound: 10, ActivationRound: 13,
		PredecessorBodyID: bytes.Repeat([]byte{0x11}, 32), FrozenID: bytes.Repeat([]byte{0x44}, 32),
		NextBodyID: bytes.Repeat([]byte{0x22}, 32), SuccessorTRHash: bytes.Repeat([]byte{0x55}, 32), Kind: "commit"}
	ctl := evmroot.ControlState{Network: 3, Epoch: 7, Attempt: 1, OrderedRound: 10, PredecessorBodyID: r.PredecessorBodyID,
		Phase: "committed", RecordBytes: r.Bytes(), PreviousDigest: bytes.Repeat([]byte{0x66}, 32)}
	ir, err := terminal.InputRecord.Bytes()
	require.NoError(t, err)
	shard := evmroot.ShardSnapshot{Partition: 1, InputRecord: ir, TechnicalRecord: []byte("TR-H"), LastCR: []byte("last")}
	shard.Root = shard.CalculatedRoot()
	s := evmroot.FullSnapshot{Control: ctl, Shards: []evmroot.ShardSnapshot{shard}}
	root, err := s.Root()
	require.NoError(t, err)
	path, err := s.ControlPath()
	require.NoError(t, err)
	qc := evmroot.D4QC{Vote: evmroot.D4VoteInfo{Round: 101, Epoch: 7, ParentRound: 100, Timestamp: 1700000000, CurrentRoot: bytes.Clone(root)},
		Seal: evmroot.D4Seal{Commit: evmroot.D4LedgerCommitInfo{Network: 3, Round: 100, Epoch: 7, Timestamp: 1699999999, Root: bytes.Clone(root)}}}
	evmroot.D4SignQC(&qc, keys, "a", "b", "c")
	return evmroot.HandoffProof{Profile: evmroot.D4Profile, Record: r, Control: ctl, ControlPath: path, CommitQC: qc, Snapshot: s}, old
}

func TestProfile2MintedLateSuffixUC(t *testing.T) {
	terminal := uc(1, 10, []byte{0}, []byte{1}, []byte{2})
	terminal.UnicitySeal.Epoch = 7
	proof, old := profile2Proof(t, terminal)
	root, err := proof.Snapshot.Root()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "consumer.json")
	c, err := NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	_, err = c.Classify(nil, terminal)
	require.ErrorIs(t, err, ErrProfile2Unready)
	late := uc(1, 100, []byte{0}, []byte{1}, []byte{2})
	late.UnicitySeal.Epoch = 7
	late.UnicitySeal.Hash = root
	_, err = c.Classify(terminal, late)
	require.ErrorIs(t, err, ErrProfile2Unready)
	require.NoError(t, c.Install(proof))
	_, err = c.Classify(terminal, late)
	require.ErrorIs(t, err, ErrProfile2TerminalRepeat)
	wrongRoot := *late
	wrongRootSeal := *late.UnicitySeal
	wrongRootSeal.Hash = bytes.Repeat([]byte{0xee}, 32)
	wrongRoot.UnicitySeal = &wrongRootSeal
	_, err = c.Classify(terminal, &wrongRoot)
	require.ErrorIs(t, err, ErrProfile2Epoch)
	c, err = NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	_, err = c.Classify(terminal, late)
	require.ErrorIs(t, err, ErrProfile2TerminalRepeat)
	newUC := uc(2, 13, []byte{1}, []byte{3}, []byte{4})
	newUC.UnicitySeal.Epoch = 8
	_, err = c.Classify(late, newUC)
	require.ErrorIs(t, err, ErrProfile2Unready)
	require.NoError(t, c.SetReady())
	_, err = c.Classify(terminal, late)
	require.ErrorIs(t, err, ErrProfile2TerminalRepeat)
	class, err := c.Classify(late, newUC)
	require.NoError(t, err)
	require.Equal(t, UCValid, class)
	bad := *newUC
	badSeal := *newUC.UnicitySeal
	badSeal.Epoch = 9
	bad.UnicitySeal = &badSeal
	_, err = c.Classify(late, &bad)
	require.ErrorIs(t, err, ErrProfile2Epoch)
}

func TestProfile2OrdinaryRepeatBeforeKnownHandoff(t *testing.T) {
	for _, orderedRound := range []uint64{0, 10} {
		t.Run(fmt.Sprintf("ordered_%d", orderedRound), func(t *testing.T) {
			_, old := profile2Proof(t, uc(1, 10, []byte{0}, []byte{1}, []byte{2}))
			c, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "consumer.json"), 1, old, orderedRound)
			require.NoError(t, err)
			prev := uc(1, 7, []byte{0}, []byte{1}, []byte{2})
			prev.UnicitySeal.Epoch = 7
			repeat := uc(1, 8, []byte{0}, []byte{1}, []byte{2})
			repeat.UnicitySeal.Epoch = 7
			class, err := c.Classify(prev, repeat)
			require.NoError(t, err)
			require.Equal(t, UCRepeat, class)
		})
	}
}

func TestProfile2NewEpochOrderingAndBoundary(t *testing.T) {
	terminal := uc(1, 10, []byte{0}, []byte{1}, []byte{2})
	terminal.UnicitySeal.Epoch = 7
	proof, old := profile2Proof(t, terminal)
	root, err := proof.Snapshot.Root()
	require.NoError(t, err)
	c, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "consumer.json"), 1, old, 10)
	require.NoError(t, err)
	require.NoError(t, c.Install(proof))
	require.NoError(t, c.SetReady())

	otherIR := uc(1, 100, []byte{0}, []byte{9}, []byte{2})
	otherIR.UnicitySeal.Epoch, otherIR.UnicitySeal.Hash = 7, root
	_, err = c.Classify(terminal, otherIR)
	require.ErrorIs(t, err, ErrProfile2Epoch)
	belowOrder := uc(1, 9, []byte{0}, []byte{1}, []byte{2})
	belowOrder.UnicitySeal.Epoch, belowOrder.UnicitySeal.Hash = 7, root
	_, err = c.Classify(terminal, belowOrder)
	require.ErrorIs(t, err, ErrProfile2Epoch)

	below := uc(0, 13, []byte{0}, []byte{1}, []byte{2})
	below.UnicitySeal.Epoch = 8
	_, err = c.Classify(terminal, below)
	require.ErrorIs(t, err, ErrImpossibleUCOrder)
	atBoundary := uc(1, 13, []byte{0}, []byte{9}, []byte{2})
	atBoundary.UnicitySeal.Epoch = 8
	_, err = c.Classify(terminal, atBoundary)
	require.ErrorIs(t, err, ErrEquivocatingUC)

	held := uc(3, 15, []byte{3}, []byte{4}, []byte{5})
	held.UnicitySeal.Epoch = 8
	older := uc(2, 14, []byte{1}, []byte{3}, []byte{4})
	older.UnicitySeal.Epoch = 8
	class, err := c.Classify(held, older)
	require.NoError(t, err)
	require.Equal(t, UCStale, class)
	class, err = c.Classify(held, held)
	require.NoError(t, err)
	require.Equal(t, UCDuplicate, class)
	conflict := uc(3, 16, []byte{3}, []byte{8}, []byte{5})
	conflict.UnicitySeal.Epoch = 8
	_, err = c.Classify(held, conflict)
	require.ErrorIs(t, err, ErrEquivocatingUC)
}

func TestProfile2ProofAndContinuityGuards(t *testing.T) {
	terminal := uc(1, 10, []byte{0}, []byte{1}, []byte{2})
	terminal.UnicitySeal.Epoch = 7
	proof, old := profile2Proof(t, terminal)
	wrongPartition, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "wrong.json"), 2, old, 10)
	require.NoError(t, err)
	require.ErrorIs(t, wrongPartition.Install(proof), ErrProfile2Epoch)
	for _, tc := range []struct {
		name   string
		mutate func(*evmroot.HandoffProof)
		want   error
	}{
		{"record attempt", func(p *evmroot.HandoffProof) { p.Record.Attempt++ }, evmroot.ErrD4Record},
		{"control key", func(p *evmroot.HandoffProof) { p.ControlPath.Partition++ }, evmroot.ErrD4Control},
		{"commit epoch", func(p *evmroot.HandoffProof) { p.CommitQC.Vote.Epoch++ }, evmroot.ErrD4Proof},
		{"under quorum", func(p *evmroot.HandoffProof) { delete(p.CommitQC.Signatures, "c") }, evmroot.ErrD4Quorum},
		{"snapshot root", func(p *evmroot.HandoffProof) { p.Snapshot.Shards[0].Root[0] ^= 1 }, evmroot.ErrD4Snapshot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bad evmroot.HandoffProof
			// Clone nested proof data before each mutation so cases are independent.
			require.NoError(t, json.Unmarshal(mustJSON(t, proof), &bad))
			tc.mutate(&bad)
			c, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "consumer.json"), 1, old, 10)
			require.NoError(t, err)
			require.ErrorIs(t, c.Install(bad), tc.want)
			require.Nil(t, c.verified)
		})
	}
	path := filepath.Join(t.TempDir(), "consumer.json")
	c, err := NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	require.ErrorIs(t, c.SetReady(), ErrProfile2Unready)
	require.NoError(t, c.Install(proof))
	require.NoError(t, c.SetReady())
	broken := uc(2, 13, []byte{0xee}, []byte{3}, []byte{4})
	broken.UnicitySeal.Epoch = 8
	_, err = c.Classify(terminal, broken)
	require.ErrorIs(t, err, ErrEquivocatingUC)
	jump := uc(2, 13, []byte{1}, []byte{3}, []byte{4})
	jump.UnicitySeal.Epoch = 9
	_, err = c.Classify(terminal, jump)
	require.ErrorIs(t, err, ErrProfile2Epoch)
	for _, tc := range []struct {
		name   string
		mutate func(*profile2Checkpoint)
	}{
		{"version", func(cp *profile2Checkpoint) { cp.Version++ }},
		{"floor", func(cp *profile2Checkpoint) { cp.EpochFloor++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cp profile2Checkpoint
			require.NoError(t, json.Unmarshal(mustJSON(t, profile2Checkpoint{Version: 1, EpochFloor: 8, Proof: proof}), &cp))
			tc.mutate(&cp)
			badPath := filepath.Join(t.TempDir(), "bad.json")
			require.NoError(t, os.WriteFile(badPath, mustJSON(t, cp), 0600))
			_, err := NewProfile2Consumer(badPath, 1, old, 10)
			require.ErrorIs(t, err, ErrProfile2Epoch)
		})
	}
}

func TestProfile2ReloadAndInstallBindings(t *testing.T) {
	terminal := uc(1, 10, []byte{0}, []byte{1}, []byte{2})
	terminal.UnicitySeal.Epoch = 7
	proof, old := profile2Proof(t, terminal)
	path := filepath.Join(t.TempDir(), "consumer.json")
	c, err := NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err)
	require.NoError(t, c.Install(proof))
	_, err = NewProfile2Consumer(path, 1, old, 11)
	require.ErrorIs(t, err, ErrProfile2Epoch)
	_, err = NewProfile2Consumer(path, 2, old, 10)
	require.ErrorIs(t, err, ErrProfile2Epoch)

	wrongOrder, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "order.json"), 1, old, 11)
	require.NoError(t, err)
	require.ErrorIs(t, wrongOrder.Install(proof), ErrProfile2Epoch)
	wrongPartition, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "partition.json"), 2, old, 10)
	require.NoError(t, err)
	require.ErrorIs(t, wrongPartition.Install(proof), ErrProfile2Epoch)

	var second evmroot.HandoffProof
	require.NoError(t, json.Unmarshal(mustJSON(t, proof), &second))
	second.Record.SuccessorTRHash[0] ^= 1
	second.Control.RecordBytes = second.Record.Bytes()
	second.Snapshot.Control = second.Control
	root, err := second.Snapshot.Root()
	require.NoError(t, err)
	second.ControlPath, err = second.Snapshot.ControlPath()
	require.NoError(t, err)
	second.CommitQC.Vote.CurrentRoot = root
	second.CommitQC.Seal.Commit.Root = root
	_, keys := evmroot.D4FixtureTrustBase(7, map[string]uint64{"a": 1, "b": 1, "c": 1, "d": 1})
	evmroot.D4SignQC(&second.CommitQC, keys, "a", "b", "c")
	require.ErrorIs(t, c.Install(second), ErrProfile2Epoch)
	_, err = NewProfile2Consumer(path, 1, old, 10)
	require.NoError(t, err, "a conflicting second proof must not overwrite the checkpoint")
}

func TestProfile2ConcurrentInstall(t *testing.T) {
	terminal := uc(1, 10, []byte{0}, []byte{1}, []byte{2})
	terminal.UnicitySeal.Epoch = 7
	proof, old := profile2Proof(t, terminal)
	c, err := NewProfile2Consumer(filepath.Join(t.TempDir(), "consumer.json"), 1, old, 10)
	require.NoError(t, err)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- c.Install(proof)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	require.NoError(t, err)
	return b
}

func TestProfile2ConfiguredAdmissionFailsClosed(t *testing.T) {
	consumer := &Profile2Consumer{}
	first := &BFTClient{}
	require.NoError(t, first.SetProfile2Consumer(consumer))
	require.ErrorIs(t, first.SetCertificateAdmission(&admissionTestFactory{}, admissionTestGate{}, &admissionSink{}), ErrAdmissionMode)
	second := &BFTClient{}
	require.NoError(t, second.SetCertificateAdmission(&admissionTestFactory{}, admissionTestGate{}, &admissionSink{}))
	require.ErrorIs(t, second.SetProfile2Consumer(consumer), ErrAdmissionMode)
}
