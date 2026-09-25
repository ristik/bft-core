package shardnode

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
