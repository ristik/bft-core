package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

func runVRChange(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newVRChangeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return strings.TrimSpace(out.String()), err
}

func writeJSONTest(t *testing.T, dir, name string, v any) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, writeJSONFile(p, v))
	return p
}

// The operator tooling builds the payloads VR queues and the roots accept: every validator of a new partition signs its VR-context proof
// for the change id, add-partition assembles them in validator order, and update-partition binds the installed configuration's hash; each
// payload is what the frozen fold accepts, and an input the roots would reject is refused before anything is queued.
func TestVRChangeToolingBuildsPayloadsTheRootsAccept(t *testing.T) {
	dir := t.TempDir()
	var keyFiles []string
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 10, PartitionTypeID: 10, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 3 * time.Second, Epoch: 0, PartitionParams: map[string]string{"proof_type": "none"}}
	for i := 0; i < 2; i++ {
		keys, err := generateKeys()
		require.NoError(t, err)
		signer, err := keys.Signer()
		require.NoError(t, err)
		v, err := signer.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := keys.NodeID()
		require.NoError(t, err)
		pdr.Validators = append(pdr.Validators, &types.NodeInfo{NodeID: id.String(), SigKey: pub, Stake: 1})
		keyFiles = append(keyFiles, writeJSONTest(t, dir, "keys"+strconv.Itoa(i)+".json", keys))
	}
	unordered := writeJSONTest(t, dir, "unordered.json", pdr)
	if pdr.Validators[0].NodeID < pdr.Validators[1].NodeID {
		unordered = writeJSONTest(t, dir, "unordered.json", &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 10, PartitionTypeID: 10,
			TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 3 * time.Second, Validators: []*types.NodeInfo{pdr.Validators[1], pdr.Validators[0]}})
	} else {
		pdr.Validators[0], pdr.Validators[1] = pdr.Validators[1], pdr.Validators[0]
		keyFiles[0], keyFiles[1] = keyFiles[1], keyFiles[0]
	}
	_, err := runVRChange(t, "add-partition", "--network", "5", "--change-id", "12", "--pdr", unordered, "--pop", keyFiles[0])
	require.ErrorContains(t, err, "strictly ordered", "validators in node id order")
	pdrFile := writeJSONTest(t, dir, "pdr.json", pdr)

	// the proofs, signed in reverse order: add-partition orders them by validator
	var pops []string
	for i := len(keyFiles) - 1; i >= 0; i-- {
		out := filepath.Join(dir, "pop"+strconv.Itoa(i)+".json")
		_, err := runVRChange(t, "pop", "--network", "5", "--change-id", "12", "--key-conf", keyFiles[i], "--pdr", pdrFile, "--out", out)
		require.NoError(t, err)
		pops = append(pops, out)
	}
	payloadHex, err := runVRChange(t, "add-partition", "--network", "5", "--change-id", "12", "--pdr", pdrFile, "--pop", strings.Join(pops, ","))
	require.NoError(t, err)
	payload, err := hex.DecodeString(strings.TrimPrefix(payloadHex, "0x"))
	require.NoError(t, err)
	verdicts, err := vrschema.FoldVerdicts(vrschema.FoldInput{Network: 5, Installed: map[vrschema.ShardKey]*types.PartitionDescriptionRecord{}, PartitionCeiling: 64},
		[]vrschema.RegistryChange{{ID: 12, Kind: uint64(vrschema.KindAddPartition), Payload: payload}})
	require.NoError(t, err)
	require.Equal(t, []uint8{vrschema.VerdictAccepted}, verdicts)

	split := *pdr
	split.ShardID, _ = types.ShardID{}.Split()
	_, err = runVRChange(t, "add-partition", "--network", "5", "--change-id", "12", "--pdr", writeJSONTest(t, dir, "split.json", &split), "--pop", strings.Join(pops, ","))
	require.ErrorContains(t, err, "Invalid", "a new partition is one unsplit shard (FD-30)")
	_, err = runVRChange(t, "add-partition", "--network", "5", "--change-id", "13", "--pdr", pdrFile, "--pop", strings.Join(pops, ","))
	require.ErrorContains(t, err, "BadPoP", "proofs for another change id (a lost queue race)")
	_, err = runVRChange(t, "add-partition", "--network", "5", "--change-id", "12", "--pdr", pdrFile, "--pop", pops[0])
	require.ErrorIs(t, err, ErrVRChange, "a validator without a proof")
	stranger, err := generateKeys()
	require.NoError(t, err)
	_, err = runVRChange(t, "pop", "--network", "5", "--change-id", "12", "--key-conf", writeJSONTest(t, dir, "stranger.json", stranger), "--pdr", pdrFile)
	require.ErrorIs(t, err, ErrVRChange, "a key that is not a validator")
	started := *pdr
	started.EpochStart = 50
	_, err = runVRChange(t, "pop", "--network", "5", "--change-id", "12", "--key-conf", keyFiles[0], "--pdr", writeJSONTest(t, dir, "started.json", &started))
	require.ErrorIs(t, err, ErrVRChange, "the roots set the epoch start")

	// update-partition: the installed configuration (as `ubft q3 shard-conf` returns it, with its activation round) and its successor
	installed := *pdr
	installed.EpochStart = 200
	currentFile := writeJSONTest(t, dir, "current.json", &installed)
	succ, err := evmassign.NewSuccessor(&installed, installed.Validators)
	require.NoError(t, err)
	succ.T2Timeout = 6 * time.Second
	succ.PartitionParams = map[string]string{"proof_type": "none", "fee_floor": "3"}
	succFile := writeJSONTest(t, dir, "succ.json", succ)
	payloadHex, err = runVRChange(t, "update-partition", "--network", "5", "--current", currentFile, "--successor", succFile)
	require.NoError(t, err)
	payload, err = hex.DecodeString(strings.TrimPrefix(payloadHex, "0x"))
	require.NoError(t, err)
	v, err := vrschema.DecodeChangePayload(vrschema.KindUpdatePartition, payload)
	require.NoError(t, err)
	h, err := evmassign.PDRHash(&installed)
	require.NoError(t, err)
	require.Equal(t, h, v[2].(vrschema.Word), "the expected hash is the installed configuration's")

	changed := *succ
	changed.Validators = pdr.Validators[:1]
	_, err = runVRChange(t, "update-partition", "--network", "5", "--current", currentFile, "--successor", writeJSONTest(t, dir, "changed.json", &changed))
	require.ErrorContains(t, err, "Invalid", "an update never changes the validators")
	_, err = runVRChange(t, "update-partition", "--network", "6", "--current", currentFile, "--successor", succFile)
	require.ErrorContains(t, err, "Invalid", "another network")

	raw, err := os.ReadFile(pops[0])
	require.NoError(t, err)
	var p evmassign.PoP
	require.NoError(t, json.Unmarshal(raw, &p))
	require.Len(t, []byte(p.Signature), 65)
}

func vrTestKeys(t *testing.T, dir string, n int, pdr *types.PartitionDescriptionRecord) []string {
	var files []string
	for i := 0; i < n; i++ {
		keys, err := generateKeys()
		require.NoError(t, err)
		signer, err := keys.Signer()
		require.NoError(t, err)
		v, err := signer.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := keys.NodeID()
		require.NoError(t, err)
		pdr.Validators = append(pdr.Validators, &types.NodeInfo{NodeID: id.String(), SigKey: pub, Stake: 1})
		files = append(files, writeJSONTest(t, dir, "agg-keys"+strconv.Itoa(i)+".json", keys))
	}
	// validators in node id order, key files kept in step
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if pdr.Validators[j].NodeID < pdr.Validators[i].NodeID {
				pdr.Validators[i], pdr.Validators[j] = pdr.Validators[j], pdr.Validators[i]
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	return files
}

func TestVRChangeReplaceAggregatorsAndCommitteeLimits(t *testing.T) {
	dir := t.TempDir()
	installed := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 3 * time.Second, Epoch: 2, EpochStart: 300, PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}}
	_ = vrTestKeys(t, dir, 1, installed)
	currentFile := writeJSONTest(t, dir, "current.json", installed)

	succ := &types.PartitionDescriptionRecord{}
	*succ = *installed
	succ.Validators = nil
	succ.Epoch, succ.EpochStart = 3, 0
	newKeys := vrTestKeys(t, dir, 2, succ)
	succFile := writeJSONTest(t, dir, "succ.json", succ)
	var pops []string
	for i, k := range newKeys {
		out := filepath.Join(dir, "agg-pop"+strconv.Itoa(i)+".json")
		_, err := runVRChange(t, "pop", "--network", "5", "--change-id", "21", "--key-conf", k, "--pdr", succFile, "--out", out)
		require.NoError(t, err)
		pops = append(pops, out)
	}
	args := func(changeID string, popList []string, successor string) []string {
		return []string{"replace-aggregators", "--network", "5", "--change-id", changeID, "--current", currentFile, "--successor", successor, "--pop", strings.Join(popList, ",")}
	}
	payloadHex, err := runVRChange(t, args("21", pops, succFile)...)
	require.NoError(t, err)
	payload, err := hex.DecodeString(strings.TrimPrefix(payloadHex, "0x"))
	require.NoError(t, err)
	v, err := vrschema.DecodeChangePayload(vrschema.KindReplaceAggregator, payload)
	require.NoError(t, err)
	require.EqualValues(t, 9, v[0].(uint64))
	h, err := evmassign.PDRHash(installed)
	require.NoError(t, err)
	require.Equal(t, h, v[2].(vrschema.Word))
	verdicts, err := vrschema.FoldVerdicts(vrschema.FoldInput{Network: 5, Installed: map[vrschema.ShardKey]*types.PartitionDescriptionRecord{
		{Partition: 9, Shard: string(installed.ShardID.Bytes())}: installed}, PartitionCeiling: 64},
		[]vrschema.RegistryChange{{ID: 21, Kind: uint64(vrschema.KindReplaceAggregator), Payload: payload}})
	require.NoError(t, err)
	require.Equal(t, []uint8{vrschema.VerdictAccepted}, verdicts)

	_, err = runVRChange(t, args("22", pops, succFile)...)
	require.ErrorContains(t, err, "BadPoP", "proofs for another change id (a lost queue race)")
	_, err = runVRChange(t, args("21", pops[:1], succFile)...)
	require.ErrorIs(t, err, ErrVRChange, "a validator without a proof")
	changed := *succ
	changed.T2Timeout = 9 * time.Second
	_, err = runVRChange(t, args("21", pops, writeJSONTest(t, dir, "changed.json", &changed))...)
	require.ErrorIs(t, err, ErrVRChange, "only the validators may change")
	skipped := *succ
	skipped.Epoch = 5
	_, err = runVRChange(t, args("21", pops, writeJSONTest(t, dir, "skipped.json", &skipped))...)
	require.ErrorIs(t, err, ErrVRChange, "epoch + 1")

	out, err := runVRChange(t, "committee-limits", "--n-min", "4", "--n-target", "7", "--n-max", "16")
	require.NoError(t, err)
	raw, err := hex.DecodeString(strings.TrimPrefix(out, "0x"))
	require.NoError(t, err)
	l, err := vrschema.DecodeChangePayload(vrschema.KindCommitteeLimits, raw)
	require.NoError(t, err)
	require.Equal(t, []any{uint64(4), uint64(7), uint64(16)}, l)
	for _, bad := range [][3]string{{"0", "1", "1"}, {"3", "2", "5"}, {"1", "5", "4"}, {"1", "5", "17"}} {
		_, err = runVRChange(t, "committee-limits", "--n-min", bad[0], "--n-target", bad[1], "--n-max", bad[2])
		require.ErrorIs(t, err, ErrVRChange, "%v", bad)
	}
}
