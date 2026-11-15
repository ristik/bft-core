package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The deployment document and the PDR bytes of the combined CI lane's protocol 6/7 bridge deploy are byte-identical to those of the
// dnb-tool built with bridgeprofile (integration/enshrined-evm 76d612b3f, before bft-core#1106 inlined its three values): the
// golden files are that binary's output on the same inputs.
func TestDeploymentBytesArePinned(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "deployment.json")
	require.NoError(t, deployment([]string{"--identities", "testdata/identities.json", "--agg-conf", "testdata/agg-shard-conf.json", "--out", out}))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	want, err := os.ReadFile("testdata/deployment.golden.json")
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))

	out = filepath.Join(dir, "pdr.cbor")
	require.NoError(t, pdr([]string{"--full-shard-conf", "testdata/agg-shard-conf.json", "--out", out}))
	got, err = os.ReadFile(out)
	require.NoError(t, err)
	want, err = os.ReadFile("testdata/pdr.golden.cbor")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPolicyBodyEncodesEveryPartitionWidth(t *testing.T) {
	prefix := "835818554e49434954595f42525f4147475f504152544954494f4e02"
	for partition, tail := range map[uint32]string{7: "07", 23: "17", 24: "1818", 256: "190100", 1 << 16: "1a00010000"} {
		require.Equal(t, prefix+tail, hex.EncodeToString(policyBody(partition)), "partition %d", partition)
	}
}
