package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/utbprofile"
)

func writeGenesisTrustBase(t *testing.T, dir string) string {
	var signers []abcrypto.Signer
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers = append(signers, s)
	}
	tb := testtrustbase.NewTrustBase(t, signers...).(*types.RootTrustBaseV1)
	path := filepath.Join(dir, "trust-base.json")
	require.NoError(t, util.WriteJsonFile(path, tb))
	return path
}

func TestUTBGenesisToolAndStoreOpening(t *testing.T) {
	dir := t.TempDir()
	tbPath := writeGenesisTrustBase(t, dir)
	tb, err := util.ReadJsonFile(tbPath, &types.RootTrustBaseV1{})
	require.NoError(t, err)
	out := filepath.Join(dir, "utb-genesis.cbor")

	cmd := trustBaseUTBGenesisCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--trust-base", tbPath, "--out", out})
	require.NoError(t, cmd.Execute())
	pin := string(bytes.TrimSpace(stdout.Bytes()))
	require.Len(t, pin, 2+64)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	genesis, err := types.DecodeRootTrustBaseV2(raw)
	require.NoError(t, err)
	require.NoError(t, genesis.VerifyGenesis())
	id, _ := genesis.EntryID()
	require.Equal(t, "0x"+string(bytesHex(id[:])), pin)

	flags := func(mut func(f *rootNodeRunFlags)) *rootNodeRunFlags {
		f := &rootNodeRunFlags{baseFlags: &baseFlags{HomeDir: dir}, Profile2: true, UTBGenesisFile: out, UTBGenesisID: pin}
		if mut != nil {
			mut(f)
		}
		return f
	}
	store, closeStore, err := flags(nil).openUTBStore(tb)
	require.NoError(t, err)
	require.EqualValues(t, 1, store.Tip().Epoch)
	closeStore()
	_, closeStore, err = flags(nil).openUTBStore(tb)
	require.NoError(t, err, "the store reopens")
	closeStore()

	for name, mut := range map[string]func(f *rootNodeRunFlags){
		"not the handoff profile":                func(f *rootNodeRunFlags) { f.Profile2 = false },
		"no pin":                                 func(f *rootNodeRunFlags) { f.UTBGenesisID = "" },
		"a malformed pin":                        func(f *rootNodeRunFlags) { f.UTBGenesisID = "0x12" },
		"another genesis's pin":                  func(f *rootNodeRunFlags) { f.UTBGenesisID = "0x" + string(bytesHex(make([]byte, 32))) },
		"no genesis file":                        func(f *rootNodeRunFlags) { f.UTBGenesisFile = filepath.Join(dir, "missing") },
		"a trust base file as the genesis entry": func(f *rootNodeRunFlags) { f.UTBGenesisFile = tbPath },
	} {
		t.Run(name, func(t *testing.T) {
			f := flags(mut)
			f.UTBEntriesDBFile = filepath.Join(t.TempDir(), "other.db")
			_, _, err := f.openUTBStore(tb)
			require.Error(t, err)
		})
	}

	t.Run("a genesis entry of another trust base is a start-up error", func(t *testing.T) {
		otherDir := t.TempDir()
		otherPath := writeGenesisTrustBase(t, otherDir)
		otherOut := filepath.Join(otherDir, "utb-genesis.cbor")
		c := trustBaseUTBGenesisCmd()
		var o bytes.Buffer
		c.SetOut(&o)
		c.SetArgs([]string{"--trust-base", otherPath, "--out", otherOut})
		require.NoError(t, c.Execute())
		f := flags(func(f *rootNodeRunFlags) {
			f.UTBGenesisFile, f.UTBGenesisID = otherOut, string(bytes.TrimSpace(o.Bytes()))
			f.UTBEntriesDBFile = filepath.Join(t.TempDir(), "x.db")
		})
		_, _, err := f.openUTBStore(tb) // a self-consistent file and pin, but not this deployment's genesis
		require.ErrorContains(t, err, "does not match the genesis trust base")
	})
	t.Run("a genesis trust base that is not epoch 1", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.json")
		tb, err := util.ReadJsonFile(tbPath, &types.RootTrustBaseV1{})
		require.NoError(t, err)
		tb.Epoch = 2
		require.NoError(t, util.WriteJsonFile(bad, tb))
		c := trustBaseUTBGenesisCmd()
		c.SetArgs([]string{"--trust-base", bad, "--out", filepath.Join(dir, "x.cbor")})
		require.ErrorContains(t, c.Execute(), "epoch-1")
	})
}

func bytesHex(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return out
}

// The profile's start-up check is the first thing a node does: a mixed or legacy configuration is refused before any database is opened or any key read.
func TestNodesRefuseAMixedUTBConfigurationBeforeAnythingElse(t *testing.T) {
	dir := t.TempDir()
	genesis := filepath.Join(dir, "g.cbor")
	require.NoError(t, os.WriteFile(genesis, []byte{1}, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, rootDBFileName), []byte("a legacy root database"), 0o644))

	root := &rootNodeRunFlags{baseFlags: &baseFlags{HomeDir: dir}, Profile2: true, UTBGenesisFile: genesis, UTBGenesisID: "0x01"}
	err := rootNodeRun(context.Background(), root)
	require.ErrorIs(t, err, utbprofile.ErrRefused)
	require.ErrorContains(t, err, "no approved migration")

	root = &rootNodeRunFlags{baseFlags: &baseFlags{HomeDir: dir}, Profile2: true, UTBGenesisFile: genesis}
	require.ErrorContains(t, rootNodeRun(context.Background(), root), "go together")

	shard := &shardNodeRunFlags{baseFlags: &baseFlags{HomeDir: dir}, UTBGenesisID: "0x01"}
	err = shardNodeRun(context.Background(), shard, func(string) bool { return false })
	require.ErrorIs(t, err, utbprofile.ErrRefused)

	require.NoError(t, os.WriteFile(filepath.Join(dir, shardUTBEntriesDBFileName), []byte("entries"), 0o644))
	err = shardNodeRun(context.Background(), &shardNodeRunFlags{baseFlags: &baseFlags{HomeDir: dir}}, func(string) bool { return false })
	require.ErrorContains(t, err, "profile is off")
}

func TestTheProfileFlagsAreRegisteredOnBothNodes(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{"root-node run": rootNodeRunCmd(&baseFlags{}), "shard-node run": shardNodeRunCmd(&baseFlags{})} {
		for _, f := range []string{"utb-genesis", "utb-genesis-id", "utb-entries-db"} {
			require.NotNil(t, cmd.Flags().Lookup(f), "%s --%s", name, f)
		}
	}
}
