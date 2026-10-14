package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
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
	store, closeStore, err := flags(nil).openUTBStore()
	require.NoError(t, err)
	require.EqualValues(t, 1, store.Tip().Epoch)
	closeStore()
	_, closeStore, err = flags(nil).openUTBStore()
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
			_, _, err := f.openUTBStore()
			require.Error(t, err)
		})
	}

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
