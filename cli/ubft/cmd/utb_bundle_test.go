package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/utb"
)

func TestUTBExportVerifyImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	type member struct {
		id     string
		key    []byte
		signer abcrypto.Signer
	}
	var ms []member
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		ms = append(ms, member{id.String(), pk, s})
	}
	facts := func(epoch, start uint64) utb.SuccessorFacts {
		var um []utb.Member
		for _, m := range ms {
			um = append(um, utb.Member{NodeID: m.id, Key: m.key, Weight: 1})
		}
		return utb.SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: um, Threshold: 3,
			StateHash: bytes.Repeat([]byte{1}, 32), ChangeRecordHash: bytes.Repeat([]byte{2}, 32)}
	}
	g, err := utb.BuildUnsigned(nil, facts(1, 1))
	require.NoError(t, err)
	graw, _ := g.MarshalCBOR()
	gid, _ := g.EntryID()
	genesisPath := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesisPath, graw, 0o644))
	pin := "0x" + string(bytesHex(gid[:]))

	base := &baseFlags{HomeDir: dir}
	srcDB := filepath.Join(dir, "src.db")
	src := &rootNodeRunFlags{baseFlags: base, Profile2: true, UTBGenesisFile: genesisPath, UTBGenesisID: pin, UTBEntriesDBFile: srcDB}
	store, closeStore, err := src.openUTBStore()
	require.NoError(t, err)
	prev := g
	for e := uint64(2); e <= 8; e++ {
		next, err := utb.BuildUnsigned(prev, facts(e, e*100))
		require.NoError(t, err)
		for _, m := range ms[:3] {
			require.NoError(t, next.Sign(m.id, m.signer))
		}
		raw, _ := next.MarshalCBOR()
		_, err = store.Append(raw)
		require.NoError(t, err)
		prev = next
	}
	closeStore()

	run := func(c interface {
		SetArgs([]string)
		Execute() error
	}, args ...string) error {
		c.SetArgs(args)
		return c.Execute()
	}
	bundle := filepath.Join(dir, "bundle.cbor")
	require.NoError(t, run(trustBaseUTBExportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", srcDB, "--out", bundle))

	require.NoError(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", pin))
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", bundle, "--utb-genesis-id", "0x"+string(bytesHex(make([]byte, 32)))), "another pin")
	data, err := os.ReadFile(bundle)
	require.NoError(t, err)
	tampered := filepath.Join(dir, "tampered.cbor")
	bad := bytes.Clone(data)
	bad[len(bad)/2] ^= 1
	require.NoError(t, os.WriteFile(tampered, bad, 0o644))
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", tampered, "--utb-genesis-id", pin))
	require.NoError(t, os.WriteFile(tampered, append(bytes.Clone(data), 0), 0o644))
	require.Error(t, run(trustBaseUTBVerifyCmd(), "--bundle", tampered, "--utb-genesis-id", pin), "trailing bytes")

	// a fresh store takes the shipped history; a second import is idempotent; the export of the result is the same file
	dstDB := filepath.Join(dir, "dst.db")
	require.NoError(t, run(trustBaseUTBImportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--bundle", bundle))
	require.NoError(t, run(trustBaseUTBImportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--bundle", bundle))
	again := filepath.Join(dir, "again.cbor")
	require.NoError(t, run(trustBaseUTBExportCmd(base), "--utb-genesis", genesisPath, "--utb-genesis-id", pin, "--utb-entries-db", dstDB, "--out", again))
	got, err := os.ReadFile(again)
	require.NoError(t, err)
	require.Equal(t, data, got)
}
