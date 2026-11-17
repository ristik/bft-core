package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrclient/vrfake"
)

// fileDigest identifies a file's bytes without printing them (they are secrets).
func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return sha256.Sum256(b)
}

// TestEnsureKeysConcurrent: of concurrent creators at one absent path exactly one installs its key, every other returns the winner's
// key, and the file holds it.
func TestEnsureKeysConcurrent(t *testing.T) {
	const n = 32
	dir := t.TempDir()
	conf := filepath.Join(dir, "root", keyConfFileName)
	secret := filepath.Join(dir, "ureth-key", "p2p-secret")
	var (
		wg            sync.WaitGroup
		mu            sync.Mutex
		confCreated   int
		secretCreated int
		sigKeys       = map[string]bool{}
		start         = make(chan struct{})
		errs          []error
	)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			kc, created, err := ensureKeyConf(conf)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if created {
				confCreated++
			}
			sigKeys[hex.EncodeToString(kc.SigKey.PrivateKey)] = true
		}()
		go func() {
			defer wg.Done()
			<-start
			created, err := ensureSecretHex(secret, "")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else if created {
				secretCreated++
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Empty(t, errs)
	require.Equal(t, 1, confCreated, "exactly one creator installs the key file")
	require.Equal(t, 1, secretCreated, "exactly one creator installs the secret")
	require.Len(t, sigKeys, 1, "every caller holds the installed key")
	onDisk, err := readKeyConf(conf)
	require.NoError(t, err)
	require.True(t, sigKeys[hex.EncodeToString(onDisk.SigKey.PrivateKey)])
	_, err = readUrethKey(secret)
	require.NoError(t, err)
	left, err := filepath.Glob(filepath.Join(dir, "*", ".*tmp-*"))
	require.NoError(t, err)
	require.Empty(t, left, "no temporary files are left behind")

	// an existing file is kept as it is
	before := fileDigest(t, conf)
	_, created, err := ensureKeyConf(conf)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, before, fileDigest(t, conf))
}

// TestValidatorInitRefusesSharedFiles: no role may share a file with another, whatever the spelling; nothing is written and an existing
// key is preserved, --force included.
func TestValidatorInitRefusesSharedFiles(t *testing.T) {
	// an existing operator key at the config path: refused, the key kept byte for byte
	home := t.TempDir()
	cfgPath := filepath.Join(home, validatorConfigFile)
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, []byte("0x"+hex.EncodeToString(ethcrypto.FromECDSA(k))), 0o600))
	before := fileDigest(t, cfgPath)
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--operator-key", validatorConfigFile, "--force")
	require.ErrorContains(t, err, "the validator config and the operator key are the same file")
	require.Equal(t, before, fileDigest(t, cfgPath))
	_, err = os.Stat(filepath.Join(home, "root"))
	require.True(t, os.IsNotExist(err), "nothing was created")

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"config as the operator key, no file yet", []string{"--operator-key", validatorConfigFile}, "the validator config and the operator key"},
		{"operator key in the root key file", []string{"--operator-key", "root/" + keyConfFileName}, "the root node keys and the operator key"},
		{"both node key files in one directory", []string{"--evm-keys", "root/evm-keys.json"}, "the root node info and the EVM shard node info"},
		{"JWT as the ureth key", []string{"--jwt", "ureth-key/p2p-secret"}, "the ureth devp2p key and the Engine JWT"},
		{"a second spelling", []string{"--operator-key", "./jwt/../jwt/jwt.hex"}, "the Engine JWT and the operator key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			_, err := runValidator(t, home, append([]string{"init", "--rpc", "http://127.0.0.1:1"}, tc.args...)...)
			require.ErrorContains(t, err, tc.want)
			ents, err := os.ReadDir(home)
			require.NoError(t, err)
			require.Empty(t, ents, "nothing was created")
		})
	}

	// a symlinked alias of the home, and a hard link of an existing key
	home = t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(home, alias))
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--operator-key", filepath.Join(alias, "ureth-key", "p2p-secret"))
	require.ErrorContains(t, err, "the ureth devp2p key and the operator key")
	out, err := runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1")
	require.NoError(t, err, out)
	digests := map[string][32]byte{}
	for _, p := range []string{"root/keys.json", "evm/keys.json", "ureth-key/p2p-secret", "jwt/jwt.hex", "operator/key"} {
		digests[p] = fileDigest(t, filepath.Join(home, p))
	}
	other := filepath.Join(home, "operator", "same-key")
	require.NoError(t, os.Link(filepath.Join(home, "jwt", "jwt.hex"), other))
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:1", "--force", "--operator-key", "operator/same-key")
	require.ErrorContains(t, err, "the Engine JWT and the operator key are the same file")
	// --force rewrites only the config
	out, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:2", "--force")
	require.NoError(t, err, out)
	for p, d := range digests {
		require.Equal(t, d, fileDigest(t, filepath.Join(home, p)), "%s is preserved", p)
	}
	require.Equal(t, "http://127.0.0.1:2", readConfig(t, home).RPC)

	// a node info that describes other keys is refused, not rewritten
	ni := filepath.Join(home, "evm", nodeInfoFileName)
	rootNI, err := os.ReadFile(filepath.Join(home, "root", nodeInfoFileName))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(ni, rootNI, 0o600))
	_, err = runValidator(t, home, "init", "--rpc", "http://127.0.0.1:2", "--force")
	require.ErrorContains(t, err, "does not describe the keys")
	b, err := os.ReadFile(ni)
	require.NoError(t, err)
	require.Equal(t, rootNI, b)
}

// TestValidatorJWTIsParsed: init and doctor read the Engine JWT with engineapi.ParseSecret; a bad one is refused and kept.
func TestValidatorJWTIsParsed(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"malformed", "not a JWT secret"},
		{"empty", ""},
		{"31 bytes", strings.Repeat("ab", 31)},
		{"33 bytes", strings.Repeat("ab", 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, url := fakeNetwork(t)
			home := initHome(t, url)
			jwt := filepath.Join(home, "jwt", "jwt.hex")
			require.NoError(t, os.WriteFile(jwt, []byte(tc.content), 0o600))
			before := fileDigest(t, jwt)
			_, err := runValidator(t, home, "init", "--rpc", url, "--force")
			require.ErrorContains(t, err, "the existing Engine JWT is not usable")
			require.Equal(t, before, fileDigest(t, jwt))
			out, err := runDoctor(t, home)
			require.Error(t, err)
			require.Contains(t, out, "[FAIL] engine JWT")
			require.Contains(t, out, "openssl rand -hex 32")
			require.Equal(t, before, fileDigest(t, jwt))
		})
	}
	// 0x-prefixed with a newline is the reth convention, and passes
	_, url := fakeNetwork(t)
	home := initHome(t, url)
	require.NoError(t, os.WriteFile(filepath.Join(home, "jwt", "jwt.hex"), []byte("0x"+strings.Repeat("ab", 32)+"\n"), 0o600))
	out, _ := runDoctor(t, home)
	require.Contains(t, out, "[PASS] engine JWT")
}

// TestValidatorStatusUnknownIsNotNone: a failed identity lookup or eth_syncing is reported as unknown, with the diagnostic, and status
// fails; "no identity" and "in sync" come only from reads that succeeded.
func TestValidatorStatusUnknownIsNotNone(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)

	chain.With(func(c *vrfake.Chain) { c.NoLogs = true })
	out, err := runValidator(t, home, "status")
	require.ErrorContains(t, err, "status is incomplete")
	require.ErrorContains(t, err, "pass --id")
	require.NotContains(t, out, "no VR identity")
	require.Contains(t, out, "validator: UNKNOWN")
	require.Contains(t, out, "UNKNOWN: identity:")
	out, err = runValidator(t, home, "status", "--json")
	require.Error(t, err)
	var rep validatorStatusReport
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	require.Equal(t, "unknown", rep.Identity)
	require.Zero(t, rep.ID)
	require.NotEmpty(t, rep.Unknown)

	// the lookup succeeds again: "none" now means none
	chain.With(func(c *vrfake.Chain) { c.NoLogs = false })
	out, err = runValidator(t, home, "status", "--json")
	require.NoError(t, err, out)
	rep = validatorStatusReport{}
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	require.Equal(t, "none", rep.Identity)
	require.NotNil(t, rep.PublicSyncing)
	require.False(t, *rep.PublicSyncing)
	require.Equal(t, "in sync", rep.LocalSync)

	// eth_syncing fails on the public endpoint and on the local ureth (the same fake): neither is "in sync"
	chain.With(func(c *vrfake.Chain) { c.FailSyncing = true })
	out, err = runValidator(t, home, "status")
	require.ErrorContains(t, err, "public sync: eth_syncing")
	require.ErrorContains(t, err, "local sync: head")
	require.Contains(t, out, "syncing UNKNOWN")
	require.NotContains(t, out, "in sync")
	out, err = runValidator(t, home, "status", "--json")
	require.Error(t, err)
	rep = validatorStatusReport{}
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	require.Nil(t, rep.PublicSyncing)
	require.True(t, strings.HasPrefix(rep.LocalSync, "unknown:"), rep.LocalSync)

	// an unreadable operator key: the identity is unknown, not absent
	chain.With(func(c *vrfake.Chain) { c.FailSyncing = false })
	require.NoError(t, os.WriteFile(filepath.Join(home, "operator", "key"), []byte("garbage"), 0o600))
	out, err = runValidator(t, home, "status")
	require.ErrorContains(t, err, "operator key is not readable")
	require.NotContains(t, out, "no VR identity")
}

// TestValidatorLookupChecksLogsAndOwner: a log answer that is not VR's Registered event for this owner is refused, and an identity the
// logs name must be the operator's by VR.ownerOf.
func TestValidatorLookupChecksLogsAndOwner(t *testing.T) {
	chain, url := fakeNetwork(t)
	home := initHome(t, url)
	v, keys := loadHome(t, home)
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	ev := vrclient.VRABI.Events["Registered"].ID
	ownerTopic := ethcommon.BytesToHash(operator.Bytes())
	idTopic := func(id int64) ethcommon.Hash { return ethcommon.BigToHash(big.NewInt(id)) }
	for _, tc := range []struct {
		name string
		log  map[string]any
		want string
	}{
		{"foreign address", map[string]any{"address": ethcommon.HexToAddress("0xdead"), "topics": []ethcommon.Hash{ev, idTopic(1), ownerTopic}}, "not VR's Registered log"},
		{"foreign event", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ethcommon.HexToHash("0xbad"), idTopic(1), ownerTopic}}, "not VR's Registered log"},
		{"other owner", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ev, idTopic(1), ethcommon.BytesToHash([]byte{2})}}, "not VR's Registered log"},
		{"two topics", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ev, idTopic(1)}}, "not VR's Registered log"},
		{"id beyond uint64", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ev, ethcommon.HexToHash("0x010000000000000000"), ownerTopic}}, "id topic"},
		{"id 0", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ev, idTopic(0), ownerTopic}}, "id topic"},
		// a well-formed log naming genesis identity 2, which VR says another account owns
		{"identity of another owner", map[string]any{"address": chain.Registry, "topics": []ethcommon.Hash{ev, idTopic(2), ownerTopic}}, "VR says its owner is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain.With(func(c *vrfake.Chain) { c.ExtraLogs = []map[string]any{tc.log} })
			ch, err := v.dial(t.Context())
			require.NoError(t, err)
			defer ch.close()
			_, have, err := findID(t.Context(), v, ch, operator)
			require.ErrorContains(t, err, tc.want)
			require.False(t, have)
			_, err = runValidator(t, home, "exit")
			require.ErrorContains(t, err, tc.want)
		})
	}
	// a removed (reorged-out) log is ignored, a duplicate counted once
	chain.Fund(operator, big.NewInt(1e18))
	chain.With(func(c *vrfake.Chain) { c.ExtraLogs = nil })
	out, err := runValidator(t, home, "apply")
	require.NoError(t, err, out)
	chain.With(func(c *vrfake.Chain) {
		c.ExtraLogs = []map[string]any{{"address": c.Registry, "topics": []ethcommon.Hash{ev, idTopic(5), ownerTopic}},
			{"address": c.Registry, "topics": []ethcommon.Hash{ev, idTopic(3), ownerTopic}, "removed": true}}
	})
	cfg := readConfig(t, home)
	cfg.ID = 0
	b, err := configBytes(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, validatorConfigFile), b, 0o600))
	ch, err := v.dial(t.Context())
	require.NoError(t, err)
	defer ch.close()
	id, have, err := findID(t.Context(), v, ch, operator)
	require.NoError(t, err)
	require.True(t, have)
	require.Equal(t, uint64(5), id)
}

// runDoctor runs doctor with host facts that meet the reference hardware, against the home's config.
func runDoctor(t *testing.T, home string) (string, error) {
	t.Helper()
	host := hostFacts{OS: "linux", Cores: 6, Threads: 12, MemBytes: 66_500_000_000, NVMe: []uint64{1_000_204_886_016, 1_000_204_886_016},
		FreeBytes: func(string) (uint64, error) { return 900e9, nil }, NTPSynced: func() (bool, string) { return true, "NTPSynchronized=yes" },
		CanListen: func(int) error { return nil }, Now: time.Now, HTTPTimeout: 2 * time.Second}
	var out bytes.Buffer
	f := &validatorDoctorFlags{validatorFlags: validatorFlags{baseFlags: &baseFlags{HomeDir: home}}}
	err := validatorDoctor(context.Background(), &out, f, host)
	return out.String(), err
}
