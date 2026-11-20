package cmd

// `ubft validator`: one node, one CLI (VT-10, bft-core#1150). The operator's side of the validator registry (VR) under proof of
// authority, Ethereum-familiar (design briefs/validator-registry-design-final.md section 3.5.6):
//
//	init     create or locate each service's own key (root node, EVM shard node, ureth's devp2p key) and the operator account; write
//	         validator.json
//	doctor   local preflight: reference hardware, ports, clock, disk, keys, RPC reachability
//	status   from public RPC: the VR identity, its PoA state, the committee, epoch, next boundary, sync
//	apply    VR.register + PoaElection.submitApplication (deposit)
//	exit     PoaElection.requestExit (voluntary exit), or withdrawApplication before admission
//	rejoin   PoaElection.rejoin (a parked joiner)
//	rotate   VR.proposeBinding: new node keys or payee, effective at the next boundary
//
// Every state-changing command shows a decoded, simulated preview and takes --dry-run. Only public JSON-RPC is used; nothing here needs
// an operator endpoint of a node. Governance (Admit, ConfirmExit, Remove) is the Foundation multisig's: `ubft governance`.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/vrclient"
)

// ErrValidator is returned for a refusal of a `ubft validator` command.
var ErrValidator = errors.New("validator")

const (
	validatorConfigFile   = "validator.json"
	validatorConfigFormat = "unicity.validator.config.v1"
)

// validatorConfig is validator.json. Paths are relative to the validator home (the entity directory of the testnet layout: root/,
// evm/, ureth-key/, jwt/).
type validatorConfig struct {
	Format string `json:"format"`
	// RPC is the public JSON-RPC endpoint every read and transaction uses.
	RPC string `json:"rpc"`
	// LocalRPC is this validator's own ureth (sync state only).
	LocalRPC string `json:"localRpc,omitempty"`
	Registry string `json:"registry"`
	ChainID  uint64 `json:"chainId,omitempty"`

	RootKeys string `json:"rootKeys"`
	EVMKeys  string `json:"evmKeys"`
	// EVMAuthority, when set, holds the EVM key in a signing authority instead of EVMKeys (VT-10): apply and rotate then take the EVM
	// proof from the authority's registration operation.
	EVMAuthority *evmAuthorityConfig `json:"evmAuthority,omitempty"`
	UrethKey     string              `json:"urethKey"`
	JWT          string              `json:"jwt"`
	OperatorKey  string              `json:"operatorKey"`
	Payee        string              `json:"payee"`
	// ID is the VR identity, written by apply once registered.
	ID uint64 `json:"id,omitempty"`
	// DataDir is where the services keep their data (doctor checks its disk).
	DataDir string `json:"dataDir,omitempty"`
	// Ports are the listen ports of the services (root p2p, shard p2p, ureth devp2p).
	Ports []int `json:"ports,omitempty"`
}

var defaultValidatorPorts = []int{8000, 9000, 30303}

// validatorFlags are the flags every validator command shares.
type validatorFlags struct {
	*baseFlags
	Config   string
	RPC      string
	Registry string
	ID       uint64
}

func (f *validatorFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.Config, "validator-config", "", "validator config (default $UBFT_HOME/"+validatorConfigFile+")")
	cmd.Flags().StringVar(&f.RPC, "rpc", "", "public JSON-RPC endpoint (overrides the config)")
	cmd.Flags().StringVar(&f.Registry, "registry", "", "ValidatorRegistry address (overrides the config; default 0xff..03)")
	cmd.Flags().Uint64Var(&f.ID, "id", 0, "VR identity id (overrides the config)")
}

func (f *validatorFlags) home() string {
	f.initConfigFileLocation()
	return f.HomeDir
}

func (f *validatorFlags) configPath() string {
	if f.Config != "" {
		return f.Config
	}
	return filepath.Join(f.home(), validatorConfigFile)
}

// loadedValidator is a config with its paths resolved.
type loadedValidator struct {
	cfg  validatorConfig
	path string
	home string
}

func (f *validatorFlags) load() (*loadedValidator, error) {
	p := f.configPath()
	var cfg validatorConfig
	raw, err := os.ReadFile(p) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s (run `ubft validator init` first): %v", ErrValidator, p, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrValidator, p, err)
	}
	if cfg.EVMAuthority != nil && cfg.EVMKeys != "" {
		return nil, fmt.Errorf("%w: %s: evmKeys and evmAuthority are two holders of the EVM key: clear evmKeys (the config is edited by hand to select an authority)", ErrValidator, p)
	}
	if cfg.Format != validatorConfigFormat {
		return nil, fmt.Errorf("%w: %s: format %q, want %q", ErrValidator, p, cfg.Format, validatorConfigFormat)
	}
	if f.RPC != "" {
		cfg.RPC = f.RPC
	}
	if f.Registry != "" {
		cfg.Registry = f.Registry
	}
	if f.ID != 0 {
		cfg.ID = f.ID
	}
	return &loadedValidator{cfg: cfg, path: p, home: filepath.Dir(p)}, nil
}

func (v *loadedValidator) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(v.home, p)
}

// save rewrites the config (apply records the id). It refuses a config path that is also a key path, and replaces the file through a
// temporary file and a rename, so a reader never sees half a config.
func (v *loadedValidator) save() error {
	if err := v.checkPaths(); err != nil {
		return err
	}
	b, err := configBytes(v.cfg)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(v.path, b)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(v.path))
}

// syncDir fsyncs a directory, so a link or rename just made in it survives a power loss.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of an operator supplied path
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// tempPattern is the name of init's temporary files next to path; staleTemp is the age after which one is a crash's leftover.
func tempPattern(path string) string { return "." + filepath.Base(path) + ".tmp-*" }

const staleTemp = 10 * time.Minute

// removeStaleTemps deletes this tool's temporary files next to each path that are older than staleTemp: what a crash between writing
// and linking left behind (key material, mode 0600). A younger one may belong to a concurrent init and is left alone.
func removeStaleTemps(paths []string, now time.Time) {
	for _, p := range paths {
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(p), tempPattern(p)))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if st, err := os.Lstat(m); err == nil && st.Mode().IsRegular() && now.Sub(st.ModTime()) > staleTemp {
				_ = os.Remove(m)
			}
		}
	}
}

func configBytes(cfg validatorConfig) ([]byte, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// writeTemp writes b to a new 0600 file next to path and returns its name.
func writeTemp(path string, b []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), tempPattern(path))
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr, os.Chmod(name, 0o600)); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// createExclusive installs b at path only if nothing is there: the content is written to a temporary file first and then hard-linked
// into place, which fails if path exists. So a concurrent creator never overwrites a winner, and a reader never sees a partial file.
// It reports false (and no error) when another file is already at path.
func createExclusive(path string, b []byte) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	tmp, err := writeTemp(path, b)
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp) }()
	err = os.Link(tmp, path)
	switch {
	case err == nil:
		return true, syncDir(filepath.Dir(path))
	case errors.Is(err, os.ErrExist):
		return false, nil
	}
	// a file system without hard links: exclusive open (a concurrent reader may then see the file before it is complete)
	f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator supplied local path
	if errors.Is(oerr, os.ErrExist) {
		return false, nil
	}
	if oerr != nil {
		return false, errors.Join(err, oerr)
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return false, err
	}
	return true, syncDir(filepath.Dir(path))
}

// keyPaths are every file init creates or keeps, by role: no two may be the same file.
func (v *loadedValidator) keyPaths() []struct{ name, path string } {
	root := v.abs(v.cfg.RootKeys)
	out := []struct{ name, path string }{
		{"validator config", v.path},
		{"root node keys", root}, {"root node info", filepath.Join(filepath.Dir(root), nodeInfoFileName)},
	}
	if a := v.cfg.EVMAuthority; a != nil {
		out = append(out, struct{ name, path string }{"EVM authority node info", v.abs(a.NodeInfo)},
			struct{ name, path string }{"EVM authority credential", v.abs(a.Credential)}, struct{ name, path string }{"EVM authority socket", v.abs(a.Socket)})
	} else {
		evm := v.abs(v.cfg.EVMKeys)
		out = append(out, struct{ name, path string }{"EVM shard node keys", evm}, struct{ name, path string }{"EVM shard node info", filepath.Join(filepath.Dir(evm), nodeInfoFileName)})
	}
	return append(out, struct{ name, path string }{"ureth devp2p key", v.abs(v.cfg.UrethKey)}, struct{ name, path string }{"Engine JWT", v.abs(v.cfg.JWT)},
		struct{ name, path string }{"operator key", v.abs(v.cfg.OperatorKey)})
}

// canonicalPath resolves symlinks of the longest existing prefix, so two spellings of one file compare equal before it exists.
func canonicalPath(p string) string {
	p, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	dir, rest := p, ""
	for {
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// checkPaths refuses a layout in which two roles share a file (a config written over a key, two services' keys or node infos in one
// file), by resolved path and, for existing files, by identity (hard links).
func (v *loadedValidator) checkPaths() error {
	ps := v.keyPaths()
	var errs []error
	for i := range ps {
		if ps[i].path == "" {
			errs = append(errs, fmt.Errorf("no path for the %s", ps[i].name))
			continue
		}
		for j := i + 1; j < len(ps); j++ {
			if ps[j].path == "" {
				continue
			}
			same := canonicalPath(ps[i].path) == canonicalPath(ps[j].path)
			if !same {
				a, errA := os.Stat(ps[i].path)
				b, errB := os.Stat(ps[j].path)
				same = errA == nil && errB == nil && os.SameFile(a, b)
			}
			if same {
				errs = append(errs, fmt.Errorf("the %s and the %s are the same file %s", ps[i].name, ps[j].name, ps[i].path))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: every key and the config need their own file: %w", ErrValidator, err)
	}
	return nil
}

func (v *loadedValidator) registry() (common.Address, error) {
	if v.cfg.Registry == "" {
		return vrclient.DefaultRegistry, nil
	}
	if !common.IsHexAddress(v.cfg.Registry) {
		return common.Address{}, fmt.Errorf("%w: registry %q is not an address", ErrValidator, v.cfg.Registry)
	}
	return common.HexToAddress(v.cfg.Registry), nil
}

func (v *loadedValidator) payee() (common.Address, error) {
	if !common.IsHexAddress(v.cfg.Payee) || common.HexToAddress(v.cfg.Payee) == (common.Address{}) {
		return common.Address{}, fmt.Errorf("%w: payee %q is not a nonzero address", ErrValidator, v.cfg.Payee)
	}
	return common.HexToAddress(v.cfg.Payee), nil
}

// ---- keys ----------------------------------------------------------------------------------------------------------------------------

// validatorKeys are the entity's keys: one per service, plus the operator account that owns the VR identity.
type validatorKeys struct {
	Root *KeyConf
	// EVM is the EVM shard node's key file; nil when a signing authority holds the key (EVMAuth).
	EVM      *KeyConf
	EVMAuth  *evmAuthority
	Ureth    *ecdsa.PrivateKey
	Operator *ecdsa.PrivateKey
}

func readKeyConf(path string) (*KeyConf, error) {
	var kc KeyConf
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := kc.NodeID(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := kc.Signer(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &kc, nil
}

// readUrethKey reads ureth's devp2p key file: 64 hex digits (deploy/testnet/ureth_key.py; reth --p2p-secret-key).
func readUrethKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s: not 64 hex digits", path)
	}
	return ethcrypto.ToECDSA(b)
}

// readOperatorKey reads the operator account key: 0x-prefixed hex (the format of the pos-relayer --sender-key files).
func readOperatorKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	b, err := hexutil.Decode(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: a private key must be 0x-prefixed hex", path)
	}
	return ethcrypto.ToECDSA(b)
}

func (v *loadedValidator) keys() (*validatorKeys, error) {
	var k validatorKeys
	var errs []error
	var err error
	if k.Root, err = readKeyConf(v.abs(v.cfg.RootKeys)); err != nil {
		errs = append(errs, fmt.Errorf("root node keys: %w", err))
	}
	if a := v.cfg.EVMAuthority; a != nil {
		ac := evmAuthorityConfig{Socket: v.abs(a.Socket), Credential: v.abs(a.Credential), NodeInfo: v.abs(a.NodeInfo)}
		if k.EVMAuth, err = loadEVMAuthority(ac); err != nil {
			errs = append(errs, err)
		}
	} else if k.EVM, err = readKeyConf(v.abs(v.cfg.EVMKeys)); err != nil {
		errs = append(errs, fmt.Errorf("EVM shard node keys: %w", err))
	}
	if k.Ureth, err = readUrethKey(v.abs(v.cfg.UrethKey)); err != nil {
		errs = append(errs, fmt.Errorf("ureth devp2p key: %w", err))
	}
	if k.Operator, err = readOperatorKey(v.abs(v.cfg.OperatorKey)); err != nil {
		errs = append(errs, fmt.Errorf("operator key: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidator, err)
	}
	if err := k.distinct(); err != nil {
		return nil, err
	}
	return &k, nil
}

// distinct refuses any key used twice: keys are never shared between services (owner decision, design 1.1).
func (k *validatorKeys) distinct() error {
	type named struct {
		name string
		key  []byte
	}
	all := []named{{"root node signing key", k.Root.SigKey.PrivateKey}, {"root node authentication key", k.Root.AuthKey.PrivateKey},
		{"ureth devp2p key", ethcrypto.FromECDSA(k.Ureth)}, {"operator account key", ethcrypto.FromECDSA(k.Operator)}}
	if k.EVM != nil {
		all = append(all, named{"EVM shard node signing key", k.EVM.SigKey.PrivateKey}, named{"EVM shard node authentication key", k.EVM.AuthKey.PrivateKey})
	}
	if k.EVMAuth != nil && k.Root != nil {
		// the authority's key is public here: it must not be the root node's signing key
		if rn, err := nodeKeys(k.Root); err == nil && bytes.Equal(rn.Public(), k.EVMAuth.pub) {
			return fmt.Errorf("%w: the EVM authority's key is the root node's signing key", ErrValidator)
		}
	}
	var errs []error
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if bytes.Equal(all[i].key, all[j].key) {
				errs = append(errs, fmt.Errorf("the %s is the %s", all[i].name, all[j].name))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: keys are shared between services (each service keeps its own key): %w", ErrValidator, err)
	}
	return nil
}

// nodeKeys is a service's VR binding keys: its peer id and its signing key.
func nodeKeys(kc *KeyConf) (vrclient.NodeKeys, error) {
	id, err := kc.NodeID()
	if err != nil {
		return vrclient.NodeKeys{}, err
	}
	key, err := ethcrypto.ToECDSA(kc.SigKey.PrivateKey)
	if err != nil {
		return vrclient.NodeKeys{}, fmt.Errorf("signing key: %w", err)
	}
	nk := vrclient.NodeKeys{NodeID: id.String(), Key: key}
	// the node signs with the same key in the same encoding (the trust base and the shard conf carry this public key)
	signer, err := kc.Signer()
	if err != nil {
		return nk, err
	}
	ver, err := signer.Verifier()
	if err != nil {
		return nk, err
	}
	pub, err := ver.MarshalPublicKey()
	if err != nil {
		return nk, err
	}
	if !bytes.Equal(pub, nk.Public()) {
		return nk, fmt.Errorf("%w: the signing key's public key does not round-trip", ErrValidator)
	}
	return nk, nil
}

// ---- init ----------------------------------------------------------------------------------------------------------------------------

// keyOutcome is what init did for one key.
type keyOutcome struct {
	name, path string
	created    bool
	public     string
}

// ensureKeyConf loads the key file at path, or creates it exclusively when absent. Of concurrent creators exactly one installs its keys;
// the others load the winner's file. An existing file is never replaced.
func ensureKeyConf(path string) (*KeyConf, bool, error) {
	if !util.FileExists(path) {
		kc, err := generateKeys()
		if err != nil {
			return nil, false, err
		}
		b, err := json.MarshalIndent(kc, "", "  ")
		if err != nil {
			return nil, false, err
		}
		created, err := createExclusive(path, b)
		if err != nil {
			return nil, false, err
		}
		if created {
			return kc, true, nil
		}
	}
	kc, err := readKeyConf(path)
	return kc, false, err
}

// writeNodeInfo writes node-info.json next to a key file, as `root-node init` and `shard-node init` do, if it is not there. An existing
// node info must describe these keys.
func writeNodeInfo(keyPath string, kc *KeyConf) error {
	p := filepath.Join(filepath.Dir(keyPath), nodeInfoFileName)
	nk, err := nodeKeys(kc)
	if err != nil {
		return err
	}
	// an existing node info is only read (the key directory may be read-only); a missing one is created exclusively
	if !util.FileExists(p) {
		b, err := json.MarshalIndent(&types.NodeInfo{NodeID: nk.NodeID, SigKey: nk.Public(), Stake: 1}, "", "  ")
		if err != nil {
			return err
		}
		if created, err := createExclusive(p, b); err != nil || created {
			return err
		}
	}
	var have types.NodeInfo
	raw, err := os.ReadFile(p) // #nosec G304 -- operator supplied local path
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &have); err != nil || have.NodeID != nk.NodeID || !bytes.Equal(have.SigKey, nk.Public()) {
		return fmt.Errorf("%w: %s does not describe the keys in %s (kept as it is)", ErrValidator, p, keyPath)
	}
	return nil
}

// ensureSecretHex makes a 32-byte secret (a secp256k1 scalar in [1, n-1]) as 64 hex digits, prefixed and without a newline, in a 0600
// file in a 0700 directory, exclusively; an existing file is kept, never replaced, and the caller validates it.
func ensureSecretHex(path, prefix string) (bool, error) {
	if util.FileExists(path) {
		return false, nil
	}
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return false, err
		}
		if _, err := ethcrypto.ToECDSA(b[:]); err != nil {
			continue
		}
		return createExclusive(path, []byte(prefix+hex.EncodeToString(b[:])))
	}
}

// readJWT reads the Engine API secret with the parser the shard node and doctor use (engineapi.ParseSecret: 32 bytes of hex).
func readJWT(path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local path
	if err != nil {
		return err
	}
	if _, err := engineapi.ParseSecret(string(raw)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// evmKeyCount is how many of init's node key files exist: the root node's, and the EVM shard node's unless a signing authority holds that key.
func evmKeyCount(auth *evmAuthorityConfig) int {
	if auth != nil {
		return 1
	}
	return 2
}

type validatorInitFlags struct {
	validatorFlags
	LocalRPC    string
	ChainID     uint64
	Payee       string
	RootKeys    string
	EVMKeys     string
	UrethKey    string
	JWT         string
	OperatorKey string
	DataDir     string
	Ports       []int
	Force       bool
	// the EVM key held by a signing authority (VT-10) instead of EVMKeys
	AuthoritySocket, AuthorityCredential, AuthorityNodeInfo string
}

func validatorInitCmd(base *baseFlags) *cobra.Command {
	f := &validatorInitFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create or locate each service's own key and write the validator config",
		Long: `Creates, or finds and keeps, one key per service in the validator home (the testnet entity layout):
  root/keys.json         the root node's signing and authentication keys (as root-node init)
  evm/keys.json          the EVM shard node's keys (as shard-node init)
  ureth-key/p2p-secret   ureth's persisted devp2p key (reth --p2p-secret-key)
  jwt/jwt.hex            the Engine API secret shared by this entity's shard node and ureth
  operator/key           the operator account (EVM) that owns the VR identity and pays for its transactions
An existing key is never replaced, and a key is never shared between services: init refuses a home where two of them are equal.
The payee (where rewards and withdrawals go) is a plain EVM address; it defaults to the operator account.`,
		RunE: func(cmd *cobra.Command, _ []string) error { return validatorInit(cmd, f) },
	}
	f.validatorFlags.add(cmd)
	cmd.Flags().StringVar(&f.LocalRPC, "local-rpc", "http://127.0.0.1:8545", "this validator's own ureth JSON-RPC (sync state)")
	cmd.Flags().Uint64Var(&f.ChainID, "chain-id", 0, "expected EVM chain id (checked against the RPC; 0 = take the RPC's)")
	cmd.Flags().StringVar(&f.Payee, "payee", "", "payee address (default: the operator account)")
	cmd.Flags().StringVar(&f.RootKeys, "root-keys", "root/"+keyConfFileName, "root node key file")
	cmd.Flags().StringVar(&f.EVMKeys, "evm-keys", "evm/"+keyConfFileName, "EVM shard node key file")
	cmd.Flags().StringVar(&f.UrethKey, "ureth-key", "ureth-key/p2p-secret", "ureth devp2p key file")
	cmd.Flags().StringVar(&f.JWT, "jwt", "jwt/jwt.hex", "Engine API JWT secret")
	cmd.Flags().StringVar(&f.OperatorKey, "operator-key", "operator/key", "operator account key file (0x-hex)")
	cmd.Flags().StringVar(&f.DataDir, "data-dir", ".", "where the services keep their data (doctor checks its disk)")
	cmd.Flags().IntSliceVar(&f.Ports, "ports", defaultValidatorPorts, "the services' listen ports (root p2p, shard p2p, ureth devp2p)")
	cmd.Flags().StringVar(&f.AuthoritySocket, "evm-authority-socket", "", "the EVM key is held by a signing authority: its operator socket, relative to the validator home (instead of --evm-keys; needs --evm-authority-credential and --evm-authority-node-info). No EVM key file is created")
	cmd.Flags().StringVar(&f.AuthorityCredential, "evm-authority-credential", "", "the authority's operator credential file (relative paths are resolved against the validator home)")
	cmd.Flags().StringVar(&f.AuthorityNodeInfo, "evm-authority-node-info", "", "the authority's node info (`signing-authority node-info`): its enrolled EVM node and public key (relative to the validator home)")
	cmd.Flags().BoolVar(&f.Force, "force", false, "rewrite an existing validator config (keys are still never replaced)")
	return cmd
}

func validatorInit(cmd *cobra.Command, f *validatorInitFlags) error {
	path := f.configPath()
	if util.FileExists(path) && !f.Force {
		return fmt.Errorf("%w: %s exists (use --force to rewrite it; keys are never replaced)", ErrValidator, path)
	}
	home := filepath.Dir(path)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	// the holder of the EVM key: flags select an authority; --force keeps the authority an existing config selected unless --evm-keys was
	// given explicitly (a deliberate switch back to a key file)
	var auth *evmAuthorityConfig
	var holderErr error
	if f.AuthoritySocket != "" || f.AuthorityCredential != "" || f.AuthorityNodeInfo != "" {
		auth = &evmAuthorityConfig{Socket: f.AuthoritySocket, Credential: f.AuthorityCredential, NodeInfo: f.AuthorityNodeInfo}
		if err := auth.validate(); err != nil {
			return err
		}
		if cmd.Flags().Changed("evm-keys") {
			return fmt.Errorf("%w: --evm-keys and --evm-authority-* are two holders of the EVM key: give one", ErrValidator)
		}
	} else if f.Force && !cmd.Flags().Changed("evm-keys") {
		if util.FileExists(path) {
			// a config that cannot be read is not silently replaced by one with a new EVM key file: fix it, or say which holder is meant
			old, err := (&validatorFlags{baseFlags: f.baseFlags, Config: f.Config}).load()
			if err != nil {
				// raised after the shared-file check below, which names the more specific problem when the "config" is a key file
				holderErr = fmt.Errorf("%w: --force cannot tell which holder the existing config selects (%v); fix it, or give --evm-keys or --evm-authority-* explicitly", ErrValidator, err)
			} else {
				auth = old.cfg.EVMAuthority
			}
		}
	}
	if f.RPC == "" {
		return fmt.Errorf("%w: --rpc (the public JSON-RPC endpoint) is required", ErrValidator)
	}
	v := &loadedValidator{path: path, home: home, cfg: validatorConfig{Format: validatorConfigFormat, RPC: f.RPC, LocalRPC: f.LocalRPC,
		Registry: f.Registry, ChainID: f.ChainID, RootKeys: f.RootKeys, EVMKeys: f.EVMKeys, UrethKey: f.UrethKey, JWT: f.JWT,
		OperatorKey: f.OperatorKey, ID: f.ID, DataDir: f.DataDir, Ports: f.Ports}}
	if auth != nil {
		v.cfg.EVMAuthority, v.cfg.EVMKeys = auth, ""
	}
	if v.cfg.Registry == "" {
		v.cfg.Registry = strings.ToLower(vrclient.DefaultRegistry.Hex())
	}
	// before anything is created: no two roles in one file (a config over a key would destroy the key)
	if err := v.checkPaths(); err != nil {
		return err
	}
	if holderErr != nil {
		return holderErr
	}
	var all []string
	for _, kp := range v.keyPaths() {
		all = append(all, kp.path)
	}
	removeStaleTemps(all, time.Now())
	var out []keyOutcome
	var kcs []*KeyConf
	for _, s := range []struct {
		name string
		path string
	}{{"root node", v.abs(f.RootKeys)}, {"EVM shard node", v.abs(f.EVMKeys)}}[:evmKeyCount(auth)] {
		kc, created, err := ensureKeyConf(s.path)
		if err != nil {
			return fmt.Errorf("%w: %s keys: %w", ErrValidator, s.name, err)
		}
		kcs = append(kcs, kc)
		nk, err := nodeKeys(kc)
		if err != nil {
			return err
		}
		out = append(out, keyOutcome{s.name, s.path, created, nk.NodeID})
	}
	for _, s := range []struct {
		name, path, prefix string
	}{{"ureth devp2p", v.abs(f.UrethKey), ""}, {"Engine JWT", v.abs(f.JWT), ""}, {"operator account", v.abs(f.OperatorKey), "0x"}} {
		created, err := ensureSecretHex(s.path, s.prefix)
		if err != nil {
			return fmt.Errorf("%w: %s key: %w", ErrValidator, s.name, err)
		}
		out = append(out, keyOutcome{name: s.name, path: s.path, created: created})
	}
	// again, now that every file exists: an alias that only resolves once its target exists (a dangling directory symlink, a case
	// variant on a case-insensitive file system) is caught by file identity before anything uses the files
	if err := v.checkPaths(); err != nil {
		return err
	}
	if err := readJWT(v.abs(f.JWT)); err != nil {
		return fmt.Errorf("%w: the existing Engine JWT is not usable (kept as it is; replace it by hand): %w", ErrValidator, err)
	}
	keys, err := v.keys()
	if err != nil {
		return err
	}
	// node infos only for keys that passed the separation check
	for i, p := range []string{v.abs(f.RootKeys), v.abs(f.EVMKeys)}[:evmKeyCount(auth)] {
		if err := writeNodeInfo(p, kcs[i]); err != nil {
			return err
		}
	}
	operator := ethcrypto.PubkeyToAddress(keys.Operator.PublicKey)
	for i := range out {
		switch out[i].name {
		case "ureth devp2p":
			out[i].public = "enode public key " + hex.EncodeToString(ethcrypto.FromECDSAPub(&keys.Ureth.PublicKey)[1:])
		case "operator account":
			out[i].public = operator.Hex()
		}
	}
	v.cfg.Payee = f.Payee
	if v.cfg.Payee == "" {
		v.cfg.Payee = operator.Hex()
	}
	if _, err := v.payee(); err != nil {
		return err
	}
	if f.Force {
		if err := v.save(); err != nil {
			return err
		}
	} else {
		b, err := configBytes(v.cfg)
		if err != nil {
			return err
		}
		created, err := createExclusive(path, b)
		if err != nil {
			return err
		}
		if !created {
			return fmt.Errorf("%w: %s was created by another init meanwhile (kept; use --force to rewrite it)", ErrValidator, path)
		}
	}
	w := cmd.OutOrStdout()
	for _, o := range out {
		verb := "found  "
		if o.created {
			verb = "created"
		}
		fmt.Fprintf(w, "%s %-17s %s", verb, o.name, o.path)
		if o.public != "" {
			fmt.Fprintf(w, "  (%s)", o.public)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "payee             %s\nwrote %s\n", v.cfg.Payee, path)
	fmt.Fprintf(w, "\nnext: fund the operator account %s for gas, run `ubft validator doctor`, then `ubft validator apply`\n", operator.Hex())
	return nil
}

func newValidatorCmd(base *baseFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validator",
		Short: "Operate a validator: init, doctor, status, apply, exit, rejoin, rotate",
		Long: `The operator's side of the validator registry under proof of authority, in the Ethereum order:
apply (deposit) -> the Foundation admits (activation at the next boundary) -> exit (voluntary exit) -> the Foundation confirms.
Reads and transactions go to a public JSON-RPC endpoint only. Every transaction is previewed decoded and simulated first;
--dry-run stops there.`,
	}
	cmd.AddCommand(validatorInitCmd(base), validatorDoctorCmd(base), validatorStatusCmd(base), validatorExporterCmd(base), validatorApplyCmd(base),
		validatorExitCmd(base), validatorRejoinCmd(base), validatorRotateCmd(base), validatorClaimCmd(base), validatorPosPublishCmd(base))
	return cmd
}
