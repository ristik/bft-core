package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// The reference hardware (owner decision, design 14): the staging server, 6 cores / 12 threads, 64 GB RAM, 2 x 1 TB NVMe.
const (
	refCores    = 6
	refThreads  = 12
	refMemBytes = 64e9
	refNVMe     = 2
	refNVMeSize = 1e12
	// minFreeBytes is the free space below which the data disk is a warning.
	minFreeBytes = 200e9
	// maxSkew is the clock skew against the RPC server's clock that fails the check.
	maxSkew = 2 * time.Second
)

// hostFacts is what the doctor reads about the machine; tests replace it.
type hostFacts struct {
	OS          string
	Cores       int // physical cores (0: unknown)
	Threads     int
	MemBytes    uint64 // 0: unknown
	NVMe        []uint64
	FreeBytes   func(path string) (uint64, error)
	NTPSynced   func() (bool, string)
	CanListen   func(port int) error
	Now         func() time.Time
	HTTPTimeout time.Duration
}

func realHost() hostFacts {
	h := hostFacts{OS: runtime.GOOS, Threads: runtime.NumCPU(), Now: time.Now, HTTPTimeout: 5 * time.Second}
	if runtime.GOOS == "linux" {
		h.Cores = linuxPhysicalCores("/proc/cpuinfo")
		h.MemBytes = linuxMemTotal("/proc/meminfo")
		h.NVMe = linuxNVMe("/sys/block")
	}
	h.FreeBytes = func(path string) (uint64, error) {
		var st unix.Statfs_t
		if err := unix.Statfs(path, &st); err != nil {
			return 0, err
		}
		return uint64(st.Bavail) * uint64(st.Bsize), nil // #nosec G115 -- block size is positive
	}
	h.NTPSynced = func() (bool, string) {
		out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output() // #nosec G204 -- fixed command
		if err != nil {
			return false, ""
		}
		v := strings.TrimSpace(string(out))
		return v == "yes", "timedatectl NTPSynchronized=" + v
	}
	h.CanListen = func(port int) error {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return err
		}
		return l.Close()
	}
	return h
}

func linuxPhysicalCores(path string) int {
	f, err := os.Open(path) // #nosec G304 -- fixed path
	if err != nil {
		return 0
	}
	defer f.Close()
	cores := map[string]bool{}
	phys := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "physical id":
			phys = strings.TrimSpace(val)
		case "core id":
			cores[phys+"/"+strings.TrimSpace(val)] = true
		}
	}
	return len(cores)
}

func linuxMemTotal(path string) uint64 {
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed path
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// linuxNVMe is the size of every NVMe namespace (/sys/block/nvme*n*), in bytes.
func linuxNVMe(dir string) []uint64 {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "nvme") || strings.Contains(n, "p") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, n, "size")) // #nosec G304 -- sysfs
		if err != nil {
			continue
		}
		sectors, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		out = append(out, sectors*512)
	}
	return out
}

func gb(b uint64) string { return fmt.Sprintf("%.0f GB", float64(b)/1e9) }

type validatorDoctorFlags struct {
	validatorFlags
	DialTimeout time.Duration
}

func validatorDoctorCmd(base *baseFlags) *cobra.Command {
	f := &validatorDoctorFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Local preflight: reference hardware, ports, clock, disk, keys and RPC reachability",
		Long: `Checks this machine and the validator config before apply, and prints one PASS, WARN or FAIL line per check.
The reference hardware is 6 cores / 12 threads, 64 GB RAM and 2 x 1 TB NVMe. A port is free (PASS) or already held
(WARN: by the running service, or by something else). The clock is compared with the RPC server's (HTTP Date) and with
the head block's timestamp. The node services' own checks are in shard-node doctor.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return validatorDoctor(cmd.Context(), cmd.OutOrStdout(), f, realHost())
		},
	}
	f.validatorFlags.add(cmd)
	cmd.Flags().DurationVar(&f.DialTimeout, "dial-timeout", 5*time.Second, "timeout of each network check")
	return cmd
}

func validatorDoctor(ctx context.Context, w io.Writer, f *validatorDoctorFlags, h hostFacts) error {
	v, err := f.load()
	if err != nil {
		return err
	}
	if f.DialTimeout > 0 {
		h.HTTPTimeout = f.DialTimeout
	}
	checks := append(hardwareChecks(v, h), keyChecks(v)...)
	checks = append(checks, rpcChecks(v, h)...)
	failed, warned := 0, 0
	for _, c := range checks {
		cctx, cancel := context.WithTimeout(ctx, h.HTTPTimeout*3)
		ok, detail, fix := c.run(cctx)
		cancel()
		status := "PASS"
		switch {
		case !ok:
			status = "FAIL"
			failed++
		case fix != "":
			status = "WARN"
			warned++
		}
		fmt.Fprintf(w, "[%s] %-16s %s\n", status, c.name, detail)
		if fix != "" {
			fmt.Fprintf(w, "       fix: %s\n", fix)
		}
	}
	fmt.Fprintln(w)
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d checks failed", ErrValidator, failed, len(checks))
	}
	fmt.Fprintf(w, "all %d checks passed (%d warnings)\n", len(checks), warned)
	return nil
}

func hardwareChecks(v *loadedValidator, h hostFacts) []doctorCheck {
	cs := []doctorCheck{
		{"cpu", func(context.Context) (bool, string, string) {
			d := fmt.Sprintf("%d threads", h.Threads)
			if h.Cores > 0 {
				d = fmt.Sprintf("%d cores, %d threads", h.Cores, h.Threads)
			}
			if (h.Cores > 0 && h.Cores < refCores) || h.Threads < refThreads {
				return false, d + fmt.Sprintf(" (reference: %d cores, %d threads)", refCores, refThreads), "run on the reference hardware or better"
			}
			return true, d, ""
		}},
		{"memory", func(context.Context) (bool, string, string) {
			if h.MemBytes == 0 {
				return true, "unknown on " + h.OS, "check by hand: 64 GB RAM"
			}
			// MemTotal is the installed memory less the kernel's reservations: 64 GB shows as about 62 GiB
			if float64(h.MemBytes) < 0.95*refMemBytes {
				return false, gb(h.MemBytes) + " (reference: 64 GB)", "add memory"
			}
			return true, gb(h.MemBytes), ""
		}},
		{"nvme", func(context.Context) (bool, string, string) {
			if h.OS != "linux" {
				return true, "unknown on " + h.OS, "check by hand: 2 x 1 TB NVMe"
			}
			big := 0
			var sizes []string
			for _, s := range h.NVMe {
				sizes = append(sizes, gb(s))
				if float64(s) >= 0.95*refNVMeSize {
					big++
				}
			}
			d := fmt.Sprintf("%d NVMe devices %v", len(h.NVMe), sizes)
			if big < refNVMe {
				return false, d + " (reference: 2 x 1 TB)", "use two NVMe drives of 1 TB or more"
			}
			return true, d, ""
		}},
		{"disk", func(context.Context) (bool, string, string) {
			dir := v.abs(v.cfg.DataDir)
			if dir == "" {
				dir = v.home
			}
			free, err := h.FreeBytes(dir)
			if err != nil {
				return false, err.Error(), "create the data directory"
			}
			d := fmt.Sprintf("%s free at %s", gb(free), dir)
			if free < minFreeBytes {
				return true, d, fmt.Sprintf("free at least %s for chain data", gb(minFreeBytes))
			}
			return true, d, ""
		}},
		{"clock sync", func(context.Context) (bool, string, string) {
			ok, d := h.NTPSynced()
			if d == "" {
				return true, "NTP state unknown (no timedatectl)", "run an NTP client (chrony or systemd-timesyncd)"
			}
			if !ok {
				return false, d, "enable NTP: timedatectl set-ntp true"
			}
			return true, d, ""
		}},
	}
	ports := v.cfg.Ports
	if len(ports) == 0 {
		ports = defaultValidatorPorts
	}
	for _, p := range ports {
		cs = append(cs, doctorCheck{fmt.Sprintf("port %d", p), func(context.Context) (bool, string, string) {
			if err := h.CanListen(p); err != nil {
				return true, "in use: " + err.Error(), "make sure it is this validator's service that holds it"
			}
			return true, "free", ""
		}})
	}
	return cs
}

func fileMode(path string) (os.FileMode, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Mode().Perm(), nil
}

func keyChecks(v *loadedValidator) []doctorCheck {
	var cs []doctorCheck
	files := []struct{ name, path string }{{"root keys", v.cfg.RootKeys}}
	if v.cfg.EVMAuthority == nil {
		files = append(files, struct{ name, path string }{"EVM keys", v.cfg.EVMKeys})
	} else {
		cs = append(cs, authorityChecks(v)...)
	}
	files = append(files, struct{ name, path string }{"ureth key", v.cfg.UrethKey}, struct{ name, path string }{"engine JWT", v.cfg.JWT},
		struct{ name, path string }{"operator key", v.cfg.OperatorKey})
	for _, k := range files {
		path := v.abs(k.path)
		cs = append(cs, doctorCheck{k.name, func(context.Context) (bool, string, string) {
			if path == "" {
				return false, "not configured", "run `ubft validator init`"
			}
			mode, err := fileMode(path)
			if err != nil {
				return false, err.Error(), "run `ubft validator init` (it creates missing keys and keeps existing ones)"
			}
			if k.name == "engine JWT" {
				if err := readJWT(path); err != nil {
					return false, err.Error(), "write 32 random bytes as 64 hex digits (openssl rand -hex 32), the same file for this entity's shard node and ureth"
				}
			}
			if mode&0o077 != 0 {
				return true, fmt.Sprintf("%s (mode %o)", path, mode), "chmod 600 " + path
			}
			return true, path, ""
		}})
	}
	cs = append(cs, doctorCheck{"key separation", func(context.Context) (bool, string, string) {
		if err := v.checkPaths(); err != nil {
			return false, err.Error(), "give each key and the config their own file"
		}
		if _, err := v.keys(); err != nil {
			return false, err.Error(), "give each service its own key"
		}
		return true, "every service has its own key", ""
	}})
	return cs
}

// rpcPost is one JSON-RPC call over plain HTTP, for the server's Date header.
func rpcPost(ctx context.Context, url, method string, timeout time.Duration) (json.RawMessage, time.Time, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":[]}`, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, time.Time{}, err
	}
	if out.Error != nil {
		return nil, time.Time{}, fmt.Errorf("%s", out.Error.Message)
	}
	date, _ := http.ParseTime(resp.Header.Get("Date"))
	return out.Result, date, nil
}

func rpcChecks(v *loadedValidator, h hostFacts) []doctorCheck {
	cs := []doctorCheck{
		{"public RPC", func(ctx context.Context) (bool, string, string) {
			if v.cfg.RPC == "" {
				return false, "not configured", "set \"rpc\" in validator.json"
			}
			res, _, err := rpcPost(ctx, v.cfg.RPC, "eth_chainId", h.HTTPTimeout)
			if err != nil {
				return false, fmt.Sprintf("%s: %v", v.cfg.RPC, err), "check the URL and the network path"
			}
			var id hexutil.Big
			if err := json.Unmarshal(res, &id); err != nil {
				return false, "eth_chainId: " + err.Error(), ""
			}
			if v.cfg.ChainID != 0 && id.ToInt().Cmp(new(big.Int).SetUint64(v.cfg.ChainID)) != 0 {
				return false, fmt.Sprintf("chain %s, config expects %d", id.ToInt(), v.cfg.ChainID), "point --rpc at this network's endpoint"
			}
			return true, fmt.Sprintf("%s, chain %s", v.cfg.RPC, id.ToInt()), ""
		}},
		{"clock skew", func(ctx context.Context) (bool, string, string) {
			_, date, err := rpcPost(ctx, v.cfg.RPC, "eth_blockNumber", h.HTTPTimeout)
			if err != nil {
				return false, err.Error(), ""
			}
			if date.IsZero() {
				return true, "the RPC server sends no Date header", "check the clock by hand"
			}
			// the Date header has whole seconds: allow its truncation
			skew := h.Now().Sub(date) - 500*time.Millisecond
			d := fmt.Sprintf("local clock %+.1fs against the RPC server", skew.Seconds())
			if skew > maxSkew+500*time.Millisecond || skew < -maxSkew-500*time.Millisecond {
				return false, d, "synchronize the clock (NTP)"
			}
			return true, d, ""
		}},
		{"VR", func(ctx context.Context) (bool, string, string) {
			ch, err := v.dial(ctx)
			if err != nil {
				return false, err.Error(), "check --registry and that the endpoint serves this network"
			}
			defer ch.close()
			mode := "PoA"
			if ch.isPoS() {
				mode = "PoS"
				_, election, err := ch.posAddrs(ctx)
				if err != nil {
					return false, err.Error(), ""
				}
				if _, err := ch.vr.OpenResult(ctx, election); err != nil {
					return false, fmt.Sprintf("P85 election %s does not serve openResult: %v", election.Hex(), err), ""
				}
			} else if _, err := ch.poa(); err != nil {
				return false, err.Error(), ""
			}
			n, ts, err := blockInfo(ctx, ch.rpc, "latest")
			if err != nil {
				return false, err.Error(), ""
			}
			age := h.Now().Sub(time.Unix(int64(ts), 0)) // #nosec G115 -- a block timestamp
			d := fmt.Sprintf("%s, %s module %s, %s; root epoch %d; head %d (%s old)", ch.vr.Registry.Hex(), mode, ch.module.Module.Hex(),
				"health "+vrclient.Health(ch.module.Health), ch.cfg.KnownRootEpoch, n, age.Round(time.Second))
			if age < -maxSkew {
				return false, d, "the head block is from the future: the local clock is behind"
			}
			if age > 5*time.Minute {
				return true, d, "the chain head is old: the endpoint is behind or the chain is stalled"
			}
			return true, d, ""
		}},
	}
	if v.cfg.LocalRPC != "" {
		cs = append(cs, doctorCheck{"local ureth", func(ctx context.Context) (bool, string, string) {
			if _, _, err := rpcPost(ctx, v.cfg.LocalRPC, "eth_blockNumber", h.HTTPTimeout); err != nil {
				return true, fmt.Sprintf("%s: %v", v.cfg.LocalRPC, err), "start ureth before apply (status reports its sync)"
			}
			return true, v.cfg.LocalRPC + " answers", ""
		}})
	}
	cs = append(cs, doctorCheck{"operator funds", func(ctx context.Context) (bool, string, string) {
		keys, err := v.keys()
		if err != nil {
			return false, "no operator key", ""
		}
		ch, err := v.dial(ctx)
		if err != nil {
			return false, err.Error(), ""
		}
		defer ch.close()
		addr := operatorAddress(keys)
		var bal hexutil.Big
		if err := ch.rpc.CallContext(ctx, &bal, "eth_getBalance", addr, "latest"); err != nil {
			return false, err.Error(), ""
		}
		d := fmt.Sprintf("%s holds %s wei", addr.Hex(), bal.ToInt())
		if bal.ToInt().Sign() == 0 {
			return true, d, "fund the operator account for gas and any required stake"
		}
		return true, d, ""
	}})
	return cs
}

// authorityChecks are the checks of an EVM key held by a signing authority: the public node info, the credential and the socket (and the
// authority's own enrollment against the node info), instead of a local key file.
func authorityChecks(v *loadedValidator) []doctorCheck {
	a := v.cfg.EVMAuthority
	info, cred, socket := v.abs(a.NodeInfo), v.abs(a.Credential), v.abs(a.Socket)
	var ident *evmAuthority
	return []doctorCheck{
		{"EVM authority node info", func(context.Context) (bool, string, string) {
			var err error
			if ident, err = loadEVMAuthority(evmAuthorityConfig{Socket: socket, Credential: cred, NodeInfo: info}); err != nil {
				return false, err.Error(), "write it with `ubft signing-authority node-info --out " + info + "`"
			}
			return true, fmt.Sprintf("%s (EVM node %s)", info, ident.nodeID), ""
		}},
		{"EVM authority credential", func(context.Context) (bool, string, string) {
			mode, err := fileMode(cred)
			if err != nil {
				return false, err.Error(), "the authority operator credential file (`ubft signing-authority credential`)"
			}
			if _, err := readCredentialFile(cred); err != nil {
				return false, err.Error(), "write a credential with `ubft signing-authority credential --out`"
			}
			if mode&0o077 != 0 {
				return true, fmt.Sprintf("%s (mode %o)", cred, mode), "chmod 600 " + cred
			}
			return true, cred, ""
		}},
		{"EVM authority socket", func(ctx context.Context) (bool, string, string) {
			st, err := os.Stat(socket)
			if err != nil || st.Mode()&os.ModeSocket == 0 {
				return false, fmt.Sprintf("%s is not a socket (%v)", socket, err), "start `ubft signing-authority run` with this --operator-socket"
			}
			if ident == nil {
				return true, socket, ""
			}
			op, err := openOperator(socket, cred)
			if err != nil {
				return false, err.Error(), ""
			}
			defer func() { _ = op.Close() }()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			enrolled, key, err := op.Enrollment(ctx)
			if err != nil {
				return false, "the authority did not answer: " + err.Error(), "check the credential and that the authority runs"
			}
			if enrolled.NodeID != ident.nodeID || !bytes.Equal(key, ident.pub) {
				return false, fmt.Sprintf("the authority is node %s with another key than the node info", enrolled.NodeID), "an authority restart generates a new key: re-run `signing-authority node-info` and the enrollment"
			}
			return true, socket + " (enrollment matches the node info)", ""
		}},
	}
}
