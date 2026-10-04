package cmd

/*
The signing record at the process boundary (#105).

Every authority here is the real `ubft signing-authority run`, built from this checkout by buildUbft
and started as its own operating-system process. It is enrolled with the real operator commands
(`credential`, `node-info`, `shard-conf generate`, `complete-enrollment`), and its sessions are
replaced with the real `replace-session` command. Every client is a separate operating-system process
too: this test binary re-executed with saClientJobEnv set, holding a socket path and a client
credential and nothing else, and speaking the real client transport (service.Client). Nothing signs
in this process.

Every request is a valid authenticated input: a certificate signed by the root key of the trust base
the authority was started with, under the shard configuration naming the authority's own key, a
technical record that certificate binds, and a proposal that belongs to the assignment. Every released
response is decoded and verified under the enrolled key. A refusal is checked by name, and each
request refused in one authority is shown to be admitted and signed when it is the first request an
authority sees, so that a refusal cannot be an authentication failure in disguise.

Set BFT_F6C_PROCESS_EVIDENCE to a directory to keep each lane's commands, authority log, client jobs
and client results there.
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

const (
	saClientJobEnv = "BFT_TEST_SIGNING_CLIENT_JOB"
	saEvidenceEnv  = "BFT_F6C_PROCESS_EVIDENCE"

	saFenced     = "signing-session-fenced"
	saConflict   = "signing-conflict"
	saStale      = "signing-stale"
	saT2Millis   = 5000
	saNetworkID  = "5"
	saPartition  = "7"
	saCommandCap = 30 * time.Second
)

func TestMain(m *testing.M) {
	if job := os.Getenv(saClientJobEnv); job != "" {
		os.Exit(runSigningClientJob(job))
	}
	os.Exit(m.Run())
}

// --- the client process -------------------------------------------------------------------------------

// saClientJob is what a client process is told to do. Steps run in order once per iteration:
// "reserve:<i>" reserves request i; "sign" and "retain" act on whatever the authority holds;
// "release-reserved" releases the reservation this iteration obtained; "release:<i>" releases by the
// round and digest of request i as the client computes them, without having reserved it.
type saClientJob struct {
	Socket     string   `json:"socket"`
	Credential string   `json:"credential"`
	Requests   []string `json:"requests"`
	Steps      []string `json:"steps"`
	Iterations int      `json:"iterations"`
	// Start, when set, is a file the client waits for before its first operation.
	Start string `json:"start,omitempty"`
	// Ready, when set, is created once the client has finished its setup (job decoded, requests read, service client
	// built) and is about to wait for Start. A test that races several clients touches Start only after every Ready
	// exists, so no client is still starting up while another runs its whole series.
	Ready string `json:"ready,omitempty"`
	// Marker, when set, is a file whose existence is recorded when each iteration begins.
	Marker string `json:"marker,omitempty"`
	// Stop, when set, ends the loop once it exists.
	Stop string `json:"stop,omitempty"`
	// Progress, when set, is created after the first iteration whose every step succeeded.
	Progress string `json:"progress,omitempty"`
	Out      string `json:"out"`
	BudgetMs int64  `json:"budgetMs"`
}

type saStep struct {
	Step            string `json:"step"`
	Outcome         string `json:"outcome"`
	Round           uint64 `json:"round,omitempty"`
	Digest          string `json:"digest,omitempty"`
	LocalDigest     string `json:"localDigest,omitempty"`
	AuthorizationID string `json:"authorizationId,omitempty"`
	Released        string `json:"released,omitempty"`
}

type saExchange struct {
	Seq        int  `json:"seq"`
	PID        int  `json:"pid"`
	MarkerSeen bool `json:"markerSeen"`
	// StartedNs and EndedNs are wall-clock times on this host, used only to show that two racing
	// processes' exchanges overlapped.
	StartedNs int64    `json:"startedNs"`
	EndedNs   int64    `json:"endedNs"`
	Steps     []saStep `json:"steps"`
}

type saRequestFile struct {
	_         struct{} `cbor:",toarray"`
	UC        []byte
	Technical []byte
	Proposed  []byte
}

var saRefusals = []error{
	signingauthority.ErrFenced, signingauthority.ErrConflict, signingauthority.ErrStale,
	signingauthority.ErrUnavailable, signingauthority.ErrNoReservation, signingauthority.ErrResponseNotRetained,
	signingauthority.ErrUnauthenticated, signingauthority.ErrProposalMismatch, signingauthority.ErrContextMismatch,
	signingauthority.ErrKeyLost, signingauthority.ErrStateUntrusted, signingauthority.ErrEnrollmentIncomplete,
	signingauthority.ErrRequestTooLarge, signingauthority.ErrUnsupportedVersion,
}

// saOutcome names what an operation returned: "ok", a refusal name, or "other: ..." for anything
// else, which no assertion accepts.
func saOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	for _, refusal := range saRefusals {
		if errors.Is(err, refusal) {
			return refusal.Error()
		}
	}
	return "other: " + err.Error()
}

func saExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runSigningClientJob(jobPath string) int {
	fail := func(format string, args ...any) int {
		_, _ = fmt.Fprintf(os.Stderr, "signing client: "+format+"\n", args...)
		return 2
	}
	raw, err := os.ReadFile(jobPath)
	if err != nil {
		return fail("reading the job: %v", err)
	}
	var job saClientJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return fail("decoding the job: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(job.BudgetMs)*time.Millisecond)
	defer cancel()

	credential, err := readCredentialFile(job.Credential)
	if err != nil {
		return fail("reading the credential: %v", err)
	}
	requests := make([]signingauthority.Request, len(job.Requests))
	digests := make([][32]byte, len(job.Requests))
	for i, path := range job.Requests {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return fail("reading request %d: %v", i, err)
		}
		var file saRequestFile
		if err := types.Cbor.Unmarshal(encoded, &file); err != nil {
			return fail("decoding request %d: %v", i, err)
		}
		var uc types.UnicityCertificate
		var tr certification.TechnicalRecord
		var proposed certification.BlockCertificationRequest
		if err := types.Cbor.Unmarshal(file.UC, &uc); err != nil {
			return fail("decoding request %d certificate: %v", i, err)
		}
		if err := types.Cbor.Unmarshal(file.Technical, &tr); err != nil {
			return fail("decoding request %d technical record: %v", i, err)
		}
		if err := types.Cbor.Unmarshal(file.Proposed, &proposed); err != nil {
			return fail("decoding request %d proposal: %v", i, err)
		}
		requests[i] = signingauthority.Request{UC: &uc, Technical: &tr, Proposed: &proposed}
		unsigned, err := types.Cbor.Marshal(&proposed)
		if err != nil {
			return fail("encoding request %d proposal: %v", i, err)
		}
		digests[i] = sha256.Sum256(unsigned)
	}

	client, err := service.NewClient(service.ClientConfig{
		Dial: service.UnixDialer(job.Socket), Credential: credential, Timeout: 10 * time.Second,
	})
	if err != nil {
		return fail("creating the client: %v", err)
	}
	defer func() { _ = client.Close() }()

	out, err := os.Create(job.Out)
	if err != nil {
		return fail("creating the results file: %v", err)
	}
	defer func() { _ = out.Close() }()
	encoder := json.NewEncoder(out)

	if job.Ready != "" {
		if err := os.WriteFile(job.Ready, nil, 0o600); err != nil {
			return fail("creating the ready file: %v", err)
		}
	}
	for job.Start != "" && !saExists(job.Start) {
		if ctx.Err() != nil {
			return fail("the start file never appeared")
		}
		time.Sleep(2 * time.Millisecond)
	}

	index := func(step, prefix string) (int, bool) {
		i, err := strconv.Atoi(strings.TrimPrefix(step, prefix))
		return i, err == nil && i >= 0 && i < len(requests)
	}
	progressed := false
	for iteration := 0; iteration < job.Iterations; iteration++ {
		if job.Stop != "" && saExists(job.Stop) {
			break
		}
		if ctx.Err() != nil {
			return fail("budget exhausted after %d iterations", iteration)
		}
		exchange := saExchange{
			Seq: iteration, PID: os.Getpid(), MarkerSeen: job.Marker != "" && saExists(job.Marker),
			StartedNs: time.Now().UnixNano(),
		}
		var reserved *signingauthority.Authorization
		allOK := true
		for _, step := range job.Steps {
			record := saStep{Step: step}
			switch {
			case strings.HasPrefix(step, "reserve:"):
				i, ok := index(step, "reserve:")
				if !ok {
					return fail("bad step %q", step)
				}
				authorization, err := client.Reserve(ctx, requests[i])
				record.Outcome = saOutcome(err)
				record.LocalDigest = hex.EncodeToString(digests[i][:])
				if err == nil {
					reserved = authorization
					record.Round = authorization.AssignedRound
					record.Digest = hex.EncodeToString(authorization.UnsignedDigest[:])
					record.AuthorizationID = hex.EncodeToString(authorization.ID)
				}
			case step == "sign":
				record.Outcome = saOutcome(client.Sign(ctx))
			case step == "retain":
				record.Outcome = saOutcome(client.RetainResponse(ctx))
			case step == "release-reserved":
				if reserved == nil {
					record.Outcome = "skipped"
					break
				}
				released, err := client.Release(ctx, reserved.AssignedRound, reserved.UnsignedDigest)
				record.Outcome = saOutcome(err)
				record.Round = reserved.AssignedRound
				record.Digest = hex.EncodeToString(reserved.UnsignedDigest[:])
				record.Released = hex.EncodeToString(released)
			case strings.HasPrefix(step, "release:"):
				i, ok := index(step, "release:")
				if !ok {
					return fail("bad step %q", step)
				}
				released, err := client.Release(ctx, requests[i].Technical.Round, digests[i])
				record.Outcome = saOutcome(err)
				record.Round = requests[i].Technical.Round
				record.Digest = hex.EncodeToString(digests[i][:])
				record.Released = hex.EncodeToString(released)
			default:
				return fail("unknown step %q", step)
			}
			if record.Outcome != "ok" {
				allOK = false
			}
			exchange.Steps = append(exchange.Steps, record)
		}
		exchange.EndedNs = time.Now().UnixNano()
		if err := encoder.Encode(exchange); err != nil {
			return fail("writing a result: %v", err)
		}
		if allOK && job.Progress != "" && !progressed {
			if err := os.WriteFile(job.Progress, nil, 0o600); err != nil {
				return fail("writing the progress file: %v", err)
			}
			progressed = true
		}
	}
	if err := out.Sync(); err != nil {
		return fail("syncing the results: %v", err)
	}
	return 0
}

// --- the authority lane ---------------------------------------------------------------------------------

// saLane is one authority process, enrolled, with the operator's end of it and the material to build
// valid requests for it.
type saLane struct {
	t          *testing.T
	bin        string
	name       string
	dir        string
	sockets    string
	nodeID     string
	rootSigner abcrypto.Signer
	conf       *types.PartitionDescriptionRecord
	key        []byte
	verifier   abcrypto.Verifier
	authority  *exec.Cmd
	logMu      sync.Mutex
}

func saEvidenceDir(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv(saEvidenceEnv)
	if root == "" {
		return t.TempDir()
	}
	dir := filepath.Join(root, strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), name)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	return dir
}

func (l *saLane) logf(format string, args ...any) {
	l.t.Helper()
	line := fmt.Sprintf(format, args...)
	l.t.Logf("[%s] %s", l.name, line)
	l.logMu.Lock()
	defer l.logMu.Unlock()
	f, err := os.OpenFile(filepath.Join(l.dir, "lane.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(l.t, err)
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), line)
	require.NoError(l.t, err)
	require.NoError(l.t, f.Close())
}

// ubft runs one bounded build/ubft command and returns its standard output.
func (l *saLane) ubft(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), saCommandCap)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	l.logf("ubft %s -> %v", strings.Join(args, " "), err)
	if err != nil {
		return stdout.String(), fmt.Errorf("ubft %s: %w: %s", args[0], err, stderr.String())
	}
	return stdout.String(), nil
}

func (l *saLane) operator(verb string, extra ...string) []string {
	return append(append([]string{"signing-authority", verb}, extra...),
		"--home", l.dir,
		"--operator-socket", filepath.Join(l.sockets, "operator", "operator.sock"),
		"--operator-credential", filepath.Join(l.sockets, "operator.cred"))
}

func (l *saLane) clientSocket() string { return filepath.Join(l.sockets, "client", "client.sock") }

func (l *saLane) status() (signingAuthorityStatus, error) {
	var s signingAuthorityStatus
	out, err := l.ubft(l.operator("status")...)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal([]byte(out), &s)
}

func (l *saLane) mustStatus() signingAuthorityStatus {
	l.t.Helper()
	s, err := l.status()
	require.NoError(l.t, err)
	return s
}

// replaceSession runs the real replace-session command and returns the path of the credential it wrote.
func (l *saLane) replaceSession(name string) string {
	l.t.Helper()
	path := filepath.Join(l.sockets, name+".cred")
	_, err := l.ubft(l.operator("replace-session", "--out", path)...)
	require.NoError(l.t, err)
	return path
}

// newSALane starts and enrolls one authority process.
func newSALane(t *testing.T, bin, name string) *saLane {
	t.Helper()
	l := &saLane{t: t, bin: bin, name: name, dir: saEvidenceDir(t, name), sockets: authoritySocketDir(t)}

	keyConf, err := (&keyConfFlags{KeyConfFile: filepath.Join(t.TempDir(), keyConfFileName)}).loadKeyConf(&baseFlags{}, true)
	require.NoError(t, err)
	nodeID, err := keyConf.NodeID()
	require.NoError(t, err)
	l.nodeID = nodeID.String()

	l.rootSigner, err = abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, l.rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)
	trustBasePath := filepath.Join(l.dir, "trust-base.json")
	require.NoError(t, util.WriteJsonFile(trustBasePath, tb))

	_, err = l.ubft("signing-authority", "credential", "--home", l.dir, "--out", filepath.Join(l.sockets, "operator.cred"))
	require.NoError(t, err)

	logFile, err := os.Create(filepath.Join(l.dir, "authority.log"))
	require.NoError(t, err)
	args := []string{
		"signing-authority", "run", "--home", l.dir,
		"--client-socket", l.clientSocket(),
		"--operator-socket", filepath.Join(l.sockets, "operator", "operator.sock"),
		"--operator-credential", filepath.Join(l.sockets, "operator.cred"),
		"--trust-base", trustBasePath, "--authority-id", "f6c-process-" + name, "--node-id", l.nodeID,
		"--network-id", saNetworkID, "--partition-id", saPartition, "--shard-epoch", "0",
		"--root-epoch", strconv.FormatUint(tb.GetEpoch(), 10), "--log-format", "text", "--log-level", "debug",
	}
	l.authority = exec.Command(bin, args...)
	l.authority.Stdout, l.authority.Stderr = logFile, logFile
	require.NoError(t, l.authority.Start())
	exited := make(chan struct{})
	go func() { _ = l.authority.Wait(); close(exited) }()
	t.Cleanup(func() {
		// Bounded teardown: SIGTERM, five seconds, then SIGKILL.
		_ = l.authority.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = l.authority.Process.Kill()
			<-exited
		}
		_ = logFile.Close()
	})
	l.logf("started the authority process, pid %d (this test is pid %d)", l.authority.Process.Pid, os.Getpid())

	require.Eventually(t, func() bool { _, err := l.status(); return err == nil }, 20*time.Second, 100*time.Millisecond,
		"the authority process did not answer status")

	nodeInfo := filepath.Join(l.dir, "authority-node-info.json")
	_, err = l.ubft(l.operator("node-info", "--out", nodeInfo)...)
	require.NoError(t, err)
	_, err = l.ubft("shard-conf", "generate", "--home", l.dir, "--network-id", saNetworkID, "--partition-id", saPartition,
		"--partition-type-id", "1", "--epoch-start", "1", "--t2-timeout", strconv.Itoa(saT2Millis), "--node-info", nodeInfo)
	require.NoError(t, err)
	confPath := filepath.Join(l.dir, "shard-conf-"+saPartition+"_0.json")
	raw, err := os.ReadFile(confPath)
	require.NoError(t, err)
	l.conf = &types.PartitionDescriptionRecord{}
	require.NoError(t, json.Unmarshal(raw, l.conf))
	require.Equal(t, time.Duration(saT2Millis)*time.Millisecond, l.conf.T2Timeout, "T2 is at least the 5000ms testing floor")
	require.Len(t, l.conf.Validators, 1)
	require.Equal(t, l.nodeID, l.conf.Validators[0].NodeID)

	_, err = l.ubft(l.operator("complete-enrollment", "--shard-conf", confPath)...)
	require.NoError(t, err)

	l.key = l.conf.Validators[0].SigKey
	l.verifier, err = abcrypto.NewVerifierSecp256k1(l.key)
	require.NoError(t, err)
	enrolled := l.mustStatus()
	fingerprint := sha256.Sum256(l.key)
	require.True(t, enrolled.EnrollmentComplete)
	require.Equal(t, hex.EncodeToString(fingerprint[:]), enrolled.SigningKeyFingerprint,
		"the configuration names the key the authority process holds")
	l.logf("enrolled: node %s, key fingerprint %x, T2 %s", l.nodeID, fingerprint, l.conf.T2Timeout)
	return l
}

// work is a valid request for this lane's authority: a certificate for round assigned-1 at the given
// root round, its technical record assigning round assigned, and a proposal for that assignment.
// timestamp, when non-zero, replaces the seal's timestamp and the root key signs the seal again; the
// proposal always carries the seal's timestamp. variant changes only the proposed state root.
func (l *saLane) work(assigned, rootRound, timestamp uint64, variant byte) signingauthority.Request {
	t := l.t
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: assigned, Epoch: 0, Leader: l.nodeID, StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	stateRoot := bytes.Repeat([]byte{0xa1}, 32)
	uc := testcertificates.CreateUnicityCertificate(t, l.rootSigner, &types.InputRecord{
		Version: 1, RoundNumber: assigned - 1, PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: stateRoot,
		BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
	}, l.conf, rootRound, zero, trHash)
	if timestamp != 0 && uc.UnicitySeal.Timestamp != timestamp {
		seal := *uc.UnicitySeal
		var signerID string
		for id := range seal.Signatures {
			signerID = id
		}
		require.NotEmpty(t, signerID)
		seal.Timestamp = timestamp
		seal.Signatures = nil
		require.NoError(t, seal.Sign(signerID, l.rootSigner))
		uc.UnicitySeal = &seal
	}
	return signingauthority.Request{UC: uc, Technical: tr, Proposed: &certification.BlockCertificationRequest{
		PartitionID: l.conf.PartitionID, ShardID: l.conf.ShardID, NodeID: l.nodeID,
		InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: assigned, Epoch: 0, PreviousHash: stateRoot,
			Hash: bytes.Repeat([]byte{0xc0 + variant}, 32), BlockHash: bytes.Repeat([]byte{0xc2}, 32),
			SummaryValue: []byte{}, Timestamp: uc.UnicitySeal.Timestamp,
		},
	}}
}

func (l *saLane) writeRequest(name string, req signingauthority.Request) string {
	l.t.Helper()
	uc, err := types.Cbor.Marshal(req.UC)
	require.NoError(l.t, err)
	tr, err := types.Cbor.Marshal(req.Technical)
	require.NoError(l.t, err)
	proposed, err := types.Cbor.Marshal(req.Proposed)
	require.NoError(l.t, err)
	encoded, err := types.Cbor.Marshal(saRequestFile{UC: uc, Technical: tr, Proposed: proposed})
	require.NoError(l.t, err)
	path := filepath.Join(l.dir, "request-"+name+".cbor")
	require.NoError(l.t, os.WriteFile(path, encoded, 0o600))
	return path
}

func proposalBytes(t *testing.T, req signingauthority.Request) []byte {
	t.Helper()
	b, err := req.Proposed.Bytes()
	require.NoError(t, err)
	return b
}

// verifyReleased decodes a released response, verifies it under the enrolled key, and requires it to be
// the given proposal, signed.
func (l *saLane) verifyReleased(released string, proposed *certification.BlockCertificationRequest) []byte {
	t := l.t
	t.Helper()
	raw, err := hex.DecodeString(released)
	require.NoError(t, err)
	require.NotEmpty(t, raw, "a released response carries bytes")
	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(raw, &signed))
	require.NoError(t, signed.IsValid(l.verifier), "a released response verifies under the enrolled key")
	unsigned, err := signed.Bytes()
	require.NoError(t, err)
	want, err := proposed.Bytes()
	require.NoError(t, err)
	require.Equal(t, want, unsigned, "the released response is the proposal that was reserved, signed")
	return raw
}

// saClientProcess is one running client process.
type saClientProcess struct {
	lane     *saLane
	name     string
	cmd      *exec.Cmd
	out      string
	stderr   string
	finished chan struct{}
	err      error
}

func (l *saLane) startClient(name string, job saClientJob) *saClientProcess {
	t := l.t
	t.Helper()
	job.Socket = l.clientSocket()
	job.Out = filepath.Join(l.dir, "client-"+name+".jsonl")
	if job.BudgetMs == 0 {
		job.BudgetMs = 60_000
	}
	encoded, err := json.MarshalIndent(job, "", "  ")
	require.NoError(t, err)
	jobPath := filepath.Join(l.dir, "client-"+name+".job.json")
	require.NoError(t, os.WriteFile(jobPath, encoded, 0o600))

	c := &saClientProcess{lane: l, name: name, out: job.Out, stderr: filepath.Join(l.dir, "client-"+name+".stderr"), finished: make(chan struct{})}
	stderr, err := os.Create(c.stderr)
	require.NoError(t, err)
	c.cmd = exec.Command(os.Args[0], "-test.run=^$")
	c.cmd.Env = append(os.Environ(), saClientJobEnv+"="+jobPath)
	c.cmd.Stdout, c.cmd.Stderr = stderr, stderr
	require.NoError(t, c.cmd.Start())
	go func() {
		c.err = c.cmd.Wait()
		_ = stderr.Close()
		close(c.finished)
	}()
	t.Cleanup(func() {
		select {
		case <-c.finished:
		default:
			_ = c.cmd.Process.Kill()
			select {
			case <-c.finished:
			case <-time.After(5 * time.Second):
			}
		}
	})
	l.logf("started client process %s, pid %d", name, c.cmd.Process.Pid)
	return c
}

// wait waits a bounded time for the client to exit successfully and returns its exchanges.
func (c *saClientProcess) wait(budget time.Duration) []saExchange {
	t := c.lane.t
	t.Helper()
	select {
	case <-c.finished:
	case <-time.After(budget):
		_ = c.cmd.Process.Kill()
		<-c.finished
		t.Fatalf("client process %s did not finish within %s", c.name, budget)
	}
	stderr, _ := os.ReadFile(c.stderr)
	require.NoErrorf(t, c.err, "client process %s: %s", c.name, stderr)
	f, err := os.Open(c.out)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var exchanges []saExchange
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 8<<20)
	for scanner.Scan() {
		var exchange saExchange
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &exchange))
		require.Equal(t, c.cmd.Process.Pid, exchange.PID, "each result comes from the client process itself")
		exchanges = append(exchanges, exchange)
	}
	require.NoError(t, scanner.Err())
	c.lane.logf("client process %s finished with %d exchanges", c.name, len(exchanges))
	return exchanges
}

func (l *saLane) runClient(name string, job saClientJob) []saExchange {
	l.t.Helper()
	return l.startClient(name, job).wait(90 * time.Second)
}

// stepsNamed returns the records of every step with that name in an exchange, in order.
func stepsNamed(exchange saExchange, name string) []saStep {
	var steps []saStep
	for _, s := range exchange.Steps {
		if s.Step == name {
			steps = append(steps, s)
		}
	}
	return steps
}

func stepNamed(t *testing.T, exchange saExchange, name string) saStep {
	t.Helper()
	steps := stepsNamed(exchange, name)
	require.NotEmptyf(t, steps, "exchange %d has no step %s", exchange.Seq, name)
	return steps[0]
}

func requireAllOK(t *testing.T, exchange saExchange) {
	t.Helper()
	for _, s := range exchange.Steps {
		require.Equalf(t, "ok", s.Outcome, "exchange %d step %s", exchange.Seq, s.Step)
	}
}

// requireOverlap requires two client processes' exchanges to have run at the same time: the first
// exchange of each began before the last exchange of the other ended. Without it, a "race" could be
// one process finishing before the other started.
func requireOverlap(t *testing.T, a, b []saExchange) {
	t.Helper()
	require.NotEmpty(t, a)
	require.NotEmpty(t, b)
	aStart, aEnd := a[0].StartedNs, a[len(a)-1].EndedNs
	bStart, bEnd := b[0].StartedNs, b[len(b)-1].EndedNs
	require.Lessf(t, aStart, bEnd, "process %d began after process %d had finished", a[0].PID, b[0].PID)
	require.Lessf(t, bStart, aEnd, "process %d began after process %d had finished", b[0].PID, a[0].PID)
}

func saWaitFile(t *testing.T, path string, budget time.Duration) {
	t.Helper()
	require.Eventuallyf(t, func() bool { return saExists(path) }, budget, 5*time.Millisecond, "%s never appeared", path)
}

func saTouch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0o600))
}

var saExchangeSteps = []string{"reserve:0", "sign", "retain", "release-reserved"}

// --- the scenarios ----------------------------------------------------------------------------------------

// saBuildUbft builds the CLI from this checkout into the test's temporary directory. It is this file's
// own, because the similar helper in shard_node_startup_test.go belongs to the external cmd_test
// package and is not visible here.
func saBuildUbft(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	bin := filepath.Join(t.TempDir(), "ubft")
	cmd := exec.Command("go", "build", "-o", bin, "./cli/ubft")
	// this package is <root>/cli/ubft/cmd
	cmd.Dir = filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "building ubft: %s", out)
	return bin
}

func TestSigningRecordAtTheProcessBoundary(t *testing.T) {
	bin := saBuildUbft(t)

	t.Run("identical requests and a repeat authorization replay one retained signature", func(t *testing.T) {
		l := newSALane(t, bin, "identical")
		credential := l.replaceSession("current")

		first := l.work(6, 41, 0, 0)
		repeat := l.work(6, 51, first.UC.UnicitySeal.Timestamp, 0)
		require.NotEqual(t, first.UC.GetRootRoundNumber(), repeat.UC.GetRootRoundNumber())
		require.Equal(t, proposalBytes(t, first), proposalBytes(t, repeat),
			"the repeat authorization assigns the same round and the same proposal bytes")
		firstPath, repeatPath := l.writeRequest("first", first), l.writeRequest("repeat", repeat)

		original := l.runClient("original", saClientJob{Credential: credential, Requests: []string{firstPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, original, 1)
		requireAllOK(t, original[0])
		reserved := stepNamed(t, original[0], "reserve:0")
		require.Equal(t, reserved.LocalDigest, reserved.Digest, "the client computes the digest the authority reserved")
		signed := l.verifyReleased(stepNamed(t, original[0], "release-reserved").Released, first.Proposed)

		// A second client instance with the same credential asks for the same round three times, and also
		// releases by naming the request alone.
		second := l.runClient("second-instance", saClientJob{
			Credential: credential, Requests: []string{firstPath},
			Steps: []string{"reserve:0", "sign", "retain", "release-reserved", "release:0"}, Iterations: 3,
		})
		require.Len(t, second, 3)
		for _, exchange := range second {
			requireAllOK(t, exchange)
			require.Equal(t, reserved.AuthorizationID, stepNamed(t, exchange, "reserve:0").AuthorizationID)
			for _, name := range []string{"release-reserved", "release:0"} {
				require.Equal(t, hex.EncodeToString(signed), stepNamed(t, exchange, name).Released,
					"a repeated release returns the retained signed bytes, not a new signature")
			}
		}

		// A different root authorization for the same assigned round, with identical bytes.
		repeated := l.runClient("repeat-authorization", saClientJob{Credential: credential, Requests: []string{repeatPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, repeated, 1)
		requireAllOK(t, repeated[0])
		repeatReserved := stepNamed(t, repeated[0], "reserve:0")
		require.NotEqual(t, reserved.AuthorizationID, repeatReserved.AuthorizationID, "a different root round is a different authorization")
		require.Equal(t, reserved.Digest, repeatReserved.Digest)
		require.Equal(t, hex.EncodeToString(signed), stepNamed(t, repeated[0], "release-reserved").Released,
			"the repeat authorization releases the retained signature")

		status := l.mustStatus()
		require.EqualValues(t, 1, status.Generation)
		require.True(t, status.HasReservation)
		require.EqualValues(t, 6, status.ReservedRound)
		require.True(t, status.ResponseRetained)
		require.False(t, status.Faulted)
		l.logf("one signature for round 6 across %d releases from three client processes and two root authorizations", 1+2*3+1)
	})

	t.Run("conflicting requests for one assigned round never obtain a second signature", func(t *testing.T) {
		l := newSALane(t, bin, "conflict")
		credential := l.replaceSession("current")

		first := l.work(6, 41, 0, 0)
		timestamp := first.UC.UnicitySeal.Timestamp
		sameAuthorization := l.work(6, 41, timestamp, 1)
		otherAuthorization := l.work(6, 51, timestamp+7, 0)
		lower := l.work(5, 40, 0, 0)
		require.NotEqual(t, proposalBytes(t, first), proposalBytes(t, sameAuthorization))
		require.NotEqual(t, proposalBytes(t, first), proposalBytes(t, otherAuthorization))
		firstPath := l.writeRequest("first", first)

		original := l.runClient("original", saClientJob{Credential: credential, Requests: []string{firstPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, original, 1)
		requireAllOK(t, original[0])
		signed := hex.EncodeToString(l.verifyReleased(stepNamed(t, original[0], "release-reserved").Released, first.Proposed))

		for name, tc := range map[string]struct {
			req     signingauthority.Request
			refusal string
		}{
			"same-authorization-other-bytes": {sameAuthorization, saConflict},
			"other-root-authorization":       {otherAuthorization, saConflict},
			"lower-assigned-round":           {lower, saStale},
		} {
			path := l.writeRequest(name, tc.req)
			result := l.runClient(name, saClientJob{
				Credential: credential, Requests: []string{firstPath, path},
				Steps: []string{"reserve:1", "release:1", "sign", "retain", "release:1", "release:0"}, Iterations: 1,
			})
			require.Len(t, result, 1)
			exchange := result[0]
			require.Equal(t, tc.refusal, stepNamed(t, exchange, "reserve:1").Outcome, name)
			for _, release := range stepsNamed(exchange, "release:1") {
				require.Equal(t, tc.refusal, release.Outcome, "%s: releasing the refused request's own digest obtains nothing", name)
				require.Empty(t, release.Released)
			}
			require.Equal(t, "ok", stepNamed(t, exchange, "sign").Outcome, "signing after a refusal acts on the existing reservation")
			require.Equal(t, "ok", stepNamed(t, exchange, "retain").Outcome)
			require.Equal(t, "ok", stepNamed(t, exchange, "release:0").Outcome)
			require.Equal(t, signed, stepNamed(t, exchange, "release:0").Released,
				"%s: the original response is still the one retained, byte for byte", name)
			l.logf("%s refused as %s; the retained response is unchanged", name, tc.refusal)
		}
		status := l.mustStatus()
		require.EqualValues(t, 6, status.ReservedRound)
		require.True(t, status.ResponseRetained)
		require.False(t, status.Faulted)

		// Order-swapped controls: each refused request is admitted and signed when it is the first
		// request a fresh authority sees for its round, so the refusals above were decisions of the
		// record and not failures to authenticate.
		c1 := newSALane(t, bin, "control-lower-then-same-authorization")
		c1Credential := c1.replaceSession("current")
		c1First := c1.work(6, 41, 0, 0)
		c1Requests := []signingauthority.Request{
			c1.work(5, 40, 0, 0),
			c1.work(6, 41, c1First.UC.UnicitySeal.Timestamp, 1),
			c1First,
		}
		var c1Paths []string
		for i, req := range c1Requests {
			c1Paths = append(c1Paths, c1.writeRequest(strconv.Itoa(i), req))
		}
		control := c1.runClient("control", saClientJob{
			Credential: c1Credential, Requests: c1Paths, Iterations: 1,
			Steps: []string{"reserve:0", "sign", "retain", "release-reserved", "reserve:1", "sign", "retain", "release-reserved", "reserve:2"},
		})
		require.Len(t, control, 1)
		releases := stepsNamed(control[0], "release-reserved")
		require.Len(t, releases, 2)
		c1.verifyReleased(releases[0].Released, c1Requests[0].Proposed)
		c1.verifyReleased(releases[1].Released, c1Requests[1].Proposed)
		reserves := stepsNamed(control[0], "reserve:1")
		require.Equal(t, "ok", reserves[0].Outcome)
		require.Equal(t, saConflict, stepNamed(t, control[0], "reserve:2").Outcome,
			"with the order swapped, the request admitted first above is the one refused")

		c2 := newSALane(t, bin, "control-other-root-authorization")
		c2Credential := c2.replaceSession("current")
		c2First := c2.work(6, 41, 0, 0)
		c2Other := c2.work(6, 51, c2First.UC.UnicitySeal.Timestamp+7, 0)
		c2Paths := []string{c2.writeRequest("other", c2Other), c2.writeRequest("first", c2First)}
		control2 := c2.runClient("control", saClientJob{
			Credential: c2Credential, Requests: c2Paths, Iterations: 1,
			Steps: []string{"reserve:0", "sign", "retain", "release-reserved", "reserve:1"},
		})
		require.Len(t, control2, 1)
		c2.verifyReleased(stepNamed(t, control2[0], "release-reserved").Released, c2Other.Proposed)
		require.Equal(t, saConflict, stepNamed(t, control2[0], "reserve:1").Outcome)
		l.logf("order-swapped controls: the lower round, the other proposal and the other root authorization were each admitted and signed when first")
	})

	t.Run("racing client processes get one signature per assigned round", func(t *testing.T) {
		l := newSALane(t, bin, "race-requests")
		credential := l.replaceSession("current")

		x := l.work(6, 41, 0, 0)
		y := l.work(6, 41, x.UC.UnicitySeal.Timestamp, 1)
		xPath, yPath := l.writeRequest("x", x), l.writeRequest("y", y)
		start := filepath.Join(l.dir, "start-conflicting")
		const iterations = 40
		readyX, readyY := filepath.Join(l.dir, "ready-race-x"), filepath.Join(l.dir, "ready-race-y")
		px := l.startClient("race-x", saClientJob{Credential: credential, Requests: []string{xPath}, Steps: saExchangeSteps, Iterations: iterations, Start: start, Ready: readyX})
		py := l.startClient("race-y", saClientJob{Credential: credential, Requests: []string{yPath}, Steps: saExchangeSteps, Iterations: iterations, Start: start, Ready: readyY})
		// both processes are fully set up before either may begin: a process still starting while the other runs its
		// whole series is not a race, and under load that skew exceeded the series
		saWaitFile(t, readyX, 60*time.Second)
		saWaitFile(t, readyY, 60*time.Second)
		saTouch(t, start)
		results := map[string][]saExchange{"x": px.wait(90 * time.Second), "y": py.wait(90 * time.Second)}
		requireOverlap(t, results["x"], results["y"])
		proposals := map[string]*certification.BlockCertificationRequest{"x": x.Proposed, "y": y.Proposed}

		released := map[string]bool{}
		var winner string
		for variant, exchanges := range results {
			require.Len(t, exchanges, iterations)
			for _, exchange := range exchanges {
				reserve := stepNamed(t, exchange, "reserve:0")
				if reserve.Outcome == "ok" {
					requireAllOK(t, exchange)
					require.True(t, winner == "" || winner == variant, "only one proposal is ever reserved for round 6")
					winner = variant
					released[stepNamed(t, exchange, "release-reserved").Released] = true
				} else {
					require.Equal(t, saConflict, reserve.Outcome)
					require.Equal(t, "skipped", stepNamed(t, exchange, "release-reserved").Outcome)
				}
			}
		}
		require.NotEmpty(t, winner)
		require.Len(t, released, 1, "every release across both processes is the same signed bytes")
		for bytesHex := range released {
			l.verifyReleased(bytesHex, proposals[winner])
		}
		loser := map[string]string{"x": "y", "y": "x"}[winner]
		l.logf("conflicting race: proposal %s won all %d of its exchanges; proposal %s was refused as %s in all %d", winner, iterations, loser, saConflict, iterations)

		// Identical requests racing for a later round: both processes succeed, with one signature.
		z := l.work(7, 42, 0, 0)
		zPath := l.writeRequest("z", z)
		startIdentical := filepath.Join(l.dir, "start-identical")
		ready1, ready2 := filepath.Join(l.dir, "ready-identical-1"), filepath.Join(l.dir, "ready-identical-2")
		p1 := l.startClient("identical-1", saClientJob{Credential: credential, Requests: []string{zPath}, Steps: saExchangeSteps, Iterations: iterations, Start: startIdentical, Ready: ready1})
		p2 := l.startClient("identical-2", saClientJob{Credential: credential, Requests: []string{zPath}, Steps: saExchangeSteps, Iterations: iterations, Start: startIdentical, Ready: ready2})
		saWaitFile(t, ready1, 60*time.Second)
		saWaitFile(t, ready2, 60*time.Second)
		saTouch(t, startIdentical)
		identical := map[string]bool{}
		first, second := p1.wait(90*time.Second), p2.wait(90*time.Second)
		requireOverlap(t, first, second)
		for _, exchanges := range [][]saExchange{first, second} {
			require.Len(t, exchanges, iterations)
			for _, exchange := range exchanges {
				requireAllOK(t, exchange)
				identical[stepNamed(t, exchange, "release-reserved").Released] = true
			}
		}
		require.Len(t, identical, 1, "identical requests racing obtain one signature between them")
		for bytesHex := range identical {
			l.verifyReleased(bytesHex, z.Proposed)
		}
		status := l.mustStatus()
		require.EqualValues(t, 7, status.ReservedRound)
		require.False(t, status.Faulted)
		l.logf("identical race: %d exchanges from two processes released one signature for round 7", 2*iterations)
	})

	t.Run("a session replacement racing two client instances admits only the current credential", func(t *testing.T) {
		l := newSALane(t, bin, "fencing")
		oldCredential := l.replaceSession("old")

		x := l.work(6, 41, 0, 0)
		xPath := l.writeRequest("x", x)
		marker := filepath.Join(l.dir, "replaced")
		stop := filepath.Join(l.dir, "stop")
		oldProgress := filepath.Join(l.dir, "old-progress")
		newProgress := filepath.Join(l.dir, "new-progress")

		old := l.startClient("old-instance", saClientJob{
			Credential: oldCredential, Requests: []string{xPath}, Steps: saExchangeSteps, Iterations: 1_000_000,
			Marker: marker, Stop: stop, Progress: oldProgress,
		})
		saWaitFile(t, oldProgress, 30*time.Second)
		// The replacement runs while the old instance is looping. The marker is written only after the
		// command has returned, so an exchange that saw the marker began after the old session ended.
		newCredential := l.replaceSession("new")
		saTouch(t, marker)
		current := l.startClient("new-instance", saClientJob{
			Credential: newCredential, Requests: []string{xPath}, Steps: saExchangeSteps, Iterations: 1_000_000,
			Stop: stop, Progress: newProgress,
		})
		saWaitFile(t, newProgress, 30*time.Second)
		time.Sleep(time.Second)
		saTouch(t, stop)
		oldExchanges := old.wait(90 * time.Second)
		newExchanges := current.wait(90 * time.Second)

		var signed string
		before, after := 0, 0
		for _, exchange := range oldExchanges {
			reserve := stepNamed(t, exchange, "reserve:0")
			if exchange.MarkerSeen {
				after++
				for _, s := range exchange.Steps {
					require.NotEqualf(t, "ok", s.Outcome, "exchange %d began after the replacement and was admitted", exchange.Seq)
				}
				require.Equal(t, saFenced, reserve.Outcome)
				continue
			}
			before++
			if reserve.Outcome != "ok" {
				require.Equal(t, saFenced, reserve.Outcome, "before the marker an exchange is admitted or fenced, nothing else")
				continue
			}
			for _, s := range exchange.Steps {
				require.Containsf(t, []string{"ok", saFenced}, s.Outcome, "exchange %d step %s", exchange.Seq, s.Step)
			}
			if release := stepNamed(t, exchange, "release-reserved"); release.Outcome == "ok" {
				if signed == "" {
					signed = release.Released
					l.verifyReleased(signed, x.Proposed)
				}
				require.Equal(t, signed, release.Released)
			}
		}
		require.NotEmpty(t, signed, "the old instance obtained the signature before it was fenced")
		require.GreaterOrEqual(t, after, 3, "the old instance kept trying after the replacement")

		require.NotEmpty(t, newExchanges)
		for _, exchange := range newExchanges {
			requireAllOK(t, exchange)
			require.Equal(t, signed, stepNamed(t, exchange, "release-reserved").Released,
				"the record survived fencing: the current instance receives the signature issued before it")
		}
		status := l.mustStatus()
		require.EqualValues(t, 2, status.Generation)
		require.EqualValues(t, 6, status.ReservedRound)
		require.True(t, status.ResponseRetained)
		require.False(t, status.Faulted)
		l.logf("fencing race: old instance %d exchanges before the marker, %d after (all fenced); new instance %d exchanges, all admitted, same signature",
			before, after, len(newExchanges))

		// Positive control for the remaining current session, and the old credential on the same work.
		z := l.work(7, 60, 0, 0)
		zPath := l.writeRequest("z", z)
		control := l.runClient("current-after-race", saClientJob{Credential: newCredential, Requests: []string{zPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, control, 1)
		requireAllOK(t, control[0])
		controlSigned := stepNamed(t, control[0], "release-reserved").Released
		l.verifyReleased(controlSigned, z.Proposed)
		require.NotEqual(t, signed, controlSigned)
		stale := l.runClient("old-after-race", saClientJob{Credential: oldCredential, Requests: []string{zPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, stale, 1)
		require.Equal(t, saFenced, stepNamed(t, stale[0], "reserve:0").Outcome)
		l.logf("positive control: the current credential completed round 7; the old credential was fenced on the same request")
	})

	t.Run("concurrent session replacements admit exactly one credential", func(t *testing.T) {
		l := newSALane(t, bin, "replacements")
		_ = l.replaceSession("initial")
		x := l.work(6, 41, 0, 0)
		xPath := l.writeRequest("x", x)

		paths := []string{filepath.Join(l.sockets, "a.cred"), filepath.Join(l.sockets, "b.cred")}
		errs := make([]error, len(paths))
		var wg sync.WaitGroup
		for i, path := range paths {
			wg.Add(1)
			go func(i int, path string) {
				defer wg.Done()
				_, errs[i] = l.ubft(l.operator("replace-session", "--out", path)...)
			}(i, path)
		}
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}

		admitted := -1
		for i, path := range paths {
			result := l.runClient("credential-"+strconv.Itoa(i), saClientJob{Credential: path, Requests: []string{xPath}, Steps: saExchangeSteps, Iterations: 1})
			require.Len(t, result, 1)
			reserve := stepNamed(t, result[0], "reserve:0")
			if reserve.Outcome == "ok" {
				require.Equal(t, -1, admitted, "exactly one of the concurrently issued credentials is admitted")
				admitted = i
				requireAllOK(t, result[0])
				l.verifyReleased(stepNamed(t, result[0], "release-reserved").Released, x.Proposed)
			} else {
				require.Equal(t, saFenced, reserve.Outcome)
			}
		}
		require.NotEqual(t, -1, admitted, "one credential remains usable")
		require.EqualValues(t, 3, l.mustStatus().Generation)

		z := l.work(7, 60, 0, 0)
		zPath := l.writeRequest("z", z)
		control := l.runClient("current-after-replacements", saClientJob{Credential: paths[admitted], Requests: []string{zPath}, Steps: saExchangeSteps, Iterations: 1})
		require.Len(t, control, 1)
		requireAllOK(t, control[0])
		l.verifyReleased(stepNamed(t, control[0], "release-reserved").Released, z.Proposed)
		l.logf("two concurrent replace-session processes: credential %d admitted and completed round 7, the other fenced", admitted)
	})
}
