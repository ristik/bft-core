package shardnode

/*
Restored voting through an independent signing authority (#105 step 4).

The restore path is the production one: FileStore.LoadLUC, verifyRestoredLUC against the configured
trust base and shard configuration hash, and resumeFrom, which seeds the certificate cursor and marks
the Round restored. The authority is the real `ubft signing-authority run`, built from this checkout
and started as its own process, enrolled with the real operator commands. The Round's signer is
NewAuthoritySigner over the real client transport, with the verification key taken from the shard
configuration. Rounds stand in for shard processes: each "process" below is a fresh Round, restored or
not, holding only a socket path and a client credential.

These tests are written against the admission conditions posted on #105: a restored Round signs only
through a signer that keeps an independent record, only after P-id, and only what that record admits.
*/

import (
	"bytes"
	"context"
	gocrypto "crypto"
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

const restoredNodeID = "restored-authority-node"

// buildUbftForShardnode builds the CLI from this checkout. This package is <root>/shardnode.
func buildUbftForShardnode(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	bin := filepath.Join(t.TempDir(), "ubft")
	cmd := exec.Command("go", "build", "-o", bin, "./cli/ubft")
	cmd.Dir = filepath.Clean(filepath.Join(wd, ".."))
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "building ubft: %s", out)
	return bin
}

// authorityProcess is one real authority process with its operator's end.
type authorityProcess struct {
	t        *testing.T
	bin      string
	home     string
	sockets  string
	args     []string
	cmd      *exec.Cmd
	exited   chan struct{}
	conf     *types.PartitionDescriptionRecord
	confPath string
	confHash []byte
	verifier abcrypto.Verifier
}

func (p *authorityProcess) ubft(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ubft %s: %w: %s", strings.Join(args[:2], " "), err, stderr.String())
	}
	return stdout.String(), nil
}

func (p *authorityProcess) operator(verb string, extra ...string) []string {
	return append(append([]string{"signing-authority", verb}, extra...),
		"--home", p.home,
		"--operator-socket", filepath.Join(p.sockets, "operator", "operator.sock"),
		"--operator-credential", filepath.Join(p.sockets, "operator.cred"))
}

type authorityStatus struct {
	EnrollmentComplete bool   `json:"enrollmentComplete"`
	Generation         uint64 `json:"generation"`
	HasReservation     bool   `json:"hasReservation"`
	ReservedRound      uint64 `json:"reservedRound"`
	ResponseRetained   bool   `json:"responseRetained"`
	Faulted            bool   `json:"faulted"`
	KeyLost            bool   `json:"keyLost"`
}

func (p *authorityProcess) status() (authorityStatus, error) {
	var s authorityStatus
	out, err := p.ubft(p.operator("status")...)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal([]byte(out), &s)
}

func (p *authorityProcess) mustStatus() authorityStatus {
	p.t.Helper()
	s, err := p.status()
	require.NoError(p.t, err)
	return s
}

// start runs the authority process and waits until its operator endpoint answers.
func (p *authorityProcess) start() {
	t := p.t
	t.Helper()
	logFile, err := os.OpenFile(filepath.Join(p.home, "authority.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	p.cmd = exec.Command(p.bin, p.args...)
	p.cmd.Stdout, p.cmd.Stderr = logFile, logFile
	require.NoError(t, p.cmd.Start())
	exited := make(chan struct{})
	p.exited = exited
	cmd := p.cmd
	go func() { _ = cmd.Wait(); _ = logFile.Close(); close(exited) }()
	t.Cleanup(func() { p.stopProcess(cmd, exited, syscall.SIGTERM) })
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for {
		if _, lastErr = p.status(); lastErr == nil {
			return
		}
		select {
		case <-exited:
			authorityLog, _ := os.ReadFile(filepath.Join(p.home, "authority.log"))
			t.Fatalf("the authority process exited before answering status: %v\nauthority log:\n%s", lastErr, authorityLog)
		default:
		}
		if time.Now().After(deadline) {
			authorityLog, _ := os.ReadFile(filepath.Join(p.home, "authority.log"))
			t.Fatalf("the authority process did not answer status within 20s: %v\nauthority log:\n%s", lastErr, authorityLog)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *authorityProcess) stopProcess(cmd *exec.Cmd, exited chan struct{}, sig syscall.Signal) {
	select {
	case <-exited:
		return
	default:
	}
	_ = cmd.Process.Signal(sig)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
}

// kill ends the authority process with SIGKILL: its key and record are gone.
func (p *authorityProcess) kill() {
	p.t.Helper()
	p.stopProcess(p.cmd, p.exited, syscall.SIGKILL)
}

// startEnrolledAuthority starts a real authority for restoredNodeID and completes its enrollment with a
// shard configuration naming its key. rootSigner signs the trust base the authority is started with.
func startEnrolledAuthority(t *testing.T, bin string, rootSigner abcrypto.Signer) *authorityProcess {
	t.Helper()
	sockets, err := os.MkdirTemp("/tmp", "f6c-restore-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	// Not t.TempDir: its path contains the subtest name, and a comma in it splits the --trust-base
	// value, which is a list flag, so the authority process exits before it starts.
	home, err := os.MkdirTemp("", "f6c-restore-home-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	p := &authorityProcess{t: t, bin: bin, home: home, sockets: sockets}

	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
	require.True(t, ok)
	trustBasePath := filepath.Join(p.home, "trust-base.json")
	require.NoError(t, util.WriteJsonFile(trustBasePath, tb))
	_, err = p.ubft("signing-authority", "credential", "--home", p.home, "--out", filepath.Join(sockets, "operator.cred"))
	require.NoError(t, err)

	p.args = []string{
		"signing-authority", "run", "--home", p.home,
		"--client-socket", filepath.Join(sockets, "client", "client.sock"),
		"--operator-socket", filepath.Join(sockets, "operator", "operator.sock"),
		"--operator-credential", filepath.Join(sockets, "operator.cred"),
		"--trust-base", trustBasePath, "--authority-id", "restore-" + strconv.Itoa(os.Getpid()),
		"--node-id", restoredNodeID, "--network-id", "5", "--partition-id", strconv.FormatUint(uint64(authPartitionID), 10),
		"--shard-id", "0x80", "--shard-epoch", "0", "--root-epoch", strconv.FormatUint(tb.GetEpoch(), 10),
		"--log-format", "text", "--log-level", "debug",
	}
	p.start()

	nodeInfoPath := filepath.Join(p.home, "node-info.json")
	_, err = p.ubft(p.operator("node-info", "--out", nodeInfoPath)...)
	require.NoError(t, err)
	raw, err := os.ReadFile(nodeInfoPath)
	require.NoError(t, err)
	var nodeInfo types.NodeInfo
	require.NoError(t, json.Unmarshal(raw, &nodeInfo))

	p.conf = &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: 5, PartitionID: authPartitionID, PartitionTypeID: 1, ShardID: types.ShardID{},
		Epoch: 0, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5000 * time.Millisecond,
		Validators: []*types.NodeInfo{{NodeID: restoredNodeID, SigKey: nodeInfo.SigKey, Stake: 1}},
	}
	require.NoError(t, p.conf.IsValid())
	p.confPath = filepath.Join(p.home, "shard-conf.json")
	require.NoError(t, util.WriteJsonFile(p.confPath, p.conf))
	_, err = p.ubft(p.operator("complete-enrollment", "--shard-conf", p.confPath)...)
	require.NoError(t, err)
	p.confHash, err = p.conf.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	p.verifier, err = abcrypto.NewVerifierSecp256k1(nodeInfo.SigKey)
	require.NoError(t, err)
	return p
}

// replaceSession runs the real replace-session command and returns the client credential it issued.
func (p *authorityProcess) replaceSession(name string) []byte {
	p.t.Helper()
	path := filepath.Join(p.sockets, name+".cred")
	_, err := p.ubft(p.operator("replace-session", "--out", path)...)
	require.NoError(p.t, err)
	raw, err := os.ReadFile(path)
	require.NoError(p.t, err)
	credential, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	require.NoError(p.t, err)
	return credential
}

// countingClient is the real transport client with a count of every operation the round asked for, so
// that "the signer was not reached" is an observation rather than an inference.
type countingClient struct {
	inner SigningAuthorityClient
	mu    sync.Mutex
	calls int
}

func (c *countingClient) count() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
}

func (c *countingClient) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingClient) Reserve(ctx context.Context, req signingauthority.Request) (*signingauthority.Authorization, error) {
	c.count()
	return c.inner.Reserve(ctx, req)
}
func (c *countingClient) Sign(ctx context.Context) error { c.count(); return c.inner.Sign(ctx) }
func (c *countingClient) RetainResponse(ctx context.Context) error {
	c.count()
	return c.inner.RetainResponse(ctx)
}
func (c *countingClient) Release(ctx context.Context, round uint64, digest [32]byte) ([]byte, error) {
	c.count()
	return c.inner.Release(ctx, round, digest)
}

func (p *authorityProcess) client(credential []byte) *countingClient {
	p.t.Helper()
	client, err := service.NewClient(service.ClientConfig{
		Dial: service.UnixDialer(filepath.Join(p.sockets, "client", "client.sock")), Credential: credential, Timeout: 10 * time.Second,
	})
	require.NoError(p.t, err)
	p.t.Cleanup(func() { _ = client.Close() })
	return &countingClient{inner: client}
}

// restoreChain is the certified history the shard nodes below observe, under the authority's
// configuration: round 4 non-quiet (the older checkpoint), round 5 non-quiet (the anchor) assigning 6,
// and quiet rounds after it, each assigning the next.
type restoreChain struct {
	t          *testing.T
	rootSigner abcrypto.Signer
	tb         *types.RootTrustBaseV1
	auth       *authorityProcess
	prevState  []byte
	stateRoot  []byte
	blockHash  []byte
}

func (c *restoreChain) technical(round uint64) *certification.TechnicalRecord {
	zero := make([]byte, 32)
	return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: restoredNodeID, StatHash: zero, FeeHash: zero}
}

// certificate is a certificate for partition round `round` at root round `rootRound`, assigning `next`.
func (c *restoreChain) certificate(round, rootRound uint64, next uint64) *types.UnicityCertificate {
	t := c.t
	t.Helper()
	zero := make([]byte, 32)
	var ir *types.InputRecord
	if round <= 5 {
		ir = &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: c.prevState, Hash: c.stateRoot, BlockHash: c.blockHash, SummaryValue: []byte{}, Timestamp: 1}
	} else {
		ir = &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: c.stateRoot, Hash: c.stateRoot, SummaryValue: []byte{}, Timestamp: 1}
	}
	trHash, err := c.technical(next).Hash()
	require.NoError(t, err)
	return testcertificates.CreateUnicityCertificate(t, c.rootSigner, ir, c.auth.conf, rootRound, zero, trHash)
}

// changingExecutor is steadyExecutor whose sealed block can be replaced, so that a rebuilt candidate
// for a round differs from the one an earlier process asked the authority to sign.
type changingExecutor struct {
	steadyExecutor
	sealed *Block
}

func (e *changingExecutor) Seal(ctx context.Context, id BuildID) (Block, error) {
	if e.sealed != nil {
		e.mu.Lock()
		e.seals++
		e.mu.Unlock()
		return *e.sealed, nil
	}
	return e.steadyExecutor.Seal(ctx, id)
}

// shardProcess is one shard node: a Round, its submitter, its health and the client it signs through.
type shardProcess struct {
	round  *Round
	sub    *countingSubmitter
	health *Health
	client *countingClient
	exec   *changingExecutor
}

func (c *restoreChain) executorOnCertifiedBlock() *changingExecutor {
	return &changingExecutor{steadyExecutor: steadyExecutor{head: BlockRef{Number: 5, Hash: c.blockHash, StateRoot: c.stateRoot}}}
}

// process builds a shard node signing through the authority with the given credential and verification
// key. If checkpoint is non-nil, the node is resumed from it by the production restore sequence.
func (c *restoreChain) process(credential []byte, verifier abcrypto.Verifier, checkpoint *types.UnicityCertificate, exec *changingExecutor) *shardProcess {
	t := c.t
	t.Helper()
	if exec == nil {
		exec = c.executorOnCertifiedBlock()
	}
	sub := &countingSubmitter{}
	round := NewRound(restoredNodeID, authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, sub, nil)
	health := NewHealth()
	round.SetHealth(health)
	client := c.auth.client(credential)
	signer, err := NewAuthoritySigner(client, verifier)
	require.NoError(t, err)
	round.SetCertificationSigner(signer)
	if checkpoint != nil {
		c.restore(round, checkpoint)
	}
	return &shardProcess{round: round, sub: sub, health: health, client: client, exec: exec}
}

// restore resumes a Round from a checkpoint exactly as Node.New does.
func (c *restoreChain) restore(round *Round, checkpoint *types.UnicityCertificate) {
	t := c.t
	t.Helper()
	store := NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
	require.NoError(t, store.SaveLUC(checkpoint))
	loaded, err := store.LoadLUC()
	require.NoError(t, err)
	require.NoError(t, verifyRestoredLUC(loaded, stubTrustBaseStore{tb: c.tb}, authPartitionID, types.ShardID{}, c.auth.confHash),
		"the older checkpoint is genuine")
	resumeFrom(&BFTClient{}, round, loaded)
	require.NotNil(t, round.restoredFrom)
}

func signedBytes(t *testing.T, req *certification.BlockCertificationRequest) []byte {
	t.Helper()
	b, err := types.Cbor.Marshal(req)
	require.NoError(t, err)
	return b
}

func TestRestoredVotingThroughAnIndependentAuthority(t *testing.T) {
	ctx := context.Background()
	bin := buildUbftForShardnode(t)

	newChain := func(t *testing.T) *restoreChain {
		rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*types.RootTrustBaseV1)
		require.True(t, ok)
		c := &restoreChain{
			t: t, rootSigner: rootSigner, tb: tb,
			prevState: bytes.Repeat([]byte{0xa0}, 32), stateRoot: bytes.Repeat([]byte{0xa1}, 32), blockHash: bytes.Repeat([]byte{0xb1}, 32),
		}
		c.auth = startEnrolledAuthority(t, bin, rootSigner)
		return c
	}

	t.Run("an older checkpoint cannot lower signing history, and fresh work is signed", func(t *testing.T) {
		c := newChain(t)
		credential := c.auth.replaceSession("first")
		checkpoint := c.certificate(4, 40, 5)
		cert5, cert6, cert7 := c.certificate(5, 41, 6), c.certificate(6, 42, 7), c.certificate(7, 43, 8)

		// The first process signs rounds 6 and 7 through the authority, then stops.
		first := c.process(credential, c.auth.verifier, nil, nil)
		require.NoError(t, first.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.NoError(t, first.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.Equal(t, []uint64{6, 7}, first.sub.rounds())
		for _, req := range first.sub.requests() {
			require.NoError(t, req.IsValid(c.auth.verifier))
		}
		round7 := signedBytes(t, first.sub.requests()[1])
		require.EqualValues(t, 7, c.auth.mustStatus().ReservedRound)

		// A second process resumes from the OLDER checkpoint (round 4), with the same credential: the
		// authority survived the shard restart.
		restored := c.process(credential, c.auth.verifier, checkpoint, nil)
		require.NoError(t, restored.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.Empty(t, restored.sub.rounds(), "round 6 is below the authority's reservation: nothing is signed or sent")
		require.Contains(t, restored.health.Snapshot().NonVotingReason, signingauthority.ErrStale.Error())

		require.NoError(t, restored.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.Equal(t, []uint64{7}, restored.sub.rounds(), "the identical request for the reserved round is answered")
		require.Equal(t, round7, signedBytes(t, restored.sub.requests()[0]),
			"with the retained bytes, byte for byte: the same signature, not a new one")

		// Changed bytes for round 7, under the same authorization and under a different root
		// authorization: never a second signature.
		different := Block{Number: 6, Hash: bytes.Repeat([]byte{0xe1}, 32), StateRoot: bytes.Repeat([]byte{0xe2}, 32), ParentHash: c.blockHash}
		for name, cert := range map[string]*types.UnicityCertificate{
			"same authorization":           cert6,
			"different root authorization": c.certificate(6, 44, 7),
		} {
			exec := c.executorOnCertifiedBlock()
			exec.sealed = &different
			changed := c.process(credential, c.auth.verifier, checkpoint, exec)
			require.NoError(t, changed.round.HandleCertificate(ctx, cert5, c.technical(6)))
			require.NoError(t, changed.round.HandleCertificate(ctx, cert, c.technical(7)))
			require.Empty(t, changed.sub.rounds(), "%s: a changed request for round 7 is not signed", name)
			require.Contains(t, changed.health.Snapshot().NonVotingReason, signingauthority.ErrConflict.Error(), name)
		}
		status := c.auth.mustStatus()
		require.EqualValues(t, 7, status.ReservedRound)
		require.True(t, status.ResponseRetained)

		// Fresh work above the reservation is signed, verifies under the configured key, and the
		// record moves on.
		require.NoError(t, restored.round.HandleCertificate(ctx, cert7, c.technical(8)))
		require.Equal(t, []uint64{7, 8}, restored.sub.rounds())
		require.NoError(t, restored.sub.requests()[1].IsValid(c.auth.verifier))
		require.True(t, restored.health.Snapshot().Voting)
		require.EqualValues(t, 8, c.auth.mustStatus().ReservedRound)
	})

	t.Run("P-id comes before the authority for a restored process", func(t *testing.T) {
		c := newChain(t)
		credential := c.auth.replaceSession("first")
		checkpoint := c.certificate(4, 40, 5)
		cert5, cert6 := c.certificate(5, 41, 6), c.certificate(6, 42, 7)

		// Same state root, different block.
		wrong := &changingExecutor{steadyExecutor: steadyExecutor{head: BlockRef{Number: 5, Hash: bytes.Repeat([]byte{0xcc}, 32), StateRoot: c.stateRoot}}}
		wrongBlock := c.process(credential, c.auth.verifier, checkpoint, wrong)
		require.NoError(t, wrongBlock.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.NoError(t, wrongBlock.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.Zero(t, wrongBlock.client.Calls(), "a current credential does not authorize signing on the wrong block")
		require.Empty(t, wrongBlock.sub.rounds())

		// No anchor: only a quiet certificate has been observed since the restart.
		noAnchor := c.process(credential, c.auth.verifier, checkpoint, nil)
		require.NoError(t, noAnchor.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.Zero(t, noAnchor.client.Calls(), "nor with no anchor")
		require.Empty(t, noAnchor.sub.rounds())
		_, seals := noAnchor.exec.observed()
		require.Zero(t, seals, "and a node that fails P-id does not lead")

		require.False(t, c.auth.mustStatus().HasReservation, "the authority was asked for nothing")

		// The same two checks for a restored FOLLOWER. A leader that fails P-id stops at the leadership
		// check before Build; a follower awaits the leader's block and reaches the vote-level P-id
		// verdict, which must also come before the authority.
		followerCert5, followerTR6 := c.certificateLedBy(5, 41, 6, followerLeader)
		followerCert6, followerTR7 := c.certificateLedBy(6, 42, 7, followerLeader)
		leaders := leaderBlock{block: Block{Number: 5, Hash: c.blockHash, StateRoot: c.stateRoot, ParentHash: c.blockHash}}
		follower := func(exec *changingExecutor) (*Round, *countingSubmitter, *countingClient) {
			sub := &countingSubmitter{}
			round := NewRound(restoredNodeID, authPartitionID, types.ShardID{}, exec, leaders, nil, sub, nil)
			round.SetHealth(NewHealth())
			client := c.auth.client(credential)
			signer, err := NewAuthoritySigner(client, c.auth.verifier)
			require.NoError(t, err)
			round.SetCertificationSigner(signer)
			c.restore(round, checkpoint)
			return round, sub, client
		}

		wrongFollower := &changingExecutor{steadyExecutor: steadyExecutor{head: BlockRef{Number: 5, Hash: bytes.Repeat([]byte{0xcc}, 32), StateRoot: c.stateRoot}}}
		round, sub, client := follower(wrongFollower)
		require.NoError(t, round.HandleCertificate(ctx, followerCert5, followerTR6))
		require.NoError(t, round.HandleCertificate(ctx, followerCert6, followerTR7))
		require.Zero(t, client.Calls(), "a restored follower on the wrong block does not reach the authority")
		require.Empty(t, sub.rounds())
		require.False(t, c.auth.mustStatus().HasReservation)

		// Positive control: the same follower fixture on the certified block reaches the authority and
		// signs, so the case above was stopped by P-id and not by the fixture.
		round, sub, client = follower(c.executorOnCertifiedBlock())
		require.NoError(t, round.HandleCertificate(ctx, followerCert5, followerTR6))
		require.NotZero(t, client.Calls())
		require.Equal(t, []uint64{6}, sub.rounds(), "a restored follower on the certified block signs through the authority")
		require.NoError(t, sub.requests()[0].IsValid(c.auth.verifier))
	})

	t.Run("the local key keeps the blanket restored refusal", func(t *testing.T) {
		c := newChain(t)
		checkpoint := c.certificate(4, 40, 5)
		localKey, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		sub := &countingSubmitter{}
		round := NewRound(restoredNodeID, authPartitionID, types.ShardID{}, c.executorOnCertifiedBlock(), NewLoopbackDisseminator(), localKey, sub, nil)
		health := NewHealth()
		round.SetHealth(health)
		c.restore(round, checkpoint)
		require.NoError(t, round.HandleCertificate(ctx, c.certificate(5, 41, 6), c.technical(6)))
		require.NoError(t, round.HandleCertificate(ctx, c.certificate(6, 42, 7), c.technical(7)))
		require.Empty(t, sub.rounds(), "a restored process signing with a local key keeps no record, and does not vote")
		require.False(t, health.Snapshot().Voting)

		// A wrapper around a signer that would sign is not a record-keeping signer either.
		wrapped := &recordingSigner{signer: localKey}
		round2 := NewRound(restoredNodeID, authPartitionID, types.ShardID{}, c.executorOnCertifiedBlock(), NewLoopbackDisseminator(), nil, &countingSubmitter{}, nil)
		round2.SetHealth(NewHealth())
		round2.SetCertificationSigner(wrapped)
		c.restore(round2, checkpoint)
		require.NoError(t, round2.HandleCertificate(ctx, c.certificate(5, 41, 6), c.technical(6)))
		require.Zero(t, wrapped.calls(), "only the authority signer lifts the restored refusal")
	})

	t.Run("a lost response, concurrent instances and session replacement", func(t *testing.T) {
		c := newChain(t)
		oldCredential := c.auth.replaceSession("old")
		checkpoint := c.certificate(4, 40, 5)
		cert5, cert6, cert7 := c.certificate(5, 41, 6), c.certificate(6, 42, 7), c.certificate(7, 43, 8)

		old := c.process(oldCredential, c.auth.verifier, nil, nil)
		require.NoError(t, old.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.Equal(t, []uint64{6}, old.sub.rounds())

		// The old process asks the authority to sign its round-7 candidate and loses the answer: the
		// authority reserved, signed and retained it, and nothing was released.
		scratch := c.process(oldCredential, c.auth.verifier, nil, nil)
		var lost *certification.BlockCertificationRequest
		scratch.round.certSigner = signerFunc(func(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
			owned, err := cloneRequest(proposed)
			require.NoError(t, err)
			_, err = scratch.client.Reserve(ctx, signingauthority.Request{UC: uc, Technical: tr, Proposed: owned})
			require.NoError(t, err)
			require.NoError(t, scratch.client.Sign(ctx))
			require.NoError(t, scratch.client.RetainResponse(ctx))
			lost = owned
			return nil, errors.New("the response was lost")
		})
		require.NoError(t, scratch.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.NoError(t, scratch.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.NotNil(t, lost)
		status := c.auth.mustStatus()
		require.EqualValues(t, 7, status.ReservedRound)
		require.True(t, status.ResponseRetained)

		// The operator replaces the session for a new, restored instance, while the old instance is
		// still running and receives the next certificate at the same time.
		newCredential := c.auth.replaceSession("new")
		restored := c.process(newCredential, c.auth.verifier, checkpoint, nil)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errs[0] = old.round.HandleCertificate(ctx, cert6, c.technical(7)) }()
		go func() {
			defer wg.Done()
			if err := restored.round.HandleCertificate(ctx, cert5, c.technical(6)); err != nil {
				errs[1] = err
				return
			}
			errs[1] = restored.round.HandleCertificate(ctx, cert6, c.technical(7))
		}()
		wg.Wait()
		require.NoError(t, errs[0])
		require.NoError(t, errs[1])

		require.Equal(t, []uint64{6}, old.sub.rounds(), "the old instance is fenced and sends nothing more")
		require.Contains(t, old.health.Snapshot().NonVotingReason, signingauthority.ErrFenced.Error())
		require.Equal(t, []uint64{7}, restored.sub.rounds(), "the restored instance recovers the lost response")
		recovered := restored.sub.requests()[0]
		require.NoError(t, recovered.IsValid(c.auth.verifier))
		recoveredUnsigned, err := recovered.Bytes()
		require.NoError(t, err)
		lostUnsigned, err := lost.Bytes()
		require.NoError(t, err)
		require.Equal(t, lostUnsigned, recoveredUnsigned, "it is the request the authority signed before the answer was lost")
		status = c.auth.mustStatus()
		require.EqualValues(t, 2, status.Generation)
		require.EqualValues(t, 7, status.ReservedRound, "fencing kept the record")

		// And the new instance does fresh work.
		require.NoError(t, restored.round.HandleCertificate(ctx, cert7, c.technical(8)))
		require.Equal(t, []uint64{7, 8}, restored.sub.rounds())
		require.NoError(t, restored.sub.requests()[1].IsValid(c.auth.verifier))
	})

	t.Run("an unreachable authority, a wrong key and a new authority lifetime abstain", func(t *testing.T) {
		c := newChain(t)
		credential := c.auth.replaceSession("first")
		checkpoint := c.certificate(4, 40, 5)
		cert5, cert6 := c.certificate(5, 41, 6), c.certificate(6, 42, 7)

		// A response under a key other than the configured one is not sent.
		otherKey, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		otherVerifier, err := otherKey.Verifier()
		require.NoError(t, err)
		wrongKey := c.process(credential, otherVerifier, checkpoint, nil)
		require.NoError(t, wrongKey.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.Empty(t, wrongKey.sub.rounds())
		require.Contains(t, wrongKey.health.Snapshot().NonVotingReason, "does not verify under the enrolled signing key")

		// The authority process is killed: its key and record are gone.
		c.auth.kill()
		unreachable := c.process(credential, c.auth.verifier, checkpoint, nil)
		require.NoError(t, unreachable.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.Empty(t, unreachable.sub.rounds())
		require.Contains(t, unreachable.health.Snapshot().NonVotingReason, signingauthority.ErrUnavailable.Error())

		// A new authority lifetime on the same paths has a new key. The old configuration does not
		// complete its enrollment, it issues no session, and the old credential is not admitted.
		c.auth.start()
		_, err = c.auth.ubft(c.auth.operator("complete-enrollment", "--shard-conf", c.auth.confPath)...)
		require.ErrorContains(t, err, signingauthority.ErrContextMismatch.Error(),
			"the configuration names the previous lifetime's key")
		_, err = c.auth.ubft(c.auth.operator("replace-session", "--out", filepath.Join(c.auth.sockets, "never.cred"))...)
		require.ErrorContains(t, err, signingauthority.ErrEnrollmentIncomplete.Error())
		newLifetime := c.process(credential, c.auth.verifier, checkpoint, nil)
		require.NoError(t, newLifetime.round.HandleCertificate(ctx, cert5, c.technical(6)))
		require.NoError(t, newLifetime.round.HandleCertificate(ctx, cert6, c.technical(7)))
		require.Empty(t, newLifetime.sub.rounds(), "a new authority lifetime does not take over the validator assignment")
		require.False(t, c.auth.mustStatus().EnrollmentComplete)
	})
}

// followerLeader is the validator that leads the rounds in the follower cases, so that the restored
// node under test follows: it awaits the leader's block instead of building one, and so reaches the
// vote-level P-id verdict rather than the leadership check that precedes Build.
const followerLeader = "another-validator"

// certificateLedBy is certificate with a technical record naming another leader.
func (c *restoreChain) certificateLedBy(round, rootRound, next uint64, leader string) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t := c.t
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: next, Epoch: 0, Leader: leader, StatHash: zero, FeeHash: zero}
	var ir *types.InputRecord
	if round <= 5 {
		ir = &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: c.prevState, Hash: c.stateRoot, BlockHash: c.blockHash, SummaryValue: []byte{}, Timestamp: 1}
	} else {
		ir = &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: c.stateRoot, Hash: c.stateRoot, SummaryValue: []byte{}, Timestamp: 1}
	}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	return testcertificates.CreateUnicityCertificate(t, c.rootSigner, ir, c.auth.conf, rootRound, zero, trHash), tr
}

// leaderBlock is a Disseminator that hands a follower the leader's block for any round: a quiet block
// on the certified state, as the leader of an idle round would publish.
type leaderBlock struct{ block Block }

func (d leaderBlock) Publish(context.Context, uint64, Block) error { return nil }
func (d leaderBlock) Await(context.Context, uint64) (Block, error) { return d.block, nil }

// signerFunc adapts a function to CertificationSigner, for the lost-response step only.
type signerFunc func(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error)

func (f signerFunc) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	return f(ctx, uc, tr, proposed)
}
