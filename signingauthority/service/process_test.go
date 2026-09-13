package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/signingauthority"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The authority in a second process, which is what §3 requires and what an in-process authority cannot
give: its own lifetime, its own memory and its own credentials.

These tests run a real child process. The child is this test binary re-executed with an environment
variable set, which keeps the evidence honest without a command this unit is not authorized to add:
what is killed is a separate operating-system process holding the key, and what the shard node holds
is a socket path and a credential.
*/

const (
	authorityProcessEnv = "BFT_TEST_AUTHORITY_PROCESS"
	// The child reads everything else from files an operator would have provisioned.
	trustBaseFile  = "trustbase.cbor"
	enrollmentFile = "enrollment.cbor"
	operatorFile   = "operator.cred"
)

func TestMain(m *testing.M) {
	if os.Getenv(authorityProcessEnv) != "" {
		runAuthorityProcess(os.Getenv(authorityProcessEnv))
		return
	}
	os.Exit(m.Run())
}

// runAuthorityProcess is the child: an authority, its two endpoints, and nothing else. It never
// returns; the parent kills it.
func runAuthorityProcess(dir string) {
	fail := func(err error) {
		_, _ = os.Stderr.WriteString("authority process: " + err.Error() + "\n")
		os.Exit(2)
	}
	trustBaseBytes, err := os.ReadFile(filepath.Join(dir, trustBaseFile))
	if err != nil {
		fail(err)
	}
	var tb types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(trustBaseBytes, &tb); err != nil {
		fail(err)
	}
	enrollmentBytes, err := os.ReadFile(filepath.Join(dir, enrollmentFile))
	if err != nil {
		fail(err)
	}
	var enrollment signingauthority.Enrollment
	if err := types.Cbor.Unmarshal(enrollmentBytes, &enrollment); err != nil {
		fail(err)
	}
	operatorCredential, err := os.ReadFile(filepath.Join(dir, operatorFile))
	if err != nil {
		fail(err)
	}

	// The key is generated here, in this process, and has never been anywhere else.
	authority, err := signingauthority.New(enrollment, staticTrust{tb: &tb})
	if err != nil {
		fail(err)
	}
	server, err := NewServer(authority, Config{OperatorCredential: operatorCredential})
	if err != nil {
		fail(err)
	}
	clientListener, err := ListenUnix(filepath.Join(dir, "client.sock"))
	if err != nil {
		fail(err)
	}
	operatorListener, err := ListenUnix(filepath.Join(dir, "operator.sock"))
	if err != nil {
		fail(err)
	}
	go func() { _ = server.Serve(clientListener, ClientEndpoint) }()
	_ = server.Serve(operatorListener, OperatorEndpoint)
	os.Exit(0)
}

// authorityProcess is a running child, with the operator's end of it.
type authorityProcess struct {
	cmd      *exec.Cmd
	dir      string
	operator *OperatorClient
}

func (p *authorityProcess) kill(t *testing.T) {
	t.Helper()
	require.NoError(t, p.cmd.Process.Signal(syscall.SIGKILL))
	_, _ = p.cmd.Process.Wait()
	// The sockets outlive the process that made them; nothing is listening on them any more.
}

func (f *fixture) startAuthorityProcess(t *testing.T, dir string, operatorCredential []byte) *authorityProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), authorityProcessEnv+"="+dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})

	operator, err := NewOperatorClient(ClientConfig{
		Dial:       UnixDialer(filepath.Join(dir, "operator.sock")),
		Credential: operatorCredential, Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })

	// The child is up when its operator endpoint answers.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, _, err := operator.Enrollment(context.Background()); err == nil {
			break
		}
		require.True(t, time.Now().Before(deadline), "the authority process did not start")
		time.Sleep(20 * time.Millisecond)
	}
	return &authorityProcess{cmd: cmd, dir: dir, operator: operator}
}

// provision writes what an operator would have handed the authority host, and starts it.
func (f *fixture) provision(t *testing.T) (*authorityProcess, []byte) {
	t.Helper()
	dir := socketDir(t)

	tb, err := types.Cbor.Marshal(f.trustBase)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, trustBaseFile), tb, 0o600))

	enrollment := f.authority.Enrollment()
	// The fingerprint is an output of enrollment, not an input: the child generates its own key.
	enrollment.SigningKeyFingerprint = nil
	encoded, err := types.Cbor.Marshal(enrollment)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, enrollmentFile), encoded, 0o600))

	operatorCredential, err := NewCredential()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, operatorFile), operatorCredential, 0o600))

	return f.startAuthorityProcess(t, dir, operatorCredential), operatorCredential
}

func (p *authorityProcess) admit(t *testing.T) *Client {
	t.Helper()
	credential, err := p.operator.ReplaceSession(context.Background())
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{
		Dial: UnixDialer(filepath.Join(p.dir, "client.sock")), Credential: credential, Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTheAuthorityRunsInItsOwnProcess(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	authority, _ := f.provision(t)
	client := authority.admit(t)

	require.NotEqual(t, os.Getpid(), authority.cmd.Process.Pid,
		"the key is held by another process, which is the whole point")

	authorization, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)
	require.NoError(t, client.Sign(ctx))
	require.NoError(t, client.RetainResponse(ctx))
	released, err := client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)

	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(released, &signed))
	_, key, err := authority.operator.Enrollment(ctx)
	require.NoError(t, err)
	verifier, err := abcrypto.NewVerifierSecp256k1(key)
	require.NoError(t, err)
	require.NoError(t, signed.IsValid(verifier))

	// The key that signed is not one this process has, or could produce: the local authority in this
	// test has its own, and they are different keys for the same enrollment.
	localKey, err := f.authority.SigningPublicKey()
	require.NoError(t, err)
	require.NotEqual(t, localKey, key)
	require.Error(t, signed.IsValid(mustVerifier(t, localKey)))
}

func TestKillingTheAuthorityMakesTheClientUnavailableAndNothingElse(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	authority, _ := f.provision(t)
	client := authority.admit(t)

	authorization, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	authority.kill(t)

	// Every remaining operation of the exchange is unavailability, not a decision. There is no
	// local signer to fall back to and no answer to invent: the round abstains on this (§3, §6).
	err = client.Sign(ctx)
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
	require.NotErrorIs(t, err, signingauthority.ErrFenced)
	require.NotErrorIs(t, err, signingauthority.ErrKeyLost)
	require.ErrorIs(t, client.RetainResponse(ctx), signingauthority.ErrUnavailable)
	_, err = client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
	_, err = client.Reserve(ctx, f.request())
	require.ErrorIs(t, err, signingauthority.ErrUnavailable)
}

func TestARestartedAuthorityIsANewOneAndNotARecoveredOne(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	first, operatorCredential := f.provision(t)
	client := first.admit(t)
	_, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)
	_, firstKey, err := first.operator.Enrollment(ctx)
	require.NoError(t, err)

	first.kill(t)

	// The same provisioning directory, the same enrollment, the same operator credential: everything
	// an operator would reuse. What cannot be reused is the key.
	second := f.startAuthorityProcess(t, first.dir, operatorCredential)
	_, secondKey, err := second.operator.Enrollment(ctx)
	require.NoError(t, err)
	require.NotEqual(t, firstKey, secondKey,
		"a restarted authority generates a new key; there is no import path that could recover the old identity")

	// The client the operator provisioned against the dead authority is not admitted by the new one.
	_, err = client.Reserve(ctx, f.request())
	require.ErrorIs(t, err, signingauthority.ErrFenced)

	// Returning to service is an operator act, and it is a fresh assignment rather than a reset.
	resumed := second.admit(t)
	authorization, err := resumed.Reserve(ctx, f.request())
	require.NoError(t, err)
	require.NoError(t, resumed.Sign(ctx))
	require.NoError(t, resumed.RetainResponse(ctx))
	released, err := resumed.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)

	var signed certification.BlockCertificationRequest
	require.NoError(t, types.Cbor.Unmarshal(released, &signed))
	require.NoError(t, signed.IsValid(mustVerifier(t, secondKey)))
	require.Error(t, signed.IsValid(mustVerifier(t, firstKey)),
		"work signed after the restart is signed by the new key, and an operator must treat it as a new authority")
}

func TestTheShardSideHoldsNoKeyAndNoSession(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	authority, operatorCredential := f.provision(t)
	client := authority.admit(t)
	_, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	// What the shard side has is a socket path and a bearer credential. With both, it can reserve,
	// sign, retain and release; it cannot replace its session, read the key, or start an authority.
	stray, err := NewOperatorClient(ClientConfig{
		Dial: UnixDialer(filepath.Join(authority.dir, "client.sock")), Credential: client.ex.credential,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = stray.Close() })
	_, err = stray.ReplaceSession(ctx)
	require.ErrorIs(t, err, errWrongEndpoint, "session replacement is not served where the shard node can reach")
	_, _, err = stray.Enrollment(ctx)
	require.ErrorIs(t, err, errWrongEndpoint)

	// And the operator credential is a different secret: holding the client's does not produce it.
	require.NotEqual(t, operatorCredential, client.ex.credential)

	// Killing the shard's client changes nothing about the authority: it keeps the reservation and
	// the same operator connection keeps working.
	require.NoError(t, client.Close())
	status, err := authority.operator.Status(ctx)
	require.NoError(t, err)
	require.True(t, status.HasReservation)
	require.EqualValues(t, 6, status.ReservedRound,
		"the authority's lifetime is its own; a client going away does not end it")
}

func TestARunningAuthorityKeepsItsSocketPath(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	authority, _ := f.provision(t)
	client := authority.admit(t)
	authorization, err := client.Reserve(ctx, f.request())
	require.NoError(t, err)

	// A second authority started on the same path would be a second key for one enrolled node, and
	// the shard node dialling that path could not tell which one it had reached: same operations,
	// same refusals, a different signer holding a different reservation.
	path := filepath.Join(authority.dir, "client.sock")
	second, err := ListenUnix(path)
	require.ErrorIs(t, err, ErrPathHeld)
	require.Nil(t, second)

	// The process that owns the path is still the one serving it, and still holding its reservation.
	status, err := authority.operator.Status(ctx)
	require.NoError(t, err)
	require.True(t, status.HasReservation)
	require.NoError(t, client.Sign(ctx))
	require.NoError(t, client.RetainResponse(ctx))
	_, err = client.Release(ctx, authorization.AssignedRound, authorization.UnsignedDigest)
	require.NoError(t, err)

	// When that process is gone the path is free, and the socket it left behind is removed rather
	// than inherited: the claim is what separates the two cases.
	authority.kill(t)
	third, err := ListenUnix(path)
	require.NoError(t, err)
	require.NoError(t, third.Close())
}

func mustVerifier(t *testing.T, key []byte) abcrypto.Verifier {
	t.Helper()
	verifier, err := abcrypto.NewVerifierSecp256k1(key)
	require.NoError(t, err)
	return verifier
}
