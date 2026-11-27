package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

// fakeAdvanceOperator is the authority as advance-with-proof sees it: a scope that advances once, the session it admits, and the client
// socket's view of a credential file. A replacement can lose its answer (the authority issued the session, the caller never got it).
type fakeAdvanceOperator struct {
	status       signingauthority.Status
	advanced     bool
	admitted     []byte
	loseAnswer   bool
	replacements int
}

func (f *fakeAdvanceOperator) AdvanceWithProof(_ context.Context, bundle []byte) (signingauthority.AdvanceResult, error) {
	if string(bundle) == "bad" {
		return signingauthority.AdvanceResult{}, signingauthority.ErrLineageUnverified
	}
	if f.advanced {
		return signingauthority.AdvanceResult{Epoch: 2, Replay: true, RootEpoch: 2}, nil
	}
	f.advanced = true
	f.status.RootEpoch, f.status.SessionIssued, f.admitted = 2, false, nil
	return signingauthority.AdvanceResult{Epoch: 2, Advanced: true, RootEpoch: 2}, nil
}

func (f *fakeAdvanceOperator) Status(context.Context) (signingauthority.Status, error) {
	return f.status, nil
}

func (f *fakeAdvanceOperator) ReplaceSession(context.Context) ([]byte, error) {
	f.replacements++
	credential := bytes.Repeat([]byte{byte(f.replacements)}, service.CredentialBytes)
	f.admitted, f.status.SessionIssued = credential, true
	if f.loseAnswer {
		f.loseAnswer = false
		return nil, errors.New("the operator socket closed before the answer")
	}
	return credential, nil
}

// current is the client socket's answer for the credential in path: the real check reads the file the same way.
func (f *fakeAdvanceOperator) current(path string) func(context.Context) error {
	return func(context.Context) error {
		credential, err := readCredentialFile(path)
		if err != nil {
			return err
		}
		if f.admitted == nil || !bytes.Equal(credential, f.admitted) {
			return signingauthority.ErrFenced
		}
		return nil
	}
}

func proofFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func admittedOnFile(t *testing.T, f *fakeAdvanceOperator, path string) {
	t.Helper()
	require.NoError(t, f.current(path)(context.Background()), "--out holds the admitted credential")
}

func testAdvanceWithProof(ctx context.Context, operator interface {
	advanceOperator
	ReplaceSession(context.Context) ([]byte, error)
}, proofs []string, out string, current func(context.Context) error) (advanceWithProofReport, error) {
	return advanceWithProof(ctx, operator, proofs, func(ctx context.Context, status signingauthority.Status) (service.SessionPublication, error) {
		issued, err := ensureAuthoritySession(ctx, status, out, current, operator.ReplaceSession)
		return service.SessionPublication{Issued: issued}, err
	})
}

// Every crash point of the one operation is repaired by running it again with the same proof (the drive always passes the target's):
// after the proof was published, after the session was issued but its answer lost, after a failed write, after a complete run.
func TestAdvanceWithProofIsRepairedByARerunAtEveryCrashPoint(t *testing.T) {
	ctx := context.Background()
	for _, old := range []bool{false, true} {
		name := map[bool]string{false: "no credential file", true: "an old credential on file"}[old]
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			proof := proofFile(t, dir, "q3-bundle-2.cbor", "bundle")
			cred := filepath.Join(dir, "client.cred")
			if old {
				require.NoError(t, writeCredentialFile(cred, bytes.Repeat([]byte{0xee}, service.CredentialBytes), true))
			}
			op := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, SessionIssued: true}, loseAnswer: true}

			_, err := testAdvanceWithProof(ctx, op, []string{proof}, cred, op.current(cred))
			require.Error(t, err, "the proof was published and the session issued, but its answer was lost")

			report, err := testAdvanceWithProof(ctx, op, []string{proof}, cred, op.current(cred))
			require.NoError(t, err, "the rerun replays the proof and replaces the session whose credential never reached the file")
			require.False(t, report.Advanced)
			require.True(t, report.SessionIssued)
			admittedOnFile(t, op, cred)

			// a failed write: the session is replaced, the file cannot be written
			op.status.SessionIssued, op.admitted = false, nil
			require.NoError(t, os.Chmod(dir, 0o500))
			_, err = testAdvanceWithProof(ctx, op, []string{proof}, cred, op.current(cred))
			require.NoError(t, os.Chmod(dir, 0o700))
			require.Error(t, err, "the credential could not be written")
			report, err = testAdvanceWithProof(ctx, op, []string{proof}, cred, op.current(cred))
			require.NoError(t, err)
			require.True(t, report.SessionIssued, "the rerun issues again: the file does not hold the admitted credential")
			admittedOnFile(t, op, cred)

			replaced := op.replacements
			report, err = testAdvanceWithProof(ctx, op, []string{proof}, cred, op.current(cred))
			require.NoError(t, err)
			require.False(t, report.SessionIssued, "a rerun after a complete run replaces nothing")
			require.Equal(t, replaced, op.replacements)
		})
	}
}

func TestAdvanceWithProofStopsAtARefusedBundleAndIssuesNothingForARetiredAuthority(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cred := filepath.Join(dir, "client.cred")
	op := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, SessionIssued: true}}
	_, err := testAdvanceWithProof(ctx, op, []string{proofFile(t, dir, "bad.cbor", "bad")}, cred, op.current(cred))
	require.ErrorIs(t, err, signingauthority.ErrLineageUnverified)
	require.Equal(t, 0, op.replacements)

	retired := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, Retired: true}, advanced: true}
	report, err := testAdvanceWithProof(ctx, retired, []string{proofFile(t, dir, "b.cbor", "bundle")}, cred, retired.current(cred))
	require.NoError(t, err)
	require.True(t, report.Retired)
	require.Equal(t, 0, retired.replacements, "a retired authority issues no session")

	_, err = testAdvanceWithProof(ctx, op, nil, cred, op.current(cred))
	require.Error(t, err, "no proof: a resume passes the target's")
	big := filepath.Join(dir, "big.cbor")
	require.NoError(t, os.WriteFile(big, make([]byte, service.MaxAdvanceProofBytes+1), 0o600))
	_, err = testAdvanceWithProof(ctx, op, []string{big}, cred, op.current(cred))
	require.ErrorContains(t, err, "an activation proof is at most")
}

// The command itself requires a proof, the credential file and the client socket: the drive's arguments are checked against the real
// flag validation, not a fake.
func TestTheAdvanceWithProofCommandRequiresProofOutAndClientSocket(t *testing.T) {
	for name, args := range map[string][]string{
		"proof":         {"--out", "c", "--client-socket", "s"},
		"out":           {"--proof", "p", "--client-socket", "s"},
		"client-socket": {"--proof", "p", "--out", "c"},
	} {
		cmd := signingAuthorityAdvanceWithProofCmd(&baseFlags{})
		cmd.SetArgs(append(args, "--operator-socket", "o", "--operator-credential", "oc"))
		cmd.SetOut(new(strings.Builder))
		cmd.SetErr(new(strings.Builder))
		err := cmd.Execute()
		require.ErrorContains(t, err, `"`+name+`" not set`, "without --%s", name)
	}
}

// The pre-read size check is the operator frame's bound exactly: a proof of MaxAdvanceProofBytes is read and sent, one byte more is refused
// before it is read (the largest legitimate activation, measured in the service tests, is far below it).
type sizeOperator struct {
	fakeAdvanceOperator
	sent int
}

func (s *sizeOperator) AdvanceWithProof(ctx context.Context, bundle []byte) (signingauthority.AdvanceResult, error) {
	s.sent = len(bundle)
	return s.fakeAdvanceOperator.AdvanceWithProof(ctx, []byte("bundle"))
}

func TestThePreReadSizeCheckIsTheFrameBound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cred := filepath.Join(dir, "client.cred")
	op := &sizeOperator{fakeAdvanceOperator: fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1}}}
	at := filepath.Join(dir, "at.cbor")
	require.NoError(t, os.WriteFile(at, make([]byte, service.MaxAdvanceProofBytes), 0o600))
	_, err := testAdvanceWithProof(ctx, op, []string{at}, cred, op.current(cred))
	require.NoError(t, err)
	require.Equal(t, service.MaxAdvanceProofBytes, op.sent)
	over := filepath.Join(dir, "over.cbor")
	require.NoError(t, os.WriteFile(over, make([]byte, service.MaxAdvanceProofBytes+1), 0o600))
	op.sent = 0
	_, err = testAdvanceWithProof(ctx, op, []string{over}, cred, op.current(cred))
	require.ErrorContains(t, err, "an activation proof is at most")
	require.Zero(t, op.sent, "refused before it is read or sent")
}
