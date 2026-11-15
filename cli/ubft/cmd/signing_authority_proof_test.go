package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

// fakeAdvanceOperator is the authority as advance-with-proof sees it: a scope that advances once, a session flag, and a replacement that
// can be made to fail once.
type fakeAdvanceOperator struct {
	status       signingauthority.Status
	advanced     bool
	failReplace  bool
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
	f.status.RootEpoch, f.status.SessionIssued = 2, false
	return signingauthority.AdvanceResult{Epoch: 2, Advanced: true, RootEpoch: 2}, nil
}

func (f *fakeAdvanceOperator) Status(context.Context) (signingauthority.Status, error) {
	return f.status, nil
}

func (f *fakeAdvanceOperator) ReplaceSession(context.Context) ([]byte, error) {
	if f.failReplace {
		f.failReplace = false
		return nil, errors.New("the operator socket went away")
	}
	f.replacements++
	f.status.SessionIssued = true
	return make([]byte, 32), nil
}

func proofFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestAdvanceWithProofIssuesTheNextSessionOnceAndARerunRepairsAFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	proof := proofFile(t, dir, "q3-bundle-2.cbor", "bundle")
	cred := filepath.Join(dir, "client.cred")
	op := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, SessionIssued: true}, failReplace: true}

	_, err := advanceWithProof(ctx, op, []string{proof}, cred, nil)
	require.Error(t, err, "advanced, but the credential could not be issued")
	require.NoFileExists(t, cred)

	report, err := advanceWithProof(ctx, op, []string{proof}, cred, nil)
	require.NoError(t, err, "the rerun repairs it: the proof is a replay, and no session was issued since the scope changed")
	require.False(t, report.Advanced)
	require.True(t, report.SessionIssued)
	require.FileExists(t, cred)
	require.Equal(t, 1, op.replacements)

	report, err = advanceWithProof(ctx, op, []string{proof}, cred, func(context.Context) error { return nil })
	require.NoError(t, err)
	require.False(t, report.SessionIssued, "a third run with the credential admitted replaces nothing")
	require.Equal(t, 1, op.replacements)
}

func TestAdvanceWithProofReplacesASessionWhoseCredentialWasNeverWritten(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	proof := proofFile(t, dir, "q3-bundle-2.cbor", "bundle")
	op := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 2, SessionIssued: true}, advanced: true}
	report, err := advanceWithProof(ctx, op, []string{proof}, filepath.Join(dir, "client.cred"),
		func(context.Context) error { return signingauthority.ErrFenced })
	require.NoError(t, err)
	require.True(t, report.SessionIssued)
	require.Equal(t, 1, op.replacements)
}

func TestAdvanceWithProofStopsAtARefusedBundleAndIssuesNothingForARetiredAuthority(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	op := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, SessionIssued: true}}
	_, err := advanceWithProof(ctx, op, []string{proofFile(t, dir, "bad.cbor", "bad")}, filepath.Join(dir, "client.cred"), nil)
	require.ErrorIs(t, err, signingauthority.ErrLineageUnverified)
	require.Equal(t, 0, op.replacements)

	retired := &fakeAdvanceOperator{status: signingauthority.Status{RootEpoch: 1, Retired: true}, advanced: true}
	report, err := advanceWithProof(ctx, retired, []string{proofFile(t, dir, "b.cbor", "bundle")}, filepath.Join(dir, "client.cred"), nil)
	require.NoError(t, err)
	require.True(t, report.Retired)
	require.Equal(t, 0, retired.replacements, "a retired authority issues no session")
}
