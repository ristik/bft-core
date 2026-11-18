package vrschedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// fakeAuthority stands in for the authority's operation: it signs the structured request it was given with its key and records it.
type fakeAuthority struct {
	key  abcrypto.Signer
	seen []signingauthority.HandoffPoPRequest
	fail error
}

func (f *fakeAuthority) SignHandoffPoP(_ context.Context, req signingauthority.HandoffPoPRequest) (evmassign.PoP, error) {
	f.seen = append(f.seen, req)
	if f.fail != nil {
		return evmassign.PoP{}, f.fail
	}
	return evmassign.SignPoP(f.key, req.Context, req.Successor, req.NodeID)
}

// The authority provider asks for exactly the canonical context of the committed intent, and the member wraps, verifies and persists the
// result like a local proof: the intent verifies it, the same bytes are kept sticky.
func TestTheAuthorityPoPVerifiesAgainstTheIntent(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	fa := &fakeAuthority{key: self.EK.Signer}
	path := filepath.Join(t.TempDir(), "m.json")
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc.Update(w.committed(0))
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: fa}, Path: path})
	require.NoError(t, err)
	require.NoError(t, m.Step())

	require.Len(t, fa.seen, 1)
	wantCtx, wantSucc, err := vrhandoff.PoPContext(w.in)
	require.NoError(t, err)
	require.Equal(t, evmassign.PoPDomain, fa.seen[0].Domain, "the member names the one domain; it supplies no bytes")
	require.Equal(t, wantCtx, fa.seen[0].Context)
	require.Equal(t, wantSucc, fa.seen[0].Successor)
	require.Equal(t, self.EVM, fa.seen[0].NodeID)

	f := readFile(t, path)
	require.Len(t, f.Intents, 1)
	require.NotEmpty(t, f.Intents[0].PoP, "persisted before release")
	got, ok := svc.Stage(w.d, 0)
	require.True(t, ok)
	require.Len(t, got.PoPs, 1)
	require.NoError(t, vrhandoff.VerifyPoP(w.in, got.PoPs[0]))

	// sticky: a restarted member over the same file does not ask the authority again
	svc2 := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc2.Update(w.committed(0))
	m2, err := NewMember(svc2, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: fa}, Path: path})
	require.NoError(t, err)
	require.NoError(t, m2.Step())
	require.Len(t, fa.seen, 1)
}

// An authority that refuses, or answers with another key's proof, releases and persists nothing.
func TestAnAuthorityRefusalOrAWrongKeyProofReleasesNothing(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	for name, fa := range map[string]*fakeAuthority{
		"refusal":   {key: self.EK.Signer, fail: signingauthority.ErrContextMismatch},
		"wrong key": {key: w.Members[1].EK.Signer},
	} {
		path := filepath.Join(t.TempDir(), "m.json")
		svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
		svc.Update(w.committed(0))
		m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: fa}, Path: path})
		require.NoError(t, err)
		err = m.Step()
		require.ErrorIs(t, err, ErrMember, name)
		if name == "refusal" {
			require.True(t, errors.Is(err, signingauthority.ErrContextMismatch), "the authority's refusal is kept")
		}
		_, statErr := os.Stat(path)
		require.True(t, os.IsNotExist(statErr), "%s: nothing persisted", name)
		set, _ := svc.Stage(w.d, 0)
		require.Empty(t, set.PoPs, "%s: nothing released", name)
	}
}
