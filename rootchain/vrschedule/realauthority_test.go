package vrschedule

// The member's AuthorityPoP against a real signingauthority served on the PoP endpoint.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type staticTrustBases struct{ tb *types.RootTrustBaseV1 }

func (s staticTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

func realAuthority(t *testing.T, nodeID string, shardEpoch uint64) (*signingauthority.Authority, []byte) {
	rs, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := trustbase.NewTrustBase(t, rs).(*types.RootTrustBaseV1)
	require.True(t, ok)
	// a joiner's authority: pending (no ShardConfHash), enrolled for the successor epoch
	a, err := signingauthority.New(signingauthority.Enrollment{AuthorityID: "member-test", NodeID: nodeID, NetworkID: vrhandofffix.Network,
		PartitionID: vrhandofffix.EVMPart, ShardID: types.ShardID{}, ShardEpoch: shardEpoch, RootEpoch: signingauthority.PinRootEpoch(1),
		Profile: signingauthority.ProfileLegacyBCRv1}, staticTrustBases{tb})
	require.NoError(t, err)
	t.Cleanup(a.Close)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	return a, pub
}

func TestTheMemberAgainstARealAuthority(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	a, pub := realAuthority(t, self.EVM, w.RC.Installed.Epoch+1)
	// member 5's EVM key is the authority's: rebuild J, the output and the intent around it
	self.EK = vrhandofffix.Key{Pub: pub}
	w.Members[5] = self
	w.J = nil
	for _, i := range []uint64{1, 2, 3, 5} {
		w.J = append(w.J, w.Identity(i))
	}
	w.Out = w.Output(w.J, w.Out.Changes)
	w.Src.OutputCommit = append([]byte(nil), w.Out.State.Output.OutputCommit[:]...)
	w.in, w.d = w.Intent()

	cred, err := service.NewCredential()
	require.NoError(t, err)
	opCred, err := service.NewCredential()
	require.NoError(t, err)
	srv, err := service.NewServer(a, service.Config{OperatorCredential: opCred, PoPCredential: cred})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	dir, err := os.MkdirTemp("/tmp", "member-pop-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := service.ListenUnix(filepath.Join(dir, "pop.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l, service.PoPEndpoint) }()
	c, err := service.NewPoPClient(service.ClientConfig{Dial: service.UnixDialer(filepath.Join(dir, "pop.sock")), Credential: cred, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	path := filepath.Join(t.TempDir(), "m.json")
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc.Update(w.committed(0))
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: c}, Path: path})
	require.NoError(t, err)
	require.NoError(t, m.Step())
	got, ok := svc.Stage(w.d, 0)
	require.True(t, ok)
	require.Len(t, got.PoPs, 1)
	require.NoError(t, vrhandoff.VerifyPoP(w.in, got.PoPs[0]))
	f := readFile(t, path)
	require.Len(t, f.Intents, 1)
	require.NotEmpty(t, f.Intents[0].PoP)

	// wrong credential: refused, nothing persisted for a fresh member
	bad, err := service.NewPoPClient(service.ClientConfig{Dial: service.UnixDialer(filepath.Join(dir, "pop.sock")), Credential: opCred, Timeout: 10 * time.Second})
	require.NoError(t, err)
	path2 := filepath.Join(t.TempDir(), "m2.json")
	svc2 := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc2.Update(w.committed(0))
	m2, err := NewMember(svc2, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: bad}, Path: path2})
	require.NoError(t, err)
	err = m2.Step()
	require.ErrorIs(t, err, ErrMember)
	t.Logf("wrong credential: %v", err)
	_, statErr := os.Stat(path2)
	require.True(t, os.IsNotExist(statErr))
}

// An authority enrolled for another node refuses; the member releases nothing.
func TestARealAuthorityOfAnotherNodeRefusesTheMember(t *testing.T) {
	w := newWorld(t)
	self := w.Members[5]
	a, pub := realAuthority(t, "evm-other", w.RC.Installed.Epoch+1)
	_ = pub
	cred, err := service.NewCredential()
	require.NoError(t, err)
	opCred, err := service.NewCredential()
	require.NoError(t, err)
	srv, err := service.NewServer(a, service.Config{OperatorCredential: opCred, PoPCredential: cred})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	dir, err := os.MkdirTemp("/tmp", "member-pop-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := service.ListenUnix(filepath.Join(dir, "pop.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l, service.PoPEndpoint) }()
	c, err := service.NewPoPClient(service.ClientConfig{Dial: service.UnixDialer(filepath.Join(dir, "pop.sock")), Credential: cred, Timeout: 10 * time.Second})
	require.NoError(t, err)
	svc := NewService(ServiceConfig{Self: self.Root, Signer: self.RK.Signer})
	svc.Update(w.committed(0))
	m, err := NewMember(svc, MemberConfig{Self: self.Root, RootSigner: self.RK.Signer, EVMPoP: AuthorityPoP{Client: c}})
	require.NoError(t, err)
	err = m.Step()
	require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	set, _ := svc.Stage(w.d, 0)
	require.Empty(t, set.PoPs)
}
