package trustbase

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// historyOf is a verified-history stand-in: the configuration of each epoch it holds, an error for any other.
type historyOf map[uint64]votesig.Config

var errNotHeld = errors.New("epoch not in the history")

func (h historyOf) Signing(epoch uint64) (votesig.Config, error) {
	if c, ok := h[epoch]; ok {
		return c, nil
	}
	return votesig.Config{}, errNotHeld
}

type pointerHistory struct{ historyOf }

func legacy() votesig.Config { return votesig.Config{Scheme: votesig.SchemeLegacy, Network: 5} }

func TestABoundStoreTakesEveryConfigurationFromTheHistory(t *testing.T) {
	s := threeEpochStore(t)
	require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy(), 2: cfg2()}))

	c, err := s.SigningConfig(1)
	require.NoError(t, err)
	require.Equal(t, legacy(), c)
	c, err = s.SigningConfig(2)
	require.NoError(t, err)
	require.Equal(t, cfg2(), c)

	// epoch 3 has a trust base in the store but is unknown to the history: unknown is not scheme 1
	_, err = s.SigningConfig(3)
	require.ErrorIs(t, err, ErrSigningHistory)
	require.ErrorIs(t, err, errNotHeld)
	// and an epoch with no trust base is an error whatever the history says
	_, err = s.SigningConfig(4)
	require.ErrorIs(t, err, ErrSigningHistory)
}

func TestABoundStoreRefusesTheInMemoryActivationSeam(t *testing.T) {
	s := threeEpochStore(t)
	require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy(), 2: legacy(), 3: legacy()}))
	err := s.ActivateSigning(2, cfg2())
	require.ErrorIs(t, err, ErrSigningHistory)
	c, err := s.SigningConfig(2)
	require.NoError(t, err)
	require.Equal(t, legacy(), c, "the refused activation changed nothing")
}

func TestBindingRefusals(t *testing.T) {
	require.ErrorIs(t, threeEpochStore(t).BindSigningAuthority(nil), ErrSigningHistory)

	s := threeEpochStore(t)
	require.NoError(t, s.ActivateSigning(2, cfg2()))
	require.ErrorIs(t, s.BindSigningAuthority(historyOf{}), ErrSigningHistory, "two sources of configuration would disagree")

	s = threeEpochStore(t)
	h := &pointerHistory{}
	require.NoError(t, s.BindSigningAuthority(h))
	require.NoError(t, s.BindSigningAuthority(h), "binding the same authority again is a no-op")
	require.ErrorIs(t, s.BindSigningAuthority(&pointerHistory{}), ErrSigningHistory, "another authority")
	require.ErrorIs(t, s.BindSigningAuthority(historyOf{1: legacy()}), ErrSigningHistory, "another type")

	s = threeEpochStore(t)
	require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy()}))
	require.ErrorIs(t, s.BindSigningAuthority(historyOf{1: legacy()}), ErrSigningHistory, "an uncomparable authority is never the same one, and is refused without a panic")
}

func TestABoundStoreRefusesAConfigurationOfAnotherNetwork(t *testing.T) {
	s := threeEpochStore(t)
	other := legacy()
	other.Network = 6
	require.NoError(t, s.BindSigningAuthority(historyOf{1: other}))
	_, err := s.SigningConfig(1)
	require.ErrorIs(t, err, ErrSigningHistory)
}

func TestInstallVerifiedNeedsTheHistoryAndItsExactConfiguration(t *testing.T) {
	build := func(t *testing.T) (*TrustBaseStore, *types.RootTrustBaseV1) {
		s := threeEpochStore(t)
		// epoch 4 is the successor of the installed epoch 3
		old, err := s.GetByEpoch(3)
		require.NoError(t, err)
		next := successorOf(t, old, 4)
		return s, next
	}
	t.Run("an unbound store", func(t *testing.T) {
		s, next := build(t)
		_, err := s.InstallVerified(next, cfg2())
		require.ErrorIs(t, err, ErrSigningHistory)
		_, err = s.GetByEpoch(4)
		require.ErrorIs(t, err, ErrNotFound, "nothing was installed")
	})
	t.Run("a configuration the history does not hold", func(t *testing.T) {
		s, next := build(t)
		require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy()}))
		_, err := s.InstallVerified(next, cfg2())
		require.ErrorIs(t, err, ErrSigningHistory)
		_, err = s.GetByEpoch(4)
		require.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("another configuration than the history's", func(t *testing.T) {
		s, next := build(t)
		require.NoError(t, s.BindSigningAuthority(historyOf{4: cfg2()}))
		changed := cfg2()
		changed.Genesis = sha256.Sum256([]byte("another genesis"))
		_, err := s.InstallVerified(next, changed)
		require.ErrorIs(t, err, ErrSigningHistory, "the projection cannot pick its own genesis identity")
		_, err = s.InstallVerified(next, legacy())
		require.ErrorIs(t, err, ErrSigningHistory, "nor its own scheme")
		_, err = s.GetByEpoch(4)
		require.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("a configuration of another network than the projection's", func(t *testing.T) {
		s, next := build(t)
		other := cfg2()
		other.Network = 6
		require.NoError(t, s.BindSigningAuthority(historyOf{4: other}))
		_, err := s.InstallVerified(next, other)
		require.ErrorIs(t, err, ErrSigningHistory)
	})
	t.Run("nil", func(t *testing.T) {
		s, _ := build(t)
		require.NoError(t, s.BindSigningAuthority(historyOf{4: cfg2()}))
		_, err := s.InstallVerified(nil, cfg2())
		require.ErrorIs(t, err, ErrNoProjection)
	})
	t.Run("acceptance control, and idempotence", func(t *testing.T) {
		s, next := build(t)
		require.NoError(t, s.BindSigningAuthority(historyOf{1: legacy(), 2: legacy(), 3: legacy(), 4: cfg2()}))
		installed, err := s.InstallVerified(next, cfg2())
		require.NoError(t, err)
		require.EqualValues(t, 4, installed.Epoch)
		again, err := s.InstallVerified(next, cfg2())
		require.NoError(t, err)
		require.EqualValues(t, 4, again.Epoch)
		c, err := s.SigningConfig(4)
		require.NoError(t, err)
		require.Equal(t, cfg2(), c)
		c, err = s.SigningConfig(3)
		require.NoError(t, err)
		require.Equal(t, legacy(), c, "the boundary is the epoch")
	})
}

func successorOf(t *testing.T, old *types.RootTrustBaseV1, epoch uint64) *types.RootTrustBaseV1 {
	t.Helper()
	h, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	tb, err := types.NewTrustBase(old.NetworkID, old.RootNodes, types.WithEpoch(epoch), types.WithEpochStart(epoch*10), types.WithPreviousTrustBaseHash(h))
	require.NoError(t, err)
	return tb
}

// activateSigningCalls are the positions of the calls of a method named ActivateSigning in f.
func activateSigningCalls(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ActivateSigning" {
				out = append(out, fset.Position(call.Pos()).String())
			}
		}
		return true
	})
	return out
}

// No production code calls ActivateSigning: the switch is the verified history's committed record, not a call. The method is the
// seam the tests of the signing rules use.
func TestNoProductionCallerOfActivateSigning(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	var callers []string
	fset := token.NewFileSet()
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		callers = append(callers, activateSigningCalls(fset, f)...)
		return nil
	}))
	require.Empty(t, callers, "ActivateSigning has a production caller")
}

func TestTheCallerScanSeesACall(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", "package p\nfunc f(s interface{ ActivateSigning() }) { s.ActivateSigning() }\n", 0)
	require.NoError(t, err)
	require.Len(t, activateSigningCalls(fset, f), 1)
	f, err = parser.ParseFile(fset, "q.go", "package p\nfunc f(s interface{ Other() }) { s.Other() }\n", 0)
	require.NoError(t, err)
	require.Empty(t, activateSigningCalls(fset, f))
}
