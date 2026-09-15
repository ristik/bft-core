package registrywitness

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
)

// measurement is testdata/reth-proof-window.json, recorded by testdata/reth-proof-window.sh against the
// pinned reth in dev mode on the registrygenesis vector genesis.
type measurement struct {
	Generator        string      `json:"generator"`
	ClientVersion    string      `json:"clientVersion"`
	GenesisHash      common.Hash `json:"genesisHash"`
	ProofWindowError RPCError    `json:"proofWindowError"`
	Runs             []struct {
		Window   uint64      `json:"window"`
		Block1   common.Hash `json:"block1"`
		Observed []struct {
			Target   uint64 `json:"target"`
			Distance uint64 `json:"distance"`
			Outcome  string `json:"outcome"`
			Samples  int    `json:"samples"`
		} `json:"observed"`
	} `json:"runs"`
	UnknownBlock struct {
		Hash        common.Hash     `json:"hash"`
		RawHeader   json.RawMessage `json:"rawHeader"`
		Proof       json.RawMessage `json:"proof"`
		BlockByHash json.RawMessage `json:"blockByHash"`
	} `json:"unknownBlock"`
	Vectors map[string]struct {
		Hash   common.Hash     `json:"hash"`
		Header string          `json:"header"`
		Proof  json.RawMessage `json:"proof"`
	} `json:"vectors"`
}

func loadMeasurement(t *testing.T) measurement {
	raw, err := os.ReadFile("testdata/reth-proof-window.json")
	require.NoError(t, err)
	var m measurement
	require.NoError(t, json.Unmarshal(raw, &m))
	t.Logf("generator: %s", m.Generator)
	return m
}

// The recorded runs show the pinned reth's rule: a proof for a block by hash is served while
// head - block <= window and refused after, for windows 0 (the default) and 3.
func TestMeasuredProofWindow(t *testing.T) {
	m := loadMeasurement(t)
	require.Equal(t, genesisFor(t, registrygenesis.DefaultEVMParams).EVMGenesisHash(), m.GenesisHash)
	require.Contains(t, m.ClientVersion, "189c0df")

	windows := map[uint64]bool{}
	for _, run := range m.Runs {
		windows[run.Window] = true
		sawLastProof, sawFirstRefusal := false, false
		for _, o := range run.Observed {
			require.Positive(t, o.Samples)
			if o.Distance <= run.Window {
				require.Equal(t, "proof", o.Outcome, "window %d, block %d at distance %d", run.Window, o.Target, o.Distance)
			} else {
				require.Equal(t, "refused", o.Outcome, "window %d, block %d at distance %d", run.Window, o.Target, o.Distance)
			}
			if o.Target == 1 && o.Distance == run.Window {
				sawLastProof = true
			}
			if o.Target == 1 && o.Distance == run.Window+1 {
				sawFirstRefusal = true
			}
		}
		require.True(t, sawLastProof && sawFirstRefusal, "window %d: both boundary distances were observed", run.Window)
	}
	require.Equal(t, map[uint64]bool{0: true, 3: true}, windows)
}

// replay serves the recorded responses: a proof by hash for the in-window vectors, and the recorded
// errors for the refused and unknown cases.
func replay(t *testing.T, header, proof string) *server {
	return newServer(t, func(r request) string {
		if r.Method == "debug_getRawHeader" {
			return header
		}
		return proof
	})
}

func TestMeasuredRefusalsAreUnavailable(t *testing.T) {
	m := loadMeasurement(t)
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	require.Contains(t, m.ProofWindowError.Message, proofWindowMessage, "the classifier matches the message reth actually sends")
	windowErr, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "error": m.ProofWindowError})
	require.NoError(t, err)

	genesis := m.Vectors["genesis"]
	t.Run("genesis behind the proof window", func(t *testing.T) {
		s := replay(t, result(genesis.Header), string(windowErr))
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), genesis.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
		require.NotErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "behind the client's proof window")
	})
	t.Run("a block hash the client does not have", func(t *testing.T) {
		s := replay(t, string(m.UnknownBlock.RawHeader), string(m.UnknownBlock.Proof))
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), m.UnknownBlock.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
		require.NotErrorIs(t, err, ErrInvalid)
	})
	t.Run("unknown block: proof error after a header", func(t *testing.T) {
		s := replay(t, result(genesis.Header), string(m.UnknownBlock.Proof))
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), genesis.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func TestMeasuredInWindowVectors(t *testing.T) {
	m := loadMeasurement(t)
	g := genesisFor(t, registrygenesis.DefaultEVMParams)

	t.Run("genesis taken inside the window verifies", func(t *testing.T) {
		v := m.Vectors["genesis"]
		require.Equal(t, g.EVMGenesisHash(), v.Hash)
		s := replay(t, result(v.Header), rawResult(v.Proof))
		w, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
		require.NoError(t, err)
		require.True(t, w.Snapshot().Genesis())
	})

	// Block 1 was mined by reth's dev miner, which runs no registry transitions. Its proof is genuine and its
	// header hashes to the block, but the registry there is still at genesis values under a non-genesis
	// hash, so §7.3 step 6 refuses it. That is invalid evidence for a parent, not unavailable evidence.
	t.Run("dev-mined block 1 is authentic but not a finalized parent", func(t *testing.T) {
		v := m.Vectors["block1"]
		header, err := hexutil.Decode(v.Header)
		require.NoError(t, err)
		require.Equal(t, v.Hash, crypto.Keccak256Hash(header), "premise: the recorded header is block 1's")
		s := replay(t, result(v.Header), rawResult(v.Proof))
		_, err = Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorIs(t, err, registryproof.ErrNotFinalized)
		require.NotErrorIs(t, err, ErrUnavailable)
	})

	t.Run("block 1's evidence does not stand in for genesis", func(t *testing.T) {
		v := m.Vectors["block1"]
		s := replay(t, result(v.Header), rawResult(v.Proof))
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), m.GenesisHash)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorIs(t, err, registryproof.ErrHeaderHash)
	})
}
