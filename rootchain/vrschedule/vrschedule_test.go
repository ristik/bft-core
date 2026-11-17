package vrschedule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type fakeReader struct {
	at    map[[32]byte]*vrhandoff.Output
	calls int
	err   error
}

func (f *fakeReader) OpenOutput(_ context.Context, _, root [32]byte) (*vrhandoff.Output, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.at[root], nil
}

func published(r vrschema.Word) *vrhandoff.Output {
	return &vrhandoff.Output{State: vradmit.OutputState{ResultID: r, OpenOutput: r, Output: vrschema.OutputRecord{State: vrschema.OutPublished, OutputCommit: vrschema.Word{0xc0}}}}
}

func cert(round uint64, block, root byte) CertifiedEVM {
	return CertifiedEVM{RootRound: round, RootUCTime: 1000 + round, BlockHash: [32]byte{block}, StateRoot: [32]byte{root}, BlockNumber: uint64(block)}
}

// Stage 0: the first certified block at which R is the open Published output, recorded only after the block before it was observed
// without R; first observation wins, repeated blocks are skipped, and a restarted observer that starts while R is published guesses
// nothing (it keeps the persisted source).
func TestTheObserverRecordsTheFirstPublishedBlock(t *testing.T) {
	r := vrschema.Word{0x52}
	path := filepath.Join(t.TempDir(), "sources.json")
	sources, err := NewSources(path)
	require.NoError(t, err)
	reader := &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r), {3}: published(r)}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	ctx := context.Background()
	require.NoError(t, o.Observe(ctx, cert(10, 1, 1)))
	_, ok := sources.Get(r)
	require.False(t, ok)
	require.NoError(t, o.Observe(ctx, cert(11, 1, 1)))
	require.Equal(t, 1, reader.calls, "a block already observed is skipped")
	require.NoError(t, o.Observe(ctx, cert(12, 2, 2)))
	require.NoError(t, o.Observe(ctx, cert(14, 3, 3)))
	s, ok := sources.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 12, s.CertRootRound, "the first certified block at which R is published")
	require.EqualValues(t, 1012, s.CertUCTime)
	require.Equal(t, []byte{2}, s.EVMBlockHash[:1])
	got, ok := o.Outputs.At([32]byte{3})
	require.True(t, ok)
	require.Equal(t, r, got.State.ResultID)

	// a restarted root reads the persisted source; a fresh one that starts while R is published records nothing
	again, err := NewSources(path)
	require.NoError(t, err)
	s2, ok := again.Get(r)
	require.True(t, ok)
	require.Equal(t, s, s2)
	fresh, err := NewSources("")
	require.NoError(t, err)
	late := &Observer{Reader: reader, Sources: fresh, Outputs: NewOutputs()}
	require.NoError(t, late.Observe(ctx, cert(14, 3, 3)))
	require.NoError(t, late.Observe(ctx, cert(15, 4, 3)))
	_, ok = fresh.Get(r)
	require.False(t, ok, "never a guessed source")

	reader.err = errors.New("unreachable")
	require.Error(t, (&Observer{Reader: reader, Sources: fresh, Outputs: NewOutputs()}).Observe(ctx, cert(16, 5, 5)))
}

// The served preimages are read through VR's view ABI at the block's hash: the output's members with their binding preimages (by the
// binding reference keccak256(abi.encode(words, payee))) and the bound changes' payloads.
func TestServedPreimagesThroughTheViewABI(t *testing.T) {
	res := vrschema.Word{0x52}
	blockHash := [32]byte{0xbb}
	rootKey, evmKey := bytes.Repeat([]byte{2}, 33), bytes.Repeat([]byte{3}, 33)
	payee := common.Address{0x9a, 19: 7}
	m := abiMember{Id: 7, Generation: 2, Weight: 1, RawWeight: 1, RootNodeWord: ethcrypto.Keccak256Hash([]byte("root-7")), RootKeyHash: ethcrypto.Keccak256Hash(rootKey),
		EvmNodeWord: ethcrypto.Keccak256Hash([]byte("evm-7")), EvmKeyHash: ethcrypto.Keccak256Hash(evmKey), Payee: payee, ExposureDigest: [32]byte{0xe0}}
	ref := ethcrypto.Keccak256Hash(m.RootNodeWord[:], m.RootKeyHash[:], m.EvmNodeWord[:], m.EvmKeyHash[:], common.LeftPadBytes(payee[:], 32))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var call struct {
			ID     json.RawMessage   `json:"id"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.Unmarshal(body, &call))
		var tx struct {
			To   common.Address `json:"to"`
			Data hexutil.Bytes  `json:"data"`
		}
		require.NoError(t, json.Unmarshal(call.Params[0], &tx))
		var at map[string]string
		require.NoError(t, json.Unmarshal(call.Params[1], &at))
		require.Equal(t, hexutil.Encode(blockHash[:]), at["blockHash"])
		require.Equal(t, common.Address(vrschema.ValidatorRegistry), tx.To)
		method, err := parsedABI.MethodById(tx.Data[:4])
		require.NoError(t, err)
		args, err := method.Inputs.Unpack(tx.Data[4:])
		require.NoError(t, err)
		var out []byte
		switch method.Name {
		case "output":
			require.Equal(t, [32]byte(res), args[0])
			out, err = method.Outputs.Pack(abiOutput{State: vrschema.OutPublished, Members: []abiMember{m}, Changes: []uint64{4}})
		case "binding":
			require.Equal(t, [32]byte(ref), args[0])
			out, err = method.Outputs.Pack(abiBinding{RootNodeWord: m.RootNodeWord, RootKeyHash: m.RootKeyHash, EvmNodeWord: m.EvmNodeWord, EvmKeyHash: m.EvmKeyHash,
				Payee: payee, RootNodeID: "root-7", RootKey: rootKey, EvmNodeID: "evm-7", EvmKey: evmKey})
		case "change":
			require.Equal(t, uint64(4), args[0])
			out, err = method.Outputs.Pack(abiChange{Kind: vrschema.KindCommitteeLimits, Payload: []byte("payload")})
		}
		require.NoError(t, err)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": hexutil.Bytes(out)})
	}))
	defer srv.Close()
	client, err := rpc.Dial(srv.URL)
	require.NoError(t, err)
	r := RPC{Client: client, Pins: vrstate.Pins{Registry: vrschema.ValidatorRegistry}}
	members, changes, err := r.Served(context.Background(), blockHash, res)
	require.NoError(t, err)
	require.Len(t, members, 1)
	got := members[0]
	require.Equal(t, vrschema.U64(7), vrschema.Word(got.StakingID))
	require.EqualValues(t, 2, got.Generation)
	require.Equal(t, "root-7", got.RootNodeID)
	require.Equal(t, rootKey, got.RootKey)
	require.Equal(t, "evm-7", got.EVMNodeID)
	require.Equal(t, evmKey, got.EVMKey)
	require.Equal(t, payee[:], got.OperatorPayee)
	require.Equal(t, []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: []byte("payload")}}, changes)
	mw, err := vradmit.MemberOf(got)
	require.NoError(t, err)
	require.Equal(t, vrschema.Word(m.RootNodeWord), mw.RootNodeWord, "the words recompute from the served preimages")
}
