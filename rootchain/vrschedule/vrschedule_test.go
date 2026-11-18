package vrschedule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	return CertifiedEVM{RootRound: round, ParentRound: round - 1, RootUCTime: 1000 + round, BlockHash: [32]byte{block}, StateRoot: [32]byte{root}, BlockNumber: uint64(block)}
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
	require.NoError(t, o.Observe(ctx, cert(13, 3, 3)))
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
	require.NoError(t, late.Observe(ctx, cert(13, 3, 3)))
	require.NoError(t, late.Observe(ctx, cert(14, 4, 3)))
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

type flakyReader struct {
	at   map[[32]byte]*vrhandoff.Output
	fail map[[32]byte]bool
}

func (f *flakyReader) OpenOutput(_ context.Context, _, root [32]byte) (*vrhandoff.Output, error) {
	if f.fail[root] {
		return nil, errors.New("rpc down")
	}
	return f.at[root], nil
}

// A gap never yields a wrong source (#1185 review F1, the reviewer's probe): a failed read of the first published block, a skipped
// committed block (a dropped batch, a recovery jump) or an observation after a reset leaves R without a source, so the intent is
// unavailable here rather than derived over a later block.
func TestAGapNeverRecordsALaterSource(t *testing.T) {
	r := vrschema.Word{0x52}
	ctx := context.Background()
	sources, err := NewSources("")
	require.NoError(t, err)
	reader := &flakyReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r), {3}: published(r)}, fail: map[[32]byte]bool{{2}: true}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(ctx, cert(10, 1, 1))) // R not published
	require.Error(t, o.Observe(ctx, cert(11, 2, 2)))   // the first published block: the read fails (the worker gives up)
	require.NoError(t, o.Observe(ctx, cert(12, 3, 3))) // a later block
	_, ok := sources.Get(r)
	require.False(t, ok, "the failed read broke the run")

	skip, err := NewSources("")
	require.NoError(t, err)
	o = &Observer{Reader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{{3}: published(r)}}, Sources: skip, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(ctx, cert(10, 1, 1)))
	require.NoError(t, o.Observe(ctx, cert(12, 3, 3)), "round 11 was never observed (a dropped batch, a recovery jump)")
	_, ok = skip.Get(r)
	require.False(t, ok)

	// a failed read retried for the same block is no gap: the run continues and the first published block is recorded
	retry, err := NewSources("")
	require.NoError(t, err)
	flaky := &flakyReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}, fail: map[[32]byte]bool{{2}: true}}
	o = &Observer{Reader: flaky, Sources: retry, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(ctx, cert(10, 1, 1)))
	require.Error(t, o.Observe(ctx, cert(11, 2, 2)), "the execution client does not hold the block yet")
	flaky.fail = nil
	require.NoError(t, o.Observe(ctx, cert(11, 2, 2)), "the worker's retry")
	s0, ok := retry.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 11, s0.CertRootRound)

	// the same sequence without a gap records the first published block
	ok2, err := NewSources("")
	require.NoError(t, err)
	o = &Observer{Reader: &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r), {3}: published(r)}}, Sources: ok2, Outputs: NewOutputs()}
	for i, c := range []CertifiedEVM{cert(10, 1, 1), cert(11, 2, 2), cert(12, 3, 3)} {
		require.NoError(t, o.Observe(ctx, c), i)
	}
	s, ok := ok2.Get(r)
	require.True(t, ok)
	require.EqualValues(t, 11, s.CertRootRound)
}

// A source of root round 0 is refused (the anchor is never a default zero), on record and on load.
func TestSourcesRefuseRoundZero(t *testing.T) {
	s, err := NewSources(filepath.Join(t.TempDir(), "s.json"))
	require.NoError(t, err)
	_, err = s.Record(SourceEntry{Source: vrhandoff.Source{ResultID: make([]byte, 32), EVMBlockHash: make([]byte, 32), OutputCommit: make([]byte, 32)}})
	require.Error(t, err)
	path := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`[{"resultId":"0x`+strings.Repeat("11", 32)+`","evmBlockHash":"0x`+strings.Repeat("22", 32)+
		`","evmBlockNumber":1,"certRootRound":0,"outputCommit":"0x`+strings.Repeat("33", 32)+`","certUcTime":5}]`), 0o600))
	_, err = NewSources(path)
	require.Error(t, err)
}

// sol's review of #1185: a source is kept only once it is durable. A write that fails (here the rename, with a directory in the file's
// place) leaves neither the store nor the observer advanced, so the worker's retry of the same block records the same first source, and
// it survives a reopen. The same holds when the record evicts the oldest source: a failed write evicts nothing.
func TestAFailedSourceWriteIsRetriedAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	sources, err := NewSources(path)
	require.NoError(t, err)
	r := vrschema.Word{0x52}
	reader := &fakeReader{at: map[[32]byte]*vrhandoff.Output{{2}: published(r)}}
	o := &Observer{Reader: reader, Sources: sources, Outputs: NewOutputs()}
	require.NoError(t, o.Observe(context.Background(), cert(10, 1, 1)))
	require.NoError(t, os.Mkdir(path, 0o700))
	require.Error(t, o.Observe(context.Background(), cert(11, 2, 2)), "the write fails")
	_, kept := sources.Get(r)
	require.False(t, kept, "nothing that is not durable is kept")
	require.NoError(t, os.Remove(path))
	require.NoError(t, o.Observe(context.Background(), cert(11, 2, 2)), "the worker retries the same block")
	reopened, err := NewSources(path)
	require.NoError(t, err)
	got, ok := reopened.Get(r)
	require.True(t, ok, "the retried source survives a restart")
	require.EqualValues(t, 11, got.CertRootRound, "the exact first source")
	require.Equal(t, []byte{2}, got.EVMBlockHash[:1])
	// a later block where R is still published records nothing new
	require.NoError(t, o.Observe(context.Background(), cert(12, 3, 2)))
	got, _ = reopened.Get(r)
	require.EqualValues(t, 11, got.CertRootRound)

	// a record that evicts the oldest source: a failed write evicts nothing, the retry evicts it durably
	full, err := NewSources(filepath.Join(t.TempDir(), "full.json"))
	require.NoError(t, err)
	for i := 0; i < maxSources; i++ {
		recorded, err := full.Record(SourceEntry{Source: vrhandoff.Source{ResultID: append([]byte{byte(i + 1)}, make([]byte, 31)...), EVMBlockHash: make([]byte, 32),
			CertRootRound: uint64(10 + i), OutputCommit: make([]byte, 32)}})
		require.NoError(t, err)
		require.True(t, recorded)
	}
	oldest := vrschema.Word{1}
	require.NoError(t, os.Remove(full.path))
	require.NoError(t, os.Mkdir(full.path, 0o700))
	next := SourceEntry{Source: vrhandoff.Source{ResultID: append([]byte{0xee}, make([]byte, 31)...), EVMBlockHash: make([]byte, 32), CertRootRound: 99,
		OutputCommit: make([]byte, 32)}}
	_, err = full.Record(next)
	require.Error(t, err)
	_, ok = full.Get(oldest)
	require.True(t, ok, "a failed write evicts nothing")
	_, ok = full.Get(vrschema.Word{0xee})
	require.False(t, ok)
	require.NoError(t, os.Remove(full.path))
	recorded, err := full.Record(next)
	require.NoError(t, err)
	require.True(t, recorded)
	again, err := NewSources(full.path)
	require.NoError(t, err)
	_, ok = again.Get(oldest)
	require.False(t, ok, "the retry evicted the oldest durably")
	_, ok = again.Get(vrschema.Word{0xee})
	require.True(t, ok)
}
