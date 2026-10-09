package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
)

// txRPC is an execution client that mines everything it is sent: it records the decoded transactions.
func txRPC(t *testing.T, revert bool) (*httptest.Server, *[]*types.Transaction) {
	sent := &[]*types.Transaction{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		var res any
		switch req.Method {
		case "eth_getTransactionCount":
			res = "0x7"
		case "eth_getBlockByNumber":
			res = map[string]any{"baseFeePerGas": "0x3b9aca00"}
		case "eth_estimateGas":
			res = "0x30d40"
		case "eth_sendRawTransaction":
			var raw hexutil.Bytes
			require.NoError(t, json.Unmarshal(req.Params[0], &raw))
			tx := new(types.Transaction)
			require.NoError(t, tx.UnmarshalBinary(raw))
			*sent = append(*sent, tx)
			res = tx.Hash().Hex()
		case "eth_getTransactionReceipt":
			if revert {
				res = map[string]any{"status": "0x0"}
			} else {
				res = map[string]any{"status": "0x1"}
			}
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": res})
	}))
	t.Cleanup(srv.Close)
	return srv, sent
}

func TestPosRelayerTxSendsTheRecordedCalldata(t *testing.T) {
	var fx struct {
		ResultId      string
		RelayerWrites struct{ SubmitPops, Finalize string }
	}
	raw, err := os.ReadFile(publicationFixture)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &fx))
	p := loadFixturePoPs(t)
	dir := t.TempDir()
	deployment := writeJSON(t, dir, "pos-deployment.json", map[string]string{
		"networkWord": "0x" + hex32(p.networkWord), "chainId": "31337",
		"custody": hexutil.Encode(p.custody[:]), "custodyCodeHash": "0x" + "aa" + string(bytes.Repeat([]byte("00"), 31)),
		"registry": "0xff00000000000000000000000000000000000002", "registryCodeHash": "0x" + "bb" + string(bytes.Repeat([]byte("00"), 31)),
		"election": hexutil.Encode(p.election[:]), "electionCodeHash": "0x" + "cc" + string(bytes.Repeat([]byte("00"), 31))})
	senderKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "sender.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(hexutil.Encode(ethcrypto.FromECDSA(senderKey))), 0o600))
	popsFile := writeJSON(t, dir, "evm-pops.json", map[string]any{"evmPops": p.pops})

	run := func(args ...string) error {
		var buf bytes.Buffer
		var cmd *cobra.Command = newPosRelayerCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		return cmd.Execute()
	}

	t.Run("submit-pops and finalize send exactly the contracts' calldata, signed by the sender, to the election", func(t *testing.T) {
		srv, sent := txRPC(t, false)
		require.NoError(t, run("tx", "submit-pops", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--sender-key", keyFile,
			"--result-id", fx.ResultId, "--evm-pops", popsFile))
		require.NoError(t, run("tx", "finalize", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--sender-key", keyFile, "--result-id", fx.ResultId))
		require.Len(t, *sent, 2)
		for i, want := range []string{fx.RelayerWrites.SubmitPops, fx.RelayerWrites.Finalize} {
			tx := (*sent)[i]
			require.Equal(t, want, hexutil.Encode(tx.Data()))
			require.Equal(t, p.election, [20]byte(*tx.To()))
			require.EqualValues(t, 7, tx.Nonce())
			from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
			require.NoError(t, err)
			require.Equal(t, ethcrypto.PubkeyToAddress(senderKey.PublicKey), from)
			require.EqualValues(t, 31337, tx.ChainId().Int64())
		}
	})
	t.Run("a transaction that reverts on chain is an error, not a success", func(t *testing.T) {
		srv, _ := txRPC(t, true)
		err := run("tx", "finalize", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--sender-key", keyFile, "--result-id", fx.ResultId)
		require.ErrorIs(t, err, ErrPosRelayer)
		require.Contains(t, err.Error(), "reverted")
	})
	t.Run("a result id that is not 32 bytes is refused before anything is sent", func(t *testing.T) {
		srv, sent := txRPC(t, false)
		require.ErrorIs(t, run("tx", "finalize", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--sender-key", keyFile, "--result-id", "0x1234"), ErrPosRelayer)
		require.Empty(t, *sent)
	})
}

type fixturePoPs struct {
	networkWord [32]byte
	custody     [20]byte
	election    [20]byte
	pops        []popJSON
}

func hex32(b [32]byte) string { return hexutil.Encode(b[:])[2:] }

func loadFixturePoPs(t *testing.T) fixturePoPs {
	p := evmstatetestLoad(t)
	var out fixturePoPs
	out.networkWord, out.custody, out.election = p.Pins.NetworkWord, p.Pins.Custody, p.Pins.Election
	for _, x := range p.PoPs {
		out.pops = append(out.pops, toPoPJSON(x))
	}
	return out
}

func evmstatetestLoad(t *testing.T) *evmstatetest.Published {
	return evmstatetest.Load(t, publicationFixture)
}
