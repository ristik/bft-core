package nb2ref

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func flatCertifiedEvent(t *testing.T, w *World, v *FlatVerifier, e FlatEvent, opts ReceiptOpts) []byte {
	t.Helper()
	proof, err := w.ReceiptProof(e.Log(v.deployment.Recovery), opts)
	require.NoError(t, err)
	return proof.Bytes()
}

func flatGaps(t *testing.T, k uint64, eta [32]byte) ([32]byte, []byte, [][32]byte) {
	t.Helper()
	var ids [][32]byte
	for i := range k {
		id := HE([]byte("flat-gap/neighbor"), flatU64(i))
		require.NotEqual(t, eta, id)
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	tree, ok := BuildGapTree(ids)
	require.True(t, ok)
	proof, ok := tree.Prove(eta)
	require.True(t, ok)
	return tree.Root(), proof, ids
}

type flatCustodyFixture struct {
	Deposits, Segment, Population             uint64
	Liability, VaultBalance, RecipientBalance string
	Head, PreviousHead                        string
	Current, Previous                         []string
	Events                                    []Event
}

func flatCustodyState(v *FlatVault, recipient [20]byte) flatCustodyFixture {
	n, c, m, q, h, p := v.State()
	current, previous := v.LiveIDs()
	ids := func(src [][32]byte) []string {
		out := make([]string, 0, len(src))
		for _, id := range src {
			out = append(out, hex.EncodeToString(id[:]))
		}
		return out
	}
	return flatCustodyFixture{n, c, m, q.String(), v.Balance(v.model.Cfg.Vault).String(), v.Balance(recipient).String(),
		hex.EncodeToString(h[:]), hex.EncodeToString(p[:]), ids(current), ids(previous), v.Logs()}
}

func flatExportCold(t *testing.T, name string, wire []byte, meta any) {
	t.Helper()
	dir := os.Getenv("NB2_FLAT_VECTOR_OUT")
	if dir == "" {
		return
	}
	dir = filepath.Join(dir, "cold", name)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "calldata.bin"), wire, 0644))
	j, err := json.MarshalIndent(meta, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outcome.json"), append(j, '\n'), 0644))
}

func TestFlatGapAndSettlementMatrix(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	key := Key("flat-root")
	evidence, records := flatFixtureEncode(t, v, flatFixtureLineage(t, w, v, 0, 0, false))
	_, completion := flatFixtureRun(t, w, v, evidence, records, 2)
	header := mustFlatEvidence(t, evidence).Header()
	vd := completion.Verdict
	start := vd.MinSegment
	require.NotZero(t, start)
	root, proof, ids := flatGaps(t, v.cfg.K, vd.Eta)
	h0 := HE([]byte("certified model head before signed index"))
	h1 := NextHead(v.domain, start, h0, root)
	h2 := NextHead(v.domain, start+1, h1, root)
	heads := map[uint64][32]byte{start: h0, start + 1: h1, start + 2: h2}
	receipt := flatCertifiedEvent(t, w, v, completion, ReceiptOpts{Type: 2})
	prefix, err := (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt, StartHead: &h0, Proofs: [][]byte{proof}}).Calldata(FlatAdvanceGaps, v.cfg.K)
	require.NoError(t, err)
	gap, err := v.AdvanceFlatGaps(prefix)
	require.NoError(t, err)
	require.Equal(t, h1, gap.Head)
	require.Equal(t, start+1, gap.NextSegment)
	require.Equal(t, completion.Seq+1, gap.Seq)
	require.Equal(t, vd.ABI(), gap.Verdict.ABI())
	gapReceipt := flatCertifiedEvent(t, w, v, gap, ReceiptOpts{Type: 2, Rotated: true})

	for _, startGap := range []bool{false, true} {
		for _, suffix := range []bool{false, true} {
			for _, previous := range []bool{false, true} {
				t.Run(fmt.Sprintf("gap=%t/suffix=%t/previous=%t", startGap, suffix, previous), func(t *testing.T) {
					vault, err := NewFlatVault(v, w.Env())
					require.NoError(t, err)
					require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), HE([]byte("model rho"))))
					e := start
					packet := FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}
					if startGap {
						packet.Kind, packet.Receipt = FlatGapEvent, gapReceipt
						e++
					}
					if suffix {
						packet.Proofs = [][]byte{proof}
						if !startGap {
							packet.StartHead = &h0
						}
						e++
					}
					c := e
					if previous {
						c++
					}
					vault.model.SetState(1, c, 0, big.NewInt(100), heads[c], heads[c-1], nil, ids)
					data, err := packet.Calldata(FlatRedeemRecovered, v.cfg.K)
					require.NoError(t, err)
					before := vault.Logs()
					initial := flatCustodyState(vault, vd.Recipient)
					_, err = vault.RedeemRecovered(data, RecipientPropagatesReentry)
					require.ErrorIs(t, err, ErrPayoutFailed)
					require.Equal(t, before, vault.Logs())
					require.Equal(t, int64(100), vault.Balance(v.cfg.Vault).Int64())
					got, err := vault.RedeemRecovered(data, RecipientReentersRedeem)
					require.NoError(t, err)
					require.ErrorIs(t, got.Inner, ErrReentrancy)
					require.Equal(t, int64(100), vault.Balance(vd.Recipient).Int64())
					n, cOut, pop, q, head, prev := vault.State()
					require.Equal(t, uint64(1), n)
					require.Equal(t, c, cOut)
					require.Equal(t, uint64(1), pop)
					require.Zero(t, q.Sign())
					require.Equal(t, heads[c], head)
					require.Equal(t, heads[c-1], prev)
					_, err = vault.RedeemRecovered(data, RecipientAccepts)
					require.ErrorIs(t, err, ErrAlreadyPaid)
					require.Len(t, vault.Logs(), len(before)+1)
					flatExportCold(t, fmt.Sprintf("settle-kind%d-suffix%t-prev%t", packet.Kind, suffix, previous), data, struct {
						Before, After                         flatCustodyFixture
						FailedPayout, CaughtInnerCall, Replay string
					}{initial, flatCustodyState(vault, vd.Recipient), "PayoutFailed", "Reentrancy", "AlreadyPaid"})
				})
			}
		}
	}
	t.Run("advance-bounds", func(t *testing.T) {
		for _, event := range []FlatEvent{completion, gap} {
			for _, count := range []int{0, 1, 1024, 1025} {
				p := FlatGapPacket{Header: header, Kind: event.Kind, Receipt: flatCertifiedEvent(t, w, v, event, ReceiptOpts{})}
				if count > 0 && event.Kind == FlatCompleteEvent {
					p.StartHead = &h0
				}
				for range count {
					p.Proofs = append(p.Proofs, proof)
				}
				wire, err := p.Calldata(FlatAdvanceGaps, v.cfg.K)
				if count == 0 || count > 1024 {
					require.ErrorIs(t, err, ErrFlatPacket)
					continue
				}
				require.NoError(t, err)
				got, err := v.AdvanceFlatGaps(wire)
				require.NoError(t, err)
				index, head := start, h0
				if event.Kind == FlatGapEvent {
					index, head = start+1, h1
				}
				for i := range count {
					head = NextHead(v.domain, index+uint64(i), head, root)
				}
				require.Equal(t, index+uint64(count), got.NextSegment)
				require.Equal(t, head, got.Head)
				log := got.Log(v.deployment.Recovery)
				flatExportCold(t, fmt.Sprintf("advance-kind%d-count%d", event.Kind, count), wire, struct {
					Topics  []string
					Data    string
					Receipt string
				}{[]string{hex.EncodeToString(log.Topics[0][:]), hex.EncodeToString(log.Topics[1][:])},
					hex.EncodeToString(log.Data), hex.EncodeToString(flatCertifiedEvent(t, w, v, got, ReceiptOpts{}))})
			}
		}
	})
	t.Run("zero-gap-wrong-head-and-skipped-signed-start", func(t *testing.T) {
		vault, err := NewFlatVault(v, w.Env())
		require.NoError(t, err)
		require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), [32]byte{1}))
		vault.model.SetState(1, start+2, 0, big.NewInt(100), h2, h1, nil, ids)
		forged := gap
		forged.Head[0] ^= 1
		data, err := (FlatGapPacket{Header: header, Kind: FlatGapEvent, Receipt: flatCertifiedEvent(t, w, v, forged, ReceiptOpts{})}).Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		_, err = vault.RedeemRecovered(data, RecipientAccepts)
		require.ErrorIs(t, err, ErrChainMismatch)
		data, err = (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}).Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		_, err = vault.RedeemRecovered(data, RecipientAccepts)
		require.ErrorIs(t, err, ErrStaleEndpoint)
		require.Len(t, vault.Logs(), 1)
	})
	for _, ordinaryFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("race/ordinary-first=%t", ordinaryFirst), func(t *testing.T) {
			vault, err := NewFlatVault(v, w.Env())
			require.NoError(t, err)
			require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), [32]byte{1}))
			vault.model.SetState(1, start, 0, big.NewInt(100), h0, [32]byte{}, nil, ids)
			wire, err := (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}).Calldata(FlatRedeemRecovered, v.cfg.K)
			require.NoError(t, err)
			ordinary := func() error { _, e := vault.Redeem(evidence, vd.Eta, start, nil, RecipientAccepts); return e }
			recovered := func() error { _, e := vault.RedeemRecovered(wire, RecipientAccepts); return e }
			first, second := recovered, ordinary
			if ordinaryFirst {
				first, second = ordinary, recovered
			}
			require.NoError(t, first())
			require.ErrorIs(t, second(), ErrAlreadyPaid)
			require.Equal(t, int64(100), vault.Balance(vd.Recipient).Int64())
		})
	}
}
