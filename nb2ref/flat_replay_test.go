package nb2ref

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
)

// Replay reads the checked-in corpus, not generator objects. This also
// verifies every receipt and predecessor link in the published traces.
func TestFlatPublishedReplay(t *testing.T) {
	for _, dir := range []string{flatVectorDir, filepath.Join(flatVectorDir, "transcripts")} {
		manifest := mustFlatFile(t, dir, "MANIFEST")
		for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
			parts := strings.SplitN(line, "  ", 2)
			require.Len(t, parts, 2)
			h := HU(mustFlatFile(t, dir, parts[1]))
			require.Equal(t, parts[0], hex.EncodeToString(h[:]), parts[1])
		}
	}
	dir := filepath.Join(flatVectorDir, "transcripts")
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range files {
		if !entry.IsDir() || entry.Name() == "cold" || entry.Name() == "refusals" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(dir, entry.Name())
			var ctx struct {
				GenesisCommitment, RegistryProfile, RecoveryAddress, RecoveryRuntimeHash, Session, PageRoot string
				EvidenceLength                                                                              uint64
				Registry                                                                                    map[string]string
			}
			require.NoError(t, json.Unmarshal(mustFlatFile(t, dir, "context.json"), &ctx))
			registry := make(b1ref.Words, len(ctx.Registry))
			for k, val := range ctx.Registry {
				registry[[32]byte(mustHex(k))] = [32]byte(mustHex(val))
			}
			config, err := DecodeFlatConfig(flatGolden(t, "gamma"))
			require.NoError(t, err)
			_, err = LoadTrustInput(mustFlatFile(t, dir, "utb.cbor"), config.RootGenesis)
			require.NoError(t, err)
			deploy := FlatDeployment{Salt: [32]byte(flatGolden(t, "generation-salt")), Pins: [32]byte(flatGolden(t, "pins")),
				Runtime: [32]byte(mustHex(ctx.RecoveryRuntimeHash)), Recovery: [20]byte(mustHex(ctx.RecoveryAddress))}
			oracle, err := NewFlatVerifier(flatGolden(t, "gamma"), deploy, FlatAuthority{Registry: registry,
				Pins: b1ref.Pins{GenesisCommitment: [32]byte(mustHex(ctx.GenesisCommitment)), ProfileHash: [32]byte(mustHex(ctx.RegistryProfile))}})
			require.NoError(t, err)
			raw := mustFlatFile(t, dir, "evidence.bin")
			header := mustFlatEvidence(t, raw).Header()
			require.Equal(t, ctx.EvidenceLength, header.Length)
			require.Equal(t, [32]byte(mustHex(ctx.PageRoot)), header.Root)
			require.Equal(t, [32]byte(mustHex(ctx.Session)), oracle.Session(header))
			expected := mustFlatFile(t, dir, "verdict.bin")
			gz, err := gzip.NewReader(bytes.NewReader(mustFlatFile(t, dir, "trace.bin.gz")))
			require.NoError(t, err)
			trace, err := io.ReadAll(gz)
			require.NoError(t, err)
			require.NoError(t, gz.Close())
			if len(expected) == 0 {
				holding, err := oracle.VerifyFlatHeld(raw)
				require.NoError(t, err)
				want := mustFlatFile(t, dir, "holding.bin")
				require.Len(t, want, 129)
				require.Equal(t, want, bytes.Join([][]byte{holding.Owner[:], holding.State[:], holding.TokenID[:], holding.Amount[:]}, nil))
				require.Empty(t, trace)
				return
			}
			want, err := oracle.VerifyFlatReturn(raw)
			require.NoError(t, err)
			require.Equal(t, expected, want.ABI())
			r := flatReader{raw: trace}
			var state, prior []byte
			var completed bool
			for len(r.raw) > 0 {
				calldata, old, next := r.blob(FlatMaxCalldata), r.blob(FlatStateBytes), r.blob(FlatStateBytes)
				topics, data, receipt := r.blob(64), r.blob(288), r.blob(FlatMaxReceipt)
				require.NoError(t, r.err)
				require.False(t, completed)
				require.True(t, bytes.Equal(old, state))
				packet, err := DecodeFlatRun(calldata)
				require.NoError(t, err)
				require.True(t, bytes.Equal(prior, packet.Receipt))
				result, err := oracle.RunFlat(calldata)
				require.NoError(t, err)
				log := result.Event.Log(deploy.Recovery)
				require.Equal(t, topics, cat(log.Topics[0][:], log.Topics[1][:]))
				require.Equal(t, data, log.Data)
				got, err := oracle.event(header, result.Event.Kind, receipt)
				require.NoError(t, err)
				require.Equal(t, result.Event, got)
				if result.Event.Kind == FlatCompleteEvent {
					require.Nil(t, result.State)
					require.Empty(t, next)
					require.Equal(t, expected, result.Event.Verdict.ABI())
					completed = true
				} else {
					require.Equal(t, next, result.State.Bytes())
				}
				state, prior = next, receipt
			}
			require.True(t, completed)
		})
	}
}

func mustFlatFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return b
}

func TestFlatPublishedColdAndRefusalReplay(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	root := filepath.Join(flatVectorDir, "transcripts")
	entries, err := os.ReadDir(filepath.Join(root, "cold"))
	require.NoError(t, err)
	for _, entry := range entries {
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(root, "cold", entry.Name())
			wire, meta := mustFlatFile(t, dir, "calldata.bin"), mustFlatFile(t, dir, "outcome.json")
			if strings.HasPrefix(entry.Name(), "advance-") {
				var want struct {
					Topics        []string
					Data, Receipt string
				}
				require.NoError(t, json.Unmarshal(meta, &want))
				got, err := v.AdvanceFlatGaps(wire)
				require.NoError(t, err)
				log := got.Log(v.deployment.Recovery)
				require.Len(t, want.Topics, 2)
				for i, topic := range log.Topics {
					require.Equal(t, topic, [32]byte(mustHex(want.Topics[i])))
				}
				require.Equal(t, mustHex(want.Data), log.Data)
				p, err := DecodeFlatGap(wire, FlatAdvanceGaps, v.cfg.K)
				require.NoError(t, err)
				verified, err := v.event(p.Header, FlatGapEvent, mustHex(want.Receipt))
				require.NoError(t, err)
				require.Equal(t, got, verified)
				return
			}
			var want struct {
				Before, After                                       flatCustodyFixture
				FailedPayout, FirstFailure, CaughtInnerCall, Replay string
			}
			require.NoError(t, json.Unmarshal(meta, &want))
			packet, err := DecodeFlatGap(wire, FlatRedeemRecovered, v.cfg.K)
			require.NoError(t, err)
			event, err := v.event(packet.Header, packet.Kind, packet.Receipt)
			require.NoError(t, err)
			recipient := event.Verdict.Recipient
			before := want.Before
			vault := restoreFlatCustody(t, v, w.Env(), recipient, before)
			if want.FailedPayout != "" || want.FirstFailure != "" {
				_, err := vault.RedeemRecovered(wire, RecipientReverts)
				require.ErrorIs(t, err, ErrPayoutFailed)
				require.Equal(t, before, flatCustodyState(vault, recipient))
			}
			rcp := RecipientAccepts
			if want.CaughtInnerCall != "" {
				rcp = RecipientReentersRedeem
			}
			r, err := vault.RedeemRecovered(wire, rcp)
			require.NoError(t, err)
			if rcp == RecipientReentersRedeem {
				require.ErrorIs(t, r.Inner, ErrReentrancy)
			}
			require.Equal(t, want.After, flatCustodyState(vault, recipient))
			if want.Replay != "" {
				_, err := vault.RedeemRecovered(wire, RecipientAccepts)
				require.ErrorIs(t, err, ErrAlreadyPaid)
			}
		})
	}
	files, err := os.ReadDir(filepath.Join(root, "refusals"))
	require.NoError(t, err)
	stages := map[string]error{"BadPacket": ErrFlatPacket, "BadPredecessor": ErrFlatPredecessor,
		"BadPage": ErrFlatPage, "BadStep": ErrFlatStep, "ChainMismatch": ErrChainMismatch}
	for _, entry := range files {
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(root, "refusals", entry.Name())
			wire := mustFlatFile(t, dir, "calldata.bin")
			stage := strings.TrimSpace(string(mustFlatFile(t, dir, "stage.txt")))
			require.Contains(t, stages, stage)
			prior := mustFlatFile(t, dir, "last-usable-predecessor.cbor")
			var retry []byte
			if len(prior) != 0 {
				retry = mustFlatFile(t, dir, "retry-calldata.bin")
				require.Equal(t, wire[:4], retry[:4])
				entry := FlatRun
				switch [4]byte(wire[:4]) {
				case FlatAdvanceGaps.Selector():
					entry = FlatAdvanceGaps
				case FlatRedeemRecovered.Selector():
					entry = FlatRedeemRecovered
				}
				originalPacked, err := entry.DecodeCalldata(wire)
				require.NoError(t, err)
				retryPacked, err := entry.DecodeCalldata(retry)
				require.NoError(t, err)
				require.Equal(t, originalPacked[:42], retryPacked[:42], "retry binds the same evidence")
			} else {
				_, err := os.Stat(filepath.Join(dir, "retry-calldata.bin"))
				require.ErrorIs(t, err, os.ErrNotExist)
			}
			switch [4]byte(wire[:4]) {
			case FlatRun.Selector():
				out, err := v.RunFlat(wire)
				require.Nil(t, out)
				require.ErrorIs(t, err, stages[stage])
				if len(prior) != 0 {
					packet, err := DecodeFlatRun(retry)
					require.NoError(t, err)
					require.NotNil(t, packet.Prior)
					require.Equal(t, prior, packet.Receipt)
					refused, err := DecodeFlatRun(wire)
					if err == nil {
						require.Equal(t, packet.Header, refused.Header)
						require.Equal(t, packet.Prior, refused.Prior)
					}
					_, err = v.RunFlat(retry)
					require.NoError(t, err, "retry using the published predecessor")
				}
			case FlatAdvanceGaps.Selector():
				_, err := v.AdvanceFlatGaps(wire)
				require.ErrorIs(t, err, stages[stage])
				packet, err := DecodeFlatGap(retry, FlatAdvanceGaps, v.cfg.K)
				require.NoError(t, err)
				require.Equal(t, prior, packet.Receipt)
				_, err = v.AdvanceFlatGaps(retry)
				require.NoError(t, err)
			case FlatRedeemRecovered.Selector():
				packet, err := DecodeFlatGap(retry, FlatRedeemRecovered, v.cfg.K)
				require.NoError(t, err)
				require.Equal(t, prior, packet.Receipt)
				event, err := v.event(packet.Header, packet.Kind, packet.Receipt)
				require.NoError(t, err)
				var before flatCustodyFixture
				require.NoError(t, json.Unmarshal(mustFlatFile(t, dir, "custody-before.json"), &before))
				recipient := event.Verdict.Recipient
				vault := restoreFlatCustody(t, v, w.Env(), recipient, before)
				out, err := vault.RedeemRecovered(wire, RecipientAccepts)
				require.Nil(t, out)
				require.ErrorIs(t, err, stages[stage])
				require.Equal(t, before, flatCustodyState(vault, recipient))
				_, err = vault.RedeemRecovered(retry, RecipientAccepts)
				require.NoError(t, err)
				require.Equal(t, expectedSettlement(before, event.Verdict, int(v.cfg.K)), flatCustodyState(vault, recipient))
			default:
				t.Fatalf("unknown refusal selector %x", wire[:4])
			}
		})
	}
}

func restoreFlatCustody(t *testing.T, v *FlatVerifier, env Environment, recipient [20]byte, before flatCustodyFixture) *FlatVault {
	t.Helper()
	vault, err := NewFlatVault(v, env)
	require.NoError(t, err)
	amount := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 10)
		require.True(t, ok)
		return n
	}
	ids := func(raw []string) [][32]byte {
		out := make([][32]byte, len(raw))
		for i, s := range raw {
			out[i] = [32]byte(mustHex(s))
		}
		return out
	}
	head, previous := [32]byte(mustHex(before.Head)), [32]byte(mustHex(before.PreviousHead))
	previousIDs := ids(before.Previous)
	if before.Segment > 0 {
		require.Len(t, previousIDs, int(v.cfg.K))
		require.Equal(t, head, expectedArchiveStep(v.domain, before.Segment-1, previous, expectedGapRoot(previousIDs)))
	}
	vault.model.SetState(before.Deposits, before.Segment, before.Population, amount(before.Liability),
		head, previous, ids(before.Current), previousIDs)
	vault.model.Events = before.Events
	vault.credit(v.cfg.Vault, amount(before.VaultBalance))
	vault.credit(recipient, amount(before.RecipientBalance))
	return vault
}
