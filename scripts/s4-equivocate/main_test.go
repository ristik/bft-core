package main

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	gohex "encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/cli/ubft/cmd"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

// offender is a root of a committee whose keys the harness holds: its own keys.json, the trust base of the epochs the offence lives in and the signing
// configuration of the epoch (scheme 2), as the lane's roots hold them.
type offender struct {
	keys   *cmd.KeyConf
	file   string
	id     string
	signer abcrypto.Signer
	store  *trustbase.TrustBaseStore
	cfg    votesig.Config
}

func newOffender(t *testing.T, utb bool) *offender {
	t.Helper()
	o := &offender{cfg: votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 3, Genesis: sha256.Sum256([]byte("s4-test-genesis")), UTB: utb}}
	seed := sha256.Sum256([]byte("s4-test-offender-key"))
	o.keys = &cmd.KeyConf{
		SigKey:  cmd.Key{Algorithm: cmd.KeyAlgorithmSecp256k1, PrivateKey: hex.Bytes(bytes.Clone(seed[:]))},
		AuthKey: cmd.Key{Algorithm: cmd.KeyAlgorithmSecp256k1, PrivateKey: hex.Bytes(bytes.Clone(seed[:]))},
	}
	var err error
	o.signer, err = o.keys.Signer()
	require.NoError(t, err)
	nid, err := o.keys.NodeID()
	require.NoError(t, err)
	o.id = nid.String()
	raw, err := json.Marshal(o.keys)
	require.NoError(t, err)
	o.file = filepath.Join(t.TempDir(), "keys.json")
	require.NoError(t, os.WriteFile(o.file, raw, 0o600))

	// four other members, the offender among them
	var nodes []*types.NodeInfo
	signers := map[string]abcrypto.Signer{o.id: o.signer}
	pub := func(s abcrypto.Signer) []byte {
		v, err := s.Verifier()
		require.NoError(t, err)
		k, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return k
	}
	nodes = append(nodes, &types.NodeInfo{NodeID: o.id, SigKey: pub(o.signer), Stake: 1})
	for _, n := range []string{"a", "b", "c"} {
		k := sha256.Sum256([]byte("s4-test-member/" + n))
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
		require.NoError(t, err)
		signers[n] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: n, SigKey: pub(s), Stake: 1})
	}
	o.store, err = trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	var prev *types.RootTrustBaseV1
	for epoch, start := uint64(1), uint64(1); epoch <= 2; epoch, start = epoch+1, start+99 {
		opts := []types.Option{types.WithEpoch(epoch), types.WithEpochStart(start)}
		if prev != nil {
			h, err := prev.Hash(gocrypto.SHA256)
			require.NoError(t, err)
			opts = append(opts, types.WithPreviousTrustBaseHash(h))
		}
		cp := make([]*types.NodeInfo, len(nodes))
		for i, n := range nodes {
			cp[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: n.Stake}
		}
		tb, err := types.NewTrustBase(types.NetworkID(o.cfg.Network), cp, opts...)
		require.NoError(t, err)
		for id, s := range signers {
			require.NoError(t, tb.Sign(id, s))
		}
		require.NoError(t, o.store.Store(tb))
		prev = tb
	}
	cfg := o.cfg
	cfg.UTB = false // the store's activation record carries the scheme; the UTB envelope is not part of the statement
	require.NoError(t, o.store.ActivateSigning(2, cfg))
	return o
}

func (o *offender) params(round uint64) Params {
	return Params{Cfg: o.cfg, Author: o.id, Epoch: 2, Round: round, Time: 1_700_000_000}
}

func journal(t *testing.T) *rootevidence.Journal {
	t.Helper()
	j, err := rootevidence.NewJournal(memorydb.New(), 0)
	require.NoError(t, err)
	return j
}

// The pair the harness signs is the pair the service needs: each half is kept by an observer that sees only that half, the halves meet in the
// collection of the two journals and the submitter builds the contract's call from them, with the original signatures of the committing statement.
func TestHarnessPairIsObservedAcrossTwoJournalsAndSubmittable(t *testing.T) {
	for _, utb := range []bool{false, true} {
		t.Run(map[bool]string{false: "scheme 2", true: "UTB envelope"}[utb], func(t *testing.T) {
			o := newOffender(t, utb)
			a, b, err := BuildPair(o.signer, o.params(40))
			require.NoError(t, err)
			require.Empty(t, a.SealSignature, "the non-committing statement has no seal signature")
			require.NotEmpty(t, b.SealSignature, "the committing statement carries both signatures")
			require.NotEmpty(t, a.Signature)
			require.NotEqual(t, a.VoteInfo.CurrentRootHash, b.VoteInfo.CurrentRootHash)

			oa, err := rootevidence.Observe(a, o.store)
			require.NoError(t, err)
			ob, err := rootevidence.Observe(b, o.store)
			require.NoError(t, err)
			require.Equal(t, oa.Slot(), ob.Slot(), "one (key, epoch, round)")
			require.False(t, oa.S.Committing)
			require.True(t, ob.S.Committing)

			j1, j2 := journal(t), journal(t)
			_, err = j1.Record(oa)
			require.NoError(t, err)
			_, err = j2.Record(ob)
			require.NoError(t, err)
			r1, err := j1.Get(oa.Slot())
			require.NoError(t, err)
			r2, err := j2.Get(ob.Slot())
			require.NoError(t, err)
			require.False(t, r1.Paired(), "the first observer has half of the offence")
			require.False(t, r2.Paired(), "the second observer has the other half")

			alone1, err := rootevidence.Collect(j1)
			require.NoError(t, err)
			require.Empty(t, alone1.Pairs())
			both, err := rootevidence.Collect(j1, j2)
			require.NoError(t, err)
			require.Len(t, both.Pairs(), 1, "exactly one offence for (offender key, epoch, round)")
			rec := both.Pairs()[0]
			require.Equal(t, o.id, rec.Author)
			require.EqualValues(t, 2, rec.Epoch)
			require.EqualValues(t, 40, rec.Round)

			net := sha256.Sum256([]byte("p85-network"))
			exposure := sha256.Sum256([]byte("exposure"))
			data, err := rootevidence.SubmitCalldata(net, o.cfg, rec, exposure)
			require.NoError(t, err)
			m := evidenceABI(t).Methods["submitEvidence"]
			args, err := m.Inputs.Unpack(data[4:])
			require.NoError(t, err)
			type vote struct {
				Parent          uint64
				Exec            [32]byte
				Timestamp       uint64
				Committing      bool
				CommitHash      [32]byte
				CommitRound     uint64
				CommitEpoch     uint64
				CommitTimestamp uint64
				Signature       []byte
				SealSignature   []byte
			}
			va := abi.ConvertType(args[1], new(vote)).(*vote)
			vb := abi.ConvertType(args[2], new(vote)).(*vote)
			committing, other := vb, va
			if va.Committing {
				committing, other = va, vb
			}
			require.True(t, committing.Committing)
			require.False(t, other.Committing)
			require.Equal(t, []byte(b.Signature), committing.Signature, "the original vote signature of the committing statement")
			require.Equal(t, []byte(b.SealSignature), committing.SealSignature, "the original seal signature of the committing statement")
			require.Equal(t, []byte(a.Signature), other.Signature)
			require.Empty(t, other.SealSignature)
			require.EqualValues(t, 39, committing.CommitRound)
		})
	}
}

func evidenceABI(t *testing.T) abi.ABI {
	t.Helper()
	// the same two-method slice rootevidence pins against forge inspect: the harness only needs submitEvidence's argument shapes
	const def = `[{"type":"function","name":"submitEvidence","stateMutability":"nonpayable","inputs":[
	  {"name":"h","type":"tuple","components":[{"name":"network","type":"bytes32"},{"name":"domain","type":"uint8"},{"name":"key","type":"bytes"},{"name":"votingEpoch","type":"uint64"},{"name":"votingRound","type":"uint64"}]},
	  {"name":"a","type":"tuple","components":[{"name":"parent","type":"uint64"},{"name":"exec","type":"bytes32"},{"name":"timestamp","type":"uint64"},{"name":"committing","type":"bool"},{"name":"commitHash","type":"bytes32"},{"name":"commitRound","type":"uint64"},{"name":"commitEpoch","type":"uint64"},{"name":"commitTimestamp","type":"uint64"},{"name":"signature","type":"bytes"},{"name":"sealSignature","type":"bytes"}]},
	  {"name":"b","type":"tuple","components":[{"name":"parent","type":"uint64"},{"name":"exec","type":"bytes32"},{"name":"timestamp","type":"uint64"},{"name":"committing","type":"bool"},{"name":"commitHash","type":"bytes32"},{"name":"commitRound","type":"uint64"},{"name":"commitEpoch","type":"uint64"},{"name":"commitTimestamp","type":"uint64"},{"name":"signature","type":"bytes"},{"name":"sealSignature","type":"bytes"}]},
	  {"name":"exposureID","type":"bytes32"}],"outputs":[{"name":"caseID","type":"bytes32"}]}]`
	a, err := abi.JSON(bytes.NewReader([]byte(def)))
	require.NoError(t, err)
	return a
}

// A statement is not a vote the roots would accept in another epoch's configuration: the harness refuses to sign what the contract could not rebuild.
func TestBuildPairRefusesWhatCannotBeAnOffence(t *testing.T) {
	o := newOffender(t, false)
	_, _, err := BuildPair(o.signer, Params{Cfg: votesig.Config{Scheme: votesig.SchemeLegacy}, Author: o.id, Epoch: 2, Round: 40})
	require.Error(t, err, "scheme 1 is not an offence the contract slashes")
	_, _, err = BuildPair(o.signer, Params{Cfg: o.cfg, Author: o.id, Epoch: 2, Round: 2})
	require.Error(t, err, "a round too low for the committing statement to commit below it")
	a, b, err := BuildPair(o.signer, o.params(40))
	require.NoError(t, err)
	a2, b2, err := BuildPair(o.signer, o.params(40))
	require.NoError(t, err)
	am, _ := a.MarshalCBOR()
	am2, _ := a2.MarshalCBOR()
	bm, _ := b.MarshalCBOR()
	bm2, _ := b2.MarshalCBOR()
	require.Equal(t, am, am2, "deterministic")
	require.Equal(t, bm, bm2)
	other, _, err := BuildPair(o.signer, o.params(41))
	require.NoError(t, err)
	om, _ := other.MarshalCBOR()
	require.NotEqual(t, am, om, "another round is another statement")
}

// The real ingress: the vote travels over the root vote protocol from a host with the voter's identity to a root's network, arrives decoded as the
// bytes that were signed, and the observer keeps it.
func TestSendDeliversTheVoteOverTheRootVoteProtocol(t *testing.T) {
	for _, utb := range []bool{false, true} {
		t.Run(map[bool]string{false: "scheme 2", true: "UTB envelope"}[utb], func(t *testing.T) {
			o := newOffender(t, utb)
			a, b, err := BuildPair(o.signer, o.params(41))
			require.NoError(t, err)

			// a receiving root: its own identity, the root consensus network
			rseed := sha256.Sum256([]byte("s4-test-receiver"))
			rk := &cmd.KeyConf{AuthKey: cmd.Key{Algorithm: cmd.KeyAlgorithmSecp256k1, PrivateKey: hex.Bytes(rseed[:])}}
			kp, err := rk.AuthKeyPair()
			require.NoError(t, err)
			conf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, kp, nil, nil)
			require.NoError(t, err)
			host, err := network.NewPeer(t.Context(), conf, logger.New(t), prometheus.NewRegistry())
			require.NoError(t, err)
			t.Cleanup(func() { _ = host.Close() })
			rnet, err := network.NewLibP2RootConsensusNetwork(host, 16, time.Second, testobs.NOPObservability())
			require.NoError(t, err)

			to := peer.AddrInfo{ID: host.ID(), Addrs: host.MultiAddresses()}
			for _, v := range []*abdrc.VoteMsg{a, b} {
				require.NoError(t, Send(t.Context(), o.keys, v, to, 10*time.Second))
				select {
				case m := <-rnet.ReceivedChannel():
					got, ok := m.(*abdrc.VoteMsg)
					require.True(t, ok, "a vote on the vote protocol, got %T", m)
					want, err := v.MarshalCBOR()
					require.NoError(t, err)
					have, err := got.MarshalCBOR()
					require.NoError(t, err)
					require.Equal(t, want, have, "the vote that was signed, byte for byte")
					require.Equal(t, o.id, got.Author)
					obs, err := rootevidence.Observe(got, o.store)
					require.NoError(t, err, "the receiving root's observer verifies and keeps the statement")
					require.EqualValues(t, 41, obs.Round)
				case <-time.After(10 * time.Second):
					t.Fatal("the vote did not arrive")
				}
			}
		})
	}
}

func TestMakeWritesPublicDescriptionOnly(t *testing.T) {
	o := newOffender(t, false)
	dir := t.TempDir()
	require.NoError(t, runMake([]string{"--keys", o.file, "--network", "3", "--genesis", "0x" + hexString(o.cfg.Genesis[:]), "--epoch", "2", "--round", "40", "--timestamp", "1700000000", "--out", dir}))
	for _, f := range []string{"a.vote", "b.vote", "statements.json"} {
		require.FileExists(t, filepath.Join(dir, f))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "statements.json"))
	require.NoError(t, err)
	var d Description
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Len(t, d.Statements, 2)
	require.NotEqual(t, d.Statements[0].Digest, d.Statements[1].Digest)
	require.False(t, d.Statements[0].Committing)
	require.True(t, d.Statements[1].Committing)
	seed := sha256.Sum256([]byte("s4-test-offender-key"))
	// no private key of the offender anywhere in the output
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(b), hexString(seed[:]), e.Name())
		require.False(t, bytes.Contains(b, seed[:]), e.Name())
	}
}

func hexString(b []byte) string { return gohex.EncodeToString(b) }

// The controls of the live exercise are made from the real pair: the canonical call, the pair the other way round, one statement twice, the committing
// statement changed after signing and its seal signature removed. Each differs from the canonical call exactly where it says.
func TestVariantsOfTheCanonicalCall(t *testing.T) {
	o := newOffender(t, false)
	a, b, err := BuildPair(o.signer, o.params(40))
	require.NoError(t, err)
	j1, j2 := journal(t), journal(t)
	for j, v := range map[*rootevidence.Journal]*abdrc.VoteMsg{j1: a, j2: b} {
		obs, err := rootevidence.Observe(v, o.store)
		require.NoError(t, err)
		_, err = j.Record(obs)
		require.NoError(t, err)
	}
	net := sha256.Sum256([]byte("p85-network"))
	exposure := sha256.Sum256([]byte("exposure"))
	_, err = Variants([]*rootevidence.Journal{j1}, net, o.cfg, exposure)
	require.Error(t, err, "one journal holds no offence")
	v, err := Variants([]*rootevidence.Journal{j1, j2}, net, o.cfg, exposure)
	require.NoError(t, err)
	require.Len(t, v, 5)
	m := evidenceABI(t).Methods["submitEvidence"]
	type hdr struct {
		Network     [32]byte
		Domain      uint8
		Key         []byte
		VotingEpoch uint64
		VotingRound uint64
	}
	unpack := func(name string) (hdr, evVote, evVote) {
		require.Equal(t, []byte(m.ID), v[name][:4], name)
		args, err := m.Inputs.Unpack(v[name][4:])
		require.NoError(t, err, name)
		return *abi.ConvertType(args[0], new(hdr)).(*hdr), *abi.ConvertType(args[1], new(evVote)).(*evVote), *abi.ConvertType(args[2], new(evVote)).(*evVote)
	}
	_, ca, cb := unpack("canonical")
	require.NotEqual(t, ca.Exec, cb.Exec)
	_, ra, rb := unpack("reordered")
	require.Equal(t, ca, rb)
	require.Equal(t, cb, ra)
	_, ia, ib := unpack("identical")
	require.Equal(t, ia, ib, "one statement twice")
	_, aa, ab := unpack("altered")
	_, sa, sb := unpack("sealstripped")
	commit := func(x, y evVote) (evVote, evVote) {
		if x.Committing {
			return x, y
		}
		return y, x
	}
	cc, co := commit(ca, cb)
	ac, ao := commit(aa, ab)
	sc, so := commit(sa, sb)
	require.Equal(t, co, ao, "the other statement is untouched")
	require.Equal(t, co, so)
	require.NotEqual(t, cc.Exec, ac.Exec, "altered: the committing statement's executed state changed after signing")
	require.Equal(t, cc.Signature, ac.Signature, "with its original signature")
	require.Empty(t, sc.SealSignature, "sealstripped: no seal signature")
	require.Equal(t, cc.Signature, sc.Signature)
}
