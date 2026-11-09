package types

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	base "github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// agrees runs a verification with the cache on and then with it off and requires the same outcome: the cache decides nothing, so whatever the
// uncached verifier says (accept or refuse) is what the cached path must say, for valid and invalid variants alike.
func agrees(t *testing.T, tbs *trustbase.TrustBaseStore, name string, verify func() error) error {
	t.Helper()
	cachedErr := verify()
	tbs.SetCertCacheCapacity(0)
	plainErr := verify()
	tbs.SetCertCacheCapacity(4096)
	require.Equal(t, plainErr == nil, cachedErr == nil, "%s: cached %v, uncached %v", name, cachedErr, plainErr)
	return cachedErr
}

// --- scheme 2 (domain-bound) and the UTB envelope, through the real verifier ---------------------------------------------------------------------

type scheme2Rig struct {
	sb  *structBuilder
	cfg votesig.Config
	ids []string
}

func newScheme2Rig(t *testing.T, utb bool) *scheme2Rig {
	t.Helper()
	sb := newStructBuilder(t, 4)
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("cert-cache-test")), UTB: utb}
	require.NoError(t, sb.trustBaseStore.ActivateSigning(1, cfg))
	r := &scheme2Rig{sb: sb, cfg: cfg}
	for id := range sb.signers {
		r.ids = append(r.ids, id)
	}
	sort.Strings(r.ids)
	return r
}

// qc is a committing scheme 2 QC of epoch 1 (vote round 8 commits round 7) signed by the given members.
func (r *scheme2Rig) qc(t *testing.T, signers ...string) *QuorumCert {
	t.Helper()
	info := &RoundInfo{Version: 1, RoundNumber: 8, Epoch: 1, ParentRoundNumber: 7, CurrentRootHash: bytes.Repeat([]byte{9}, 32)}
	vi := votesig.VoteInfo{Epoch: 1, Round: 8, Parent: 7}
	copy(vi.Exec[:], info.CurrentRootHash)
	vh, err := r.cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	seal := &base.UnicitySeal{Version: 1, NetworkID: 5, PreviousHash: vh[:], RootChainRoundNumber: 7, Epoch: 1, Timestamp: base.GenesisTime + 5, Hash: bytes.Repeat([]byte{8}, 32)}
	pv, sealBytes, _, err := DomainBoundStatement(r.cfg, info, seal, true)
	require.NoError(t, err)
	qc := &QuorumCert{Scheme: votesig.SchemeDomainBound, VoteInfo: info, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}, SealSignatures: map[string]hex.Bytes{}}
	for _, id := range signers {
		sig, err := r.sb.signers[id].SignBytes(pv)
		require.NoError(t, err)
		sealSig, err := r.sb.signers[id].SignBytes(sealBytes)
		require.NoError(t, err)
		qc.Signatures[id], qc.SealSignatures[id] = sig, sealSig
	}
	return qc
}

func TestCertCacheScheme2VoteAndSealMutationsAgreeWithTheVerifier(t *testing.T) {
	r := newScheme2Rig(t, false)
	tbs := r.sb.trustBaseStore
	qc := r.qc(t, r.ids...)
	require.NoError(t, qc.VerifyWith(tbs))
	require.NoError(t, recodeQC(t, qc).VerifyWith(tbs))
	s := tbs.TakeCertCacheStats()
	require.Equal(t, 1, s.Hits[trustbase.CertQC], "the decoded copy of a scheme 2 certificate is a hit")

	corrupt := func(m map[string]hex.Bytes, id string) { m[id] = append(hex.Bytes{0}, m[id][1:]...) }
	variants := map[string]func(c *QuorumCert){
		"a vote signature":      func(c *QuorumCert) { corrupt(c.Signatures, r.ids[0]) },
		"a seal signature":      func(c *QuorumCert) { corrupt(c.SealSignatures, r.ids[1]) },
		"a seal signature gone": func(c *QuorumCert) { delete(c.SealSignatures, r.ids[2]) }, // unequal signer sets
		"a voter gone (3 of 4)": func(c *QuorumCert) { delete(c.Signatures, r.ids[3]); delete(c.SealSignatures, r.ids[3]) },
		"two voters gone": func(c *QuorumCert) {
			for _, id := range r.ids[2:] {
				delete(c.Signatures, id)
				delete(c.SealSignatures, id)
			}
		},
		"the seal timestamp":  func(c *QuorumCert) { c.LedgerCommitInfo.Timestamp++ },
		"the vote info root":  func(c *QuorumCert) { c.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{7}, 32) },
		"the scheme (legacy)": func(c *QuorumCert) { c.Scheme, c.SealSignatures = 0, nil },
	}
	for name, mutate := range variants {
		v := recodeQC(t, qc)
		mutate(v)
		before := tbs.TakeCertCacheStats()
		_ = before
		err := agrees(t, tbs, name, func() error { return v.VerifyWith(tbs) })
		st := tbs.TakeCertCacheStats()
		require.Zero(t, st.Hits[trustbase.CertQC], "%s: a different certificate is never a hit (verifier said %v)", name, err)
	}
	// 3 of 4 is a quorum: the variant with a voter gone is valid and accepted, not refused for being different
	three := recodeQC(t, qc)
	delete(three.Signatures, r.ids[3])
	delete(three.SealSignatures, r.ids[3])
	require.NoError(t, three.VerifyWith(tbs))
}

func TestCertCacheUTBEnvelopeVariantsAgreeWithTheVerifier(t *testing.T) {
	r := newScheme2Rig(t, true)
	tbs := r.sb.trustBaseStore
	// the successor entry the certificate endorses: epoch 2, the network of the configuration
	var nodes []*base.NodeInfo
	for _, id := range r.ids {
		pub, err := r.sb.verifiers[id].MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &base.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
	}
	entry := &base.RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 2, EpochStart: 100, RootNodes: nodes, QuorumThreshold: 3,
		StateHash: bytes.Repeat([]byte{0x22}, 32), PreviousEntryID: bytes.Repeat([]byte{9}, 32)}
	unsigned, err := entry.SigBytes()
	require.NoError(t, err)

	qc := r.qc(t, r.ids...)
	qc.Envelope = votesig.EnvelopeUTB
	qc.UTB = &UTBCertificate{Unsigned: unsigned, Signatures: map[string]hex.Bytes{}}
	for _, id := range r.ids {
		sig, err := r.sb.signers[id].SignBytes(unsigned)
		require.NoError(t, err)
		qc.UTB.Signatures[id] = sig
	}
	require.NoError(t, qc.VerifyWith(tbs), "a committing certificate with its endorsement")
	require.NoError(t, recodeQC(t, qc).VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])

	wrongEpoch := *entry
	wrongEpoch.Epoch = 3
	wrongUnsigned, err := wrongEpoch.SigBytes()
	require.NoError(t, err)
	variants := map[string]func(c *QuorumCert){
		"an endorsement signature": func(c *QuorumCert) {
			c.UTB.Signatures[r.ids[0]] = append(hex.Bytes{0}, c.UTB.Signatures[r.ids[0]][1:]...)
		},
		"an endorser gone":   func(c *QuorumCert) { delete(c.UTB.Signatures, r.ids[1]) }, // unequal signer sets
		"the endorsed entry": func(c *QuorumCert) { c.UTB.Unsigned = wrongUnsigned },
		"no endorsement":     func(c *QuorumCert) { c.UTB = nil },
		"no envelope":        func(c *QuorumCert) { c.Envelope, c.UTB = 0, nil },
	}
	for name, mutate := range variants {
		v := recodeQC(t, qc)
		mutate(v)
		if name == "no endorsement" {
			v.Envelope = votesig.EnvelopeUTB // an envelope that carries none
		}
		err := agrees(t, tbs, name, func() error { return v.VerifyWith(tbs) })
		if name != "no endorsement" { // an envelope without an endorsement is valid for the verifier (the entry binding is checked elsewhere): a valid, different certificate
			require.Error(t, err, name)
		}
		require.Zero(t, tbs.TakeCertCacheStats().Hits[trustbase.CertQC], name)
	}
}

// --- weighted vs count quorum ----------------------------------------------------------------------------------------------------------------

func TestCertCacheWeightedQuorumIsNotCountedThroughTheCache(t *testing.T) {
	sb := newStructBuilder(t, 4)
	tb, heavy, light := skewedTrust(t, sb)
	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(tb))

	full := sb.QC(t, 10)
	byWeight := recodeQC(t, full)
	byWeight.Signatures = keep(full.Signatures, heavy, light[0]) // 2 of 4 by count, 7 of 9 by weight
	byCount := recodeQC(t, full)
	byCount.Signatures = keep(full.Signatures, light...) // 3 of 4 by count, 3 of 9 by weight

	require.NoError(t, byWeight.VerifyWith(tbs))
	require.NoError(t, recodeQC(t, byWeight).VerifyWith(tbs))
	require.Equal(t, 1, tbs.TakeCertCacheStats().Hits[trustbase.CertQC])
	err = agrees(t, tbs, "by count", func() error { return byCount.VerifyWith(tbs) })
	require.ErrorContains(t, err, "quorum")
	require.Zero(t, tbs.TakeCertCacheStats().Hits[trustbase.CertQC], "the weighted-valid result is not served to the count-majority certificate")

	tc := sb.TimeoutCert(t)
	all := tc.Signatures
	pick := func(ids ...string) map[string]*TimeoutVote {
		out := map[string]*TimeoutVote{}
		for _, id := range ids {
			out[id] = all[id]
		}
		return out
	}
	tc.Signatures = pick(heavy, light[0])
	require.NoError(t, tc.Verify(tbs))
	require.NoError(t, recodeTC(t, tc).Verify(tbs))
	tcLight := recodeTC(t, tc)
	tcLight.Signatures = pick(light...)
	require.Error(t, agrees(t, tbs, "tc by count", func() error { return tcLight.Verify(tbs) }))
}

// --- anchor-only TC and a nested QC from another epoch ----------------------------------------------------------------------------------------

type epochRig struct {
	store  *trustbase.TrustBaseStore
	signer abcrypto.Signer
}

// newEpochRig installs epoch 1 and its successor epoch 2 (one member), the arrangement the anchored-epoch tests use.
func newEpochRig(t *testing.T) *epochRig {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	old := testtrustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{"node": signer}).(*base.RootTrustBaseV1)
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, store.Store(old))
	oldID, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	projected, err := base.NewTrustBase(old.NetworkID, old.RootNodes, base.WithEpoch(2), base.WithEpochStart(13), base.WithPreviousTrustBaseHash(oldID))
	require.NoError(t, err)
	_, err = store.InstallV2Projection(projected)
	require.NoError(t, err)
	return &epochRig{store: store, signer: signer}
}

func TestCertCacheAnchorOnlyTimeoutCertificate(t *testing.T) {
	r := newEpochRig(t)
	a := testEpochAnchor()
	timeout := NewAnchorTimeout(13, a)
	vote := func(anchor *EpochAnchor, hqc uint64) *TimeoutVote {
		v := &TimeoutVote{HqcRound: hqc, Anchor: anchor}
		sig, err := r.signer.SignBytes(BytesFromTimeoutVote(timeout, "node", v))
		require.NoError(t, err)
		v.Signature = sig
		return v
	}
	tc := &TimeoutCert{Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": vote(a, a.Slot)}}
	require.NoError(t, tc.Verify(r.store))
	require.NoError(t, recodeTC(t, tc).Verify(r.store))
	require.Equal(t, 1, r.store.TakeCertCacheStats().Hits[trustbase.CertTC], "an anchor-only TC (no nested QC) is remembered and hit")

	for name, c := range map[string]*TimeoutCert{
		"no anchor on the vote": {Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": vote(nil, a.Slot)}},
		"another anchor slot":   {Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": vote(&EpochAnchor{GenesisID: a.GenesisID, Epoch: a.Epoch, Slot: a.Slot + 1, StateRoot: a.StateRoot}, a.Slot+1)}},
	} {
		err := agrees(t, r.store, name, func() error { return c.Verify(r.store) })
		require.Error(t, err, name)
		require.Zero(t, r.store.TakeCertCacheStats().Hits[trustbase.CertTC], name)
	}
}

// A TC of epoch 2 whose high QC is a QC of epoch 1: both epochs are in the context, both certificates are remembered, and a changed nested QC
// is a different TC.
func TestCertCacheNestedQCFromAnotherEpoch(t *testing.T) {
	r := newEpochRig(t)
	info := &RoundInfo{RoundNumber: 10, ParentRoundNumber: 9, Epoch: 1, Timestamp: 1670314583523, CurrentRootHash: bytes.Repeat([]byte{4}, 32)}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &base.UnicitySeal{Version: 1, PreviousHash: h}
	sig, err := r.signer.SignBytes(testcertificates.UnicitySealBytes(t, seal))
	require.NoError(t, err)
	qc := &QuorumCert{VoteInfo: info, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{"node": sig}}
	timeout := &Timeout{Epoch: 2, Round: 11, HighQc: qc}
	vsig, err := r.signer.SignBytes(BytesFromTimeoutVote(timeout, "node", &TimeoutVote{HqcRound: 10}))
	require.NoError(t, err)
	tc := &TimeoutCert{Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": {HqcRound: 10, Signature: vsig}}}

	require.NoError(t, tc.Verify(r.store))
	s := r.store.TakeCertCacheStats()
	require.Equal(t, 2, s.Inserts, "the TC of epoch 2 and its nested QC of epoch 1")
	ctx, ok := r.store.CertContextFor(1, 2)
	require.True(t, ok)
	require.Equal(t, 2, ctx.N)
	require.NoError(t, recodeTC(t, tc).Verify(r.store))
	require.Equal(t, 1, r.store.TakeCertCacheStats().Hits[trustbase.CertTC])
	require.NoError(t, recodeQC(t, qc).VerifyWith(r.store))
	require.Equal(t, 1, r.store.TakeCertCacheStats().Hits[trustbase.CertQC], "the nested QC was remembered on its own")

	changed := recodeTC(t, tc)
	changed.Timeout.HighQc.VoteInfo.Timestamp++
	err = agrees(t, r.store, "nested qc changed", func() error { return changed.Verify(r.store) })
	require.Error(t, err)
	require.Zero(t, r.store.TakeCertCacheStats().Hits[trustbase.CertTC])
}

// --- a bound authority whose answer changes with no call on the store ------------------------------------------------------------------------

// movingAuthority is a verified-history stand-in whose answer for an epoch can change at any time: nothing tells the store.
type movingAuthority struct {
	mu  sync.Mutex
	cfg map[uint64]votesig.Config
}

func (a *movingAuthority) Signing(epoch uint64) (votesig.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cfg[epoch]; ok {
		return c, nil
	}
	return votesig.Config{}, errors.New("epoch not in the history")
}

func (a *movingAuthority) LeaderPolicy(uint64) (string, error) {
	return trustbase.LeaderPolicyLegacy, nil
}

func (a *movingAuthority) set(epoch uint64, c votesig.Config) {
	a.mu.Lock()
	a.cfg[epoch] = c
	a.mu.Unlock()
}

// nestedEpochFixture is the TC of epoch 2 with a legacy high QC of epoch 1, the stores' authority bound to a movingAuthority.
func nestedEpochFixture(t *testing.T) (r *epochRig, auth *movingAuthority, qc *QuorumCert, tc *TimeoutCert, network uint64) {
	t.Helper()
	r = newEpochRig(t)
	tb1, err := r.store.GetByEpoch(1)
	require.NoError(t, err)
	network = uint64(tb1.NetworkID)
	legacyCfg := votesig.Config{Scheme: votesig.SchemeLegacy, Network: network}
	auth = &movingAuthority{cfg: map[uint64]votesig.Config{1: legacyCfg, 2: legacyCfg}}
	require.NoError(t, r.store.BindSigningAuthority(auth))

	info := &RoundInfo{RoundNumber: 10, ParentRoundNumber: 9, Epoch: 1, Timestamp: 1670314583523, CurrentRootHash: bytes.Repeat([]byte{4}, 32)}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &base.UnicitySeal{Version: 1, PreviousHash: h}
	sig, err := r.signer.SignBytes(testcertificates.UnicitySealBytes(t, seal))
	require.NoError(t, err)
	qc = &QuorumCert{VoteInfo: info, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{"node": sig}}
	timeout := &Timeout{Epoch: 2, Round: 11, HighQc: qc}
	vsig, err := r.signer.SignBytes(BytesFromTimeoutVote(timeout, "node", &TimeoutVote{HqcRound: 10}))
	require.NoError(t, err)
	tc = &TimeoutCert{Timeout: timeout, Signatures: map[string]*TimeoutVote{"node": {HqcRound: 10, Signature: vsig}}}
	return r, auth, qc, tc, network
}

// The authority's answer for the QC's epoch changes (the epoch now requires the UTB envelope, which a legacy certificate lacks) and no store method
// is called: the remembered result is not served, the verifier refuses, and the cache agrees with the uncached verifier.
func TestCertCacheFollowsABoundAuthoritysChangedAnswerForAQC(t *testing.T) {
	r, auth, qc, _, network := nestedEpochFixture(t)
	require.NoError(t, qc.VerifyWith(r.store))
	require.NoError(t, recodeQC(t, qc).VerifyWith(r.store))
	require.Equal(t, 1, r.store.TakeCertCacheStats().Hits[trustbase.CertQC])

	genBefore := r.store.VerifyGeneration()
	auth.set(1, votesig.Config{Scheme: votesig.SchemeLegacy, Network: network, UTB: true})
	require.Equal(t, genBefore, r.store.VerifyGeneration(), "nothing told the store")

	err := agrees(t, r.store, "authority changed", func() error { return recodeQC(t, qc).VerifyWith(r.store) })
	require.Error(t, err, "a legacy certificate of an epoch that now requires the UTB envelope")
	s := r.store.TakeCertCacheStats()
	require.Zero(t, s.Hits[trustbase.CertQC], "not served from the old answer")
}

// The same for a TC whose NESTED high QC's epoch changes while the TC's own epoch does not: the nested epoch is part of the TC's context.
func TestCertCacheFollowsABoundAuthoritysChangedAnswerForATCsNestedEpoch(t *testing.T) {
	r, auth, _, tc, network := nestedEpochFixture(t)
	require.NoError(t, tc.Verify(r.store))
	require.NoError(t, recodeTC(t, tc).Verify(r.store))
	require.Equal(t, 1, r.store.TakeCertCacheStats().Hits[trustbase.CertTC])

	genBefore := r.store.VerifyGeneration()
	auth.set(1, votesig.Config{Scheme: votesig.SchemeLegacy, Network: network, UTB: true}) // epoch 1 only; the TC's epoch 2 is untouched
	require.Equal(t, genBefore, r.store.VerifyGeneration())

	err := agrees(t, r.store, "nested epoch answer changed", func() error { return recodeTC(t, tc).Verify(r.store) })
	require.Error(t, err)
	require.Zero(t, r.store.TakeCertCacheStats().Hits[trustbase.CertTC], "the TC is not served from the old answer of its nested QC's epoch")

	// and the TC's own epoch: changing only epoch 2's answer is a miss as well
	r2, auth2, _, tc2, network2 := nestedEpochFixture(t)
	require.NoError(t, tc2.Verify(r2.store))
	auth2.set(2, votesig.Config{Scheme: votesig.SchemeDomainBound, Network: network2, Genesis: [32]byte{5}}) // a legacy TC of an epoch that now signs domain-bound
	err = agrees(t, r2.store, "own epoch answer changed", func() error { return recodeTC(t, tc2).Verify(r2.store) })
	require.Error(t, err)
	require.Zero(t, r2.store.TakeCertCacheStats().Hits[trustbase.CertTC])
}

// A TC hit skips the nested QC's verification, so the nested QC obeys the QC no-key rule: a scheme 2 high QC whose in-memory vote info is not
// version 1 (a field the wire form does not carry) gives the TC no key.
func TestCertCacheTimeoutCertKeyAppliesTheNestedQCNoKeyRule(t *testing.T) {
	r, _, qc, tc, _ := nestedEpochFixture(t)
	_, ok := timeoutCertCacheKey(r.store, tc)
	require.True(t, ok, "a legacy nested QC")

	scheme2 := recodeTC(t, tc)
	scheme2.Timeout.HighQc.Scheme = votesig.SchemeDomainBound
	scheme2.Timeout.HighQc.VoteInfo.Version = 1
	_, ok = timeoutCertCacheKey(r.store, scheme2)
	require.True(t, ok, "version 1: the wire form carries it")

	scheme2.Timeout.HighQc.VoteInfo.Version = 0
	_, ok = timeoutCertCacheKey(r.store, scheme2)
	require.False(t, ok, "a scheme 2 nested QC with an in-memory version the wire form cannot carry: no key")
	scheme2.Timeout.HighQc.VoteInfo.Version = 2
	_, ok = timeoutCertCacheKey(r.store, scheme2)
	require.False(t, ok)

	// the same rule on the QC's own key, for reference
	q := recodeQC(t, qc)
	q.Scheme, q.VoteInfo.Version = votesig.SchemeDomainBound, 0
	_, ok = certCacheKey(r.store, trustbase.CertQC, q, q.VoteInfo.Version, q.Scheme, q.VoteInfo.Epoch)
	require.False(t, ok)
}
