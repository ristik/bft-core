package types

import (
	"crypto/sha256"
	"time"

	base "github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// verifyCertHook runs between a successful verification and the remembering of its result. Tests use it to change the verification context
// at exactly that point; it is a no-op otherwise.
var verifyCertHook = func() {}

// certCacheKey builds the key of the verified-certificate cache (trustbase/cert_cache.go): SHA-256 of the certificate's complete CBOR
// encoding under the kind tag, plus the resolved context of the epochs it depends on. ok is false (the certificate is then verified
// without the cache, never found under a sentinel) when it cannot be encoded, a signing configuration is unknown, or the in-memory
// certificate carries a field the wire form would not (a scheme 2 vote info that is not version 1).
func certCacheKey(tbs *trustbase.TrustBaseStore, kind trustbase.CertKind, cert any, voteInfoVersion base.Version, scheme uint64, epochs ...uint64) (trustbase.CertKey, bool) {
	if tbs == nil {
		return trustbase.CertKey{}, false
	}
	if kind == trustbase.CertQC && scheme == votesig.SchemeDomainBound && voteInfoVersion != 1 {
		return trustbase.CertKey{}, false
	}
	start := time.Now()
	raw, err := base.Cbor.Marshal(cert)
	if err != nil {
		return trustbase.CertKey{}, false
	}
	ctx, ok := tbs.CertContextFor(epochs...)
	if !ok {
		return trustbase.CertKey{}, false
	}
	k := trustbase.CertKey{Kind: kind, Digest: sha256.Sum256(raw), Ctx: ctx}
	tbs.NoteCertKeyBuild(time.Since(start))
	return k, true
}
