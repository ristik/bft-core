/*
Package signingauthority is the signing-authority boundary of the F6c contract
(docs/design/f6c-signing-state-contract.md, ADR 0009), implementation step 1 of its §8.

What this step contains: immutable enrollment, a narrow structured admission interface, and
authentication of a certification request against the authority's own provisioned trust. What it
deliberately does not contain: the signing record, reservation, fencing, response retention and
release (step 2), any wiring into the shard node's round (step 3), and any change to the restored
non-voting gate (step 4 at the earliest). Nothing here re-enables restored voting.

Two properties shape the API.

First, there is no generic signing. The authority admits a structured request carrying a Unicity
Certificate, the TechnicalRecord bound to it and the proposed certification request, and it derives
the bytes to be signed itself. It offers no method that signs caller-supplied bytes, and no way to
import, export, unwrap or replace a signing key: the key is generated for one authority lifetime and
never leaves it. TestAuthorityOffersNoGenericSigningOrKeyImport pins that method set.

Second, authenticity is checked here, and freshness is not. Every check below uses the authority's
own provisioned trust and its immutable enrollment. A caller cannot pass in a verifier result, a
trust base, a round, an epoch or a configuration hash to be believed. What this step does not
provide is protection against a replayed but genuine authorization: that is the signing record's
job in step 2, and an authenticated request is not yet an authorized one.
*/
package signingauthority
