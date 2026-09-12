/*
Package signingauthority is the signing-authority boundary of the F6c contract
(docs/design/f6c-signing-state-contract.md, ADR 0009), implementation step 1 of its §8.

Steps 1 and 2 of §8 are implemented here: immutable enrollment, a narrow structured admission
interface, authentication against the authority's own provisioned trust, and then the in-memory
signing record with compare-and-reserve on the assigned partition round, retain-before-release,
exact response replay, and operator-controlled generation fencing.

What this package deliberately does not contain: any wiring into the shard node's round (step 3),
any change to the restored non-voting gate (step 4 at the earliest), any transport, and any durable
journal. Nothing here re-enables restored voting.

The record is process memory with the same lifetime as the key, which is the profile's central
trade: a record that cannot outlive its key needs no durability, because nothing can sign with that
identity afterwards. Bounding concurrency and queue length belongs to the transport that will front
this package, not to the package itself; a mutex serialises operations here, and callers wait.

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
