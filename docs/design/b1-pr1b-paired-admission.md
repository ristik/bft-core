# B1 PR1b: inactive paired admission

This completes the dependent Go slice of the A′ design. No node command configures
`VerifierContext.B1`; activation and real-client execution remain PR4 gates.

The fresh deployment pins contracts commit
`71eb6325bafe296bb58ceb93f7c4df775409f764`, artifact
`artifacts/seal-registry.json`, SHA256
`c094a1a6d56236474e68e5fda665f3d6fcc2c789743ede6e671c7f4f89279bcb`, and
runtime Keccak256
`28ebc47d5beeb45307cb92ff1521be6a5623d4e4fa1721bc13a6f755cdf0781c`.
The compiler hash is SHA256 of the compact JSON compiler object, in artifact field
order. `b1registry.Runtime` validates the complete artifact identity and fixed slots.

`b1registry.ValidateProfile` requires K=W+1≤16 and
G_rest≥1096500+1141500*K, together with the admission/write rectangle, transport
reservation, ordinary capacity and clock inequalities from PR1a. The constants
are measured plus margin; PR4 must remeasure on both target CPUs in the real client.
No larger budget lifts the measured K cap.

`q3format.History.B1Entries` derives native body identities, actual activations,
configuration identities, root consensus keys and exact weights from the private
verified history. Genesis uses the explicit signing configuration commitment
SHA256(CoreDeterministicCBOR(["UNICITY_B1_GENESIS_SIGNING_CONFIG", network,
rootGenesisID, 1, "unit", "total-(total-1)/3"])). Missing successor configuration
is refused. V3 retains its native body kind 3 and configuration identity. The
current history supports authenticated genesis and V3 successors; unsupported
historical schemes/configurations cannot silently become legacy authority.

`q3active.Runtime.B1History` checks installation of every intervening epoch, even
an expired epoch that produced no EVM block. This uses the same durable journal
and root installer that verifies coupled assignments. History extension uses
consecutive bounded Q3 segments, without bounding total skipped epochs by K.
Restart must recover the journal before admitting any activated epoch. The shared
input API holds an opaque `internal/b1authority.Source` created only by
`Runtime.B1Authority`; it cannot accept an injected authority callback. The
internal constructor/importer guard keeps root storage out of the input API
dependency graph while preserving the concrete runtime's admission checks.

`rootinput.B1Config.Derive` (also exported as `b1paired.Config`) freezes that history at the authenticated origin, rechecks
the certificate under its own committee, and proves the full parent live set
against the named parent's authenticated registry storage root. Parent-tip body,
configuration, weights and interval must match exactly. Genesis installs the
root entry before the operational clock starts; bootstrap uses that entry's start
for selection. Delta closes the former tip at the first actual successor, even
when that successor expires before the final projection. No member injection or
peer boolean grants authority.

The fresh root input has exactly twelve fields: the existing eleven-field
canonical input followed by bstr32 b1UpdateHash=SHA256(Update). The companion and
build input carry a `b1Update` DATA field. All existing transitions remain bound.
The shared `rootinput.DeriveV2` API requires B1 derivation for every fresh parent;
a direct caller cannot obtain an unbound fresh input. The Engine adapter derives the same Update on build, import,
retention checks and historical replay/recovery, comparing exact Update and root
input bytes before execution. Sealing also checks the returned job's Update,
input commitment and maximum gas. Empty user blocks still carry Update; legacy
quiet echoes are refused for B1. Archives retain Update in the canonical companion.
Raw non-Update companion fields must fit OtherCompanionBytes; Update has its own
C_max reservation. Rust's matching wire change belongs to PR4.

`registryproof.FreshB1` is only a local Go API discriminator. No version word is
stored, and the fresh path reads only `unicity.seal-registry/` slots. Historical
v1/v2 deployment readers and fixtures remain for existing inactive lanes; they
cannot authorize B1 or parse its fresh allocation. Selecting a historical artifact
alone cannot construct a B1 genesis. Local parent-proof RPC contexts preserve
FreshB1; the existing version-1 peer wire explicitly refuses layouts it cannot
represent. `GenerateB1` requires verified root genesis
and a complete pinned execution profile. Its genesis commitment binds both root
genesis and profile, without embedding its own resulting execution genesis hash.
`B1Origin` reconstructs and validates the complete fixed/dynamic allocation.

Offline export (no deployment):

```
GOCACHE=/private/tmp/gocache-b1pr1b GOMAXPROCS=4 go run -p 4 ./scripts/b1genesis \
  --profile profile.json --root-genesis root-genesis.json \
  --shard-conf unbound-shard-conf.json --out new-output-directory
```

The output contains genesis.json, full shard-conf.json and manifest.json with all
addressed genesis words, including explicit zeros and complete padded members.
Profiles use the JSON representation of `b1state.Profile` (32-byte hash arrays).
The output remains inactive. It does not migrate, backfill or activate old lanes.

Additional parent proofs are bounded before trie work or copying: at most 8390
keys, 64 nodes per proof, 64 KiB per node, 1 MiB per proof and 64 MiB aggregate.
The fetcher receives a copy of the addressed key inventory. The returned proofs
are copied and verified against the already authenticated account storage root.
`B1Words` exports all 35 fixed words, including implicit zeros; `B1Proofs` covers
both those fixed words and every addressed dynamic genesis word.

The sequential guard audit is reproducible with:

```
GOCACHE=/private/tmp/gocache-b1-audit GOMAXPROCS=4 \
  python3 b1paired/testdata/guard_mutations.py
```

It checks its named-test baseline before mutating, restores each source in a
`finally` block and records each result separately. Redundant defensive guards
are reported as uncaught rather than counted as successful mutation checks.
