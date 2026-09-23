# D2-A: configured-origin execution journal contract

2026-09-23. This is the M1 data and admission boundary. The replay coordinator and runtime readiness gate are D2-B; authority process setup and the restart lane are D2-C. No wire or consensus encoding changes are made here.

## Durable objects

`--execution-journal` opens the configured-origin v2 Bolt database. Its descriptor binds the finalized genesis origin, full shard configuration, B0 and S0, execution configuration identity, root input version and registry layout. `journal/meta` binds the same descriptor to journal format version 1 and fixed limits. The journal is enabled only at revision zero or reopened with the same marker and limits; there is no automatic import from the legacy LUC or certified-record files. Operators use fresh D2 lane state unless a separate verified import is reviewed.

Each `journal/c/<block hash>` stores the full `Block.Raw` dissemination envelope, hash, parent hash and number, state root, sizes, candidate round, original authorizing UC/TR, a `LocallyBuilt` bit, and status. A candidate begins at status 0. Admission changes it to status 1 and attaches the **resulting** UC/TR that certifies its block hash and state root. These are two distinct authenticated pairs: the original pair derives the block's canonical root input for replay, while the resulting pair authorizes finality. A locally built candidate for one authorization is immutable across a restart; a different local hash is refused before publication. Follower side branches at the same height remain separate candidates.

Each `journal/o/<root round><partition round>` stores an authenticated resulting UC/TR and its exact block-hash target. A quiet or bootstrap certificate has no target. If a non-quiet certificate arrives before its body, the observation is committed with `Unresolved=true`; no round delivery occurs while any certified target is unresolved. Later retention of the exact candidate resolves the observation and attaches the resulting pair in one transaction. The configured-progress control and journal observation/association are written in the same Bolt transaction, before the live BFT client cursor advances or execution Commit runs.

On startup, the configured descriptor, marker, every candidate, every observation, both UC/TR bindings, candidate/result associations, origin, and latest progress are reverified under the configured root trust. A corrupt, foreign, unsupported-version, conflicting, incomplete, or over-capacity image is refused. The complete history is scanned only within its explicit private-lane cap; it never grants execution readiness by itself.

## Ordering and limits

The leader retains after Seal and before Publish. The follower retains after Await and before Engine Verify or any certification signature. A failed write stops that round before exposure. Configured admission authenticates, persists progress and the resulting association, then delivers to Round. The remote signing authority remains the separate non-equivocation authority; restoring a journal marks local-key processes non-voting. The authority must remain alive across shard restarts.

Defaults: 256 candidate bodies, 512 certificate observations, 64 MiB aggregate journal values; per-candidate raw bytes at most 8 MiB. Implementation ceilings are 4096 candidates, 8192 observations and 128 MiB. No M1 pruning is allowed. Capacity refusal is explicit and leaves the prior transaction intact. D2-B must keep Build/sign closed until the executor's exact head equals the certified anchor; this data layer neither claims readiness nor imports missing payloads.

Go fault-injection tests stop candidate and admission transactions at their named precommit points and reopen the database. They cover candidate versus certified status, original versus resulting pairs, byte-identical body retention, UC-before-body resolution, quiet tails, same-height branches, cap refusal, corrupt/foreign/versioned records, and the leader's no-publish/no-sign behavior when retention fails. Power-loss and filesystem guarantees beyond Bolt's normal sync contract are deferred with the D2 lane policy.
