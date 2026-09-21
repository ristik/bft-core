# F3 (#11) acceptance ledger

What this is: a reconciliation of #11's work breakdown and acceptance list against the units
delivered under `docs/design/f3-engine-seal-delivery.md`, naming the pull request and the exact test
behind each claim, and what each one does not show.

What it is not: a closure of #11. The ledger is written by the party that did the work, so it is a
proposal for review. §4 states why #11 cannot close and what would have to change.

Base: `integration/enshrined-evm` at the #205 merge, and `ristik/ureth` `unicity/main` at the #20
merge.

## 1. The units

| Unit | Delivered as | Scope |
| --- | --- | --- |
| U3a | ureth #12 | canonical `RootInputV2` decoder, the JSON seal envelopes, binding to `BoundExecutionInput` |
| U3b | ureth #15 | `UnicityEngineTypes`, the bounded job registry, `UnicityNode`, the published builder configuration |
| U3c | ureth #16 | `engine_forkchoiceUpdatedWithSealV1` |
| U3d | ureth #17 | `engine_getPayloadWithSealV1` |
| U3e | ureth #18 | `engine_newPayloadWithSealV1` validation and the parent-accounting token |
| U3f | ureth #19 | canonical insertion: per-block execution dispatch and the engine forward |
| U3g | ureth #20, bft-core #205 | capability advertisement and the opt-in adapter requirement |

Plan and its corrections: bft-core #201, #202, #203, #204.

## 2. The work breakdown, line by line

### 2.1 "Implement the protocol call and matching builder/import validation hooks in the approved reth fork"

**Substantially met.** The bounded kernel executes exactly one privileged `open` and one `finalize`
in the accepted positions, projects their calldata from the verified input, enforces failure
invalidity and `g_sys`, and rejects other `a_sys` transactions
(`crates/unicity/execution/src/lib.rs`; `missing_wrong_code_oog_and_revert_publish_no_state`,
`privileged_calls_do_not_apply_eoa_or_fee_side_effects`,
`pre_refund_gas_is_combined_and_storage_reset_refund_is_not_credited`). The builder hook is the
per-job `UnicityEvmConfig` reached through `UnicityExecutionPayloadBuilder`; the import hook is the
per-block dispatch added in U3f, which fails with a named error when no execution input is
registered and never falls back to stock execution.

**What it does not show.** See §3.1: the reserved-sender and prefix-position rules that make the
call unimpersonatable are implemented and unexercised.

### 2.2 "Extend Engine API and companion-data persistence/transport with explicit version negotiation"

**Engine API: met.** Three sibling methods exist on `UnicityNode` as a jsonrpsee trait in
`crates/unicity`, with no upstream file edited. Version negotiation is explicit: the three
capability strings are advertised atomically (ureth #20) and bft-core requires them together behind
`Client.RequireSealCapabilities()` (#205), with four tests fixing that boundary.

**Companion persistence and transport: not met.** `getPayloadWithSealV1` returns a companion, but
nothing persists one and nothing transports one between nodes. D2 §"Companion retention on sync"
requires retention against a published horizon and archival serving for historical import and proof
export. No unit delivered either, and no unit claimed to.

### 2.3 "Run real-reth malicious-builder, synchronization and replay tests with positive-fee user transactions"

**Not met, except the replay half.** `build_replay_and_opaque_parent_token_agree_across_two_blocks`
(`crates/unicity/execution/tests/block_adapter.rs`) builds and replays two blocks with a nonzero base
fee and signed, paying user transactions, and agrees on the opaque parent token across both.

There is no real-reth run of anything in this ticket: every unit is compile-checked and unit-tested,
and nothing boots a node and speaks Engine RPC. There is no malicious-builder test, and no
synchronization test.

## 3. The acceptance list, line by line

### 3.1 "an ordinary transaction cannot impersonate or repeat the call; call failure and missing data invalidate a block; a nonzero-base-fee block with the system call and paid user transactions builds and replays identically"

Three clauses with three different verdicts.

**Impersonation and repetition: implemented, not tested.** `block_executor.rs` refuses a transaction
whose signer is `SYSTEM_CALLER` ("reserved sender") and refuses an ordinary transaction positioned
before the system prefix. I could not find a test for either, and two independent observations
support that rather than a keyword search alone: `block_executor.rs` contains no `#[test]` block at
all, and no file under `crates/unicity/*/tests/` references `SYSTEM_CALLER`. The only test naming
that address asserts that a privileged call leaves the account unchanged, which is a different
property. This is the clearest gap in the ticket, and it is the clause that carries #11's
"do not simulate this by signing an ordinary transaction with a shared private key".

**Call failure and missing data: met.** `missing_wrong_code_oog_and_revert_publish_no_state` covers a
missing registry, wrong code, out-of-gas and revert, each publishing no state. Missing data on the
import path is U3f's named refusal, asserted in `crates/unicity/payload/tests/execution_payload.rs`,
with no fallback to stock execution.

**Build and replay identity: met**, by the test named in §2.3.

### 3.2 "A syncing node obtains and verifies companion data before declaring the block valid"

**Not met, in both halves.**

It does not *obtain*: devp2p sync of seal blocks does not work, because nothing populates the
execution-input registry on that path, so a block from a peer fails with U3f's named error. D2
expects a devp2p importer to re-derive the verified inputs and re-run the check through a different
entry point, which no unit built.

It does not *verify*: the execution client is not the verifier on any path, which is correct and
settled (plan §4), so verification belongs to the shard-node adapter. bft-core does not yet call the
seal methods at all, and `VerifyCompanionWitnesses` has no caller in the adapter. That work is
activation and belongs to #10.

### 3.3 "The same rule is tested with a malicious builder"

**Not met.** No malicious-builder test exists in either repository for this ticket. Searching both
trees for the term finds only `f1-baseline.md`, which is F1's fault matrix and not this rule.

## 4. Proposal

1. #11 **cannot close**. Two acceptance clauses are unmet in full (§3.2, §3.3), one is unmet in its
   most important half (§3.1 impersonation), and one work-breakdown line is unmet apart from replay
   (§2.3). Companion persistence and transport (§2.2) has no delivery at all.
2. The smallest honest next step is §3.1's missing tests. The rules exist and are one test file away,
   and they are the clauses that make the privileged call privileged. Nothing about them needs a
   running client, so they do not wait on M1.
3. The remaining gaps split into two kinds. **Testable now**: malicious builder (§3.3), which is a
   builder that emits a forged system sender or a misplaced prefix and must be rejected on import.
   **Needs a running deployment**: real-reth runs, synchronization, and the companion transport and
   retention that a syncing node would use. The second kind is M1's gate under #41, and this ledger
   does not propose doing it here.
4. Closing #11 would discharge none of these: #10's activation of the seal path, D2 §7's `v0`
   removal, the devp2p import entry point, or any Measured evidence.

## 5. What this ledger does not do

It does not re-verify D2's own acceptance, which is recorded separately. It records no maintainer
decision: per `docs/pos/PROCESS.md` closing a ticket needs a named decision and a closing comment
linking final PRs and residual limits, and this document is neither.

## 6. Addendum: what ureth #21 changed

Added after the ledger merged, because §3.1 and §3.3 no longer describe the repository.
Base moves to `ristik/ureth` `unicity/main` at `739ecf57` (the #21 merge).

**§3.1 impersonation and repetition: now met.** `crates/unicity/execution/tests/block_adapter.rs`
covers both through the import path: `import_refuses_a_block_that_forges_the_system_sender` and
`import_refuses_a_repeated_system_sender_after_the_legitimate_prefix`, the second running a
legitimate paying transfer first so repetition is confirmed rather than inferred from the
reserved-sender rule. Every case asserts the exact refusal message, because mutating a validated
block changes its hash, state root and receipts, and a test asserting only "some error" would pass
for an incidental reason.

**§3.3 malicious builder: now met, for the rules a block can express.** The two tests above are the
malicious-builder cases: a builder emitting a forged system sender, and one emitting a repeat. A
misplaced prefix is not expressible as a block on this path, which is the next point.

**Two rules turned out to be unreachable from the import path**, and recording that is the more
useful result than the tests themselves:

- *Ordinary transaction before the system prefix.* `execute_one` always calls
  `apply_pre_execution_changes` before any transaction, so no block can put an ordinary transaction
  ahead of the prefix. The rule is exercised at the executor directly
  (`executor_refuses_an_ordinary_transaction_before_the_system_prefix`) and is defence-in-depth for
  a direct executor caller, not the import path's protection.
- *Blob rejection.* `validate_fixed_block` requires `blob_gas_used == Some(0)` and
  `validate_cancun_gas` rejects the mismatch before execution.
  `import_rejects_a_blob_transaction_at_the_header_blob_gas_check` asserts the import path is
  protected by the blob-gas-mismatch message and **explicitly not** by the executor's message, so a
  refactor that deleted the earlier check and relied on the later one would fail the test rather
  than pass quietly. `executor_refuses_a_blob_transaction` keeps the executor rule covered.

**Unchanged by #21**: §2.2 (companion persistence and transport), §2.3's real-reth and
synchronisation halves, and §3.2. §4's conclusion that #11 cannot close still stands.
`f3b-companion-retention.md` plans the §2.2 persistence and serving halves; the rest needs a running
deployment and is M1's under #41.

One non-test change was disclosed with #21: `reth-evm` and `reth-evm-ethereum` gained the `std`
feature in `crates/unicity/execution/Cargo.toml` so the crate compiles standalone. Combined builds
already enabled it through feature unification, so no behaviour changed.
