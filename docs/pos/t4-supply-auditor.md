# T4 offline supply auditor (increment 1)

`go run ./cmd/pos-supply-auditor --genesis genesis.json --state-dump certified-state.json`
reads an ordinary geth/reth standard genesis file and a versioned JSON snapshot. It prints
one machine-readable result. Exit codes are 0 for pass, 1 for a detected invariant violation,
and 2 for invalid input or incomplete accounting coverage.

The state snapshot format is `unicity/supply-audit-snapshot/v1`. It must set `fullState` and
`certifiedBlock.certified` to true, include every account's balance, code and storage at the
selected block, and list the WUCT, FeeCollector and vesting-vault addresses. The snapshot
declares `contractsCommit` as `e7eb3216549b772a9e1df2b1214976d7dd9e6e62`; the auditor uses
the storage slots and vault immutable layout from those artifacts. It requires genesis code
and selected-state code to match at each checked contract.

`blocks` contains one header accounting record for every block 1 through the certified
height. Header records include number, hash, parent hash, difficulty, base fee, gas used,
blob gas used and withdrawal count. The auditor verifies a contiguous hash-linked history,
requires zero difficulty, zero blob gas and no withdrawals, and calculates
`S0 - sum(baseFeePerGas * gasUsed) - observed permitted SELFDESTRUCT burns`.
This matches ureth's fee rule: base fees are burned and priority fees are credited to the
FeeCollector. All balance quantities accept decimal or `0x` hexadecimal notation.

The `selfdestructs` array is a normalized list with one entry per transaction/address event.
An entry identifies the transaction, contract, beneficiary, whether creation and destruction
occurred in the same transaction, the opcode, and amount actually burned. Only a
same-transaction-created contract whose beneficiary is itself contributes a burn under
Cancun. Each header must explicitly declare whether its trace list is complete. Missing trace
coverage yields `inconclusive` (exit 2); the auditor reports uncovered blocks and still flags
a balance above the maximum supply allowed by observed burns. Trace completeness and the
certified flag are input-source assertions: this offline tool does not authenticate a
certificate, state root, full-state export, or trace provider.

The report separately checks WUCT `totalSupply <= native balance`, vesting `released <=
principal` and vault balance `>= principal - released`, and FeeCollector treasury credit plus
reward pot `<= native balance`. Native-supply and custody balances cover all accounts in the
state snapshot; the contract metrics are reported separately and are not added to supply a
second time. Increment 2 (controlled devnet reconciliation and public monitoring) is outside
this change.

Synthetic tests cover a valid state, deliberate native mint and unexplained burn, permitted
and non-permitted SELFDESTRUCT handling, incomplete trace coverage, issuance/blob/withdrawal
violations, and WUCT, vault and FeeCollector invariant failures.
