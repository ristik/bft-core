# T5 immutable-code and system-contract dossier

**Draft for independent review; not a signoff.** BFT source pin:
`d2332e10878aefe1c98fab423024491468de3218`. Genesis-contract source pin:
unicity-pos-contracts `e7eb3216549b772a9e1df2b1214976d7dd9e6e62`. Ureth
source pin: `055a314f759f78f045d55ceddfeb7e14b3b6a2f7`. The values below describe
the synthetic allocation example, not a production deployment.

## Code and artifact pins

`registrygenesis/export.go:26,49-51,64-86,92-103,109-168` pins the four genesis
contracts, checks each manifest artifact SHA-256, executes each constructor in a
local EVM, verifies the deployed runtime against its artifact with immutables
substituted, and exports account code/storage. The exporter requires every vault
balance to equal its principal (`:173-204,216-220`) and omits incidental deployer
accounts (`:207-208`). Artifact file hashes cover the full compiler artifact JSON:

| Contract | Solidity source at e7eb321 | Embedded compiler-artifact SHA-256 | Default-example instance runtime code hash |
|---|---|---|---|
| WUCT | `src/WUCT.sol:3-39` | `d7d80b17a53c4889e76b8986e9169f2cba272309965e1f032218ebbaa9aca0db` | `0x551f2bd38d5574ba25f42a217d22c85f468794c5d18365410340bf115c291e5f` |
| FeeCollector | `src/FeeCollector.sol:3-68` | `f07711f6a837683628043408949c6e5443e4d1655df3ce66249a5279570fe58a` | `0x73c983e6f521aefed98e3c7f2c4face3ce8cb6c77c2d0aca0de22347c8250eb1` |
| Team ImmutableVestingVault | `src/ImmutableVestingVault.sol:3-78` | `18d059fae21cc9adc34fe825cb3997a0bde32f128e02551dd48e35ffecb9b242` | `0x5b5f31ccdda2a17f4161c71336e26aaae3b19eeff2f3ec6c71386a9be55ce4b3` |
| Ecosystem ImmutableVestingVault | same source | same artifact SHA-256, checked independently per manifest entry | `0x57147941a002fab8675efd2fc7c20fe508afc9bbc49f87ac9313d29b39af39c1` |

Instance hashes above are for
`registrygenesis/testdata/allocation-build-v1.example.json` at BFT source pin
`d2332e10`; constructor immutables change their runtime hashes. The exporter
verifies these at generation time. Source does not contain the instance-specific
patched runtime as a reusable template.

## Immutables, state and permissions

| Contract | Immutables and exact Solidity storage layout | Externally callable authority |
|---|---|---|
| WUCT | No Solidity immutables. Artifact layout: `_balances` slot 0; `_allowances` slot 1; `_totalSupply` slot 2; `_name` slot 3; `_symbol` slot 4; inherited `_status` slot 5. | Any caller may deposit native value and mint the same amount. A holder withdraws only its own tokens; `_burn` happens before the native transfer. No owner, privileged mint, permit or reserve drain (`WUCT.sol:8-39`). |
| FeeCollector | `treasury` and `treasuryShareBps` immutable (`FeeCollector.sol:22-23`); compiler immutable-reference AST IDs 45652 at byte offsets 472,579 and 45654 at 234,888, each 32 bytes. Storage: `_status` slot 0, `treasuryCredit` 1, `rewardPot` 2, `totalTreasuryCredits` 3, `totalTreasuryPaid` 4. | `split()` is permissionless and classifies unallocated balance; only immutable treasury can pull its credit (`:39-68`). No owner or governance withdrawal. |
| ImmutableVestingVault | `recipient`, `principal`, `start`, `cliff`, `duration` immutable (`ImmutableVestingVault.sol:19-23`). Compiler immutable-reference AST IDs/byte offsets: 45838: 487,1142; 45840: 336,558,1013,1057; 45842: 277,846; 45844: 687,893; 45846: 753,948 (32 bytes each). Storage: `_status` slot 0, `released` slot 1. | Anyone may call `release()`, but funds go only to immutable recipient. No owner, recipient change or rescue. Donations are surplus and do not raise principal (`:44-78`). |

The compiled layouts are embedded at
`registrygenesis/testdata/t1-artifacts/{wuct,fee-collector,vesting}.json`; their
SHA-256 values are listed above. The same values, slots and immutable references
are therefore reviewable without guessing Solidity inheritance layout.

The synthetic manifest fixes these constructor arguments for the default
example: FeeCollector treasury `0x1000000000000000000000000000000000000001` and
share 10,000 bps; team vault recipient
`0x1000000000000000000000000000000000000005`, principal
`200000000000000000000000000`, start 0, cliff 31,536,000, duration 126,144,000;
ecosystem recipient `0x1000000000000000000000000000000000000006`, principal
`300000000000000000000000000`, start 0, cliff 0, duration 126,144,000.
WUCT has no constructor arguments. These are example inputs from manifest lines
68-104, not production selections. Constructor storage begins with WUCT supply
zero and name/symbol initialized; FeeCollector status 1 and all liability/counter
slots zero; and each vault status 1 and released slot zero. The vault account
balances are exactly their respective fixed principals.

## SealRegistry and system caller

`a_sys = 0xff00000000000000000000000000000000000001` is a reserved caller identity,
not a contract allocation. `a_sr = 0xff00000000000000000000000000000000000002` is the
SealRegistry predeploy (`registrygenesis/registrygenesis.go:57-58`;
`registryproof/registryproof.go:61-86`). The registry artifact is
`registrygenesis/seal-registry-v1.json`, SHA-256
`3e8e0c1d5088a2963e086a098001d49c0ffd4bf8c54ce15ea766652d51f75faa`, code hash
`0x18b4c874e37d8563c1f672b6da073f009cd6a03bc9bfde886cc4743db6c14d3c`.
The same artifact bytes occur at contracts commit e7eb321; the source file is
`src/SealRegistry.sol` (SHA-256
`e50d959c0734f179a7cf9d0634f202ee67151a8ed0c0a54770374e9f5f0f1b25`).
The embedded-artifact provenance comment in
`registrygenesis/artifact.go:14-18` still names commit
`6b4e221737c13a645400b9e19dd5259d02e5cc5c`. The artifact bytes at that commit
and e7eb321 have the same SHA-256, and SealRegistry.sol is unchanged between
those commits; retain this explicit provenance check when updating the pin.

There are no Solidity state variables or constructor. The genesis allocation
writes the initial six words: `layoutVersion`, `genesisCommitment`,
`config.shardConfHash`, `assignment.epoch`, `assignment.rootEpoch`, and
`phase=2` (`src/SealRegistry.sol:13-20`). The 28 namespaced keys in the pinned
artifact are:

| Field | Key | Field | Key |
|---|---|---|---|
| `layoutVersion` | `0x79b704796b8c2ee2cf835e5113e27bbaf138c9831ce0b1cc259966898323094a` | `genesisCommitment` | `0x1dc271a4e4328f3a46506e6e6e1db1488418d59ca41e005534ed0eda129e6150` |
| `config.shardConfHash` | `0xabe1d0722ec7cab6bc8be8343a4900e571bdb46fad619947267449a2b9aa7497` | `assignment.epoch` | `0x7671d07e8accfd833bdccd596ad3a1c4a402a090b727f511a073a2498c590ae5` |
| `assignment.rootEpoch` | `0xe77628dabc86b477c0db337bda981ad320031675934be9c596d69ebbc20f1a24` | `clock.rootRound` | `0xc3adc23527bab9702dd784bd0b145d2ab1a7dce35235a0db3dbfd3da7a53143d` |
| `origin.rootEpoch` | `0x1dfe98fa5011e0dbfdfc5efa804744e3497514271b58499de63781a9941c9a51` | `origin.timestamp` | `0x459cf503c328e501962bcf0cd8ca53327ab531deeb9155c48d827d2478932c6c` |
| `origin.treeRoot` | `0x8af142b0300add3b2aec220298bb445eb0c9884bb45fcd5059be6fcd18e7090d` | `origin.identity` | `0xbee6419aa5a12f10d4794669dbd882527b590089e967b14012543a23e0b78e72` |
| `origin.trHash` | `0xe58f62addabf9360d9fcddf3db70a93d2b2ba476996540ecefbbed5ee3cc9c80` | `round.authorized` | `0x14386166497930a3efb28f5976da18bcbf7bec69c7b2c449c3ce32552f037844` |
| `input.commitment` | `0xa0cbe06c0b5a76b8d67341bd1bd8f162e5d5c6aea162604a10cec0dce4e0d060` | `certified.round` | `0x47a3f86feb14af4a7e5a1a1fb3362c95b32dfbf03a7a3ca31717f8e829382b3c` |
| `certified.stateHash` | `0xe39f0827feecb5f38ffbd452e7c3556ecd0ba586a94434c3f5a10f846cbbfcea` | `certified.hasBlockHash` | `0x1b118c38b50e4765caa320a933997b81ec1218283e0c260e18a4609340314deb` |
| `certified.blockHash` | `0x80ce058bdccaa08590781edd25c9005041ebaba94b6a8941896d46eb60394931` | `phase` | `0x2d5c30492e4b770265db26c3b2d89794cb0435f97f91a351ae818c18236222a7` |
| `outcomes.round` | `0xa6dfb02f4e0457f6dc0ca8f4fd82b31c4a0df5261e0214610377f2af855a5ee5` | `outcomes.commitment` | `0x435c00c3e0bb551759ef849ef59de7b0a62c300b5c1aa3011d4363b09ddef85a` |
| `transition.cursor` | `0x9071048d24ef915056944fc390854c5afc82c7b780af60912f32c98b8a009850` | `inbox.consumed` | `0x902fa8def05f8c67caa8c59344f53ee4ebbc428d5073e5fbf37e23543232cae5` |
| `transition.bodyID` | `0xf64ae08ca348865e7c42acf81d3a418af899eeafa1c21504ea348c15d212c4b8` | `transition.genesisID` | `0xdedd17782b4935024a9ff293bbd39d406d127447bf3b1d6ed496032fa0cd58e5` |
| `transition.frozenID` | `0xa17f343c4f400f901a88319ee38011c1770dfd251fb8f2afb0e66b3ac0e3d1a5` | `transition.commitID` | `0xecd1c378aba52fc330dbbc613de4db55413282426cdedf09fd6ed57a76bc90b5` |
| `transition.frozenParent` | `0xf4f5ae5954831b1d1559d70dc2cabdc751ef64cc34ab0750efbd97479665f06a` | `transition.successorTR` | `0xaf0d5400378db3d13018c5af67f324d41d95126cd3f97f3e3b4ac05ba9afdaeb` |

`open` and `finalize` permit only the `a_sys` caller
(`src/SealRegistry.sol:32-35,132-164,221-229`). The contract explicitly does not
enforce reverted-call block rejection, system-call ordering/count, post-block
phase, system gas accounting or faithful authenticated-input projection
(`src/SealRegistry.sol:26-31`); those are execution-client obligations. BFT
pins the compiler/profile, caller, all keys and code hash in
`registrygenesis/artifact.go:58-90`.

## Addresses, compiler and chain profile

The synthetic manifest is
`registrygenesis/testdata/allocation-build-v1.example.json`. It uses native
supply `10^27`, chain ID `1337`, Cancun-at-genesis forks, TTD `0` already passed,
30,000,000 genesis gas and 1,000,000,000 wei base fee (manifest lines 3-26).
These values and the allocation entries are inputs, not constants; the production
chain ID, supply, allocations and activation profile require owner selection.

| Purpose | Synthetic address |
|---|---|
| System caller `a_sys` | `0xff00000000000000000000000000000000000001` |
| SealRegistry `a_sr` | `0xff00000000000000000000000000000000000002` |
| FeeCollector / fee beneficiary | `0x9B137463d4E7986D7f535f9B79e28b4EF1938E9b` |
| WUCT | `0x2387b3383E89c164781d173B7Aa14d9c46eD2642` |
| Treasury | `0x1000000000000000000000000000000000000001` |
| Team vault | `0x22bc2df58D96CBc5f2599f2C25D1E565974749EE` |
| Ecosystem vault | `0x7bBCFa8c109B0a6888d3329a6B762Ad4782e0B26` |

`registrygenesis/manifest.go:352-421,430-483,512-568` requires the pinned
system/registry addresses, distinct nonzero contract addresses, fee-beneficiary
equality with FeeCollector, exact supply sum and rejection of precompiles
`0x...01` through `0x...0a`. These rejection checks also apply to allocations and
bootstrap gas recipients. The code at `a_sys` is not allocated as a contract;
the registry is generated through the existing standard-JSON path
(`registrygenesis/genesisjson.go:150-185`).

All contracts use Solidity 0.8.37, Cancun, optimizer enabled with 200 runs,
via-IR, `bytecode_hash = "none"`, `cbor_metadata = false`, and emitted
`storageLayout` (`unicity-pos-contracts/foundry.toml:10-35` at e7eb321).
SealRegistry's runtime code hash is pinned in its artifact. The manifest example
chain ID is 1337; runtime chain ID is also bound to the shard configuration and
must match the finalized genesis (`registrygenesis/registrygenesis.go:48-58,265-275;
`registrygenesis/genesisjson.go:166-172`).

## Immutable-defect recovery boundary

WUCT, FeeCollector and each vault have no proxy, owner or code-replacement entry
point. Their constructor values are in runtime bytecode. A wrong immutable cannot
be edited in place. Before public issuance, reject the affected genesis and
regenerate it from a corrected manifest and reviewed artifacts. After funds have
entered a deployed contract, this repository has no general migration or rescue
mechanism: WUCT holders can withdraw their own backing, the fixed treasury can
pull only its FeeCollector credit, and a vault can release only to its fixed
recipient. A bad recipient/schedule can therefore lock value. Any post-launch
recovery requires a separately reviewed protocol migration with explicit
accounting and owner authorization; do not promise it exists today.

SealRegistry likewise has no proxy or upgrade authority. Replacing a defective
registry requires a new code hash and genesis commitment, then a reviewed
software/chain migration; no secret system key can rewrite its bytecode. The
execution client is responsible for enforcing the system-call rules that the
contract itself cannot enforce. Independent T5 reviewer signoff and final
production parameter selection are still required.
