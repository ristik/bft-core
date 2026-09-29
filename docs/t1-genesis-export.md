# T1 constructor executed genesis export

The allocation/build manifest is the review input. To materialize contract accounts, run the pinned constructors offline before invoking the existing genesis compiler:

```sh
ubft engine-api export-manifest \
  --manifest allocation-build-v1.json \
  --out allocation-build-v1.exported.json
ubft engine-api genesis \
  --shard-conf shard-conf.json \
  --manifest allocation-build-v1.exported.json \
  --out genesis.json
```

`export-manifest` uses the compiler artifacts embedded under `registrygenesis/testdata/t1-artifacts`. They were built from `unicity-pos-contracts` commit `e7eb3216549b772a9e1df2b1214976d7dd9e6e62` (contracts #3 and #4 merged). The manifest records each artifact SHA-256 and source commit. Regenerate the bundles only from that pin, using the repository's pinned Foundry configuration and `forge build --force`.

The export executes FeeCollector, WUCT, team vault, and ecosystem vault constructors at the manifest's fixed deployer, first nonce, block number, and timestamp. CREATE addresses must match the addresses in the manifest. The FeeCollector constructor receives the declared treasury and split ratio. Each vault receives its allocation recipient, exact principal, and schedule. Each vault is then funded with exactly its principal; the exporter refuses a balance mismatch. A vesting beneficiary must be an EOA with no code, or a declared deployed contract whose ABI has a payable receive/fallback and whose EVM value-transfer probe succeeds.

The exported account state contains runtime code, its Keccak hash, account nonce, and initialized storage. The code is compared with the pinned runtime template after masking only compiler-declared immutable byte ranges. This preserves constructor-set immutables. In particular, vault storage slot 0 is exported as the constructor initializes ReentrancyGuard. Temporary deployer funding is not emitted: only manifest allocations enter the compiled genesis. Zero-value FeeCollector and WUCT allocations carry their deployed code and storage without changing `nativeSupply`.

Export is deterministic: repeated execution over the same manifest and embedded artifacts produces byte-identical output. The existing `engine-api genesis --manifest` path compiles exported code, storage, and balances into the standard JSON pipeline, then `PrepareGenesisJSON` adds the pinned registry account and derives the full shard configuration.
