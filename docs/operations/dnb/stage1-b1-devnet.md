# DN-B stage 1: B1/B2 paired devnet (evidence)

ureth 634bcc28b2e38b5f8caa435e41bc1cb0a66bf958 (release, built locally, sha256 5135a27d327ff32845cd7f94159324251cc5a127828505d7332a4934ded3a1d3); bft-core branch dnb/b1-activation (code commit 4a10152)

```
wrote test-nodes/b1-profile.json
profile hash:    0xcca7473a34b5198474246addf21b090e893a707b15a6b23487065e5b073d2cff
ureth flags:     --unicity.network-id=3 --unicity.root-genesis-id=0x499904de46ec9b3d18bd6968f6837bece833e59b333d6e2588b9067f07de3d03 --unicity.chain-id=31337 --unicity.profile-hash=0xcca7473a34b5198474246addf21b090e893a707b15a6b23487065e5b073d2cff --unicity.w-cert=1 --unicity.max-gas=41789324 --unicity.system-gas=34789324
wrote test-nodes/genesis-identities.json (genesis identities)
wrote test-nodes/evm-genesis-finalized.json (chainId=31337, shanghai+cancun at genesis, registry account at 0xff00000000000000000000000000000000000002)
wrote test-nodes/evm-full-shard-conf.json (full shard configuration)
registry layout:            3 (code hash 0x28ebc47d5beeb45307cb92ff1521be6a5623d4e4fa1721bc13a6f755cdf0781c)
full shard conf hash:       0x9f790500013db04b53cd17fcadadd532b0d865fff7577915f59092a9add2e276
state root:                 0x6ed8f653ac180dfc4101f45a5718ff918b07a5067879626b690ee4b2ed6c0b40
block hash:                 0xb9bb01fb5f584e8dd3eb0efe5d01ffbdbbc5ef695806b6dac650365c8333b45d
execution config identity:  0x789e09cf2fe624921fc5cc0680ab81af67198403770a0edad001cacee5b63104
origin identity:            0xbde3a8db9bc53c6e83e7a5719ae032bd2aa8af990f6953d95fa75d8bd2ffd108

status:
reth1 block=21
reth2 block=21
reth3 block=21
reth4 block=21
root round 116

registry b1.profileHash (eth_getStorageAt, reth1): {"jsonrpc":"2.0","id":1,"result":"0xcca7473a34b5198474246addf21b090e893a707b15a6b23487065e5b073d2cff"}
eth_config precompiles:
  unicity-b1-Member 0x0000000000000000000000000000000000000102
  unicity-b1-Shared 0x0000000000000000000000000000000000000101
  unicity-b1-Uc 0x0000000000000000000000000000000000000100
  unicity-b2-sdk3 0x0000000000000000000000000000000000000104
```

Reproduce (hold the shared devnet lock, `briefs/devnet-lock.sh`): `URETH_BIN=<unicity-reth at 634bcc28> scripts/dnb-devnet.sh up`, then seed one paid
transaction into every reth mempool (`go run ./scripts/evmtx -send -eth-url ... -nonce 0`): P2P transaction propagation is off in this stack.
The four reth clients reach the same height, certified by the four-root profile-2 chain, with the fresh-B1 registry (layout 3) at genesis and
B1 0x0100/0x0101/0x0102 and B2 0x0104 registered (0x0103 stays unregistered).

What this stage needed (found by running it, none was visible from unit tests): the execution-profile check now expects exactly the four Unicity
precompiles on a B1 deployment; `b1Update` is always on the wire (ureth's decoder requires the field; it was `omitempty`); the pair binding is wired
for a B1 node (`wireQ3Pair`); ureth's `--builder.gaslimit` must equal the profile's `maxGas`.
