# Unicity public testnet: instructions for an external tester

**Test assets have no real value.** UCT here is disposable gas. The network operator may reset the network at any time, without notice, compatibility or migration, and
every balance and transaction is then gone ([NOTICE](../../../deploy/testnet/NOTICE.txt)). Never use a key that guards anything valuable; make a new one for this network.

The operator publishes four things with every generation: the **RPC URL**, the **faucet URL**, the **chain ID** and the **block-zero hash** (also in the public
`manifest.json`; the faucet page shows the same two values). This page uses `<rpc-url>`, `<faucet-url>`, `<chain-id>` and `<genesis-hash>` for them. If the operator
announces a reset, all four may change: re-read them and do not reuse the old wallet configuration.

## 1. Check that the endpoint is the published network

```sh
python3 deploy/testnet/tester-check.py --rpc <rpc-url> --chain-id <chain-id> --genesis-hash <genesis-hash>
# or, with the manifest the operator published (a file, or the faucet's <faucet-url>/api/network):
python3 deploy/testnet/tester-check.py --rpc <rpc-url> --manifest <faucet-url>/api/network
```

It needs only Python 3 and sends no transaction. `ok` on chain ID, `net_version` and block-zero hash means the endpoint serves the published network. Exit status 1
and a line starting `FAIL` means it does not (a wrong URL, or the network was reset since you copied the values): stop and do not sign anything for it. Exit status 2 means the
endpoint or the values could not be read. `--wait 30` additionally requires a new block within 30 seconds; an idle chain makes no blocks, so that is optional.
The check proves identity, not safety: it cannot tell a malicious endpoint that repeats the published values from the real one, so take the values from the operator's channel, not from the endpoint.

## 2. Make a wallet for this network

Any EVM wallet works. Add a custom network with:

| field | value |
|---|---|
| network name | any (for example "Unicity testnet") |
| RPC URL | `<rpc-url>` |
| chain ID | `<chain-id>` |
| currency symbol | `UCT` (18 decimals) |

Create a **new** account for it. The gateway does not serve `eth_feeHistory`, so a wallet that cannot estimate fees without it needs a legacy (gas-price) transaction: choose that option, or set the gas price by hand (`eth_gasPrice` returns it). A wallet that pinned a previous generation's chain ID or block-zero hash is wrong after a reset; remove that network and add it again.

With command-line tools (Foundry's `cast`):

```sh
cast wallet new                      # prints an address and a private key; keep the key private
export ETH_RPC_URL=<rpc-url>
cast chain-id                        # must print <chain-id>
cast block 0 --field hash            # must print <genesis-hash>
```

## 3. Get test UCT

Open `<faucet-url>`, connect the wallet (it must be on this network), solve the captcha and claim. A claim gives 0.01 UCT, once per wallet and IP every 24 hours, subject to
availability. The faucet refuses an address that is not valid and a wallet pinned to another chain or block-zero hash, before it asks for the captcha. Wait for the transaction
it reports to have a successful receipt:

```sh
cast receipt <tx-hash> --rpc-url <rpc-url>     # status 1 (success)
cast balance <your-address> --rpc-url <rpc-url>
```

## 4. Send a transaction

```sh
cast send <recipient-address> --value 1000000000000000wei --legacy --private-key <your-key> --rpc-url <rpc-url>
```

`--legacy` is needed: without it `cast` estimates EIP-1559 fees with `eth_feeHistory`, which the gateway does not allow (it serves `eth_gasPrice` instead), and the send fails.

The gateway accepts the ordinary read methods and `eth_sendRawTransaction`; it refuses signing, admin and Engine methods, batches and bodies over 16 KiB, and answers `429`
above 10 requests per second per client IP, and the gateway also has a 100 requests per second budget for everyone together, so a busy network can answer `429` below your own 10 per second. Wait a second and retry. A receipt with status 1 means the transaction is in a block. To check that the block is certified by the network, compare a
block's hash on your endpoint with the operator's status page for the same height.

## 5. What to report

Report to the operator's published reporting channel (the incident owner role answers it): the chain ID and block-zero hash you used, the UTC time, the transaction hash
or request you sent, the response you got, and the output of `tester-check.py`. Do not send private keys.
