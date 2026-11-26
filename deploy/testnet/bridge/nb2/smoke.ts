/** Exercise the pinned reference wallet through the package gateway using disposable test value. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { toHex } from '../../../packages/native-bridge-plugin/src/bytes.js';
import { ascii } from '../../../packages/native-bridge-plugin/src/nb2/cbor.js';
import { HE } from '../../../packages/native-bridge-plugin/src/nb2/crypto.js';
import { LocalKeySigner } from '../../../packages/native-bridge-plugin/src/nb2/evm.js';
import { EvmReader, HttpJsonRpc, type JsonRpc } from '../../../packages/native-bridge-plugin/src/nb2/rpc.js';
import {
  burn, GatewayAggregator, mint, planDeposit, planReturn, redeem, resumePayout, sendDeposit, split, transfer, transportRetry, Wallet,
} from '../../../wallet/core.js';
import type { PayerPolicy } from '../../../wallet/recovery.js';

const [phase, work, rpc, authority] = process.argv.slice(2);
const hex = (bytes: Uint8Array) => '0x' + toHex(bytes);
const key = join(work, 'test-key');
const pub = '/work/nb2/public';
const releasePath = join(pub, 'nb2-release.json');
const deployment = JSON.parse(readFileSync(releasePath, 'utf8'));
assert.equal(deployment.status, 'testnet-provisional');
assert.equal(deployment.realValueAuthorized, false);

if (phase === 'key') {
  if (!existsSync(key)) writeFileSync(key, randomBytes(32), { mode: 0o600, flag: 'wx' });
  console.log(hex(new LocalKeySigner(readFileSync(key)).address));
} else {
  assert(phase === 'mint' || phase === 'return', 'wallet smoke phase');
  const result = await walk(phase);
  console.log(JSON.stringify(result, (_, value) => typeof value === 'bigint' ? String(value) : value));
}

/**
 * The package gateway limits each client to 10 requests per second, and since native-bridge-plugins#93 the transport retries a 429 only
 * briefly (three attempts within 5 s) and leaves the waiting to the caller: the plug-in's own `transportRetry`, for idempotent reads
 * only. The smoke is that caller: every read is waited out, a send (`eth_sendRawTransaction`) never is.
 */
function patient(inner: JsonRpc): JsonRpc {
  return {
    call: <T>(method: string, params: unknown[]) => method === 'eth_sendRawTransaction'
      ? inner.call<T>(method, params)
      : transportRetry(() => inner.call<T>(method, params), (why) => console.error('rpc waiting:', why)),
  };
}

async function walk(stage: string) {
  const reader = new EvmReader(patient(new HttpJsonRpc(rpc)));
  const operator = new HttpJsonRpc(authority);
  const genesis = await operator.call<{ hash: string }>('eth_getBlockByNumber', ['0x0', false]);
  assert.equal(genesis.hash.toLowerCase(), deployment.package.genesisHash.toLowerCase());
  const aggregator = rpc.replace(/\/$/, '') + '/aggregator';
  const gatewayAgg = new GatewayAggregator(aggregator);
  const wallet = new Wallet(join(work, 'wallet'), readFileSync(key), {
    release: releasePath, trustBundle: join(pub, 'trust-base.bundle.cbor'),
    trustPin: join(pub, 'trust-base.genesis.entryid'), rpc, aggregator,
  });
  await wallet.open({ aggregator: gatewayAgg, trustFreshnessMs: deployment.trust.freshnessMs, wrapRpc: patient });

  const vault = wallet.bridge.cfg.vault;
  if (stage === 'mint') {
    const before = await reader.balance(vault);
    assert.equal(before, 0n, 'fresh vault');
    await planDeposit(wallet, 'coin', 10n ** 17n);
    const deposit = await sendDeposit(wallet, 'coin');
    const issued = await mint(wallet, 'coin', (why) => console.error('mint waiting:', why));
    assert.equal(issued.amount, 10n ** 17n);
    assert.equal(await reader.balance(vault), issued.amount);
    return { stage, deposit: { ...deposit, txHash: hex(deposit.txHash) },
      mint: { ...issued, tokenId: hex(issued.tokenId) } };
  }

  const first = 6n * 10n ** 16n, second = 4n * 10n ** 16n;
  const recipient = randomBytes(20);
  const balance = await reader.balance(recipient);
  const policy: PayerPolicy = {
    signedBytes: Number(wallet.pins.maxEncodedTxBytes),
    calldataBytes: 393216, gas: wallet.pins.userGasLimit, maxNonce: 1000n, maxFeePerGas: 4_000_000_000n,
    maxPriorityFeePerGas: 2_000_000_000n, feeBudget: 10n ** 18n, archives: [rpc],
  };
  await split(wallet, 'coin', 0, [{ label: 'keep', amount: first }, { label: 'back', amount: second }]);
  await transfer(wallet, 'keep', 'moved', 1);
  const payouts = [];
  for (const [label, amount] of [['moved', first], ['back', second]] as const) {
    await planReturn(wallet, label, recipient, undefined, policy);
    const signed = await burn(wallet, label, recipient, undefined, policy, join(work, `${label}.private.json`));
    const route = label === 'back' ? 'recovery' : 'ordinary';
    const checkpoints = new Set<string>();
    let paid: Awaited<ReturnType<typeof redeem>> | Awaited<ReturnType<typeof resumePayout>> | undefined;
    if (route === 'ordinary') {
      paid = await redeem(wallet, label, 60, 3000, (why) => console.error('redeem waiting:', why), undefined, policy);
    } else {
      const record = await wallet.returnRecord(label);
      for (let attempt = 0; attempt < 120; ++attempt) {
        paid = await resumePayout(wallet, record, policy, false, true);
        if (paid.state === 'paid') break;
        if (paid.state === 'checkpoint') checkpoints.add(hex(paid.txHash));
        else if (paid.state !== 'pending' && paid.state !== 'retry') break;
        await delay(2000);
      }
      assert(checkpoints.size > 0, 'certified recovery checkpoint');
    }
    assert(paid?.state === 'paid', `${label}: ${paid?.state}`);
    const receipt = await reader.receipt(paid.txHash);
    assert.equal(receipt?.status, '0x1', label);
    const tx = await reader.rpc.call<{ input: string }>('eth_getTransactionByHash', [hex(paid.txHash)]);
    const signature = route === 'recovery' ? 'redeemRecovered(bytes)' : 'redeem(bytes,bytes32,uint64,bytes)';
    assert.equal(tx.input.slice(0, 10), hex(HE(ascii(signature)).subarray(0, 4)), label);
    payouts.push({ label, route, amount, eta: hex(signed.eta), tx: hex(paid.txHash), gasUsed: BigInt(receipt!.gasUsed!),
      checkpoints: [...checkpoints] });
    assert.equal(await reader.balance(recipient), balance + payouts.reduce((n, p) => n + p.amount, 0n));
  }
  assert.notEqual(payouts[0].eta, payouts[1].eta);
  assert.equal(await reader.balance(vault), 0n);
  assert.equal((await reader.vaultState(vault)).outstanding, 0n);
  return { stage, recipient: hex(recipient), split: [first, second], transfer: 'keep -> moved', payouts,
    liability: '0', vaultBalance: '0' };
}
