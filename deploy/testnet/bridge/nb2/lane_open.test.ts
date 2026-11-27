/**
 * A stale wallet lock left by a killed driver command does not block the next lane command (bft-core#1176 review R2-1). Offline, against
 * the plug-in's simulator, in the bridge tools image as the driver runs:
 *   npx --no-install tsx --test tests/live/nb2lane/lane_open.test.ts
 */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { toHex } from '../../../packages/native-bridge-plugin/src/bytes.js';
import { key, setup } from '../../../packages/native-bridge-plugin/test/nb2/world.js';
import { Wallet, connectionOf } from '../../../wallet/core.js';
import { LANE_OPEN } from './lane_open.js';

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const hex = (b: Uint8Array): string => `0x${toHex(b)}`;

test('a lock left by a killed driver container does not block the next lane command', async () => {
  const s = await setup();
  const pub = mkdtempSync(join(tmpdir(), 'nb2-lane-'));
  dirs.push(pub);
  const pins = {
    gamma: hex(s.pins.gamma), build: 'test', vaultRuntimeCodeHash: hex(s.pins.vaultRuntimeCodeHash), maxEncodedTxBytes: 524288,
    userGasLimit: '60000000', gasReserve: '500000', returnReserveSegments: 64, deploymentBlock: 1, stateReadOnly: false,
  };
  writeFileSync(join(pub, 'nb2-release.json'), JSON.stringify({ pins, trust: { bundle: 'trust-base.bundle.cbor' } }));
  writeFileSync(join(pub, 'trust-base.bundle.cbor'), s.root.bundle);
  writeFileSync(join(pub, 'trust-base.genesis.entryid'), `${hex(s.root.pin)}\n`);
  const conn = connectionOf({ release: join(pub, 'nb2-release.json'), rpc: 'http://127.0.0.1:9/unused' });
  const dir = join(pub, 'wallets', 'big');
  const w = new Wallet(dir, key('lane big'), conn);
  // what a SIGKILLed command in another container leaves: its PID 1 on a host (the container) that no longer exists
  const stale = JSON.stringify({ pid: 1, host: 'a1b2c3d4e5f6', at: '2026-11-17T10:00:00Z' });
  writeFileSync(join(dir, 'lock'), stale);
  // the CLI's default refuses it: the lock names another host, whose liveness this process can't see
  await assert.rejects(new Wallet(dir, key('lane big'), conn).open({ check: false, rpc: s.chain, aggregator: s.agg }), /in use by process 1 on a1b2c3d4e5f6/);
  // the lane's open does not take the lock: the next command opens, and works on the wallet
  await w.open({ ...LANE_OPEN, rpc: s.chain, aggregator: s.agg });
  s.chain.fund(w.signer.address, 10n ** 24n);
  const plan = await w.bridge.planDeposit(1n, w.ownerPub(0));
  assert.equal(plan.intent, 0n);
  assert.equal(readFileSync(join(dir, 'lock'), 'utf8'), stale, 'the lane leaves the lock file alone');
});
