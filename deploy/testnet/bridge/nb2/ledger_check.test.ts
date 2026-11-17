/**
 * The boundary stage's ledger read (ledger_check.ts): the deadline covers the requests in flight, and only a verified, fresh absence is
 * `unspent`. Run in the bridge tools image: npx --no-install tsx --test tests/live/nb2lane/ledger_check.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { bounded, Deadline, readLedger, type Answer, type LedgerOptions, type Snapshot } from './ledger_check.js';

const snap = (over: Partial<Snapshot> = {}): Snapshot => ({ networkId: 3, rootEpoch: 1n, rootRound: 3100n, sealTimestampSeconds: 1_000n, shardRound: 1000n, ...over });
const absent = (over: Partial<Snapshot> = {}): Answer => ({ kind: 'verified', verdict: 'absent_at_snapshot', snapshot: snap(over), proof: '0x01' });
const opts = (over: Partial<LedgerOptions> = {}): LedgerOptions => ({ notBefore: 1_000n, newestRound: 3000n, networkId: 3, deadlineMs: 300, pollMs: 10, ...over });

test('a transport that never completes: the read ends at its deadline with a timeout report, the request aborted', async () => {
  let aborted = false;
  const stalled = (signal: AbortSignal): Promise<Answer> => {
    signal.addEventListener('abort', () => { aborted = true; });
    return new Promise<Answer>(() => {}); // never settles, ignores its signal
  };
  const t0 = Date.now();
  const r = await readLedger(stalled, opts({ deadlineMs: 200 }));
  const took = Date.now() - t0;
  assert.equal(r.verdict, 'timeout');
  assert.match(r.reason!, /did not complete within the deadline/);
  assert.equal(r.attempts, 1);
  assert.ok(aborted, 'the request\'s signal is aborted');
  assert.ok(took >= 190 && took < 1_000, `ended after ${took} ms`);
});

test('a transport that stalls after stale answers: the deadline still bounds it', async () => {
  let n = 0;
  const ask = async (): Promise<Answer> => (n++ < 2 ? absent({ sealTimestampSeconds: 999n }) : new Promise<Answer>(() => {}));
  const r = await readLedger(ask, opts({ deadlineMs: 250 }));
  assert.equal(r.verdict, 'timeout');
  assert.equal(r.attempts, 3);
});

test('freshness: a snapshot sealed in the second after the refusal completed is fresh, one second earlier is not', async () => {
  assert.equal((await readLedger(async () => absent({ sealTimestampSeconds: 1_000n }), opts())).verdict, 'unspent');
  const early = await readLedger(async () => absent({ sealTimestampSeconds: 999n }), opts({ deadlineMs: 60 }));
  assert.equal(early.verdict, 'stale');
  assert.ok(early.attempts > 1, 'polled until the deadline');
  // and past the token's newest certificate round, strictly
  assert.equal((await readLedger(async () => absent({ rootRound: 3000n }), opts({ deadlineMs: 60 }))).verdict, 'stale');
  // a stale answer, then a fresh one
  let n = 0;
  const later = await readLedger(async () => absent({ sealTimestampSeconds: n++ === 0 ? 999n : 1_001n }), opts());
  assert.deepEqual([later.verdict, later.attempts], ['unspent', 2]);
});

test('anything but a verified fresh absence is not unspent', async () => {
  assert.equal((await readLedger(async () => ({ kind: 'hint' }), opts())).verdict, 'included');
  assert.equal((await readLedger(async () => ({ kind: 'verified', verdict: 'included_at_snapshot', snapshot: snap(), proof: '0x' }), opts())).verdict, 'included');
  assert.equal((await readLedger(async () => ({ kind: 'rejected', reason: 'authority_rejected', proof: '0x' }), opts())).verdict, 'rejected');
  assert.equal((await readLedger(async () => absent({ networkId: 4 }), opts())).verdict, 'rejected');
  const failing = await readLedger(async () => { throw new Error('connection refused'); }, opts({ deadlineMs: 60 }));
  assert.deepEqual([failing.verdict, failing.reason], ['error', 'connection refused']);
  assert.ok(failing.attempts > 1, 'an error is retried within the deadline');
});

test('bounded: a call that never settles is abandoned at its timer; one that settles is returned', async () => {
  await assert.rejects(bounded(() => new Promise(() => {}), 30), Deadline);
  assert.equal(await bounded(async () => 7, 30), 7);
  await assert.rejects(bounded(async () => { throw new Error('x'); }, 30), /x/);
});
