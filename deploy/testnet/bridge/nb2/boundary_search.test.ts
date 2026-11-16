/**
 * The boundary search (boundary_search.ts) against a model of the live preflight: gas piecewise linear in the transfers through the lane's
 * measured points (testnet-bridge runs on #1126), about 100k gas a distinct certificate and 150k a segment of need. Run in the bridge tools
 * image: npx --no-install tsx --test tests/live/nb2lane/boundary_search.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BoundaryNotFound, findBoundary, shapeHolds, type Probe, type SearchResult } from './boundary_search.js';

const LIMIT = 60_000_000n;
const START = { transfers: 16, gas: 10_826_319n };

// gas without the certificates' and the need's share: the model's step per transfer on the lane's tokens, about 251k (190k a hop and 136 a byte
// for ~1.5 KB a transfer beyond the measured 1,026; 16 transfers 10.8M and 255 transfers 71.0M measured), the bound near 204. The adjacent
// probes' gas differs by less (76k to 196k at 204..207 in the failed run): their evidence bytes vary by about 700 bytes a token (noise below)
const POINTS: [number, number][] = [[1, 6_946_000], [16, 10_711_000], [204, 57_899_000], [600, 157_295_000]];
function baseGas(k: number): number {
  for (let i = 1; i < POINTS.length; i++) {
    const [k0, g0] = POINTS[i - 1];
    const [k1, g1] = POINTS[i];
    if (k <= k1) return g0 + ((g1 - g0) * (k - k0)) / (k1 - k0);
  }
  throw new Error('out of the model');
}

function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

interface World { certs: number; need: number; noise: number; shift: number }
interface Opts { certs?: (k: number, r: () => number) => number; need?: (call: number) => number; noise?: number; shift?: number; overhead?: (k: number) => number }
interface Model { built: number; judged: number; probe: (k: number, i: number) => Promise<Probe>; rejudge: (p: Probe) => Promise<Probe> }

/** A token: its length and certificates are fixed when built; the need is the chain's at each judgement. */
function model(seed: number, o: Opts = {}): Model {
  const r = rng(seed);
  // the driver's probes: 16 rounds of certification, one more when a group straddles an aggregator round
  const certsOf = o.certs ?? ((_k, rr) => (rr() < 0.1 ? 17 : 16));
  const tokens = new Map<string, { k: number; certs: number; noise: number }>();
  const m: Model = {
    built: 0,
    judged: 0,
    probe: async (k, i) => {
      m.built++;
      const label = `g${i}c`;
      // noise and overhead: the token's unrecorded shape (its bytes and signatures beyond the measured ones), fixed when it is built
      tokens.set(label, { k, certs: certsOf(k, r), noise: (r() - 0.5) * 2 * (o.noise ?? 0) + (o.overhead?.(k) ?? 0) });
      return judge(label);
    },
    rejudge: async (p) => judge(p.label),
  };
  const judge = (label: string): Probe => {
    const t = tokens.get(label)!;
    const need = o.need?.(m.judged) ?? 3;
    m.judged++;
    const gas = BigInt(Math.round(baseGas(t.k) + (o.shift ?? 0) + 100_000 * t.certs + 150_000 * need + t.noise));
    // one more and one fewer transfer of this token's own shape: the model's steps, rounded down (the driver's shapeOf)
    const up = BigInt(Math.floor(baseGas(t.k + 1) - baseGas(t.k)));
    const down = BigInt(Math.floor(baseGas(t.k) - baseGas(t.k - 1)));
    return { label, transfers: t.k, conditions: `${t.certs} certificates, need ${need}`, gas, up, down, real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' };
  };
  return m;
}

function assertPair(res: SearchResult, maxProbes: number): void {
  assert.equal(res.pass.real, 'passes');
  assert.equal(res.fail.real, 'CapacityPreflight');
  assert.equal(res.fail.transfers, res.pass.transfers + 1, 'adjacent');
  assert.equal(res.fail.conditions, res.pass.conditions, 'under the same conditions');
  assert.equal(res.confirmed.pass.label, res.pass.label);
  assert.equal(res.confirmed.fail.label, res.fail.label);
  assert.equal(res.confirmed.pass.real, 'passes', 'the pass, judged again');
  assert.equal(res.confirmed.fail.real, 'CapacityPreflight', 'the refusal, judged again right after');
  assert.equal(res.confirmed.pass.conditions, res.pass.conditions);
  assert.equal(res.confirmed.fail.conditions, res.pass.conditions);
  assert.equal(shapeHolds(res.pass, res.fail, LIMIT), null, 'the boundary holds under each token\'s own shape');
  assert.equal(shapeHolds(res.confirmed.pass, res.confirmed.fail, LIMIT), null);
  assert.ok(res.tries.length <= maxProbes);
  const built = new Set(res.tries.map((t) => t.label));
  assert.ok(built.has(res.pass.label) && built.has(res.fail.label), 'the pair is two of the reported tokens');
}

const opts = (estimate: number, maxProbes = 20) => ({ estimate, limit: LIMIT, start: START, maxProbes });

test('the failed CI run (estimate 255, refusals at 207..204): the pair is found, which the old eight-probe walk did not', async () => {
  const m = model(43916311, { noise: 95_000 });
  const res = await findBoundary(m.probe, m.rejudge, opts(255));
  assertPair(res, 20);
  assert.ok(res.pass.transfers >= 195 && res.pass.transfers <= 206, String(res.pass.transfers));
  assert.ok(res.tries.length <= 10, `${res.tries.length} probes`);
});

test('without noise under one set of conditions the pair is the exact boundary, from any estimate', async () => {
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  for (const estimate of [17, 120, 190, n, n + 1, 230, 255, 320, 500]) {
    const m = model(1, { certs: () => 16 });
    const res = await findBoundary(m.probe, m.rejudge, opts(estimate));
    assertPair(res, 20);
    assert.equal(res.pass.transfers, n, `from ${estimate}`);
  }
});

test('an estimate below the bound searches upwards', async () => {
  const m = model(7);
  const res = await findBoundary(m.probe, m.rejudge, opts(150));
  assertPair(res, 20);
  assert.equal(res.tries[0].real, 'passes');
});

test('an adjacent pair under different certificates is not taken: the search goes on until one count holds both', async () => {
  // the first probes at N + 1 straddle a round (17 certificates): refused, beside a pass at N under 16
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  const at = new Map<number, number[]>([[n + 1, [17, 17]]]);
  const m = model(3, { certs: (k) => at.get(k)?.shift() ?? 16 });
  const res = await findBoundary(m.probe, m.rejudge, opts(n + 1));
  assertPair(res, 20);
  assert.equal(res.pass.transfers, n);
  assert.ok(res.tries.some((t) => t.transfers === n + 1 && t.conditions.startsWith('17')), 'the 17-certificate refusal was seen and not used');
});

test('a pair whose conditions move before the confirmation is judged again under the new ones', async () => {
  // the need steps from 3 to 4 at the fifth judgement: the candidate found under need 3 does not confirm; the pair reported holds under one need
  const m = model(5, { certs: () => 16, need: (call) => (call < 5 ? 3 : 4) });
  const res = await findBoundary(m.probe, m.rejudge, opts(255));
  assertPair(res, 20);
  assert.ok(res.confirmed.pass.conditions.endsWith('need 4'));
});

test('many seeds with noise and straddled rounds: a confirmed adjacent pair under one shape, or BoundaryNotFound (fail closed), never another', async () => {
  // the tokens' unrecorded shape varies by up to 95k gas (about 700 evidence bytes): now and then no pair holds under both shapes within
  // the budget, and the search must say so rather than take one
  let found = 0;
  let total = 0;
  for (let seed = 1; seed <= 500; seed++) {
    const r = rng(seed * 7919);
    const estimate = 140 + Math.floor(r() * 180);
    const m = model(seed, { noise: 95_000, shift: (r() - 0.5) * 2_000_000 });
    try {
      const res = await findBoundary(m.probe, m.rejudge, opts(estimate));
      assertPair(res, 20);
      found++;
      total += res.tries.length;
    } catch (e) {
      assert.ok(e instanceof BoundaryNotFound, String(e));
      assert.equal(m.built, 20);
    }
  }
  assert.ok(found >= 495, `${found} of 500`);
  assert.ok(total / found <= 8, `mean ${total / found}`);
});

test('certificates that follow the length (a jump at the bound) give no pair: BoundaryNotFound, never a pair across conditions', async () => {
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  // every token of N or fewer transfers under 16 certificates, every longer one under 17 (the natural rounds' pattern at 204/205)
  const m = model(9, { certs: (k) => (k <= n ? 16 : 17) });
  await assert.rejects(findBoundary(m.probe, m.rejudge, opts(255)), BoundaryNotFound);
  assert.equal(m.built, 20);
});

test('the probe budget is a bound: BoundaryNotFound carries every probe', async () => {
  const m = model(11);
  await assert.rejects(findBoundary(m.probe, m.rejudge, opts(255, 2)), (e: unknown) => {
    assert.ok(e instanceof BoundaryNotFound);
    assert.equal(e.tries.length, 2);
    return true;
  });
  assert.equal(m.built, 2);
});

test('a probe of another length than asked is refused', async () => {
  const bad = async (k: number, i: number): Promise<Probe> => ({ label: `g${i}c`, transfers: k + 1, conditions: 'x', gas: 1n, up: 1n, down: 1n, real: 'passes' });
  await assert.rejects(findBoundary(bad, async (p) => p, opts(200)), BoundaryNotFound);
});

// sol's review of #1126 (r7): the conditions held only the certificates and the need, so a confirmed 20/21 pair could stand although 21 was
// refused for its own overhead, and passes under 20's
const exactBound = (): number => {
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  return n;
};
const probeOf = (label: string, transfers: number, gas: bigint, up: bigint | null, down: bigint | null = up): Probe =>
  ({ label, transfers, conditions: '16 certificates, need 3', gas, up, down, real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' });

test('shapeHolds: the pair holds under each token\'s own shape, or it is refused', () => {
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  // 21's refusal is its overhead: 20 with one more transfer of its own shape is within the limit
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 150_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT)!, /p with one more transfer/);
  // 21 with one transfer fewer of its own shape is still over: its refusal is its overhead
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 150_000n, 100_000n), LIMIT)!, /f with one transfer fewer/);
  // sol r8: the refusal's side takes the backward step. 1,100-byte pairs at zero excess: +200,064 forward, -190,000 back; a refusal at
  // 60,195,000 is 60,005,000 with one transfer fewer, still over: refused, though its forward step would have taken it within
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_195_000n, 200_064n, 190_000n), LIMIT)!, /f with one transfer fewer of its own shape \(60195000 - 190000\)/);
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_185_000n, 200_064n, 190_000n), LIMIT), null);
  // and the pass's side the forward one
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 195_000n, 200_064n, 190_000n), probeOf('f', 21, LIMIT + 5_000n, 200_064n, 190_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT - 195_000n, 190_000n, 200_064n), probeOf('f', 21, LIMIT + 5_000n, 190_000n, 190_000n), LIMIT), null);
  // unknown inputs fail closed, and so does a pair whose model gas does not straddle the limit
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, null), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT + 1n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
});

test('an adjacent pair whose refusal is the refused token\'s unrecorded overhead is not taken; a fresh token finds the real one', async () => {
  const n = exactBound();
  // the first token of n transfers carries 300k gas of overhead its conditions do not show (more evidence bytes and seal signatures): refused,
  // beside n - 1 passing; under n - 1's shape n passes. The search refuses that pair, builds n again and ends at n / n + 1.
  const once = new Map<number, number[]>([[n, [300_000]]]);
  const m = model(13, { certs: () => 16, overhead: (k) => once.get(k)?.shift() ?? 0 });
  const res = await findBoundary(m.probe, m.rejudge, opts(n));
  assertPair(res, 20);
  assert.equal(res.pass.transfers, n);
  assert.equal(res.tries[0].transfers, n);
  assert.equal(res.tries[0].real, 'CapacityPreflight', 'the overhead token is refused');
  assert.ok(res.refused.some((r) => r.fail === res.tries[0].label && /with one more transfer/.test(r.reason)), JSON.stringify(res.refused));
});

test('an overhead every token of one length carries leaves no pair: BoundaryNotFound with the refused pairs, never the 20/21 kind', async () => {
  const n = exactBound();
  const m = model(17, { certs: () => 16, overhead: (k) => (k === n ? 300_000 : 0) });
  await assert.rejects(findBoundary(m.probe, m.rejudge, opts(n)), (e: unknown) => {
    assert.ok(e instanceof BoundaryNotFound);
    assert.ok(e.refused.length > 0 && e.refused.every((r) => /overhead/.test(r.reason)), JSON.stringify(e.refused));
    return true;
  });
});
