/**
 * The boundary search (boundary_search.ts) against a model of the live preflight: gas piecewise linear in the transfers through the lane's
 * measured points (testnet-bridge runs on #1126), about 100k gas a distinct certificate and 150k a segment of need. Run in the bridge tools
 * image: npx --no-install tsx --test tests/live/nb2lane/boundary_search.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BoundaryNotFound, findBoundary, type Probe, type SearchResult } from './boundary_search.js';

const LIMIT = 60_000_000n;
const START = { transfers: 16, gas: 10_826_319n };

// gas without the certificates' and the need's share, through the measured points (16: 10.8M; 204-212: ~96k a hop; 212-255: ~238k a hop)
const POINTS: [number, number][] = [[1, 7_000_000], [16, 8_776_319], [204, 57_850_000], [212, 58_620_000], [255, 68_850_000], [600, 150_000_000]];
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
interface Opts { certs?: (k: number, r: () => number) => number; need?: (call: number) => number; noise?: number; shift?: number }
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
      tokens.set(label, { k, certs: certsOf(k, r), noise: (r() - 0.5) * 2 * (o.noise ?? 0) });
      return judge(label);
    },
    rejudge: async (p) => judge(p.label),
  };
  const judge = (label: string): Probe => {
    const t = tokens.get(label)!;
    const need = o.need?.(m.judged) ?? 3;
    m.judged++;
    const gas = BigInt(Math.round(baseGas(t.k) + (o.shift ?? 0) + 100_000 * t.certs + 150_000 * need + t.noise));
    return { label, transfers: t.k, conditions: `${t.certs} certificates, need ${need}`, gas, real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' };
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
  assert.ok(res.tries.length <= maxProbes);
  assert.ok(res.tries.includes(res.pass) && res.tries.includes(res.fail), 'the pair is two of the reported probes');
}

const opts = (estimate: number, maxProbes = 16) => ({ estimate, limit: LIMIT, start: START, maxProbes });

test('the failed CI run (estimate 255, refusals at 207..204): the pair is found, which the old eight-probe walk did not', async () => {
  const m = model(43916311, { shift: 150_000 });
  const res = await findBoundary(m.probe, m.rejudge, opts(255));
  assertPair(res, 16);
  assert.ok(res.pass.transfers >= 195 && res.pass.transfers <= 206, String(res.pass.transfers));
  assert.ok(res.tries.length <= 10, `${res.tries.length} probes`);
});

test('without noise under one set of conditions the pair is the exact boundary, from any estimate', async () => {
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  for (const estimate of [17, 120, 190, n, n + 1, 230, 255, 320, 500]) {
    const m = model(1, { certs: () => 16 });
    const res = await findBoundary(m.probe, m.rejudge, opts(estimate));
    assertPair(res, 16);
    assert.equal(res.pass.transfers, n, `from ${estimate}`);
  }
});

test('an estimate below the bound searches upwards', async () => {
  const m = model(7);
  const res = await findBoundary(m.probe, m.rejudge, opts(150));
  assertPair(res, 16);
  assert.equal(res.tries[0].real, 'passes');
});

test('an adjacent pair under different certificates is not taken: the search goes on until one count holds both', async () => {
  // the first probes at N + 1 straddle a round (17 certificates): refused, beside a pass at N under 16
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  const at = new Map<number, number[]>([[n + 1, [17, 17]]]);
  const m = model(3, { certs: (k) => at.get(k)?.shift() ?? 16 });
  const res = await findBoundary(m.probe, m.rejudge, opts(n + 1));
  assertPair(res, 16);
  assert.equal(res.pass.transfers, n);
  assert.ok(res.tries.some((t) => t.transfers === n + 1 && t.conditions.startsWith('17')), 'the 17-certificate refusal was seen and not used');
});

test('a pair whose conditions move before the confirmation is judged again under the new ones', async () => {
  // the need steps from 3 to 4 at the fifth judgement: the candidate found under need 3 does not confirm; the pair reported holds under one need
  const m = model(5, { certs: () => 16, need: (call) => (call < 5 ? 3 : 4) });
  const res = await findBoundary(m.probe, m.rejudge, opts(255));
  assertPair(res, 16);
  assert.ok(res.confirmed.pass.conditions.endsWith('need 4'));
});

test('many seeds with noise and straddled rounds: always a confirmed adjacent pair under the same conditions within the bound', async () => {
  let worst = 0;
  let total = 0;
  for (let seed = 1; seed <= 500; seed++) {
    const r = rng(seed * 7919);
    const estimate = 140 + Math.floor(r() * 180);
    const m = model(seed, { noise: 40_000, shift: (r() - 0.5) * 2_000_000 });
    const res = await findBoundary(m.probe, m.rejudge, opts(estimate));
    assertPair(res, 16);
    worst = Math.max(worst, res.tries.length);
    total += res.tries.length;
  }
  assert.ok(worst <= 16, `worst ${worst}`);
  assert.ok(total / 500 <= 9, `mean ${total / 500}`);
});

test('certificates that follow the length (a jump at the bound) give no pair: BoundaryNotFound, never a pair across conditions', async () => {
  let n = 1;
  while (baseGas(n + 1) + 1_600_000 + 450_000 <= Number(LIMIT)) n++;
  // every token of N or fewer transfers under 16 certificates, every longer one under 17 (the natural rounds' pattern at 204/205)
  const m = model(9, { certs: (k) => (k <= n ? 16 : 17) });
  await assert.rejects(findBoundary(m.probe, m.rejudge, opts(255)), BoundaryNotFound);
  assert.equal(m.built, 16);
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
  const bad = async (k: number, i: number): Promise<Probe> => ({ label: `g${i}c`, transfers: k + 1, conditions: 'x', gas: 1n, real: 'passes' });
  await assert.rejects(findBoundary(bad, async (p) => p, opts(200)), BoundaryNotFound);
});
