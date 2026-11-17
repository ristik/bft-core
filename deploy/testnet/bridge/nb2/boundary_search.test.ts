/**
 * The boundary search (boundary_search.ts) against a model of the live preflight as run 43994509728 measured it (d26caf77d): gas linear in the
 * transfers at about 265k a transfer (the model's step on the lane's tokens), every other term constant but the evidence bytes, which drift up
 * by about 135k gas a build and deviate from that by about 160k (0.6 step) between builds; tokens built together share the build's drift and
 * deviation, and differ by a little noise of their own (assumed 30k here: the first live run measures it).
 * Run in the bridge tools image: npx --no-install tsx --test tests/live/nb2lane/boundary_search.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BoundaryNotFound, driftOf, findBoundary, shapeHolds, type Probe, type SearchOptions, type SearchResult } from './boundary_search.js';

const LIMIT = 60_000_000n;
const STEP = 265_000;
const START = { transfers: 16, gas: 10_839_647n };
const AT0 = 204; // the bound at the first build without drift or noise: 204 passes, 205 is refused
const gasAt = (k: number): number => Number(LIMIT) - 120_000 + (k - AT0) * STEP;

function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
const gauss = (r: () => number): number => Math.sqrt(-2 * Math.log(r() + 1e-12)) * Math.cos(2 * Math.PI * r());

interface World {
  drift?: number; // gas a build
  build?: number; // the sd of a build's deviation from the drift (every token of the build)
  together?: number; // the sd of a token's own noise within its build
  straddle?: number; // the chance one token of a build ends under another certificate set
}
interface Model {
  built: number;
  probe: (k: number, i: number) => Promise<Probe>;
  build: (lengths: number[], i: number) => Promise<Probe[]>;
  rejudge: (p: Probe) => Promise<Probe>;
}

const mk = (label: string, transfers: number, gas: bigint, conditions: string): Probe =>
  ({ label, transfers, conditions, gas, up: BigInt(STEP), down: BigInt(STEP), real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' });

function model(seed: number, w: World = {}): Model {
  const r = rng(seed);
  const tokens = new Map<string, { k: number; gas: number; conditions: string }>();
  const judge = (label: string): Probe => {
    const t = tokens.get(label)!;
    return mk(label, t.k, BigInt(Math.round(t.gas)), t.conditions);
  };
  const m: Model = {
    built: 0,
    probe: async (k, i) => {
      m.built++;
      tokens.set(`g${i}c`, { k, gas: gasAt(k) + (w.drift ?? 135_000) * i + gauss(r) * (w.build ?? 160_000), conditions: `single ${i}, need 64` });
      return judge(`g${i}c`);
    },
    build: async (lengths, i) => {
      m.built += lengths.length;
      const base = (w.drift ?? 135_000) * i + gauss(r) * (w.build ?? 160_000); // the build's own deviation: every token of it
      const odd = r() < (w.straddle ?? 0.1) ? Math.floor(r() * lengths.length) : -1;
      return lengths.map((k, x) => {
        const label = `g${i}${'abcdefgh'[x]}`;
        tokens.set(label, { k, gas: gasAt(k) + base + gauss(r) * (w.together ?? 30_000), conditions: x === odd ? `set ${i}', need 64` : `set ${i}, need 64` });
        return judge(label);
      });
    },
    rejudge: async (p) => judge(p.label),
  };
  return m;
}

const opts = (estimate: number, extra: Partial<SearchOptions> = {}): SearchOptions => ({ estimate, limit: LIMIT, start: START, maxProbes: 10, min: 16, ...extra });

/** sol's guarantees on a result: adjacent, identical conditions, built together, both shapes, confirmed back to back. */
function assertPair(res: SearchResult): void {
  assert.equal(res.pass.real, 'passes');
  assert.equal(res.fail.real, 'CapacityPreflight');
  assert.equal(res.fail.transfers, res.pass.transfers + 1, 'adjacent');
  assert.equal(res.fail.conditions, res.pass.conditions, 'identical conditions');
  assert.equal(shapeHolds(res.pass, res.fail, LIMIT), null, 'the bound holds under each token\'s own shape');
  assert.equal(shapeHolds(res.confirmed.pass, res.confirmed.fail, LIMIT), null);
  assert.deepEqual([res.confirmed.pass.label, res.confirmed.fail.label], [res.pass.label, res.fail.label]);
  assert.deepEqual([res.confirmed.pass.real, res.confirmed.fail.real], ['passes', 'CapacityPreflight'], 'judged again, back to back');
  assert.deepEqual([res.confirmed.pass.conditions, res.confirmed.fail.conditions], [res.pass.conditions, res.pass.conditions]);
  const last = res.windows[res.windows.length - 1];
  assert.equal(last.outcome, 'pair');
  assert.deepEqual([last.pass, last.fail], [res.pass.label, res.fail.label]);
  assert.ok(last.labels.includes(res.pass.label) && last.labels.includes(res.fail.label), 'both tokens of the pair are of one build');
  assert.ok(res.windows.length <= 6);
}

test('the drift and deviation run 43994509728 measured: a confirmed pair of one build within six builds, or BoundaryNotFound (fail closed)', async () => {
  // 999 of 1,000 seeds end in a pair in the model, with 1.7 builds on average; the rest fail closed (a crossing refused for its shape or
  // under two certificate sets, six times)
  let found = 0;
  let builds = 0;
  for (let seed = 1; seed <= 400; seed++) {
    const m = model(seed);
    try {
      const res = await findBoundary(m.probe, m.build, m.rejudge, opts(255));
      assertPair(res);
      found++;
      builds += res.windows.length;
    } catch (e) {
      assert.ok(e instanceof BoundaryNotFound, String(e));
      assert.equal(e.windows.length, 6);
    }
  }
  assert.ok(found >= 398, `${found} of 400`);
  assert.ok(builds / found <= 2, `mean builds ${builds / found}`);
});

test('a build of N and N + 1 alone (width 2) hits the crossing far less often under the same deviation: why the window is four wide', async () => {
  let two = 0;
  let four = 0;
  for (let seed = 1; seed <= 300; seed++) {
    for (const width of [2, 4]) {
      const m = model(seed);
      try {
        assertPair(await findBoundary(m.probe, m.build, m.rejudge, opts(255, { width })));
        if (width === 2) two++;
        else four++;
      } catch (e) {
        assert.ok(e instanceof BoundaryNotFound, String(e));
      }
    }
  }
  assert.ok(four >= 298, `width 4: ${four} of 300`);
  assert.ok(two <= four - 20, `width 2: ${two} of 300, width 4: ${four}`);
});

test('a stronger drift (1.5 steps a build) and twice the deviation still end in a pair, or fail closed', async () => {
  let found = 0;
  for (let seed = 1; seed <= 200; seed++) {
    const m = model(seed, { drift: 400_000, build: 320_000 });
    try {
      assertPair(await findBoundary(m.probe, m.build, m.rejudge, opts(255)));
      found++;
    } catch (e) {
      assert.ok(e instanceof BoundaryNotFound, String(e));
    }
  }
  assert.ok(found >= 190, `${found} of 200`);
});

test('a stale light pass does not hold the search: the coarse bracket is the newest probes only', async () => {
  // the first probe passes at 210 (a light token); every later token is 8 steps heavier: the bound is 196
  const heavy = (k: number): bigint => BigInt(gasAt(k) + 8 * STEP);
  const probe = async (k: number, i: number): Promise<Probe> => mk(`g${i}c`, k, i === 0 ? 59_900_000n : heavy(k), 'x');
  const build = async (lengths: number[], i: number): Promise<Probe[]> => lengths.map((k, x) => mk(`g${i}${'abcd'[x]}`, k, heavy(k), `set ${i}`));
  const res = await findBoundary(probe, build, async (p) => p, opts(210));
  assertPair(res);
  assert.equal(res.pass.transfers, AT0 - 8);
  assert.ok(res.windows.length <= 3, `${res.windows.length} builds: ${res.windows.map((w) => w.n)}`);
});

test('the stepping: all pass moves up past the window, all refused down past it, anything else builds on its crossing again', async () => {
  // the singles put the bound at 200 / 201; the scripted windows (n - 1 .. n + 2): all pass; all refused; inverted; other conditions at the
  // crossing; a shape that does not hold; not confirmed (the refusal passes when judged again); the pair
  const script = ['pass', 'refused', 'inverted', 'cond', 'shape', 'unconfirmed', 'pair'];
  const seen: number[][] = [];
  const flip = new Set<string>();
  const single = async (k: number, i: number): Promise<Probe> => mk(`s${i}`, k, BigInt(gasAt(k) + 4 * STEP), 'x'); // 200 passes, 201 is refused
  const build = async (lengths: number[], i: number): Promise<Probe[]> => {
    seen.push(lengths);
    const kind = script[seen.length - 1];
    const lo = LIMIT - 100_000n;
    const hi = LIMIT + 100_000n;
    const t = (x: number, gas: bigint, cond = `set ${i}`): Probe => mk(`g${i}${'abcd'[x]}`, lengths[x], gas, cond);
    switch (kind) {
      case 'pass': return lengths.map((_, x) => t(x, lo - 1_000_000n + BigInt(x * STEP)));
      case 'refused': return lengths.map((_, x) => t(x, hi + BigInt(x * STEP)));
      case 'inverted': return [t(0, lo - 300_000n), t(1, hi), t(2, lo), t(3, hi + 300_000n)];
      case 'cond': return [t(0, lo - 300_000n), t(1, lo), t(2, hi, `set ${i}'`), t(3, hi + 300_000n)];
      case 'shape': return [t(0, lo - 600_000n), t(1, LIMIT - 400_000n), t(2, hi), t(3, hi + 300_000n)]; // 1 + its step stays within: 2's refusal is its overhead
      case 'unconfirmed': flip.add(`g${i}c`); return [t(0, lo - 300_000n), t(1, lo), t(2, hi), t(3, hi + 300_000n)];
      default: return [t(0, lo - 300_000n), t(1, lo), t(2, hi), t(3, hi + 300_000n)];
    }
  };
  const rejudge = async (q: Probe): Promise<Probe> => (flip.has(q.label) ? { ...q, gas: LIMIT - 1n, real: 'passes' } : q);
  const res = await findBoundary(single, build, rejudge, opts(200, { maxPairs: 7 }));
  assert.deepEqual(res.windows.map((w) => w.outcome), ['all pass', 'all refused', 'inverted', 'conditions differ', 'shape', 'not confirmed', 'pair']);
  assert.deepEqual(seen[0], [199, 200, 201, 202], 'the first window is centred on the coarse crossing');
  assert.ok(seen[1][0] >= seen[0][3] - 1, `after all pass the next window starts at the old top's neighbour or above: ${seen[1]}`);
  assert.ok(seen[2][3] <= seen[1][0] + 1, `after all refused the next window ends at the old bottom's neighbour or below: ${seen[2]}`);
  for (let x = 3; x < seen.length; x++) assert.deepEqual(seen[x], seen[3], 'a window with a crossing that does not stand is built again on that crossing');
  assertPair({ ...res, windows: res.windows.slice(-6) });
});

test('the cap: six builds that never give a pair end in BoundaryNotFound with every build reported (fail closed)', async () => {
  const m = model(5);
  // every token of every build under its own certificate set
  const build = async (lengths: number[], i: number): Promise<Probe[]> => (await m.build(lengths, i)).map((t, x) => ({ ...t, conditions: `${t.conditions} #${x}` }));
  await assert.rejects(findBoundary(m.probe, build, m.rejudge, opts(255)), (e: unknown) => {
    assert.ok(e instanceof BoundaryNotFound);
    assert.match(e.message, /in 6 builds/);
    assert.equal(e.windows.length, 6);
    assert.ok(e.windows.every((w) => w.outcome !== 'pair'));
    assert.ok(e.windows.some((w) => w.outcome === 'conditions differ'));
    return true;
  });
});

test('no bracket among the single probes: BoundaryNotFound, no build', async () => {
  let builds = 0;
  const probe = async (k: number, i: number): Promise<Probe> => ({ label: `g${i}c`, transfers: k, conditions: 'x', gas: null, up: null, down: null, real: 'CapacityPreflight' });
  await assert.rejects(findBoundary(probe, async () => { builds++; return []; }, async (p) => p, opts(255, { maxProbes: 3 })), /no bracket/);
  assert.equal(builds, 0);
});

test('builds of another length than asked are refused', async () => {
  const bad = async (k: number, i: number): Promise<Probe> => mk(`g${i}c`, k + 1, 1n, 'x');
  await assert.rejects(findBoundary(bad, async () => [], async (p) => p, opts(200)), /holds/);
  const m = model(3);
  const wrong = async (lengths: number[], i: number): Promise<Probe[]> => (await m.build(lengths, i)).map((t, x) => (x === 1 ? { ...t, transfers: t.transfers + 1 } : t));
  await assert.rejects(findBoundary(m.probe, wrong, m.rejudge, opts(255)), /the build of/);
  const m2 = model(3);
  const short = async (lengths: number[], i: number): Promise<Probe[]> => (await m2.build(lengths, i)).slice(1);
  await assert.rejects(findBoundary(m2.probe, short, m2.rejudge, opts(255)), /the build of/);
});

test('every build records its residuals: the gap of each adjacent two beyond the lower one\'s own step, null across conditions', async () => {
  const m = model(9, { together: 0, straddle: 0 });
  const res = await findBoundary(m.probe, m.build, m.rejudge, opts(255));
  for (const w of res.windows) {
    assert.equal(w.residuals.length, w.lengths.length - 1);
    for (const x of w.residuals) assert.ok(x !== null && Math.abs(Number(x)) <= 2, `built together without noise: residual ${x}`);
  }
  assert.ok(res.drift !== null && Math.abs(res.drift.perBuild - 135_000) < 120_000, JSON.stringify(res.drift));
  // one token of a build under another certificate set: the residuals beside it are not recorded
  const m2 = model(9, { together: 0 });
  const build = async (lengths: number[], i: number): Promise<Probe[]> => (await m2.build(lengths, i)).map((t, x) => (x === 0 ? { ...t, conditions: 'other' } : t));
  const res2 = await findBoundary(m2.probe, build, m2.rejudge, opts(255));
  for (const w of res2.windows) assert.equal(w.residuals[0], null);
});

test('driftOf recovers the gas a build and a transfer of exact points', () => {
  const pts = [];
  for (let b = 0; b < 8; b++) for (const k of [190, 200, 210]) pts.push({ transfers: k, build: b, gas: BigInt(1_000_000 + 265_000 * k + 135_000 * b) });
  assert.deepEqual(driftOf(pts), { intercept: 1_000_000, perBuild: 135_000, perTransfer: 265_000, residualSd: 0, samples: 24 });
  assert.equal(driftOf(pts.slice(0, 3)), null, 'too few points');
  assert.equal(driftOf([0, 1, 2, 3].map(() => ({ transfers: 1, build: 0, gas: 1n }))), null, 'not determined');
});

const probeOf = (label: string, transfers: number, gas: bigint, up: bigint | null, down: bigint | null = up): Probe =>
  ({ label, transfers, conditions: 'set, need 64', gas, up, down, real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' });

test('shapeHolds: the pair holds under each token\'s own shape, or it is refused', () => {
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  // 21's refusal is its overhead: 20 with one more transfer of its own shape is within the limit
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 150_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT)!, /p with one more transfer/);
  // 21 with one transfer fewer of its own shape is still over: its refusal is its overhead
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 150_000n, 100_000n), LIMIT)!, /f with one transfer fewer/);
  // sol r8: the refusal's side takes the backward step. 1,100-byte pairs at zero excess: +200,064 forward, -190,000 back
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_195_000n, 200_064n, 190_000n), LIMIT)!, /f with one transfer fewer of its own shape \(60195000 - 190000\)/);
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_185_000n, 200_064n, 190_000n), LIMIT), null);
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 195_000n, 200_064n, 190_000n), probeOf('f', 21, LIMIT + 5_000n, 200_064n, 190_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT - 195_000n, 190_000n, 200_064n), probeOf('f', 21, LIMIT + 5_000n, 190_000n, 190_000n), LIMIT), null);
  // unknown inputs fail closed, and so does a pair whose model gas does not straddle the limit
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, null), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT + 1n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
});

test('sol r7: a crossing whose refusal is the refused token\'s own overhead is not taken; the next build\'s is', async () => {
  // no drift or deviation: 204 passes and 205 is refused. The first build's 205 token carries 300k gas beyond its step that the conditions do
  // not show: 205 with one transfer fewer of its own shape would still be over, so the crossing is refused and built again
  let first = true;
  const m = model(13, { build: 0, together: 0, drift: 0, straddle: 0 });
  const build = async (lengths: number[], i: number): Promise<Probe[]> => {
    const toks = await m.build(lengths, i);
    if (first && lengths.includes(AT0 + 1)) {
      first = false;
      return toks.map((t) => (t.transfers === AT0 + 1 ? { ...t, gas: t.gas! + 300_000n } : t));
    }
    return toks;
  };
  const res = await findBoundary(m.probe, build, m.rejudge, opts(255));
  assertPair(res);
  assert.equal(res.pass.transfers, AT0);
  assert.ok(res.windows.some((w) => w.outcome === 'shape' && /one transfer fewer/.test(w.reason!)), JSON.stringify(res.windows));
});
