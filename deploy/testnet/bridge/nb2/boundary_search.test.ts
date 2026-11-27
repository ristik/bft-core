/**
 * The boundary search (boundary_search.ts): the bound located within a margin by single tokens, the newest probes only, against a model of the
 * live preflight as runs 43994509728 and 44003156840 measured it: gas linear in the transfers at about 265k a transfer, the evidence bytes
 * drifting up about 135k gas a probe and deviating by about 160k (0.6 step). Run in the bridge tools image:
 * npx --no-install tsx --test tests/live/nb2lane/boundary_search.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BoundaryNotFound, driftOf, findBoundary, ownShape, refusalOf, shapeHolds, type Probe, type SearchOptions, type SearchResult } from './boundary_search.js';

const LIMIT = 60_000_000n;
const STEP = 265_000;
const START = { transfers: 16, gas: 10_839_647n };
const AT0 = 204; // the bound at the first probe without drift or noise: 204 passes, 205 is refused
const gasAt = (k: number): number => Number(LIMIT) - 120_000 + (k - AT0) * STEP;

function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
const gauss = (r: () => number): number => Math.sqrt(-2 * Math.log(r() + 1e-12)) * Math.cos(2 * Math.PI * r());

const mk = (label: string, transfers: number, gas: bigint | null): Probe =>
  ({ label, transfers, conditions: 'set, need 64', gas, up: BigInt(STEP), down: BigInt(STEP), real: gas !== null && gas <= LIMIT ? 'passes' : 'CapacityPreflight' });

function model(seed: number, drift = 135_000, noise = 160_000): (k: number, i: number) => Promise<Probe> {
  const r = rng(seed);
  return async (k, i) => mk(`g${i}c`, k, BigInt(Math.round(gasAt(k) + drift * i + gauss(r) * noise)));
}

const opts = (estimate: number, extra: Partial<SearchOptions> = {}): SearchOptions => ({ estimate, limit: LIMIT, start: START, maxProbes: 12, margin: 2, min: 16, ...extra });

/** The claim on a result: among the newest probes, the highest admission and the lowest refusal, at most the margin apart. */
function assertLocated(res: SearchResult): void {
  assert.equal(res.admitted.real, 'passes');
  assert.equal(res.refused.real, 'CapacityPreflight');
  assert.equal(res.spread, Math.abs(res.refused.transfers - res.admitted.transfers));
  assert.ok(res.spread <= res.margin, `spread ${res.spread}`);
  assert.ok(res.window.includes(res.admitted.label) && res.window.includes(res.refused.label), 'both from the newest probes');
  assert.deepEqual(res.window, res.tries.slice(-3).map((t) => t.label));
  for (const t of res.tries.slice(-3)) {
    if (t.real === 'passes') assert.ok(t.transfers <= res.admitted.transfers);
    else assert.ok(t.transfers >= res.refused.transfers);
  }
}

test('the measured drift and deviation: the bound within two transfers, from the newest three probes, in a few probes', async () => {
  let found = 0;
  let probes = 0;
  for (let seed = 1; seed <= 1000; seed++) {
    try {
      const res = await findBoundary(model(seed), opts(255));
      assertLocated(res);
      found++;
      probes += res.tries.length;
    } catch (e) {
      assert.ok(e instanceof BoundaryNotFound, String(e));
      assert.equal(e.tries.length, 12);
    }
  }
  assert.ok(found >= 995, `${found} of 1000`);
  assert.ok(probes / found <= 6, `mean probes ${probes / found}`);
});

test('three times the drift and twice the deviation: located, or BoundaryNotFound (fail closed)', async () => {
  let found = 0;
  for (let seed = 1; seed <= 500; seed++) {
    try {
      assertLocated(await findBoundary(model(seed, 400_000, 320_000), opts(255)));
      found++;
    } catch (e) {
      assert.ok(e instanceof BoundaryNotFound, String(e));
    }
  }
  assert.ok(found >= 475, `${found} of 500`);
});

test('a refusal below an admission is the noise when within the margin, and a stale probe otherwise', async () => {
  // 204 admitted then 203 refused: spread 1, within the margin
  const seq: [number, bigint][] = [];
  const scripted = (gas: (k: number, i: number) => bigint) => async (k: number, i: number): Promise<Probe> => {
    const g = gas(k, i);
    seq.push([k, g]);
    return mk(`g${i}c`, k, g);
  };
  const near = await findBoundary(scripted((k, i) => (i === 0 ? LIMIT + 9_000_000n : i === 1 ? LIMIT - 50_000n : LIMIT + 50_000n)), opts(255, { recent: 3 }));
  assertLocated(near);
  // an early light admission far above every later refusal is dropped from the window, never reported
  const stale = await findBoundary(scripted((k, i) => (i === 1 ? LIMIT - 1n : BigInt(gasAt(k) + 8 * STEP))), opts(210));
  assertLocated(stale);
  assert.ok(Math.abs(stale.admitted.transfers - (AT0 - 8)) <= 2 && stale.admitted.label !== 'g1c', `${stale.admitted.label} ${stale.admitted.transfers}`);
});

test('the margin is a bound: a window whose admission and refusal are further apart is never the result', async () => {
  // a token one transfer longer than the bound is always admitted and one shorter refused, every third probe: the search must keep probing
  let calls = 0;
  const probe = async (k: number, i: number): Promise<Probe> => {
    calls++;
    return mk(`g${i}c`, k, BigInt(gasAt(k)));
  };
  const res = await findBoundary(probe, opts(255, { margin: 1 }));
  assertLocated({ ...res, window: res.window });
  assert.ok(res.spread <= 1 && res.margin === 1);
  assert.ok(calls <= 12);
});

test('fail closed: no admission and refusal within the margin in maxProbes, a probe of another length, a margin under one', async () => {
  // every probe refused
  await assert.rejects(findBoundary(async (k, i) => mk(`g${i}c`, k, null), opts(255, { maxProbes: 4 })), (e: unknown) => {
    assert.ok(e instanceof BoundaryNotFound);
    assert.equal(e.tries.length, 4);
    return true;
  });
  // every probe admitted: the search climbs until its budget, never reporting a bound it did not see
  await assert.rejects(findBoundary(async (k, i) => mk(`g${i}c`, k, LIMIT - 10_000_000n), opts(255)), (e: unknown) => {
    assert.ok(e instanceof BoundaryNotFound);
    assert.equal(e.tries.length, 12);
    return true;
  });
  await assert.rejects(findBoundary(async (k, i) => mk(`g${i}c`, k + 1, LIMIT), opts(255)), /holds/);
  await assert.rejects(findBoundary(async (k, i) => mk(`g${i}c`, k, LIMIT), opts(255, { margin: 0 })), /at least one/);
});

test('every probe records the shape diagnostics, which never gate', () => {
  assert.deepEqual(ownShape(mk('a', 200, LIMIT - 100_000n), LIMIT), { nextOver: true });
  assert.deepEqual(ownShape(mk('a', 200, LIMIT - 300_000n), LIMIT), { nextOver: false });
  assert.deepEqual(ownShape(mk('r', 201, LIMIT + 100_000n), LIMIT), { prevWithin: true });
  assert.deepEqual(ownShape(mk('r', 201, LIMIT + 300_000n), LIMIT), { prevWithin: false });
  assert.deepEqual(ownShape({ ...mk('r', 201, LIMIT + 1n), down: null }, LIMIT), { prevWithin: null });
});

test('driftOf recovers the gas a probe and a transfer of exact points', () => {
  const pts = [];
  for (let b = 0; b < 8; b++) for (const k of [190, 200, 210]) pts.push({ transfers: k, build: b, gas: BigInt(1_000_000 + 265_000 * k + 135_000 * b) });
  assert.deepEqual(driftOf(pts), { intercept: 1_000_000, perBuild: 135_000, perTransfer: 265_000, residualSd: 0, samples: 24 });
  assert.equal(driftOf(pts.slice(0, 3)), null, 'too few points');
  assert.equal(driftOf([0, 1, 2, 3].map(() => ({ transfers: 1, build: 0, gas: 1n }))), null, 'not determined');
});

const probeOf = (label: string, transfers: number, gas: bigint, up: bigint | null, down: bigint | null = up): Probe =>
  ({ label, transfers, conditions: 'set, need 64', gas, up, down, real: gas <= LIMIT ? 'passes' : 'CapacityPreflight' });

test('shapeHolds (the diagnostic): forward for the admission, backward for the refusal', () => {
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 150_000n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT)!, /p with one more transfer/);
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 100_000n), probeOf('f', 21, LIMIT + 150_000n, 100_000n), LIMIT)!, /f with one transfer fewer/);
  // sol r8: 1,100-byte pairs at zero excess: +200,064 forward, -190,000 back
  assert.match(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_195_000n, 200_064n, 190_000n), LIMIT)!, /f with one transfer fewer of its own shape \(60195000 - 190000\)/);
  assert.equal(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, 200_064n, 190_000n), probeOf('f', 21, 60_185_000n, 200_064n, 190_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT - 50_000n, null), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
  assert.notEqual(shapeHolds(probeOf('p', 20, LIMIT + 1n, 100_000n), probeOf('f', 21, LIMIT + 50_000n, 100_000n), LIMIT), null);
});

test('a refusal is labelled from the preflight\'s own checks: a null bound with the bytes fitting is unbounded, never bytes (astra P2, #1186)', () => {
  const lim = 60_000_000n;
  assert.equal(refusalOf({ baseFits: true, need: 64n, pMax: 400n, gas: null, limit: lim }), 'unbounded');
  assert.equal(refusalOf({ baseFits: true, need: 64n, pMax: 400n, gas: 60_000_001n, limit: lim }), 'gas');
  assert.equal(refusalOf({ baseFits: true, need: 401n, pMax: 400n, gas: null, limit: lim }), 'bytes');
  assert.equal(refusalOf({ baseFits: false, need: 64n, pMax: 0n, gas: 1n, limit: lim }), 'bytes');
  // a bound within the limit and the bytes fitting is no refusal by either: unbounded (the stage does not count it)
  assert.equal(refusalOf({ baseFits: true, need: 64n, pMax: 400n, gas: lim, limit: lim }), 'unbounded');
});
