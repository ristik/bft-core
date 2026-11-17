/**
 * The boundary stage's search (driver.ts boundary, NB2-09 bft-core#1105): the largest transfer history N whose return the wallet's preflight
 * admits, as an adjacent pair of live tokens under identical conditions: N passes and N + 1 is refused (CapacityPreflight).
 *
 * What the live tokens showed (run 43994509728 on d26caf77d, fifteen probes): every gas term but the evidence bytes is constant across fresh
 * tokens, and those bytes grow with the aggregator (about 991 bytes, 135k gas, half a transfer's step, a probe), with about 0.6 step of
 * residual noise between tokens built apart. A pass and a refusal built minutes apart are not comparable, and an early pass is a stale anchor
 * (run 43985010186 kept probing 201 beside one until its budget ran out). So:
 *
 *   coarse   single tokens bracket the bound, from the newest probes only (RECENT of them): an older probe never anchors the search;
 *   window   N - 1 .. N + 2 (WIDTH lengths, N and N + 1 among them) are built together: the driver certifies all their chains in the same
 *            aggregator rounds, so they share the build's drift and its own deviation from it (about 0.6 step, which a build of N and N + 1
 *            alone hits only about half the time), and are judged at once, one after the other. The window's crossing, its last pass N and
 *            first refusal N + 1, under identical conditions (the same set of certificates and the same segment need, `conditions`), whose
 *            boundary holds under each token's own shape (shapeHolds, forward and backward steps), judged again back to back, is the result.
 *            All passing moves the window up and all refused down, to where the fit over every token (gas by length and build, driftOf) puts
 *            the crossing at the next build, past the window at least and at most MAX_PAIR_STEP; anything else (other conditions, a shape that
 *            does not hold, a window that is not passes then refusals, a confirmation that does not agree) builds a window on that crossing
 *            again. At most maxPairs builds, then BoundaryNotFound (fail closed), with every token and every build reported.
 *
 * Every build records its residuals: for each adjacent two under one conditions, their gas difference beyond the model's one-transfer step of
 * the lower one (b.gas - a.gas - a.up), the noise that remains between tokens built together; and the drift of the gas a build (driftOf, over
 * every token).
 *
 * Pure: the driver supplies the builds. No imports, so the unit tests run without a chain (boundary_search.test.ts).
 */

export type Verdict = 'passes' | 'CapacityPreflight';

export interface Probe {
  label: string;
  transfers: number;
  conditions: string; // what besides the transfers moves the verdict: the token's set of certificates (their hashes) and the segment need
  gas: bigint | null; // the preflight's gas for the token (the lane's replay of planReturn's inputs, the same model and inputs)
  // the model's gas of one more transfer of this token's own average shape (its bytes and signatures beyond the measured ones), and the gas
  // one fewer saves: not the same where the excess bytes clip at zero (boundary_shape.ts marginals); rounded down, which makes both of
  // shapeHolds' sides stricter; null when they cannot be computed (never a pair)
  up: bigint | null;
  down: bigint | null;
  real: Verdict; // planReturn's own verdict
  detail?: Record<string, number | string>; // the token's gas terms, for the evidence only (never read by the search)
}

/**
 * The pair's boundary under each token's own shape: PASS with one more transfer would be refused and FAIL with one fewer would pass, by the
 * model planReturn applies. Null when it holds, else why not.
 */
export function shapeHolds(pass: Probe, fail: Probe, limit: bigint): string | null {
  if (pass.gas === null || fail.gas === null || pass.up === null || fail.down === null) return 'a gas or a counterfactual step is unknown';
  if (pass.gas > limit || fail.gas <= limit) return `the model's gas (${pass.gas}, ${fail.gas}) does not straddle the limit ${limit}`;
  if (pass.gas + pass.up <= limit) return `${pass.label} with one more transfer of its own shape (${pass.gas} + ${pass.up}) is within the limit: ${fail.label}'s refusal is its overhead`;
  if (fail.gas - fail.down > limit) return `${fail.label} with one transfer fewer of its own shape (${fail.gas} - ${fail.down}) is still over the limit: its refusal is its overhead`;
  return null;
}

export interface SearchOptions {
  estimate: number; // the first length (boundary-estimate)
  limit: bigint; // userGasLimit
  start: { transfers: number; gas: bigint }; // the estimate's own probe (16 transfers)
  maxProbes: number; // single tokens of the coarse phase
  maxPairs?: number; // window builds (default 6)
  width?: number; // the lengths a window builds together, N - 1 .. N + width - 2 (default 4; 2 is N and N + 1 alone)
  recent?: number; // the newest single probes the coarse bracket is taken from (default 3)
  close?: number; // the coarse phase ends at a bracket this narrow (default 2)
  min?: number;
  max?: number;
}

export interface WindowBuild {
  n: number;
  lengths: number[];
  labels: string[];
  verdicts: ('pass' | 'refused')[];
  conditions: string[];
  outcome: 'pair' | 'all pass' | 'all refused' | 'inverted' | 'conditions differ' | 'shape' | 'not confirmed';
  reason?: string;
  pass?: string; // the crossing's two tokens, when the window has one
  fail?: string;
  // each adjacent two under one conditions: b.gas - a.gas - a.up, their gap beyond the lower token's own one-transfer step (the noise between
  // tokens built together); null across conditions
  residuals: (string | null)[];
}

export interface Drift { intercept: number; perBuild: number; perTransfer: number; residualSd: number; samples: number }

export interface SearchResult {
  pass: Probe;
  fail: Probe;
  confirmed: { pass: Probe; fail: Probe };
  tries: Probe[];
  windows: WindowBuild[];
  drift: Drift | null;
}

export class BoundaryNotFound extends Error {
  public constructor(message: string, public readonly tries: Probe[], public readonly windows: WindowBuild[] = [], public readonly drift: Drift | null = null) {
    super(message);
  }
}

const MARGIN = 2; // a bracketing step goes this many transfers past the predicted crossing
const MAX_STEP = 64;
const MAX_PAIR_STEP = 8; // the most transfers one pair build moves the next
const DRIFT_SAMPLES = 6; // the drift is subtracted from a pair step once this many tokens measure it

/** The per-transfer gas between two points, or null when it is not usable. */
function slope(a: { transfers: number; gas: bigint | null }, b: { transfers: number; gas: bigint | null }): bigint | null {
  if (a.gas === null || b.gas === null || a.transfers === b.transfers) return null;
  const s = (b.gas - a.gas) / BigInt(b.transfers - a.transfers);
  return s > 0n ? s : null;
}

const ceilDiv = (x: bigint, y: bigint): bigint => (x + y - 1n) / y;

/**
 * The least-squares fit gas = a + perTransfer * transfers + perBuild * build over the tokens (BUILD: the order they were built in, a pair's two
 * tokens sharing theirs). Null when the points cannot determine it.
 */
export function driftOf(points: { transfers: number; build: number; gas: bigint | null }[]): Drift | null {
  const ps = points.filter((p) => p.gas !== null).map((p) => [1, p.transfers, p.build, Number(p.gas)]);
  if (ps.length < 4) return null;
  const A = [0, 1, 2].map((r) => [0, 1, 2].map((c) => ps.reduce((s, p) => s + p[r] * p[c], 0)));
  const v = [0, 1, 2].map((r) => ps.reduce((s, p) => s + p[r] * p[3], 0));
  const M = A.map((row, r) => [...row, v[r]]);
  for (let c = 0; c < 3; c++) {
    let piv = c;
    for (let r = c + 1; r < 3; r++) if (Math.abs(M[r][c]) > Math.abs(M[piv][c])) piv = r;
    [M[c], M[piv]] = [M[piv], M[c]];
    if (Math.abs(M[c][c]) < 1e-9) return null;
    for (let r = 0; r < 3; r++) {
      if (r === c) continue;
      const f = M[r][c] / M[c][c];
      for (let k = c; k < 4; k++) M[r][k] -= f * M[c][k];
    }
  }
  const [a, perTransfer, perBuild] = [0, 1, 2].map((r) => M[r][3] / M[r][r]);
  const res = ps.map((p) => p[3] - (a + perTransfer * p[1] + perBuild * p[2]));
  const residualSd = Math.sqrt(res.reduce((s, x) => s + x * x, 0) / res.length);
  return { intercept: Math.round(a), perBuild: Math.round(perBuild), perTransfer: Math.round(perTransfer), residualSd: Math.round(residualSd), samples: ps.length };
}

/**
 * PROBE builds one fresh token of the given length and judges it; BUILD builds tokens of the given lengths together (in the same aggregator
 * rounds) and judges them at once, in order; REJUDGE judges a token already built again, now (the confirmation: both, back to back).
 */
export async function findBoundary(
  probe: (transfers: number, i: number) => Promise<Probe>,
  build: (lengths: number[], i: number) => Promise<Probe[]>,
  rejudge: (p: Probe) => Promise<Probe>,
  o: SearchOptions,
): Promise<SearchResult> {
  const min = o.min ?? 1;
  const max = o.max ?? 1024;
  const maxPairs = o.maxPairs ?? 6;
  const width = o.width ?? 4;
  const recent = o.recent ?? 3;
  const close = o.close ?? 2;
  const tries: Probe[] = [];
  const builds: { transfers: number; build: number; gas: bigint | null }[] = [];
  const windows: WindowBuild[] = [];
  let built = 0;
  const drift = (): Drift | null => driftOf(builds);
  const fail = (why: string): never => {
    throw new BoundaryNotFound(why, tries, windows, drift());
  };
  const clamp = (k: number): number => Math.min(max, Math.max(min, k));

  // ---- coarse: single tokens, the bracket from the newest RECENT only --------------------------------------------------------------------
  const singles: Probe[] = [];
  let k = clamp(o.estimate);
  let prev: { transfers: number; gas: bigint | null } = o.start;
  let bracketWidth = Infinity;
  let n0: number | null = null;
  while (n0 === null) {
    if (singles.length >= o.maxProbes) fail(`no bracket of the bound in ${o.maxProbes} single probes`);
    const p = await probe(k, built);
    if (p.transfers !== k) fail(`the probe of ${k} transfers holds ${p.transfers}`);
    tries.push(p);
    singles.push(p);
    builds.push({ transfers: p.transfers, build: built++, gas: p.gas });
    const window = singles.slice(-recent);
    let lo: Probe | null = null;
    for (const t of window) if (t.real === 'passes' && (lo === null || t.transfers > lo.transfers)) lo = t;
    let hi: Probe | null = null;
    for (const t of window) if (t.real === 'CapacityPreflight' && lo !== null && t.transfers > lo.transfers && (hi === null || t.transfers < hi.transfers)) hi = t;
    if (lo !== null && hi !== null) {
      const w = hi.transfers - lo.transfers;
      let next = lo.transfers + (w >> 1);
      if (w * 2 <= bracketWidth && lo.gas !== null && hi.gas !== null && hi.gas > lo.gas && o.limit >= lo.gas) {
        next = lo.transfers + Number(((o.limit - lo.gas) * BigInt(w)) / (hi.gas - lo.gas));
      }
      bracketWidth = w;
      if (w <= close) {
        n0 = Math.min(hi.transfers - 1, Math.max(lo.transfers, next)); // the pair phase starts at the crossing the newest bracket predicts
        break;
      }
      k = Math.min(hi.transfers - 1, Math.max(lo.transfers + 1, next));
    } else {
      // one side only among the newest: a secant step across the bound, from the two newest points
      const h = slope(prev, p) ?? slope(o.start, p);
      let step = MAX_STEP / 4;
      if (h !== null && p.gas !== null) {
        const off = p.gas > o.limit ? p.gas - o.limit : o.limit - p.gas;
        step = Math.min(MAX_STEP, Number(ceilDiv(off, h)) + MARGIN);
      }
      const target = clamp(p.real === 'passes' ? p.transfers + step : p.transfers - step);
      if (target === p.transfers) fail(`the search left its range [${min}, ${max}] at ${p.transfers} transfers`);
      k = target;
    }
    prev = p;
  }

  // ---- window: N - 1 .. N + WIDTH - 2 built together, judged at once ----------------------------------------------------------------------
  let n = clamp(n0);
  for (let j = 0; j < maxPairs; j++) {
    const i = built++;
    const lengths = Array.from({ length: width }, (_, x) => n - 1 + x).filter((k) => k >= min && k <= max);
    const toks = await build(lengths, i);
    if (toks.length !== lengths.length || toks.some((t, x) => t.transfers !== lengths[x])) {
      fail(`the build of ${lengths.join(', ')} holds ${toks.map((t) => t.transfers).join(', ')}`);
    }
    tries.push(...toks);
    for (const t of toks) builds.push({ transfers: t.transfers, build: i, gas: t.gas });
    // the residual of every adjacent two under one conditions: their gap beyond the lower one's own one-transfer step
    const residuals = toks.slice(1).map((b, x) => {
      const a = toks[x];
      return a.gas !== null && b.gas !== null && a.up !== null && a.conditions === b.conditions ? (b.gas - a.gas - a.up).toString() : null;
    });
    const record = (outcome: WindowBuild['outcome'], reason?: string, pass?: Probe, fail?: Probe): void => {
      windows.push({ n, labels: toks.map((t) => t.label), lengths, verdicts: toks.map((t) => (t.real === 'passes' ? 'pass' : 'refused')), conditions: toks.map((t) => t.conditions),
        outcome, reason, pass: pass?.label, fail: fail?.label, residuals });
    };
    // where the crossing is at the next build: from the fit over every token so far (the lengths, the builds' drift: one build's own noise
    // averages out) once it has DRIFT_SAMPLES of them, else from this window's own gas; beyond the window the way the verdicts say
    const target = (): number | null => {
      const d = drift();
      if (d !== null && d.samples >= DRIFT_SAMPLES && d.perTransfer > 0) return Math.floor((Number(o.limit) - d.intercept - d.perBuild * (i + 1)) / d.perTransfer);
      const lo = toks[0];
      const hi = toks[toks.length - 1];
      if (lo.gas === null || hi.gas === null || hi.transfers === lo.transfers || hi.gas <= lo.gas) return null;
      return lo.transfers + Number(((o.limit - lo.gas) * BigInt(hi.transfers - lo.transfers)) / (hi.gas - lo.gas));
    };
    const top = lengths[lengths.length - 1];
    const bottom = lengths[0];
    if (toks.every((t) => t.real === 'passes')) {
      record('all pass');
      const t = target();
      n = clamp(Math.min(top + MAX_PAIR_STEP, Math.max(top, t ?? top))); // the next window starts at the top at least: the crossing is above it
      continue;
    }
    if (toks.every((t) => t.real === 'CapacityPreflight')) {
      record('all refused');
      if (bottom === min) fail(`${min} transfers are refused: the search left its range`);
      const t = target();
      n = clamp(Math.max(bottom - MAX_PAIR_STEP, Math.min(bottom - 1, t ?? bottom - 1))); // the crossing is below the bottom
      continue;
    }
    // one crossing, from passes to refusals; anything else is noise within the build
    const m = toks.findIndex((t) => t.real !== 'passes');
    if (m < 1 || toks.slice(m).some((t) => t.real === 'passes')) {
      record('inverted');
      continue;
    }
    const a = toks[m - 1];
    const b = toks[m];
    n = a.transfers; // the next window, if any, centred on this crossing
    if (a.conditions !== b.conditions) {
      record('conditions differ', `${a.conditions} / ${b.conditions}`, a, b);
      continue;
    }
    const why = shapeHolds(a, b, o.limit);
    if (why !== null) {
      record('shape', why, a, b);
      continue;
    }
    // judged again, back to back: both verdicts, both conditions and the shapes must stand
    const ca = await rejudge(a);
    const cb = await rejudge(b);
    const again = shapeHolds(ca, cb, o.limit);
    if (ca.real === 'passes' && cb.real === 'CapacityPreflight' && ca.conditions === a.conditions && cb.conditions === a.conditions && again === null) {
      record('pair', undefined, a, b);
      return { pass: a, fail: b, confirmed: { pass: ca, fail: cb }, tries, windows, drift: drift() };
    }
    record('not confirmed', again ?? `judged again: ${ca.real} / ${cb.real} under ${ca.conditions} / ${cb.conditions}`, a, b);
  }
  return fail(`no confirmed pair under identical conditions in ${maxPairs} builds`);
}
