/**
 * The boundary stage's search (driver.ts boundary, NB2-09 bft-core#1105): where the wallet's preflight stops admitting a return, located on
 * live tokens within a measured margin.
 *
 * What the live tokens showed (runs 43994509728 and 44003156840): every gas term but the evidence bytes is constant across fresh tokens, and
 * those bytes drift up about half a transfer's step a probe and deviate by about 0.6 step (1.2 steps between tokens built together in one
 * window), so a pass beside a refusal one transfer longer is not reliably observable live, and a probe built minutes earlier is stale.
 * The stage's claim (the owner's default, briefs/owner-questions.md) is therefore two:
 *
 *   soundness   every token the stage builds is judged by the preflight and then executed: an admitted one is burned and paid within the
 *               limit, a refused one is over it by the preflight's own gas and is never burned (rehearse_nb2.py, every probe; strict);
 *   location    the bound lies within MARGIN transfers: among the newest RECENT probes, the highest admitted length and the lowest refused one
 *               are at most `margin` apart (in either order: a refusal below an admission within the margin is the measured noise).
 *
 * The search brackets with single tokens: a secant step from the newest two until the newest probes hold both verdicts, then interpolation
 * between the newest admission and refusal (bisection when a step fails to halve the bracket). At most maxProbes tokens, then
 * BoundaryNotFound (fail closed), with every probe reported. Each probe also records the shape diagnostics (ownShape: whether one more transfer
 * of an admitted token's own shape would be refused, and one fewer of a refused token's would be admitted): recorded, not gating.
 *
 * Pure: the driver supplies the probes. No imports, so the unit tests run without a chain (boundary_search.test.ts).
 */

export type Verdict = 'passes' | 'CapacityPreflight';

/**
 * Which limit refused a probe, read from the preflight's own checks (never inferred from a missing gas figure): the bytes when the proofs
 * needed do not fit L_max (or not even the evidence does), else the gas when the bound is over userGasLimit, else 'unbounded' (the model
 * gave no bound: not a measured capacity, and the boundary stage does not count it as one).
 */
export function refusalOf(r: { baseFits: boolean; need: bigint; pMax: bigint; gas: bigint | null; limit: bigint }): 'bytes' | 'gas' | 'unbounded' {
  if (!r.baseFits || r.need > r.pMax) return 'bytes';
  if (r.gas === null) return 'unbounded';
  return r.gas > r.limit ? 'gas' : 'unbounded';
}

export interface Probe {
  label: string;
  transfers: number;
  conditions: string; // the token's set of certificates (their hashes) and the segment need: recorded, for the evidence
  gas: bigint | null; // the preflight's gas for the token (the lane's replay of planReturn's inputs, the same model and inputs)
  // the model's gas of one more transfer of this token's own average shape, and the gas one fewer saves (boundary_shape.ts marginals; not
  // equal where the excess bytes clip at zero); null when they cannot be computed
  up: bigint | null;
  down: bigint | null;
  real: Verdict; // planReturn's own verdict
  detail?: Record<string, number | string>; // the token's gas terms, for the evidence only (never read by the search)
}

/**
 * The shape diagnostics of one probe (recorded, not gating): for an admitted token, whether one more transfer of its own shape is over the
 * limit (it sits within a step of the bound); for a refused one, whether one fewer is within it. Null when the gas or the step is unknown.
 */
export function ownShape(p: Probe, limit: bigint): { nextOver?: boolean | null; prevWithin?: boolean | null } {
  if (p.real === 'passes') return { nextOver: p.gas === null || p.up === null ? null : p.gas + p.up > limit };
  return { prevWithin: p.gas === null || p.down === null ? null : p.gas - p.down <= limit };
}

/**
 * The two-sided shape check of an admitted and a refused token (sol r7, r8 on #1126): PASS with one more transfer of its own shape over the
 * limit and FAIL with one fewer within it. Null when it holds, else why not. A diagnostic of the stage, not a gate.
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
  maxProbes: number;
  margin: number; // m: the most transfers between the newest highest admission and lowest refusal
  recent?: number; // the newest probes the bracket is taken from (default 3)
  min?: number;
  max?: number;
}

export interface Drift { intercept: number; perBuild: number; perTransfer: number; residualSd: number; samples: number }

export interface SearchResult {
  admitted: Probe; // the highest admitted length among the newest probes
  refused: Probe; // the lowest refused length among them
  spread: number; // |refused - admitted| transfers, at most margin
  margin: number;
  window: string[]; // the newest probes the two come from
  tries: Probe[];
  drift: Drift | null;
}

export class BoundaryNotFound extends Error {
  public constructor(message: string, public readonly tries: Probe[], public readonly drift: Drift | null = null) {
    super(message);
  }
}

const MARGIN = 2; // a bracketing step goes this many transfers past the predicted crossing
const MAX_STEP = 64;

/** The per-transfer gas between two points, or null when it is not usable. */
function slope(a: { transfers: number; gas: bigint | null }, b: { transfers: number; gas: bigint | null }): bigint | null {
  if (a.gas === null || b.gas === null || a.transfers === b.transfers) return null;
  const s = (b.gas - a.gas) / BigInt(b.transfers - a.transfers);
  return s > 0n ? s : null;
}

const ceilDiv = (x: bigint, y: bigint): bigint => (x + y - 1n) / y;

/**
 * The least-squares fit gas = intercept + perTransfer * transfers + perBuild * build over the tokens (BUILD: their order), for the evidence:
 * the drift a probe. Null when the points cannot determine it.
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

/** PROBE builds one fresh token of the given length and judges it (planReturn's verdict and the preflight's gas). */
export async function findBoundary(probe: (transfers: number, i: number) => Promise<Probe>, o: SearchOptions): Promise<SearchResult> {
  const min = o.min ?? 1;
  const max = o.max ?? 1024;
  const recent = o.recent ?? 3;
  if (!(o.margin >= 1)) throw new Error('the margin is at least one transfer');
  const tries: Probe[] = [];
  const drift = (): Drift | null => driftOf(tries.map((t, i) => ({ transfers: t.transfers, build: i, gas: t.gas })));
  const fail = (why: string): never => {
    throw new BoundaryNotFound(why, tries, drift());
  };
  const clamp = (k: number): number => Math.min(max, Math.max(min, k));
  let k = clamp(o.estimate);
  let prev: { transfers: number; gas: bigint | null } = o.start;
  let width = Infinity;
  for (;;) {
    if (tries.length >= o.maxProbes) fail(`the newest ${recent} probes never held an admission and a refusal within ${o.margin} transfers in ${o.maxProbes} probes`);
    const p = await probe(k, tries.length);
    if (p.transfers !== k) fail(`the probe of ${k} transfers holds ${p.transfers}`);
    tries.push(p);
    const window = tries.slice(-recent);
    let hi: Probe | null = null; // the highest admission
    for (const t of window) if (t.real === 'passes' && (hi === null || t.transfers > hi.transfers)) hi = t;
    let lo: Probe | null = null; // the lowest refusal
    for (const t of window) if (t.real === 'CapacityPreflight' && (lo === null || t.transfers < lo.transfers)) lo = t;
    if (hi !== null && lo !== null) {
      const spread = Math.abs(lo.transfers - hi.transfers);
      if (spread <= o.margin) return { admitted: hi, refused: lo, spread, margin: o.margin, window: window.map((t) => t.label), tries, drift: drift() };
      if (lo.transfers > hi.transfers) {
        // a bracket wider than the margin: interpolate on the newest admission and refusal, bisect when a step did not halve it
        const w = lo.transfers - hi.transfers;
        let next = hi.transfers + (w >> 1);
        if (w * 2 <= width && hi.gas !== null && lo.gas !== null && lo.gas > hi.gas && o.limit >= hi.gas) {
          next = hi.transfers + Number(((o.limit - hi.gas) * BigInt(w)) / (lo.gas - hi.gas));
        }
        width = w;
        k = Math.min(lo.transfers - 1, Math.max(hi.transfers + 1, next));
      } else {
        // a refusal further below an admission than the margin: the older of the two is stale; probe between them
        k = lo.transfers + ((hi.transfers - lo.transfers) >> 1);
      }
    } else {
      // one verdict only among the newest: a secant step across the bound, from the two newest points
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
}
