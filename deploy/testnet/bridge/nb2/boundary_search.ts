/**
 * The boundary stage's search (driver.ts boundary, NB2-09 bft-core#1105): the largest transfer history N whose return the wallet's preflight
 * admits, as an adjacent pair of live probes under the same conditions: N passes and N + 1 is refused (CapacityPreflight), with the same
 * number of distinct certificates and the same segment need (cObs - a + reserve), and the two verdicts given again back to back at the end.
 * A pass under 16 certificates beside a refusal under 17 does not locate the boundary: a certificate moves the preflight's gas by about one
 * transfer's worth, and so does a gap proof.
 *
 * The conditions do not hold every input of the wallet's gas model: the evidence bytes beyond the measured shape and the seal signatures
 * beyond the measured 3 (the mint's, the deposit's EVM UC and every transfer's) differ from one fresh token to the next, by about a transfer's
 * gas. So a candidate pair stands only when its boundary holds under each token's own shape (shapeHolds): the pass token with one more
 * transfer of its own average shape is over the limit, and the refused token with one transfer fewer of its own shape is within it. A pair
 * whose verdicts an overhead difference could explain is refused (fail closed) and one side is built again.
 *
 * The preflight's gas is not linear in the transfers on live tokens (the average per hop from the 16-transfer probe is about three times the
 * marginal one near the bound), so the steps come from the probes themselves: a secant step until the bound is bracketed, then interpolation
 * inside the bracket with a bisection whenever a step fails to halve it. Probes are grouped by their conditions; the pair must come from one
 * group. Each probe is a fresh deposit chained to its length (a token checked one transfer further has spent the one below), so the number of
 * probes is bounded and every one is reported.
 *
 * Pure: the driver supplies the probes. No imports, so the unit tests run without a chain (boundary_search.test.ts).
 */

export type Verdict = 'passes' | 'CapacityPreflight';

export interface Probe {
  label: string;
  transfers: number;
  conditions: string; // what besides the transfers moves the verdict: the distinct certificates and the segment need
  gas: bigint | null; // the preflight's gas for the token (the lane's replay of planReturn's inputs, the same model and inputs)
  // the model's gas of one more transfer of this token's own average shape (its bytes and signatures beyond the measured ones), and the gas
  // one fewer saves: not the same where the excess bytes clip at zero (boundary_shape.ts marginals); rounded down, which makes both of
  // shapeHolds' sides stricter; null when they cannot be computed (never a pair)
  up: bigint | null;
  down: bigint | null;
  real: Verdict; // planReturn's own verdict
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
  maxProbes: number; // fresh tokens
  maxConfirmations?: number; // back-to-back re-judgements of a candidate pair
  min?: number;
  max?: number;
}

export interface RefusedPair { pass: string; fail: string; reason: string }

export interface SearchResult { pass: Probe; fail: Probe; confirmed: { pass: Probe; fail: Probe }; tries: Probe[]; refused: RefusedPair[] }

export class BoundaryNotFound extends Error {
  public constructor(message: string, public readonly tries: Probe[], public readonly refused: RefusedPair[] = []) {
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

interface Bracket { lo: Probe | null; hi: Probe | null }

/** lo: the largest length that passes; hi: the smallest refused length above it (a refusal below a pass is noise, never a bound). */
function bracketOf(ps: Iterable<Probe>): Bracket {
  const all = [...ps];
  let lo: Probe | null = null;
  for (const p of all) if (p.real === 'passes' && (lo === null || p.transfers > lo.transfers)) lo = p;
  let hi: Probe | null = null;
  for (const p of all) if (p.real === 'CapacityPreflight' && (lo === null || p.transfers > lo.transfers) && (hi === null || p.transfers < hi.transfers)) hi = p;
  return { lo, hi };
}

/**
 * PROBE builds a fresh token of the given length and judges it; REJUDGE judges a token already built again, now (the pair's confirmation:
 * the pass and the refusal back to back, under one chain state).
 */
export async function findBoundary(probe: (transfers: number, i: number) => Promise<Probe>, rejudge: (p: Probe) => Promise<Probe>, o: SearchOptions): Promise<SearchResult> {
  const min = o.min ?? 1;
  const max = o.max ?? 1024;
  const maxConfirmations = o.maxConfirmations ?? 3;
  const tries: Probe[] = [];
  const refused: RefusedPair[] = [];
  const refuse = (pass: Probe, fail: Probe, reason: string): void => {
    if (!refused.some((r) => r.pass === pass.label && r.fail === fail.label && r.reason === reason)) refused.push({ pass: pass.label, fail: fail.label, reason });
  };
  const byLabel = new Map<string, Probe>(); // every token built, by its newest judgement: an older token stays usable (it is unspent)
  const latest = new Map<string, Probe>(); // the newest verdict of each length under each conditions: a re-probe or re-judgement replaces it
  const newest = new Map<number, Probe>(); // the newest verdict of each length, whatever its conditions: the global view
  const record = (p: Probe): void => {
    latest.set(`${p.conditions}\u0000${p.transfers}`, p);
    newest.set(p.transfers, p);
    byLabel.set(p.label, p);
  };
  const run = async (k: number): Promise<Probe> => {
    if (tries.length >= o.maxProbes) throw new BoundaryNotFound(`no adjacent pass/refuse pair under the same conditions in ${o.maxProbes} probes`, tries, refused);
    const p = await probe(k, tries.length);
    if (p.transfers !== k) throw new BoundaryNotFound(`the probe of ${k} transfers holds ${p.transfers}`, tries, refused);
    tries.push(p);
    record(p);
    return p;
  };
  const groups = (): Map<string, Bracket> => {
    const by = new Map<string, Probe[]>();
    for (const p of latest.values()) by.set(p.conditions, [...(by.get(p.conditions) ?? []), p]);
    return new Map([...by].map(([c, ps]) => [c, bracketOf(ps)]));
  };
  // the global view steers until one group is bracketed
  const global = (): Bracket => bracketOf(newest.values());
  const clamp = (k: number): number => Math.min(max, Math.max(min, k));
  const widths = new Map<string, number>(); // a bracket's width when it was last stepped in: a step that did not halve it bisects next
  const inside = (name: string, lo: Probe, hi: Probe): number => {
    const w = hi.transfers - lo.transfers;
    let next = lo.transfers + (w >> 1);
    if (w * 2 <= (widths.get(name) ?? Infinity) && lo.gas !== null && hi.gas !== null && hi.gas > lo.gas && o.limit >= lo.gas) {
      next = lo.transfers + Number(((o.limit - lo.gas) * BigInt(w)) / (hi.gas - lo.gas));
    }
    widths.set(name, w);
    return Math.min(hi.transfers - 1, Math.max(lo.transfers + 1, next));
  };

  // a token whose own shape puts the boundary next to it: a pass that one more transfer of its shape would take over the limit, a refusal that
  // one transfer fewer would bring within it (shapeHolds' two sides). A pair of them, adjacent and under one conditions, is the candidate.
  const goodPass = (t: Probe): boolean => t.real === 'passes' && t.gas !== null && t.up !== null && t.gas <= o.limit && t.gas + t.up > o.limit;
  const goodFail = (t: Probe): boolean => t.real === 'CapacityPreflight' && t.gas !== null && t.down !== null && t.gas > o.limit && t.gas - t.down <= o.limit;

  let k = clamp(o.estimate);
  let prev: { transfers: number; gas: bigint | null } = o.start;
  let side = 0;
  let confirmations = 0;
  for (;;) {
    const p = await run(k);
    const all = [...byLabel.values()];
    // the evidence: every adjacent pass/refusal under one conditions whose shapes do not hold the boundary
    for (const lo of all) {
      if (lo.real !== 'passes') continue;
      for (const hi of all) if (hi.real === 'CapacityPreflight' && hi.transfers === lo.transfers + 1 && hi.conditions === lo.conditions) {
        const why = shapeHolds(lo, hi, o.limit);
        if (why !== null) refuse(lo, hi, why);
      }
    }
    // candidates, the newest first
    let candidate: { lo: Probe; hi: Probe } | null = null;
    for (const hi of [...all].reverse()) {
      if (!goodFail(hi)) continue;
      const lo = [...all].reverse().find((t) => goodPass(t) && t.transfers + 1 === hi.transfers && t.conditions === hi.conditions);
      if (lo !== undefined && shapeHolds(lo, hi, o.limit) === null) { candidate = { lo, hi }; break; }
    }
    if (candidate !== null && confirmations < maxConfirmations) {
      // both judged again, back to back; the pair stands only if both verdicts, both conditions and the shapes still hold
      const { lo, hi } = candidate;
      confirmations++;
      const a = await rejudge(lo);
      const b = await rejudge(hi);
      const again = shapeHolds(a, b, o.limit);
      if (a.real === 'passes' && b.real === 'CapacityPreflight' && a.conditions === lo.conditions && b.conditions === lo.conditions && again === null) {
        return { pass: lo, fail: hi, confirmed: { pass: a, fail: b }, tries, refused };
      }
      if (again !== null) refuse(a, b, `judged again: ${again}`);
      // superseded: the newer verdicts stand (under their own conditions when the chain moved)
      latest.delete(`${lo.conditions}\u0000${lo.transfers}`);
      latest.delete(`${hi.conditions}\u0000${hi.transfers}`);
      record(a);
      record(b);
    }
    // next to a good token of the newest probe's conditions: inside the gap between a good pass and a good refusal; else its neighbour and
    // its own length in turn (a lucky light pass at N with every token of N + 1 heavy: a fresh token of N is a good refusal beside N - 1)
    const mine = [...byLabel.values()].filter((t) => t.conditions === p.conditions);
    const gp = mine.filter(goodPass).reduce<number | null>((m, t) => (m === null || t.transfers > m ? t.transfers : m), null);
    const gf = mine.filter(goodFail).reduce<number | null>((m, t) => ((gp === null || t.transfers > gp) && (m === null || t.transfers < m) ? t.transfers : m), null);
    if (gp !== null || gf !== null) {
      if (gp !== null && gf !== null && gf > gp + 1) k = gp + ((gf - gp) >> 1);
      else if (gp !== null) k = side++ % 2 === 0 ? gp + 1 : gp;
      else k = side++ % 2 === 0 ? gf! - 1 : gf!;
      k = clamp(k);
      prev = p;
      continue;
    }
    const gs = groups();
    // the bracket of the newest probe's group (the conditions the next probe most likely gets: a rare count, or the need before the chain moved,
    // is not chased), then the global bracket
    const own = gs.get(p.conditions);
    const best = own !== undefined && own.lo !== null && own.hi !== null && own.hi.transfers > own.lo.transfers + 1 ? { name: `group ${p.conditions}`, lo: own.lo, hi: own.hi } : null;
    const g = global();
    if (best !== null) {
      k = inside(best.name, best.lo, best.hi);
    } else if (g.lo !== null && g.hi !== null && g.hi.transfers > g.lo.transfers + 1) {
      k = inside('all', g.lo, g.hi);
    } else if (g.lo !== null && g.hi !== null) {
      // adjacent only across two groups: the next probe, at either length, lands in one of them and brackets it
      k = side++ % 2 === 0 ? g.hi.transfers : g.lo.transfers;
    } else {
      // one side only: a secant step across the bound, from the two newest points
      const h = slope(prev, p) ?? slope(o.start, p);
      let step = MAX_STEP / 4;
      if (h !== null && p.gas !== null) {
        const off = p.gas > o.limit ? p.gas - o.limit : o.limit - p.gas;
        step = Math.min(MAX_STEP, Number(ceilDiv(off, h)) + MARGIN);
      }
      const target = clamp(p.real === 'passes' ? p.transfers + step : p.transfers - step);
      if (target === p.transfers) throw new BoundaryNotFound(`the search left its range [${min}, ${max}] at ${p.transfers} transfers`, tries, refused);
      k = target;
    }
    prev = p;
  }
}
