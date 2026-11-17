/**
 * The boundary stage's ledger read (driver.ts ledger, sol r12 and r13 on #1126): whether a refused probe's source state is unspent, from the
 * aggregator's verified non-inclusion proof at a snapshot sealed at or after the refusal's completion. Every request runs under an abort
 * signal and a timer for the rest of one overall deadline (a stalled transport is abandoned, never awaited past it), and a report is returned
 * whatever happens: `unspent` only for a verified absence on the expected network, sealed at or after NOT_BEFORE and past the token's newest
 * certificate round; `included`, `rejected`, `stale`, `error` or `timeout` otherwise (the lane fails closed on all of them).
 *
 * Pure: ASK does one request and its verification (the driver's: getNonInclusionProof and verifyNonInclusion); no imports, so the unit tests
 * run without a chain (ledger_check.test.ts).
 */

export interface Snapshot { networkId: number; rootEpoch: bigint; rootRound: bigint; sealTimestampSeconds: bigint; shardRound: bigint }

/** One answer: the service's inclusion hint, or a proof and its verification (a snapshot for absence or inclusion, a rejection without). */
export type Answer =
  | { kind: 'hint' }
  | { kind: 'verified'; verdict: 'absent_at_snapshot' | 'included_at_snapshot'; snapshot: Snapshot; proof: string }
  | { kind: 'rejected'; reason: string; proof: string };

export interface LedgerOptions {
  notBefore: bigint; // Unix seconds: the first whole second after the refusal completed
  newestRound: bigint; // the token's newest certificate's root round
  networkId: number;
  deadlineMs: number; // the whole read
  pollMs: number; // between attempts
  now?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

export interface LedgerReport {
  verdict: 'unspent' | 'included' | 'rejected' | 'stale' | 'error' | 'timeout';
  reason?: string;
  attempts: number;
  snapshot?: Snapshot;
  proof?: string;
  elapsedMs: number;
}

export class Deadline extends Error {}

/**
 * F under SIGNAL and a timer of MS: settles by then whatever F does (a promise that never settles is abandoned, its signal aborted).
 */
export async function bounded<T>(f: (signal: AbortSignal) => Promise<T>, ms: number): Promise<T> {
  const ctl = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const e = new Deadline(`no answer within ${ms} ms`);
      ctl.abort(e);
      reject(e);
    }, Math.max(0, ms));
  });
  try {
    return await Promise.race([f(ctl.signal), expired]);
  } finally {
    clearTimeout(timer);
  }
}

const defaultSleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
  });

export async function readLedger(ask: (signal: AbortSignal) => Promise<Answer>, o: LedgerOptions): Promise<LedgerReport> {
  const now = o.now ?? (() => Date.now());
  const sleep = o.sleep ?? defaultSleep;
  const t0 = now();
  const end = t0 + o.deadlineMs;
  const report: LedgerReport = { verdict: 'timeout', reason: `no verified answer within ${o.deadlineMs} ms`, attempts: 0, elapsedMs: 0 };
  const done = (r: Partial<LedgerReport>): LedgerReport => Object.assign(report, r, { elapsedMs: now() - t0 });
  for (;;) {
    const left = end - now();
    if (left <= 0) return done({}); // the last attempt's verdict stands (stale or error), or timeout when none completed
    report.attempts++;
    let a: Answer;
    try {
      a = await bounded(ask, left);
    } catch (e) {
      if (e instanceof Deadline) return done({ verdict: 'timeout', reason: `the request did not complete within the deadline (${o.deadlineMs} ms): abandoned` });
      report.verdict = 'error';
      report.reason = String((e as Error)?.message ?? e);
      const rest = end - now();
      if (rest <= 0) return done({});
      await bounded((s) => sleep(Math.min(o.pollMs, rest), s), rest).catch(() => undefined);
      continue;
    }
    if (a.kind === 'hint') return done({ verdict: 'included', reason: 'the service says the state is certified (state_included_hint)' });
    if (a.kind === 'rejected') return done({ verdict: 'rejected', reason: a.reason, proof: a.proof });
    report.snapshot = a.snapshot;
    report.proof = a.proof;
    if (a.verdict === 'included_at_snapshot') return done({ verdict: 'included', reason: 'a verified proof that the state is certified: the token is spent' });
    const s = a.snapshot;
    if (s.networkId === o.networkId && s.sealTimestampSeconds >= o.notBefore && s.rootRound > o.newestRound) return done({ verdict: 'unspent', reason: undefined });
    report.verdict = s.networkId !== o.networkId ? 'rejected' : 'stale';
    report.reason = s.networkId !== o.networkId
      ? `a snapshot of network ${s.networkId}, not ${o.networkId}`
      : `absent at root round ${s.rootRound} sealed ${s.sealTimestampSeconds}: not at or after ${o.notBefore} and past round ${o.newestRound}`;
    if (report.verdict === 'rejected') return done({});
    const rest = end - now();
    if (rest <= 0) return done({});
    await bounded((sig) => sleep(Math.min(o.pollMs, rest), sig), rest).catch(() => undefined);
  }
}
