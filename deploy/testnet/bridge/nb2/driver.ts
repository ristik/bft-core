/**
 * The native bridge v2 live driver of the package lanes (NB2-09, bft-core#1105). It drives the TypeScript wallet plug-in (NB2-07,
 * native-bridge-plugins `packages/native-bridge-plugin/src/nb2`) against a running generation through the public gateway only: the
 * chain, the aggregator (`/aggregator`) and the trust-base pages. Its wallets are the reference wallet's (native-bridge-plugins wallet/core.ts,
 * bft-core#1107): the same directory, journal, keys and steps (deposit, mint, transfer, split, burn, redeem) that the command-line wallet runs;
 * what this file adds is the lane's measurements, mutations and fault injection. rehearse_nb2.py runs one command per container, in the bridge tools
 * image, with this directory mounted at `tests/live/nb2lane/` of the image's plug-in checkout and GENERATION/bridge at /work. State
 * lives under /work/nb2 (each wallet's journal, tokens and trust history); every command writes what the lane checks to
 * /work/nb2/out/<name>.json. Keys come from the environment (NB2_KEY_<WALLET>, never in the evidence).
 *
 *   gamma-check            the TypeScript side of the deployment check: Γ decodes, the vault constructor's rules (construct) hold for the
 *                          deployed addresses, and NativeBridgeV2.open's installation check passes (chain ID, config(), runtime code hash)
 *   envelope OUT           the published operating envelope from the pinned limits and the plug-in's measured gas model
 *   deposit W LABEL AMOUNT [--plan-only|--adopt]
 *                          deposit AMOUNT units, collect the receipt proof, mint (--plan-only journals the plan and prints its calldata for a
 *                          deposit the lane signs itself, a legacy transaction; --adopt then finds it by rho and mints)
 *   transfer W FROM TO OWNER
 *   split W FROM OWNER LABEL=AMOUNT LABEL=AMOUNT
 *   chain W FROM TO N [--rounds]   N transfers, certified in one aggregator batch (or one round each with --rounds)
 *   burn W LABEL [--recipient ADDR]   plan the return (preflight) and certify the burn; the evidence and the three verdicts' inputs
 *   preflight W LABEL      plan the return only (the capacity preflight), never burn
 *   ledger W LABEL T       the aggregator's verified non-inclusion of LABEL's head state at a snapshot sealed at T or later: unspent, never burned
 *   verdicts W LABEL...    the plug-in's verdict and the deployed verifier's (eth_call verifyReturn), byte for byte
 *   redeem W LABEL [--low-gas|--hold|--stale|--expect-ambiguous]
 *   replay W LABEL         the paid redemption again: the exact calldata re-sent, and the wallet's own refusal
 *   rotate W N [--prepare|--pay]   N small returns by wallet W (prepared ahead: deposit, mint, burn; then paid in a burst)
 *   mutations W LABEL      isolated mutations of one burned part, judged by the plug-in and by the deployed verifier
 *   faults W LABEL         fault injection of the native primitives and the helper by eth_call state overrides (validator 1 directly)
 *   admission              the production and test builds admit only their own (K, B)
 *   state                  the vault's state() and the custody inputs
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import { concat, eq, toHex } from '../../../packages/native-bridge-plugin/src/bytes.js';
import {
  ASSET_UCT, AmbiguousBroadcast, HttpJsonRpc, MeasuredGasModel, Nb2Error, RpcError, SELECTOR, WalletError,
  burnPairBound, buildParams, classifyRedeemError, construct, decodeConfig, decodeEvidence, decodeRevert, decodeToken, encodeReturnData,
  encodeToken, evidenceOf, gapProofLen, log2, maxProofs, otherBytes, redeemCalldata, redeemCalldataLength, redeemFeatures, redeemGasTerms, redeemTxFraming,
  revertDataOf, signTx, verdictAbi, verifyPart, type ReturnRecord,
} from '../../../packages/native-bridge-plugin/src/nb2/index.js';
import { appendTransfer, headOf, transferRequest, freshMask } from '../../../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { signaturePredicate, encodeProof, type Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { HE, HU } from '../../../packages/native-bridge-plugin/src/nb2/crypto.js';
import { decodeReceiptBacking } from '../../../packages/native-bridge-plugin/src/nb2/deposit.js';
import { u256 } from '../../../packages/native-bridge-plugin/src/nb2/cbor.js';
import { BoundaryNotFound, findBoundary, ownShape, refusalOf, type Probe, type Verdict } from './boundary_search.js';
import { marginals } from './boundary_shape.js';
import { history, template } from './envelope_shape.js';
import { readLedger, type Answer } from './ledger_check.js';
import { LANE_OPEN } from './lane_open.js';
import {
  GatewayAggregator, Wallet as ReferenceWallet, burn as walletBurn, mint as walletMint, pinsOf, planDeposit, redeem as walletRedeem, retry as walletRetry,
  sendDeposit, split as walletSplit, transfer as walletTransfer, type OpenOptions, type TokenEntry,
} from '../../../wallet/core.js';

// ---- configuration ------------------------------------------------------------------------------------------------------------------

const WORK = process.env.NB2_WORK ?? '/work/nb2';
interface Lane {
  rpc: string; // the public gateway
  agg: string; // the gateway's /aggregator route
  direct: string; // validator 1's execution client, for the fault-injection eth_call overrides only (an operator check, not a wallet step)
  release: string;
  trustBundle: string;
  trustPin: string;
  unit: string; // wei per scenario unit
  verifier: string;
  helper: string;
  production?: { vault: string; verifier: string; gamma: string; vaultInitcode?: string };
  test?: { gamma: string; vaultInitcode?: string };
}
const lane: Lane = JSON.parse(readFileSync(join(WORK, 'lane.json'), 'utf8'));
const release = JSON.parse(readFileSync(lane.release, 'utf8'));
const UNIT = BigInt(lane.unit);

const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const hx = (b: Uint8Array): string => `0x${toHex(b)}`;
const big = (s: string | number | bigint): bigint => BigInt(s);

const pins = pinsOf(release);
const cfg = decodeConfig(pins.gamma, buildParams(pins.build));

const out = (name: string, v: unknown): void => {
  mkdirSync(join(WORK, 'out'), { recursive: true });
  writeFileSync(join(WORK, 'out', `${name}.json`), JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? hx(x) : x), 2) + '\n');
};
const log = (...a: unknown[]): void => console.log(...a.map((x) => (typeof x === 'bigint' ? x.toString() : x)));

// ---- wallets: the reference wallet (native-bridge-plugins wallet/core.ts), one directory per lane wallet -------------------------------------

/** The lane's key of wallet NAME: NB2_KEY_<NAME> (never in a command line or the evidence). */
function laneKey(name: string): Uint8Array {
  const k = process.env[`NB2_KEY_${name.toUpperCase()}`];
  if (!k) throw new Error(`NB2_KEY_${name.toUpperCase()} is not set`);
  return unhex(k);
}

/**
 * A lane wallet: the reference wallet's directory, journal, keys and steps in WORK/wallets/NAME, with the lane's connection (lane.json) and the
 * gateway RPC counted for the ambiguous-broadcast check. Opened as LANE_OPEN says: without the installation check unless asked (gamma-check
 * runs it), and without the wallet lock (a killed container's lock would block every later command on the wallet).
 */
class Wallet extends ReferenceWallet {
  public readonly name: string;
  public constructor(name: string) {
    super(join(WORK, 'wallets', name), laneKey(name), { release: lane.release, trustBundle: lane.trustBundle, trustPin: lane.trustPin, rpc: lane.rpc, aggregator: lane.agg });
    this.name = name;
  }
  public override open(opts: OpenOptions = {}): Promise<this> {
    return super.open({ ...LANE_OPEN, wrapRpc: (r) => new CountingRpc(r), ...opts });
  }
}

/** The gateway as the wallet sees it, counting the ambiguous broadcasts (HTTP 503 "broadcast may be partial", #1121) it answered. */
const broadcasts = { sent: 0, ambiguous: 0, preSent: 0, messages: [] as string[] };
/**
 * --ambiguous: each signed transaction reaches validator 1 directly first, so the gateway's broadcast then gets "already known" from it and a hash
 * from the others; the relay calls that a partial broadcast (HTTP 503) although every pool holds the transaction: the #1121 ambiguity, on demand.
 */
let preSendDirect = false;
class CountingRpc {
  public constructor(private readonly inner: HttpJsonRpc) {}
  public async call<T>(method: string, params: unknown[]): Promise<T> {
    if (method !== 'eth_sendRawTransaction') return this.inner.call<T>(method, params);
    broadcasts.sent++;
    if (preSendDirect) {
      try {
        await direct.call('eth_sendRawTransaction', params);
        broadcasts.preSent++;
      } catch { /* already known is fine */ }
    }
    try {
      return await this.inner.call<T>(method, params);
    } catch (e) {
      if (e instanceof RpcError && e.status === 503) {
        broadcasts.ambiguous++;
        broadcasts.messages.push(e.message.slice(0, 160));
      }
      throw e;
    }
  }
}

const js = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? hx(x) : x));

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The wallet's retry of a step that is not ready yet (CompanionUnknown and the like), told on the console. */
const retrying = (what: string) => (reason: string): void => log(`  ${what}: ${reason}, retrying`);
const retry = <T>(what: string, f: () => Promise<T>): Promise<T> => walletRetry(f, retrying(what));

const rpc = new HttpJsonRpc(lane.rpc, { retries: 20, timeoutMs: 120_000 });
const direct = new HttpJsonRpc(lane.direct, { retries: 5, timeoutMs: 120_000 });

/** The rule name of revert data (the vault's or the verifier's), with VerifierRefused's inner rule. */
function ruleOf(data: Uint8Array | null): string {
  if (data === null || data.length === 0) return data === null ? 'no-data' : 'empty';
  const e = decodeRevert(data);
  if (e === null) return `unknown:${hx(data.subarray(0, Math.min(36, data.length)))}`;
  return e.inner ? `${e.rule}/${e.inner.rule}` : e.rule;
}

/** eth_call of the deployed verifier's verifyReturn(Γ, evidence): the 192-byte return, or the rule it reverts with. */
async function solidityVerdict(verifier: string, gamma: Uint8Array, evidence: Uint8Array, via: HttpJsonRpc = rpc): Promise<{ verdict?: string; rule?: string }> {
  const data = abiBytes2(SELECTOR.verifyReturn, gamma, evidence);
  try {
    const r = await via.call<string>('eth_call', [{ to: verifier, data: hx(data), gas: '0x3938700' }, 'latest']);
    return { verdict: r.toLowerCase() };
  } catch (e) {
    if (e instanceof RpcError && e.code !== 0) return { rule: ruleOf(revertDataOf(e)) };
    throw e;
  }
}

function abiBytes2(selector: Uint8Array, a: Uint8Array, b: Uint8Array): Uint8Array {
  const pad = (x: Uint8Array): Uint8Array => concat(x, new Uint8Array((32 - (x.length % 32)) % 32));
  const ta = concat(u256(a.length), pad(a));
  return concat(selector, u256(64), u256(64 + ta.length), ta, u256(b.length), pad(b));
}

/** The plug-in's verdict ABI or rule. */
async function tsVerdict(w: Wallet, evidence: Uint8Array): Promise<{ verdict?: string; rule?: string }> {
  try {
    return { verdict: hx(verdictAbi(await verifyPart(cfg, w.bridge.domain, w.trust, decodeEvidence(evidence)))) };
  } catch (e) {
    if (e instanceof Nb2Error) return { rule: e.rule };
    if (e instanceof WalletError) return { rule: `wallet:${e.reason}` };
    return { rule: `error:${String((e as Error).message ?? e).slice(0, 120)}` };
  }
}

const evidenceFile = (label: string): string => join(WORK, 'evidence', `${label}.cbor`);

// ---- commands ---------------------------------------------------------------------------------------------------------------------------

async function gammaCheck(): Promise<void> {
  const test = construct(pins.gamma, { address: cfg.vault, chainId: cfg.chainId, verifierCodeHash: cfg.verifierCodeHash }, buildParams(pins.build));
  const w = await new Wallet('main').open({ check: true }); // the installation check: chain ID, config() == Γ, runtime code hash
  const res: Record<string, unknown> = { domain: hx(w.bridge.domain), K: test.K, B: test.B, build: pins.build, vault: hx(test.vault), verifier: hx(test.verifier) };
  if (lane.production) {
    const g = unhex(lane.production.gamma);
    const p = decodeConfig(g, buildParams('production'));
    res.production = { domain: hx(HU(g)), K: p.K, B: p.B, vault: hx(p.vault) };
  }
  out('gamma-check', res);
  log('Γ accepted by the plug-in; the installation check passed', res);
}

/**
 * The operating envelope (section 12.5) from the pinned limits, by the plug-in's gas bound (gas.ts MeasuredGasModel, estimate-nb2-1179) on parts
 * built from the lane's template (envelope_shape.ts): per split depth, the largest root history in ENVELOPE_CERTIFICATES certificates whose
 * return passes the pre-burn preflight at returnReserveSegments (the burn at the decoder bounds), and the proofs that fit beside it at
 * redemption; for the reference part (one transfer, two split levels), the return delay its proofs support.
 */
const ENVELOPE_CERTIFICATES = 16;
function envelope(file: string): void {
  const K = cfg.K;
  const gp = BigInt(gapProofLen(K));
  const tp = template(Uint8Array.from(readFileSync(new URL('./envelope_template.cbor', import.meta.url))));
  const rLen = encodeReturnData({ d: new Uint8Array(32), asset: ASSET_UCT, recipient: new Uint8Array(20), amount: (1n << 255n), minIndex: (1n << 47n) }).length;
  const model = new MeasuredGasModel();
  // a part's lineage, its evidence bytes (burned: the template's burn pair; before the burn: the pair at its bound), the bound with P proofs
  const shapeOf = (lineage: Token[], pending: boolean) => {
    const part = encodeToken(lineage[lineage.length - 1]).length + 2;
    return { evidenceBytes: part + (pending ? burnPairBound(rLen) : 1 + tp.pair.raw.length + encodeProof(tp.pair.proof).length), lineage, pending };
  };
  const gasOf = (lineage: Token[], P: bigint, pending: boolean): bigint | null => {
    const s = shapeOf(lineage, pending);
    let l = s.lineage;
    if (!pending) l = [...l.slice(0, -1), { ...l[l.length - 1], transfers: [tp.pair.tx], proofs: [tp.pair.proof], transfersRaw: [tp.pair.raw] }];
    return model.redeemGasLimit({ evidenceBytes: s.evidenceBytes, lineage: l, pendingTransactions: pending ? 1 : 0, proofs: P, K });
  };
  const fits = (lineage: Token[], P: bigint, pending: boolean): boolean => {
    const lT = BigInt(shapeOf(lineage, pending).evidenceBytes);
    const mp = maxProofs(pins.maxEncodedTxBytes, lT, BigInt(otherBytes(Number(lT))), K);
    return mp.baseFits && P <= mp.pMax;
  };
  const reserve = pins.returnReserveSegments;
  const admitted = (h: number, levels: number): boolean => {
    const l = history(tp, h, levels, ENVELOPE_CERTIFICATES);
    const g = gasOf(l, reserve, true);
    return g !== null && g <= pins.userGasLimit && fits(l, reserve, true);
  };
  const proofsBeside = (l: Token[]): { byBytes: bigint; byGas: bigint } => {
    const lT = BigInt(shapeOf(l, false).evidenceBytes);
    const byBytes = maxProofs(pins.maxEncodedTxBytes, lT, BigInt(otherBytes(Number(lT))), K).pMax;
    let lo = 0n;
    let hi = byBytes + 1n;
    while (hi - lo > 1n) {
      const mid = (lo + hi) / 2n;
      const g = gasOf(l, mid, false);
      if (g !== null && g <= pins.userGasLimit) lo = mid;
      else hi = mid;
    }
    return { byBytes, byGas: lo };
  };
  const shapes: Record<string, unknown>[] = [];
  for (const levels of [0, 1, 2]) {
    let lo = 0;
    let hi = 2048;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      if (admitted(mid, levels)) lo = mid;
      else hi = mid;
    }
    const l = history(tp, lo, levels, ENVELOPE_CERTIFICATES);
    const p = proofsBeside(l);
    shapes.push({ splitLevels: levels, maxTransfersPreBurn: lo, binds: fits(history(tp, lo + 1, levels, ENVELOPE_CERTIFICATES), reserve, true) ? 'gas' : 'bytes',
      evidenceBytes: shapeOf(l, false).evidenceBytes, preflightGas: gasOf(l, reserve, true), proofsByBytes: p.byBytes, proofsByGas: p.byGas, binding: p.byGas < p.byBytes ? 'gas' : 'bytes' });
  }
  // the reference part (one transfer, two split levels): the return delay its proofs support at stated rates
  const ref = history(tp, 1, 2, 1);
  const rp = proofsBeside(ref);
  const pMax = rp.byGas < rp.byBytes ? rp.byGas : rp.byBytes;
  const payments = pMax * K;
  const delay = (perSecond: number): number => Number(payments) / perSecond;
  const bare = history(tp, 0, 0, 1);
  const env = {
    model: `native-bridge-plugins MeasuredGasModel (${model.name}) on parts built from envelope_template.cbor`,
    assumptions: 'a template estimate, not a capacity and not an admission rule. Every part is built from the lane\'s two-transfer template: '
      + `its mint, its transfer and its ${tp.pair.proof.uc.length}-byte UC in every place, the template's ${tp.pair.proof.siblings.length} RSMT siblings a proof and its `
      + `one-log deposit receipt, ${ENVELOPE_CERTIFICATES} certificates (the template UC with one hash byte varied), the template's few owner keys repeated `
      + '(so no key cache misses beyond them), a distinct state ID a step, and the whole history above the splits. Longer paths (a grown aggregator '
      + 'tree), more certificates, more signatures, distinct owner keys or a longer receipt all reach userGasLimit sooner. The wallet preflight '
      + '(section 12.5) on the actual token is what admits a burn.',
    K, gapProofBytes: Number(gp), maxEncodedTxBytes: pins.maxEncodedTxBytes, userGasLimit: pins.userGasLimit, gasReserve: pins.gasReserve, returnReserveSegments: reserve,
    preBurnBurnBound: { bytes: burnPairBound(rLen), gas: (gasOf(bare, 0n, true) ?? 0n) - (gasOf(bare, 0n, false) ?? 0n) },
    largestToken: shapes,
    referencePart: {
      transfers: 1, splitLevels: 2, evidenceBytes: shapeOf(ref, false).evidenceBytes, proofsByBytes: rp.byBytes, proofsByGas: rp.byGas, binding: rp.byGas < rp.byBytes ? 'gas' : 'bytes',
      interveningPayments: payments, returnDelaySeconds: { at1PerSecond: delay(1), at10PerSecond: delay(10), at100PerSecond: delay(100) },
    },
  };
  writeFileSync(file, JSON.stringify(env, (_k, x) => (typeof x === 'bigint' ? Number(x) : x), 2) + '\n');
  log('envelope', readFileSync(file, 'utf8'));
}

async function deposit(w: Wallet, label: string, units: bigint, mode: string | undefined): Promise<void> {
  if (mode === '--adopt') {
    const intent = big(w.entry(label).intent!);
    const r = await sendDeposit(w, label); // no send of its own: the lane's legacy deposit is found by its rho
    log(`  adopted deposit ${r.depositNumber} (tx ${hx(r.txHash)})`);
    return mintIntent(w, label, intent, r.txHash);
  }
  const plan = await planDeposit(w, label, units * UNIT);
  if (mode === '--plan-only') {
    out(`deposit-plan-${label}`, { intent: plan.intent, calldata: hx(plan.calldata), value: units * UNIT, vault: hx(cfg.vault) });
    log(`  planned intent ${plan.intent}`);
    return;
  }
  const r = await sendDeposit(w, label);
  log(`  deposit ${r.depositNumber} in block ${r.blockNumber} (tx ${hx(r.txHash)}, EIP-1559)`);
  return mintIntent(w, label, plan.intent, r.txHash);
}

async function mintIntent(w: Wallet, label: string, intent: bigint, tx: Uint8Array): Promise<void> {
  const m = await walletMint(w, label, retrying('the deposit proof'));
  out(`deposit-${label}`, { intent, depositNumber: m.depositNumber, tx, amount: m.amount, tokenId: m.tokenId, reasonBytes: m.reasonBytes });
  log(`  minted ${label}: ${m.amount} wei, J ${m.reasonBytes} bytes`);
}

async function transfer(w: Wallet, from: string, to: string, owner: number): Promise<void> {
  await walletTransfer(w, from, to, owner);
  log(`  ${from} -> ${to} (owner ${owner})`);
}

async function split(w: Wallet, from: string, owner: number, outs: string[]): Promise<void> {
  const parts = outs.map((s) => { const [l, a] = s.split('='); return { label: l, amount: big(a) * UNIT }; });
  await walletSplit(w, from, owner, parts);
  log(`  split ${from} into ${outs.join(' + ')}`);
}

/**
 * N transfers of FROM to the wallet's own keys, kept as TO, every request built offline from the known states. Certified as one aggregator
 * batch by default (the rounds the batch happens to span), one round each with ROUNDS, or as GROUPS consecutive groups, each certified before
 * the next is submitted: GROUPS distinct certificates whatever the length (one more when a group straddles a round), for the boundary probes.
 */
async function chain(w: Wallet, from: string, to: string, n: number, rounds: boolean, groups?: number): Promise<{ transfers: number; certificates: number }> {
  const agg = new GatewayAggregator(lane.agg);
  let token = w.token(from);
  let owner = w.entry(from).owner;
  const pending: { tx: Uint8Array; cd: Uint8Array }[] = [];
  // build every request against the token as it will be: the source state of transfer k+1 is the result state of transfer k
  let virt = token;
  for (let k = 0; k < n; k++) {
    const next = (owner + 1) % 4;
    const req = await transferRequest(virt, w.owner(owner), { recipient: signaturePredicate(w.ownerPub(next)), mask: freshMask(), data: null, deadline: null });
    pending.push(req);
    // a placeholder proof is never verified: only the transfers' states matter for building the next request
    virt = appendTransfer(virt, req.tx, placeholderProof(decodeToken(token)));
    owner = next;
    if (rounds) {
      const proof = await agg.certify(req.cd);
      token = appendTransfer(token, req.tx, proof);
      virt = token;
    }
  }
  if (!rounds) {
    const g = groups === undefined ? 1 : Math.min(groups, pending.length);
    for (let j = 0, at = 0; j < g; j++) {
      const group = pending.slice(at, (at = Math.round((pending.length * (j + 1)) / g)));
      for (let i = 0; i < group.length; i += 32) await Promise.all(group.slice(i, i + 32).map((p) => agg.submit(p.cd)));
      for (const p of group) token = appendTransfer(token, p.tx, await agg.proof(p.cd));
    }
  }
  const v = await w.bridge.verifyToken(token);
  w.keep(to, token, owner, { amount: v.amount.toString() });
  const ucs = new Set(decodeToken(token).proofs.map((p) => hx(HU(p.uc))));
  out(`chain-${to}`, { transfers: decodeToken(token).transfers.length, distinctCertificates: ucs.size, bytes: token.length });
  log(`  ${to}: ${decodeToken(token).transfers.length} transfers under ${ucs.size} certificates, ${token.length} bytes`);
  return { transfers: decodeToken(token).transfers.length, certificates: ucs.size };
}

/** The token's certificates as one condition: their count and a digest of the sorted set of their hashes. */
function certificateSet(token: Uint8Array): string {
  const hs = [...new Set(decodeToken(token).proofs.map((q) => hx(HU(q.uc))))].sort();
  return `${hs.length} certificates ${toHex(sha256(new TextEncoder().encode(hs.join(',')))).slice(0, 16)}`;
}

let placeholder: Uint8Array | null = null;
function placeholderProof(t: Token): Uint8Array {
  if (placeholder === null) placeholder = encodeProof(t.mintProof);
  return placeholder;
}

function recipientOf(w: Wallet, opt?: string): Uint8Array {
  return opt ? unhex(opt) : w.signer.address;
}

async function preflight(w: Wallet, label: string): Promise<void> {
  try {
    const plan = await w.bridge.planReturn(w.token(label), w.signer.address, w.signer.address);
    out(`preflight-${label}`, { ok: true, a: plan.a, cObs: plan.cObs, pMax: plan.pMax, marginSegments: plan.marginSegments, gasLimit: plan.gasLimit, evidenceBytes: evidenceOf(w.token(label)).length });
    log(`  preflight of ${label} passes: gas limit ${plan.gasLimit}, margin ${plan.marginSegments} segments`);
  } catch (e) {
    const rule = e instanceof Nb2Error ? e.rule : e instanceof WalletError ? e.reason : String(e);
    out(`preflight-${label}`, { ok: false, rule, detail: String((e as Error).message), evidenceBytes: evidenceOf(w.token(label)).length });
    log(`  preflight of ${label} refused: ${rule}: ${(e as Error).message}`);
  }
}

/**
 * The ledger's word on LABEL's source state, authenticated (the boundary stage's no-burn evidence, sol r12 and r13 on #1126): the
 * aggregator's non-inclusion proof of the state a burn (or any transfer) of the token would spend, verified against the wallet's trust history
 * (verifyNonInclusion: the certificate, the seal under its epoch's committee, the path to the certified root), at a snapshot sealed at or
 * after NOT_BEFORE (Unix seconds: the first whole second after the refusal completed; the seal timestamp is consensus-certified time) and past
 * the token's own newest certificate round. ledger_check.ts readLedger polls it within LEDGER_DEADLINE_MS, every request under an abort signal
 * and a timer for what is left of it; the report is written whatever happens, `unspent` only for a verified absence that meets both.
 */
const LEDGER_DEADLINE_MS = 120_000;
async function ledger(w: Wallet, label: string, notBefore: bigint): Promise<void> {
  const { verifyNonInclusion } = await import('@unicitylabs/state-transition-sdk/lib/api/NonInclusionVerification.js');
  const { UnicityCertificateVerifier } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js');
  const { UnicitySealQuorumSignaturesVerificationRule } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js');
  const { Secp256k1SignatureVerifier } = await import('@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js');
  const res: Record<string, unknown> = { label, notBefore, network: w.trust.network.id, deadlineMs: LEDGER_DEADLINE_MS };
  try {
    const token = w.token(label);
    const t = decodeToken(token);
    // the state a burn would spend: the head of the token, as the transfer request the wallet's burn would build names it (never submitted)
    const req = await transferRequest(token, w.owner(w.entry(label).owner), { recipient: signaturePredicate(w.ownerPub(0)), mask: freshMask(), data: null, deadline: null });
    const sid = await StateId.fromCertificationData(CertificationData.fromCBOR(req.cd));
    const newest = [t.mintProof, ...t.proofs].reduce((m, p) => {
      const r = UnicityCertificate.fromCBOR(p.uc).unicitySeal.rootChainRoundNumber;
      return r > m ? r : m;
    }, 0n);
    Object.assign(res, { stateId: hx(sid.toCBOR()), tokenNewestRootRound: newest });
    const client = new AggregatorClient(lane.agg);
    const context = {
      trustBase: w.trust.history,
      unicityCertificateVerifier: new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 })),
    };
    const ask = async (signal: AbortSignal): Promise<Answer> => {
      const r = await client.getNonInclusionProof(sid, { signal });
      if (r.kind === 'state_included_hint') return { kind: 'hint' };
      const proof = hx(r.proof.toCBOR());
      const v = await verifyNonInclusion(r.proof, context);
      if (v.snapshot === null) return { kind: 'rejected', reason: `${v.verdict}: ${v.reason}`, proof };
      const s = v.snapshot;
      return { kind: 'verified', verdict: v.verdict, proof,
        snapshot: { networkId: s.networkId, rootEpoch: s.rootEpoch, rootRound: s.rootRound, sealTimestampSeconds: s.sealTimestampSeconds, shardRound: s.shardRound } };
    };
    Object.assign(res, await readLedger(ask, { notBefore, newestRound: newest, networkId: w.trust.network.id, deadlineMs: LEDGER_DEADLINE_MS, pollMs: 3_000 }));
  } catch (e) {
    Object.assign(res, { verdict: 'error', reason: String((e as Error)?.message ?? e) });
  }
  out(`ledger-${label}`, res);
  log(`  ledger of ${label}: ${res.verdict}${res.reason ? ` (${res.reason})` : ''}`);
  // an abandoned request may keep its socket open: the report is written, so the command ends once its output is flushed
  process.stdout.write('', () => process.exit(0));
}

async function burn(w: Wallet, label: string, recipient?: string): Promise<void> {
  const e = w.entry(label);
  if (e.returnId) {
    const rec = await w.bridge.journal.ret(e.returnId);
    if (rec !== null && ['burned', 'submitted', 'paid'].includes(rec.status)) {
      log(`  ${label} is already burned (${rec.status}): resumed`);
      return;
    }
  }
  const b = await walletBurn(w, label, recipientOf(w, recipient), retrying('the burn'));
  const ev = evidenceOf(b.burned);
  mkdirSync(join(WORK, 'evidence'), { recursive: true });
  writeFileSync(evidenceFile(label), ev);
  const plan = b.plan;
  if (plan === null) {
    log(`  ${label}: an interrupted burn resumed (${ev.length} evidence bytes)`);
    return;
  }
  out(`burn-${label}`, { a: plan.a, cObs: plan.cObs, pNow: plan.pNow, pMax: plan.pMax, marginSegments: plan.marginSegments, preflightGas: plan.gasLimit, eta: b.eta, amount: plan.amount,
    recipient: hx(plan.recipient), evidenceBytes: ev.length, warnings: plan.warnings });
  log(`  burned ${label} at index a = ${plan.a} (c observed ${plan.cObs}), ${ev.length} evidence bytes`);
}

async function verdicts(w: Wallet, labels: string[]): Promise<void> {
  const res: Record<string, unknown> = {};
  for (const l of labels) {
    const ev = Uint8Array.from(readFileSync(evidenceFile(l)));
    const ts = await tsVerdict(w, ev);
    let sol = await solidityVerdict(lane.verifier, pins.gamma, ev);
    // a burn just certified may refer to a root seal the EVM chain's registry has not imported yet: the on-chain verdict is then
    // QuorumNotMet (indistinguishable from a bad quorum). Record the first answer and how long the registry took.
    const first = sol;
    const t0 = Date.now();
    while (sol.verdict === undefined && ts.verdict !== undefined && Date.now() - t0 < 60_000) {
      await sleep(1000);
      sol = await solidityVerdict(lane.verifier, pins.gamma, ev);
    }
    res[l] = { ts, solidity: sol, firstSolidity: first, secondsToAccept: sol.verdict !== undefined && first.verdict === undefined ? (Date.now() - t0) / 1000 : 0,
      equal: ts.verdict !== undefined && ts.verdict === sol.verdict, file: `evidence/${l}.cbor` };
    log(`  ${l}: plug-in ${ts.verdict ? ts.verdict.slice(0, 18) + '..' : ts.rule}, verifier ${sol.verdict ? sol.verdict.slice(0, 18) + '..' : sol.rule}`);
  }
  out(`verdicts-${labels.join('-')}`, res);
}

async function vaultState(): Promise<Record<string, unknown>> {
  const st = await new Wallet('main').open().then((x) => x.bridge.evm.vaultState(cfg.vault));
  return { segment: st.segment, population: st.population, deposits: st.deposits, outstanding: st.outstanding, head: st.head, previousHead: st.previousHead };
}

async function receiptOf(hash: Uint8Array): Promise<Record<string, unknown> | null> {
  return rpc.call<Record<string, unknown> | null>('eth_getTransactionReceipt', [hx(hash)]);
}

async function waitReceipt(hash: Uint8Array, seconds = 180): Promise<Record<string, unknown>> {
  for (let i = 0; i < seconds; i++) {
    const r = await receiptOf(hash);
    if (r !== null) return r;
    await sleep(1000);
  }
  throw new Error(`no receipt of ${hx(hash)}`);
}

/** Sign and send calldata to the vault from wallet W with an exact gas limit; the receipt. */
async function sendRedeemRaw(w: Wallet, calldata: Uint8Array, gas: bigint): Promise<{ hash: Uint8Array; receipt: Record<string, unknown> }> {
  const nonce = await w.bridge.evm.nonce(w.signer.address);
  const fees = await w.bridge.evm.fees();
  const tx = await signTx(w.signer, { chainId: cfg.chainId, nonce, maxPriorityFeePerGas: fees.priority, maxFeePerGas: 2n * fees.baseFee + fees.priority, gas, to: cfg.vault, value: 0n, data: calldata });
  try {
    await w.bridge.evm.sendRaw(tx.raw);
  } catch (e) {
    if (!(e instanceof AmbiguousBroadcast)) throw e;
  }
  return { hash: tx.hash, receipt: await waitReceipt(tx.hash) };
}

/** The rule a call reverts with, replayed by eth_call at the block before `block` (what the reverted transaction hit) or at latest. */
async function simulateRule(from: Uint8Array, calldata: Uint8Array, gas: bigint, block: string = 'latest'): Promise<string> {
  try {
    await rpc.call('eth_call', [{ from: hx(from), to: hx(cfg.vault), data: hx(calldata), gas: `0x${gas.toString(16)}` }, block]);
    return 'success';
  } catch (e) {
    if (e instanceof RpcError && e.code !== 0) return ruleOf(revertDataOf(e)) + (/out of gas/i.test(e.message) ? ' (out of gas)' : '');
    throw e;
  }
}

async function redeem(w: Wallet, label: string, mode?: string): Promise<void> {
  const rec = await w.returnRecord(label);
  const id = unhex(rec.returnId);
  if (rec.status === 'paid') {
    log(`  ${label} is already paid: resumed`);
    return;
  }
  const before = await vaultState();
  const res: Record<string, unknown> = { label, mode: mode ?? 'normal', stateBefore: before };
  if (mode === '--hold') {
    // build the witness now and keep it; --stale submits it after two rotations
    const rtx = await w.bridge.buildRedeem(id);
    writeFileSync(join(w.dir, `held-${label}.json`), JSON.stringify({ calldata: hx(rtx.calldata), gasLimit: rtx.gasLimit.toString(), endpoint: rtx.endpoint.toString(), P: rtx.P.toString() }));
    out(`hold-${label}`, { endpoint: rtx.endpoint, P: rtx.P, gasLimit: rtx.gasLimit, calldataBytes: rtx.calldata.length });
    log(`  ${label}: witness held at endpoint ${rtx.endpoint} with ${rtx.P} proofs`);
    return;
  }
  if (mode === '--stale') {
    const held = JSON.parse(readFileSync(join(w.dir, `held-${label}.json`), 'utf8'));
    const calldata = unhex(held.calldata);
    const now = before.segment as bigint;
    res.heldEndpoint = held.endpoint;
    res.segmentNow = now;
    res.simulated = await simulateRule(w.signer.address, calldata, big(held.gasLimit));
    const sent = await sendRedeemRaw(w, calldata, big(held.gasLimit));
    res.staleTx = { hash: sent.hash, status: sent.receipt.status, gasUsed: sent.receipt.gasUsed, block: sent.receipt.blockNumber };
    res.staleRule = await simulateRule(w.signer.address, calldata, big(held.gasLimit), `0x${(BigInt(sent.receipt.blockNumber as string) - 1n).toString(16)}`);
    log(`  ${label}: the stale witness (endpoint ${held.endpoint}, vault at ${now}) is refused: ${res.simulated}; tx status ${sent.receipt.status}`);
  }
  if (mode === '--low-gas') {
    const rtx = await w.bridge.buildRedeem(id);
    const low = (rtx.gasLimit - pins.gasReserve) / 2n;
    const sent = await sendRedeemRaw(w, rtx.calldata, low);
    const mid = await vaultState();
    res.lowGas = { gasLimit: low, hash: sent.hash, status: sent.receipt.status, gasUsed: sent.receipt.gasUsed, stateAfter: mid, unchanged: js(mid) === js(before) };
    log(`  ${label}: redeem with gas ${low} -> status ${sent.receipt.status} (gas used ${sent.receipt.gasUsed}); vault unchanged: ${(res.lowGas as Record<string, unknown>).unchanged}`);
  }
  const t0 = Date.now();
  // the wallet waits out the verifier's QuorumNotMet right after a burn (the seal registry's import lag, #1125); the wait is recorded
  const r = await walletRedeem(w, label, 60, 3_000, (why) => log(`  ${label}: ${why}; waiting`), (ms) => { res.registryLagSeconds = ms / 1000; });
  res.result = r.state;
  if (r.state === 'paid') {
    const receipt = await waitReceipt(r.txHash);
    const tx = await rpc.call<Record<string, string>>('eth_getTransactionByHash', [hx(r.txHash)]);
    res.paid = { tx: r.txHash, block: r.blockNumber, gasUsed: big(receipt.gasUsed as string), gasLimit: big(tx.gas), inputBytes: (tx.input.length - 2) / 2, seconds: (Date.now() - t0) / 1000 };
  }
  const recAfter = await w.returnRecord(label);
  res.sends = recAfter.sends.map((s) => ({ hash: s.hash, gas: s.gas }));
  res.stateAfter = await vaultState();
  res.broadcasts = broadcasts;
  out(`redeem-${label}${mode ? mode.replace(/^-+/, '-') : ''}`, res);
  log(`  ${label}: ${r.state}${res.paid ? ` (gas used ${(res.paid as Record<string, unknown>).gasUsed})` : ''}`);
  if (r.state !== 'paid') throw new Error(`${label} was not paid: ${r.state}`);
}

async function replay(w: Wallet, label: string): Promise<void> {
  const rec = await w.returnRecord(label);
  if (rec.status !== 'paid') throw new Error(`${label} is not paid`);
  const id = unhex(rec.returnId);
  const paidTx = await rpc.call<Record<string, string>>('eth_getTransactionByHash', [rec.paid!.txHash]);
  const calldata = unhex(paidTx.input);
  const st = await vaultState();
  const paidSegment = await segmentOfPayment(rec);
  const evicted = (st.segment as bigint) >= paidSegment + 2n;
  const res: Record<string, unknown> = { label, segmentNow: st.segment, paidInSegment: paidSegment, evicted };
  // 1. the exact paid calldata again
  res.exactCalldata = await simulateRule(w.signer.address, calldata, big(paidTx.gas));
  // 2. the wallet: a second submit reconciles to the first payment and sends nothing
  const again = await w.bridge.submitRedeem(id, w.signer);
  res.wallet = { state: again.state, sends: (await w.returnRecord(label)).sends.length };
  // 3. a fresh witness for the same burn: the wallet refuses to build one (the ID is in a sealed segment) once evicted; before that the
  //    vault's recent buffers refuse it
  const evidence = Uint8Array.from(readFileSync(evidenceFile(label)));
  const eta = unhex(rec.eta!);
  const a = big(rec.a);
  try {
    await w.bridge.buildRedeem(id);
    res.walletBuild = 'built';
  } catch (e) {
    res.walletBuild = e instanceof Nb2Error ? e.rule : e instanceof WalletError ? e.reason : String(e);
  }
  // the best attempt a submitter could make without a valid gap proof: the current endpoint with every segment's proof taken from the
  // gap next to eta (the wallet's builder would refuse), and the zero-history claim at the burn's own index
  res.zeroHistory = await simulateRule(w.signer.address, redeemCalldata(evidence, eta, a, new Uint8Array()), 10_000_000n);
  // the wallet's own history builder over the public segment logs a .. c-1 (what a fresh wallet holding this burn would run)
  if ((st.segment as bigint) > a) res.historyPaidInSegment = (await segmentsOf(w, rec, a, st.segment as bigint, eta)).paid;
  if (evicted) {
    const forged = await forgedHistory(w, rec, eta, a, st.segment as bigint);
    res.forgedGapProof = await simulateRule(w.signer.address, redeemCalldata(evidence, eta, a, forged), 10_000_000n);
  }
  out(`replay-${label}${evicted ? '-evicted' : ''}`, res);
  log(`  replay of ${label} (${evicted ? 'evicted' : 'in the recent buffers'}):`, JSON.stringify(res, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? hx(x) : x)));
}

/** The segment in which a paid return was paid: the vault's segment index at the Paid block (from the block's state). */
async function segmentOfPayment(rec: ReturnRecord): Promise<bigint> {
  const blk = big(rec.paid!.blockNumber);
  const r = await rpc.call<string>('eth_call', [{ to: hx(cfg.vault), data: hx(SELECTOR.state) }, `0x${(blk - 1n).toString(16)}`]);
  const st = unhex(r);
  // state(): deposits, segment, population, outstanding, head, previousHead; the payment went into the segment current before it,
  // or sealed it (population K - 1 before the payment)
  return BigInt(hx(st.subarray(32, 64)));
}

/** The checked segment logs a .. c-1 and where the wallet's builder finds `eta` paid (null: absent from every sealed segment). */
async function segmentsOf(w: Wallet, rec: ReturnRecord, a: bigint, c: bigint, eta: Uint8Array): Promise<{ paid: bigint | null }> {
  const { buildHistory, checkSegmentLog } = await import('../../../packages/native-bridge-plugin/src/nb2/segment.js');
  const logs = await w.bridge.evm.segmentLogs(cfg.vault, big(rec.fromBlock), a, c);
  const segs = [];
  let before = unhex(rec.startHead);
  for (const l of logs) {
    const sg = checkSegmentLog(w.bridge.domain, cfg.K, BigInt(hx(l.topics[1])), before, l.data);
    segs.push(sg);
    before = sg.after;
  }
  const r = buildHistory(segs, eta, a, c, unhex(rec.startHead));
  return { paid: r.paid === null ? null : BigInt(r.paid) };
}

/** A history whose every gap proof is the honest proof of a neighbouring identifier: it folds to some root but not the stored one. */
async function forgedHistory(w: Wallet, rec: ReturnRecord, eta: Uint8Array, a: bigint, c: bigint): Promise<Uint8Array> {
  const { buildHistory, checkSegmentLog } = await import('../../../packages/native-bridge-plugin/src/nb2/segment.js');
  const logs = await w.bridge.evm.segmentLogs(cfg.vault, big(rec.fromBlock), a, c);
  const segs = [];
  let before = unhex(rec.startHead);
  for (const l of logs) {
    const s = checkSegmentLog(w.bridge.domain, cfg.K, BigInt(hx(l.topics[1])), before, l.data);
    segs.push(s);
    before = s.after;
  }
  const neighbour = Uint8Array.from(eta);
  neighbour[31] ^= 1;
  return buildHistory(segs, neighbour, a, c, unhex(rec.startHead)).history;
}

async function rotate(w: Wallet, n: number, mode: string | undefined): Promise<void> {
  const idx = JSON.parse(existsSync(join(w.dir, 'tokens.json')) ? readFileSync(join(w.dir, 'tokens.json'), 'utf8') : '{}') as Record<string, TokenEntry>;
  if (mode !== '--pay') {
    const base = Object.keys(idx).filter((k) => /^r[0-9]+$/.test(k)).length;
    let ready = 0;
    for (const l of w.labels()) {
      if (!/^r[0-9]+$/.test(l)) continue;
      const rec = await w.returnRecord(l).catch(() => null);
      if (rec !== null && rec.status === 'burned') ready++;
    }
    // top up to n burned, unpaid small returns (a rerun keeps what an earlier one prepared)
    for (let i = 0; i < n - ready; i++) {
      const l = `r${base + i}`;
      await deposit(w, l, 1n, undefined);
      await burn(w, l);
    }
    if (mode === '--prepare') return;
  }
  const ready: string[] = [];
  for (const l of w.labels()) {
    if (!/^r[0-9]+$/.test(l)) continue;
    const rec = await w.returnRecord(l).catch(() => null);
    if (rec !== null && rec.status === 'burned') ready.push(l);
  }
  const take = ready.slice(0, n);
  if (take.length < n) throw new Error(`only ${take.length} prepared small returns, ${n} wanted`);
  const segs: unknown[] = [];
  for (const l of take) {
    const id = unhex((await w.returnRecord(l)).returnId);
    let r = await w.bridge.submitRedeem(id, w.signer);
    // a payment is 'pending' until its block's certificate is served (the child block exists): reconcile until it is verified
    for (let i = 0; r.state === 'pending' && i < 60; i++) {
      await sleep(2000);
      r = await w.bridge.reconcile(id);
    }
    if (r.state !== 'paid') throw new Error(`small return ${l}: ${r.state}`);
    segs.push((await vaultState()).segment);
  }
  out(`rotate-${w.name}-${Date.now()}`, { paid: take, segmentsAfterEach: segs });
  log(`  ${w.name}: ${take.length} small returns paid; segment now ${segs[segs.length - 1]}`);
}

// ---- the capacity boundary ----------------------------------------------------------------------------------------------------------------

/** The wallet's section 12.5 pre-burn preflight of `token`, replayed outside the plug-in (the same functions and inputs as planReturn). */
async function predict(w: Wallet, token: Uint8Array): Promise<{
  ok: boolean; gas: bigint | null; need: bigint; bytes: number; detail: string; over?: 'bytes' | 'gas' | 'unbounded'; pMax: bigint; baseFits: boolean;
}> {
  const { capacityPreflight, burnIndex, lineageOf } = await import('../../../packages/native-bridge-plugin/src/nb2/index.js');
  const sr = await w.bridge.newestSealReceipt();
  const { a } = burnIndex(cfg, w.bridge.domain, sr?.receipt ?? null);
  const st = await w.bridge.evm.vaultState(cfg.vault);
  const cObs = st.segment > a ? st.segment : a;
  const R = encodeReturnData({ d: w.bridge.domain, asset: ASSET_UCT, recipient: w.signer.address, amount: 1n << 64n, minIndex: a });
  const lT = BigInt(evidenceOf(token).length + burnPairBound(R.length));
  const lO = BigInt(otherBytes(Number(lT)));
  const lineage = lineageOf(decodeToken(token));
  const need = cObs - a + pins.returnReserveSegments;
  // the byte check on its own (section 12.5's L_max with the reserve): which limit refuses is read from it, never inferred from a null gas
  const mp = maxProofs(pins.maxEncodedTxBytes, lT, lO, cfg.K);
  const gas = w.bridge.gas.redeemGasLimit({ evidenceBytes: Number(lT), lineage, pendingTransactions: 1, proofs: need, K: cfg.K });
  const base = { gas, need, bytes: Number(lT), pMax: mp.pMax, baseFits: mp.baseFits };
  try {
    const r = capacityPreflight({ lMax: pins.maxEncodedTxBytes, lT, lO, K: cfg.K, a, cObs, reserve: pins.returnReserveSegments, gasAt: () => gas, userGasLimit: pins.userGasLimit });
    return { ...base, ok: true, gas: r.gas, detail: 'fits' };
  } catch (e) {
    const over = refusalOf({ baseFits: mp.baseFits, need, pMax: mp.pMax, gas, limit: pins.userGasLimit });
    return { ...base, ok: false, detail: String((e as Error).message), over };
  }
}

/**
 * Where the wallet's preflight stops admitting a return (the gas bound binds before L_max on this deployment), located on live tokens within
 * BOUNDARY_MARGIN transfers (boundary_search.ts): single fresh tokens, each a deposit chained to its length in BOUNDARY_CERTIFICATES rounds,
 * judged by planReturn and the lane's replay of its inputs, until the newest probes hold an admission and a refusal at most the margin apart.
 * Every probe is reported (out/boundary-<label>.json) with its shape diagnostics; rehearse_nb2.py then executes every one (soundness).
 */
/**
 * TOKEN's terms as the plug-in's bound prices it at the preflight (estimate-nb2-1179: the burn pair at its bound, NEED proofs), and the gas of one
 * more and one fewer transfer of its own shape (boundary_shape.ts: its last pair repeated or dropped, priced by the same bound). Null steps
 * where the counterfactual does not exist or the bound is null. The steps feed the probe's shape diagnostics (boundary_search.ts ownShape),
 * recorded and never gating; the terms are the evidence of where the gas goes.
 */
async function shapeOf(w: Wallet, token: Uint8Array, lT: number, need: bigint): Promise<{ up: bigint | null; down: bigint | null; detail?: Record<string, number | string> }> {
  const { lineageOf } = await import('../../../packages/native-bridge-plugin/src/nb2/index.js');
  const t = decodeToken(token);
  const lineage = lineageOf(t);
  const part = lineage[lineage.length - 1];
  const shape = (p: Token) => ({ evidenceBytes: lT + encodeToken(p).length - token.length, lineage: [...lineage.slice(0, -1), p], pendingTransactions: 1, proofs: need, K: cfg.K });
  const { up, down } = marginals(part, (p) => w.bridge.gas.redeemGasLimit(shape(p)));
  const f = redeemFeatures(shape(part));
  const terms = redeemGasTerms(shape(part));
  if (f === null || terms === null) return { up, down };
  const detail: Record<string, number | string> = {
    evidenceBytes: lT, steps: f.steps, tokens: f.tokens, distinctClaims: f.claims.length, siblings: f.siblings, ucBytes: f.ucBytes, ucSignatures: f.ucSignatures,
    scanItems: f.scan.items, skipItems: f.skip.items, keyLookups: f.keyLookups, decompressions: f.decompressions, probes: f.probes, memoryWords: terms.memoryWords,
  };
  for (const [k, v] of Object.entries(terms)) if (typeof v === 'bigint') detail[`gas.${k}`] = v.toString();
  return { up, down, detail };
}

const BOUNDARY_CERTIFICATES = 16;
const BOUNDARY_PROBES = 12;
// m, the owner's default (briefs/owner-questions.md): fresh tokens' gas deviates about 0.6 step and drifts about 0.5 step a probe (runs
// 43994509728, 44003156840), so within the newest three probes a verdict at one length moves by up to about a transfer either way; two
// transfers bound the highest admission against the lowest refusal there (each of the three runs reached it within its first five probes)
const BOUNDARY_MARGIN = 2;
async function boundary(w: Wallet, label: string, estimate: number): Promise<void> {
  const est = JSON.parse(readFileSync(join(WORK, 'out', `boundary-estimate-${label}e.json`), 'utf8'));
  const judge = async (l: string, transfers: number): Promise<Probe> => {
    const t = w.token(l);
    const p = await predict(w, t);
    // the real thing: planReturn's own preflight (it journals a plan; nothing irreversible)
    let real: string;
    try {
      await w.bridge.planReturn(t, w.signer.address, w.signer.address);
      real = 'passes';
    } catch (e) {
      real = e instanceof Nb2Error ? e.rule : e instanceof WalletError ? e.reason : String(e);
    }
    if (real !== 'passes' && real !== 'CapacityPreflight') throw new Error(`the boundary probe ${l} was refused for another reason: ${real}`);
    const sh = await shapeOf(w, t, p.bytes, p.need);
    const probe: Probe = { label: l, transfers, conditions: `${certificateSet(t)}, need ${p.need}`, gas: p.gas, up: sh.up, down: sh.down, real: real as Verdict,
      detail: { ...sh.detail, ...(p.over ? { over: p.over } : {}), need: p.need.toString(), pMax: p.pMax.toString(), baseFits: String(p.baseFits) } };
    log(`  ${l}: ${transfers} transfers, ${evidenceOf(t).length} evidence bytes, ${probe.conditions}, `
      + `preflight gas ${p.gas} (one transfer more +${sh.up}, one fewer -${sh.down}): planReturn ${real}`);
    return probe;
  };
  const probe = async (k: number, i: number): Promise<Probe> => {
    const l = `${label}${i}`;
    await deposit(w, l, 1n, undefined);
    const c = await chain(w, l, `${l}c`, k, false, BOUNDARY_CERTIFICATES);
    return judge(`${l}c`, c.transfers);
  };
  const withShape = (ts: Probe[]): (Probe & { shape: ReturnType<typeof ownShape> })[] => ts.map((t) => ({ ...t, shape: ownShape(t, pins.userGasLimit) }));
  let res;
  try {
    res = await findBoundary(probe, {
      estimate, limit: pins.userGasLimit, start: { transfers: est.probeTransfers, gas: big(est.probeGas) }, maxProbes: BOUNDARY_PROBES, margin: BOUNDARY_MARGIN,
      min: BOUNDARY_CERTIFICATES,
    });
  } catch (e) {
    if (e instanceof BoundaryNotFound) out(`boundary-${label}`, { admitted: null, refused: null, margin: BOUNDARY_MARGIN, tries: withShape(e.tries), drift: e.drift, error: e.message });
    throw e;
  }
  out(`boundary-${label}`, { admitted: res.admitted, refused: res.refused, spread: res.spread, margin: res.margin, window: res.window, tries: withShape(res.tries), drift: res.drift,
    certificatesPerProbe: BOUNDARY_CERTIFICATES });
  log(`  boundary: within ${res.spread} of ${res.margin} transfers: ${res.admitted.transfers} admitted (${res.admitted.label}), ${res.refused.transfers} refused (${res.refused.label}), `
    + `from the newest ${res.window.join(', ')} (${res.tries.length} probes); drift ${JSON.stringify(res.drift)}`);
}

/**
 * The boundary estimate from a short live chain: the bound's own step of one more transfer on this deployment's real certificates (its
 * last pair repeated, boundary_shape.ts), widened by a fifth for the verifier's memory term, which grows the step with the length (about 1.2
 * times the 16-transfer step by 300 on the K = 4 lane, bft-core#1179). The search corrects it from the first probe on.
 */
async function boundaryEstimate(w: Wallet, label: string): Promise<void> {
  await deposit(w, label, 1n, undefined);
  await chain(w, label, `${label}c`, 16, false);
  const t16 = w.token(`${label}c`);
  const p16 = await predict(w, t16);
  const sh = await shapeOf(w, t16, p16.bytes, p16.need);
  if (p16.gas === null || sh.up === null || sh.up <= 0n) throw new Error(`the 16-transfer probe has no bound or no step (${p16.detail})`);
  const perHop = (sh.up * 6n) / 5n;
  const room = pins.userGasLimit - p16.gas;
  const k = 16 + Number(room / perHop);
  out(`boundary-estimate-${label}`, { probeTransfers: 16, probeGas: p16.gas, perHop, estimate: k });
  log(`  boundary estimate: about ${k} transfers (probe ${p16.gas} gas at 16, ${perHop} a further transfer)`);
}

// ---- mutations: one isolated change of one burned part, judged by the plug-in and by the deployed verifier (the lane adds Go) ----------

interface Mutation { name: string; evidence: Uint8Array }

function flipByte(b: Uint8Array, at: number): Uint8Array {
  const c = Uint8Array.from(b);
  c[at] ^= 0x01;
  return c;
}

/** Locate `needle` in `hay` (the last occurrence when `last`). */
function find(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function mutationsOf(ev: Uint8Array): Mutation[] {
  const t = decodeToken(ev.subarray(2)); // evidence = C(1, token): array head (1 byte) + uint 1 (1 byte)
  const proofs = [t.mintProof, ...t.proofs];
  const ms: Mutation[] = [];
  const at = (part: Uint8Array): number => find(ev, part);
  // each certificate (the EVM UC inside J first, then every inclusion proof's UC): every seal signature broken (below quorum: an invalid
  // claim at that position), and one signature broken (a bad signature counts zero; the others still reach quorum: accepted)
  const sigsOf = (uc: Uint8Array): Uint8Array[] => {
    const w = UnicityCertificate.fromCBOR(uc).unicitySeal.witnesses as unknown as Map<unknown, unknown> | null;
    if (w === null) return [];
    return [...w.values()].map((v) => (v instanceof Uint8Array ? v : (v as { bytes?: Uint8Array }).bytes ?? (v as { encode: () => Uint8Array }).encode()));
  };
  const breakSigs = (uc: Uint8Array, n: number): Uint8Array | null => {
    const o = at(uc);
    if (o < 0) return null;
    const c = Uint8Array.from(ev);
    let k = 0;
    for (const sig of sigsOf(uc)) {
      if (k >= n) break;
      const so = find(c.subarray(o, o + uc.length), sig);
      if (so < 0) return null;
      c[o + so + 10] ^= 0x01;
      k++;
    }
    return k > 0 ? c : null;
  };
  const evmUc = (() => { try { return decodeReceiptBacking(t.mint.justification!).proof.uc; } catch { return null; } })();
  const ucs: [string, Uint8Array][] = [...(evmUc ? [['evm-uc', evmUc] as [string, Uint8Array]] : []), ...proofs.map((p, i) => [`uc${i}`, p.uc] as [string, Uint8Array])];
  for (const [n, uc] of ucs) {
    const all = breakSigs(uc, 1 << 30);
    if (all) ms.push({ name: `${n}-all-signatures`, evidence: all });
  }
  for (const [n, uc] of [ucs[0], ucs[ucs.length - 1]]) {
    const one = breakSigs(uc, 1);
    if (one) ms.push({ name: `${n}-one-signature`, evidence: one });
  }
  // the last certificate's seal fields: a byte early in the UC (its structure, not a signature)
  const p0 = proofs[proofs.length - 1];
  const o0 = at(p0.uc);
  if (o0 >= 0) ms.push({ name: 'uc-last-early-byte', evidence: flipByte(ev, o0 + 12) });
  // membership paths (the last inclusion proof): a sibling, the bitmap, the leaf's reference time
  const last = proofs[proofs.length - 1];
  if (last.siblings.length > 0) {
    const s = at(last.siblings[0]);
    if (s >= 0) ms.push({ name: 'rsmt-sibling', evidence: flipByte(ev, s + 5) });
  }
  const bm = at(last.bitmap);
  if (bm >= 0 && last.bitmap.length > 0) ms.push({ name: 'rsmt-bitmap', evidence: flipByte(ev, bm + last.bitmap.length - 1) });
  // the unlock of the last transfer: recovery ID 2 and 3 (the NB2 restriction), and a flipped signature byte
  const unlock = last.cd.unlock;
  const u = at(unlock);
  if (u >= 0 && unlock.length === 65) {
    for (const id of [2, 3]) {
      const c = Uint8Array.from(ev);
      c[u + 64] = id;
      ms.push({ name: `unlock-recovery-${id}`, evidence: c });
    }
    ms.push({ name: 'unlock-signature', evidence: flipByte(ev, u + 10) });
  }
  // canonical encoding: the evidence version as a non-minimal integer (0x18 0x01), and trailing bytes
  ms.push({ name: 'evidence-nonminimal-version', evidence: concat(Uint8Array.of(ev[0], 0x18, 0x01), ev.subarray(2)) });
  ms.push({ name: 'evidence-trailing-byte', evidence: concat(ev, Uint8Array.of(0x00)) });
  ms.push({ name: 'evidence-truncated', evidence: ev.subarray(0, ev.length - 1) });
  // the return data: the amount's last byte (the burn's reason hash then differs: the burn predicate refuses)
  return ms;
}

async function mutations(w: Wallet, label: string): Promise<void> {
  const ev = Uint8Array.from(readFileSync(evidenceFile(label)));
  const dir = join(WORK, 'evidence', `mut-${label}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const res: Record<string, unknown> = {};
  for (const m of mutationsOf(ev)) {
    writeFileSync(join(dir, `${m.name}.cbor`), m.evidence);
    const ts = await tsVerdict(w, m.evidence);
    const sol = await solidityVerdict(lane.verifier, pins.gamma, m.evidence);
    let gasUsed: string | undefined;
    try {
      gasUsed = (await simulate([{ to: lane.verifier, data: hx(abiBytes2(SELECTOR.verifyReturn, pins.gamma, m.evidence)) }], {}))[0].gasUsed;
    } catch { /* eth_simulateV1 is an operator read; the verdicts stand without it */ }
    res[m.name] = { ts, solidity: sol, gasUsed, file: `evidence/mut-${label}/${m.name}.cbor` };
    log(`  ${m.name}: plug-in ${ts.rule ?? 'ACCEPTS'}, verifier ${sol.rule ?? 'ACCEPTS'}`);
  }
  out(`mutations-${label}`, res);
}

// ---- fault injection by eth_call state overrides (validator 1 directly: an operator check of the deployed bytecode, not a wallet path) -------------

/**
 * The calls with state overrides on validator 1 (eth_call's third parameter; `movePrecompileToAddress` moves a native primitive away so that
 * code can stand in for it). eth_simulateV1 is not usable on ureth: its block executor refuses a simulated block without bound inputs.
 */
async function simulate(calls: { to: string; data: string }[], overrides: Record<string, unknown>): Promise<{ ok: boolean; rule: string; returnData: string; gasUsed?: string }[]> {
  const res: { ok: boolean; rule: string; returnData: string; gasUsed?: string }[] = [];
  for (const c of calls) {
    try {
      const r = await direct.call<string>('eth_call', [{ ...c, gas: '0x3938700' }, 'latest', overrides]);
      res.push({ ok: true, rule: 'success', returnData: r.slice(0, 74) });
    } catch (e) {
      if (!(e instanceof RpcError) || e.code === 0) throw e;
      const d = revertDataOf(e);
      res.push({ ok: false, rule: d === null ? `error:${e.message.slice(0, 120)}` : ruleOf(d), returnData: d === null ? '' : hx(d).slice(0, 74) });
    }
  }
  return res;
}

async function faults(w: Wallet, label: string): Promise<void> {
  const ev = Uint8Array.from(readFileSync(evidenceFile(label)));
  const call = { to: lane.verifier, data: hx(abiBytes2(SELECTOR.verifyReturn, pins.gamma, ev)) };
  const MOVED = '0x00000000000000000000000000000000000c0de0';
  const REVERT = '0x60006000fd'; // REVERT(0, 0)
  const FALSE = '0x60206000f3'; // RETURN(0, 32) of zero memory: an ABI false
  const SHORT = '0x601f6000f3'; // RETURN(0, 31): a malformed (short) answer
  const TRUE = '0x600160005260206000f3'; // RETURN an ABI true for every claim
  const helperCode = await rpc.call<string>('eth_getCode', [lane.helper, 'latest']);
  const cases: Record<string, Record<string, unknown>> = {
    baseline: {},
    'cert-batch-missing': { '0x0000000000000000000000000000000000000100': { movePrecompileToAddress: MOVED } },
    'cert-batch-reverts': { '0x0000000000000000000000000000000000000100': { movePrecompileToAddress: MOVED, code: REVERT } },
    'cert-batch-false': { '0x0000000000000000000000000000000000000100': { movePrecompileToAddress: MOVED, code: FALSE } },
    'cert-batch-short': { '0x0000000000000000000000000000000000000100': { movePrecompileToAddress: MOVED, code: SHORT } },
    'cert-batch-true': { '0x0000000000000000000000000000000000000100': { movePrecompileToAddress: MOVED, code: TRUE } },
    'membership-missing': { '0x0000000000000000000000000000000000000102': { movePrecompileToAddress: MOVED } },
    'membership-reverts': { '0x0000000000000000000000000000000000000102': { movePrecompileToAddress: MOVED, code: REVERT } },
    'membership-false': { '0x0000000000000000000000000000000000000102': { movePrecompileToAddress: MOVED, code: FALSE } },
    'membership-short': { '0x0000000000000000000000000000000000000102': { movePrecompileToAddress: MOVED, code: SHORT } },
    'helper-code-replaced': { [lane.helper]: { code: helperCode.slice(0, -2) + (helperCode.endsWith('00') ? '01' : '00') } },
    'helper-code-removed': { [lane.helper]: { code: '0x' } },
  };
  const res: Record<string, unknown> = {};
  for (const [name, ov] of Object.entries(cases)) {
    try {
      res[name] = (await simulate([call], ov))[0];
    } catch (e) {
      res[name] = { error: String((e as Error).message).slice(0, 200) };
    }
    log(`  ${name}: ${JSON.stringify(res[name])}`);
  }
  out(`faults-${label}`, res);
}

// ---- build admission -------------------------------------------------------------------------------------------------------------------

async function admission(): Promise<void> {
  const res: Record<string, unknown> = {};
  if (!lane.production || !lane.test?.vaultInitcode) throw new Error('admission needs both builds in lane.json');
  const w = await new Wallet('main').open();
  const ev = existsSync(evidenceFile('admission')) ? Uint8Array.from(readFileSync(evidenceFile('admission'))) : new Uint8Array([0x82, 0x01, 0xf6]);
  // each verifier with the other build's Γ: ConfigShape (the admitted (K, B) set is an immutable of the build)
  res.productionVerifierTestGamma = await solidityVerdict(lane.production.verifier, pins.gamma, ev);
  res.testVerifierProductionGamma = await solidityVerdict(lane.verifier, unhex(lane.production.gamma), ev);
  // each vault build's constructor with the other build's (K, B): BadConfig(16 or 17), simulated as a creation
  const createWith = async (initcode: string, gamma: Uint8Array): Promise<string> => {
    const pad = (x: Uint8Array): Uint8Array => concat(x, new Uint8Array((32 - (x.length % 32)) % 32));
    const data = concat(unhex(initcode), u256(32), u256(gamma.length), pad(gamma));
    try {
      await rpc.call('eth_call', [{ from: hx(w.signer.address), data: hx(data), gas: '0x1c9c380' }, 'latest']);
      return 'created';
    } catch (e) {
      if (e instanceof RpcError && e.code !== 0) {
        const d = revertDataOf(e);
        const r = d ? decodeRevert(d) : null;
        return r ? `${r.rule}(${r.args.map(String).join(',')})` : ruleOf(d);
      }
      throw e;
    }
  };
  const prodInit = lane.production.vaultInitcode ?? null;
  res.testVaultProductionGamma = await createWith(lane.test.vaultInitcode, unhex(lane.production.gamma));
  if (prodInit) res.productionVaultTestGamma = await createWith(prodInit, pins.gamma);
  out('admission', res);
  log('  admission:', JSON.stringify(res));
}

// ---- a transaction of an exact encoded size (the L_max measurement) -----------------------------------------------------------------------

async function sized(w: Wallet, nonce: bigint, length: number, file: string, gas?: bigint): Promise<void> {
  const latest = await rpc.call<Record<string, string>>('eth_getBlockByNumber', ['latest', false]);
  const base = BigInt(latest.baseFeePerGas);
  let n = length - 120;
  // the tip moves by one wei a try: a signature whose r or s encodes a byte short (one in 128) would otherwise send n back and forth between
  // two lengths, one short and one over (the limits stage on #1126); every try is a new signing hash, so the length settles
  for (let i = 0; i < 32; i++) {
    const tip = 1_000_000_000n + BigInt(i);
    const tx = await signTx(w.signer, { chainId: cfg.chainId, nonce, maxPriorityFeePerGas: tip, maxFeePerGas: 2n * base + tip,
      gas: gas ?? 21_000n + 4n * BigInt(n) + 10_000n, to: unhex('0x000000000000000000000000000000000000dead'), value: 0n, data: new Uint8Array(n) });
    if (tx.raw.length === length) {
      writeFileSync(file, hx(tx.raw));
      log(`  a ${length}-byte transaction ${hx(tx.hash)} (calldata ${n} bytes)`);
      return;
    }
    n += length - tx.raw.length;
  }
  throw new Error(`could not size a transaction to ${length} bytes`);
}

// ---- signing for the lane (keys stay in the driver's environment, never in a command line) -------------------------------------------------

/** The address of wallet W's EVM key. */
function address(w: Wallet, file: string): void {
  writeFileSync(file, `${hx(w.signer.address)}\n`);
}

/**
 * A transaction signed by wallet W, written to FILE as hex: --legacy (EIP-155, the untyped transaction the legacy-receipt deposit needs) or
 * EIP-1559. The lane passes everything but the key; calldata may be given as @FILE.
 */
async function mktx(w: Wallet, args: string[], file: string): Promise<void> {
  const [kind, to, value, gas, price, nonce, dataArg] = args;
  const data = dataArg.startsWith('@') ? unhex(readFileSync(dataArg.slice(1), 'utf8').trim()) : unhex(dataArg);
  const { rlpBytes, rlpList, rlpUintEnc } = await import('../../../packages/native-bridge-plugin/src/nb2/rlp.js');
  if (kind === '--legacy') {
    const fields = [rlpUintEnc(big(nonce)), rlpUintEnc(big(price)), rlpUintEnc(big(gas)), rlpBytes(unhex(to)), rlpUintEnc(big(value)), rlpBytes(data)];
    const hash = HE(rlpList([...fields, rlpUintEnc(cfg.chainId), rlpUintEnc(0n), rlpUintEnc(0n)]));
    const sig = secp256k1.sign(hash, w.evmKey, { prehash: false, lowS: true, format: 'recovered' });
    const strip = (b: Uint8Array): Uint8Array => { let i = 0; while (i < b.length && b[i] === 0) i++; return b.subarray(i); };
    const v = cfg.chainId * 2n + 35n + BigInt(sig[0]);
    writeFileSync(file, `${hx(rlpList([...fields, rlpUintEnc(v), rlpBytes(strip(sig.subarray(1, 33))), rlpBytes(strip(sig.subarray(33, 65)))]))}\n`);
    return;
  }
  const tx = await signTx(w.signer, { chainId: cfg.chainId, nonce: big(nonce), maxPriorityFeePerGas: big(price), maxFeePerGas: big(price), gas: big(gas), to: unhex(to), value: big(value), data });
  writeFileSync(file, `${hx(tx.raw)}\n`);
}

// ---- main -------------------------------------------------------------------------------------------------------------------------------

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  const flag = (name: string): boolean => args.includes(name);
  const opt = (name: string): string | undefined => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const pos = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--') && ['--recipient'].includes(args[i - 1])));
  const wallet = async (): Promise<Wallet> => new Wallet(pos[0]).open();
  switch (cmd) {
    case 'gamma-check': return gammaCheck();
    case 'envelope': return envelope(pos[0]);
    case 'deposit': return deposit(await wallet(), pos[1], big(pos[2] ?? '0'), args.find((a) => a === '--plan-only' || a === '--adopt'));
    case 'transfer': return transfer(await wallet(), pos[1], pos[2], Number(pos[3]));
    case 'split': return split(await wallet(), pos[1], Number(pos[2]), pos.slice(3));
    case 'chain': await chain(await wallet(), pos[1], pos[2], Number(pos[3]), flag('--rounds')); return;
    case 'preflight': return preflight(await wallet(), pos[1]);
    case 'ledger': return ledger(await wallet(), pos[1], big(pos[2]));
    case 'burn': return burn(await wallet(), pos[1], opt('--recipient'));
    case 'verdicts': return verdicts(await wallet(), pos.slice(1));
    case 'redeem':
      preSendDirect = flag('--ambiguous');
      return redeem(await wallet(), pos[1], args.find((a) => ['--low-gas', '--hold', '--stale'].includes(a)));
    case 'replay': return replay(await wallet(), pos[1]);
    case 'rotate': return rotate(await wallet(), Number(pos[1]), args.find((a) => a === '--prepare' || a === '--pay'));
    case 'mutations': return mutations(await wallet(), pos[1]);
    case 'faults': return faults(await wallet(), pos[1]);
    case 'admission': return admission();
    case 'boundary-estimate': return boundaryEstimate(await wallet(), pos[1]);
    case 'boundary': return boundary(await wallet(), pos[1], Number(pos[2]));
    case 'state': out('state', await vaultState()); return;
    case 'sized': return sized(new Wallet(pos[0]), big(pos[1]), Number(pos[2]), pos[3]);
    case 'address': return address(new Wallet(pos[0]), pos[1]);
    case 'mktx': return mktx(new Wallet(args[0]), args.slice(1, 8), args[8]);
    default: throw new Error(`unknown command ${cmd}`);
  }
}

main().catch((e) => {
  if (e instanceof BoundaryNotFound) {
    // one line a probe, the newest last (the lane's console keeps the last lines; every probe is in out/boundary-<label>.json)
    for (const t of e.tries) console.error(`  ${t.label}: ${t.transfers} transfers, ${t.conditions}, gas ${t.gas} (+${t.up}/-${t.down}): ${t.real}`);
    console.error(`  drift ${JSON.stringify(e.drift)}`);
    console.error(`BoundaryNotFound: ${e.message}`);
    process.exit(1);
  }
  console.error(e instanceof Nb2Error ? `Nb2Error ${e.rule}: ${e.message}` : e instanceof WalletError ? `WalletError ${e.reason}: ${e.message}` : e);
  process.exit(1);
});
