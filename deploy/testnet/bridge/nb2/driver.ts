/**
 * The native bridge v2 live driver of the package lanes (NB2-09, bft-core#1105). It drives the TypeScript wallet plug-in (NB2-07,
 * native-bridge-plugins `packages/native-bridge-plugin/src/nb2`) against a running generation through the public gateway only: the
 * chain, the aggregator (`/aggregator`) and the trust-base pages. rehearse_nb2.py runs one command per container, in the bridge tools
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
 *   verdicts W LABEL...    the plug-in's verdict and the deployed verifier's (eth_call verifyReturn), byte for byte
 *   redeem W LABEL [--low-gas|--hold|--stale|--expect-ambiguous]
 *   replay W LABEL         the paid redemption again: the exact calldata re-sent, and the wallet's own refusal
 *   rotate W N [--prepare|--pay]   N small returns by wallet W (prepared ahead: deposit, mint, burn; then paid in a burst)
 *   mutations W LABEL      isolated mutations of one burned part, judged by the plug-in and by the deployed verifier
 *   faults W LABEL         fault injection of the native primitives and the helper by eth_simulateV1 overrides (validator 1 directly)
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

import { concat, eq, toHex } from '../../../packages/native-bridge-plugin/src/bytes.js';
import {
  ASSET_UCT, AmbiguousBroadcast, HttpJsonRpc, LocalKeySigner, MEASURED, MEASURED_VERIFIER, NativeBridgeV2, Nb2Error, RpcError, SELECTOR, WalletError,
  burnPairBound, buildParams, classifyRedeemError, construct, decodeConfig, decodeEvidence, decodeRevert, decodeToken, deriveBridgeKey, encodeReturnData,
  encodeToken, evidenceOf, gapProofLen, log2, maxProofs, otherBytes, redeemCalldata, redeemCalldataLength, redeemTxFraming, revertDataOf, signTx,
  verdictAbi, verifyPart, type DeploymentPins, type JournalStore, type ReturnRecord,
} from '../../../packages/native-bridge-plugin/src/nb2/index.js';
import { appendTransfer, headOf, transferRequest, localOwner, freshMask } from '../../../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { signaturePredicate, encodeProof, type Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { HE, HU } from '../../../packages/native-bridge-plugin/src/nb2/crypto.js';
import { u256 } from '../../../packages/native-bridge-plugin/src/nb2/cbor.js';
import { TrustInput } from '../../../packages/native-bridge-plugin/src/trust.js';
import { refreshAll } from '../../../tester/trust.js';

// ---- configuration ------------------------------------------------------------------------------------------------------------------

const WORK = process.env.NB2_WORK ?? '/work/nb2';
interface Lane {
  rpc: string; // the public gateway
  agg: string; // the gateway's /aggregator route
  direct: string; // validator 1's execution client, for eth_simulateV1 only (fault injection is an operator check, not a wallet step)
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

function pinsOf(r: { pins: Record<string, unknown> }): DeploymentPins {
  const p = r.pins as Record<string, string | boolean | number>;
  return {
    gamma: unhex(p.gamma as string), build: p.build as 'test' | 'production', vaultRuntimeCodeHash: unhex(p.vaultRuntimeCodeHash as string),
    maxEncodedTxBytes: big(p.maxEncodedTxBytes as number), userGasLimit: big(p.userGasLimit as string), gasReserve: big(p.gasReserve as string),
    returnReserveSegments: big(p.returnReserveSegments as number), deploymentBlock: big(p.deploymentBlock as number), stateReadOnly: p.stateReadOnly as boolean,
  };
}
const pins = pinsOf(release);
const cfg = decodeConfig(pins.gamma, buildParams(pins.build));

const out = (name: string, v: unknown): void => {
  mkdirSync(join(WORK, 'out'), { recursive: true });
  writeFileSync(join(WORK, 'out', `${name}.json`), JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? hx(x) : x), 2) + '\n');
};
const log = (...a: unknown[]): void => console.log(...a.map((x) => (typeof x === 'bigint' ? x.toString() : x)));

// ---- a durable journal: one JSON file per wallet, written by rename -------------------------------------------------------------------

class FileJournalStore implements JournalStore {
  public constructor(private readonly file: string) {}
  private load(): Record<string, string> {
    return existsSync(this.file) ? JSON.parse(readFileSync(this.file, 'utf8')) : {};
  }
  public get(key: string): Promise<string | null> {
    return Promise.resolve(this.load()[key] ?? null);
  }
  public putIf(key: string, expected: string | null, value: string): Promise<boolean> {
    const m = this.load();
    if ((m[key] ?? null) !== expected) return Promise.resolve(false);
    m[key] = value;
    writeFileSync(`${this.file}.tmp`, JSON.stringify(m));
    renameSync(`${this.file}.tmp`, this.file);
    return Promise.resolve(true);
  }
  public list(prefix: string): Promise<string[]> {
    return Promise.resolve(Object.keys(this.load()).filter((k) => k.startsWith(prefix)).sort());
  }
}

// ---- wallets ----------------------------------------------------------------------------------------------------------------------------

interface TokenEntry { file: string; owner: number; amount: string; intent?: string; returnId?: string; note?: string }

class Wallet {
  public readonly dir: string;
  public readonly evmKey: Uint8Array;
  public readonly signer: LocalKeySigner;
  public bridge!: NativeBridgeV2;
  public trust!: TrustInput;
  public constructor(public readonly name: string) {
    this.dir = join(WORK, 'wallets', name);
    mkdirSync(join(this.dir, 'tokens'), { recursive: true });
    const k = process.env[`NB2_KEY_${name.toUpperCase()}`];
    if (!k) throw new Error(`NB2_KEY_${name.toUpperCase()} is not set`);
    this.evmKey = unhex(k);
    this.signer = new LocalKeySigner(this.evmKey);
  }
  /** Unicity owner key i of this wallet (a test derivation from the EVM key; a real wallet derives from its seed). */
  public ownerKey(i: number): Uint8Array {
    return sha256(concat(new TextEncoder().encode(`nb2-lane-owner/${i}/`), this.evmKey));
  }
  public owner(i: number) {
    return localOwner(this.ownerKey(i));
  }
  public ownerPub(i: number): Uint8Array {
    return secp256k1.getPublicKey(this.ownerKey(i), true);
  }
  public get historyFile(): string {
    return join(this.dir, 'trust-history.cbor');
  }
  public async open(check = false): Promise<Wallet> {
    const pin = unhex(readFileSync(lane.trustPin, 'utf8').trim());
    const shipped = await TrustInput.fromBundle(Uint8Array.from(readFileSync(lane.trustBundle)), pin);
    this.trust = shipped;
    if (existsSync(this.historyFile)) {
      const held = await TrustInput.fromBundle(Uint8Array.from(readFileSync(this.historyFile)), pin);
      for (const e of shipped.history.entries) await held.history.append(e);
      this.trust = held;
    }
    const persist = (b: Uint8Array): void => {
      writeFileSync(`${this.historyFile}.tmp`, b);
      renameSync(`${this.historyFile}.tmp`, this.historyFile);
    };
    const source = new AggregatorClient(lane.agg);
    const backupFile = join(this.dir, 'backup.json');
    this.bridge = await NativeBridgeV2.open({
      pins, trust: this.trust, rpc: new CountingRpc(new HttpJsonRpc(lane.rpc, { retries: 20, timeoutMs: 120_000 })), aggregator: new LaneAggregator(lane.agg),
      journal: new FileJournalStore(join(this.dir, 'journal.json')), bridgeKey: deriveBridgeKey(sha256(concat(new TextEncoder().encode('nb2-lane-seed/'), this.evmKey))),
      backup: async (intents) => writeFileSync(backupFile, JSON.stringify(intents)),
      refreshTrust: async () => { await refreshAll(this.trust, source, 64, persist); },
      receiptTimeoutMs: 180_000, pollMs: 1_000,
    }, check);
    return this;
  }
  private get index(): Record<string, TokenEntry> {
    const f = join(this.dir, 'tokens.json');
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : {};
  }
  public labels(): string[] {
    return Object.keys(this.index).sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
  }
  public entry(label: string): TokenEntry {
    const e = this.index[label];
    if (!e) throw new Error(`wallet ${this.name} holds no token ${label}`);
    return e;
  }
  public token(label: string): Uint8Array {
    return Uint8Array.from(readFileSync(join(this.dir, 'tokens', this.entry(label).file)));
  }
  public keep(label: string, token: Uint8Array, owner: number, extra: Partial<TokenEntry> = {}): void {
    writeFileSync(join(this.dir, 'tokens', `${label}.cbor`), token);
    const idx = this.index;
    idx[label] = { ...(idx[label] ?? {}), file: `${label}.cbor`, owner, amount: '0', ...extra };
    writeFileSync(join(this.dir, 'tokens.json.tmp'), JSON.stringify(idx, null, 2));
    renameSync(join(this.dir, 'tokens.json.tmp'), join(this.dir, 'tokens.json'));
  }
  public update(label: string, extra: Partial<TokenEntry>): void {
    const idx = this.index;
    idx[label] = { ...idx[label], ...extra };
    writeFileSync(join(this.dir, 'tokens.json.tmp'), JSON.stringify(idx, null, 2));
    renameSync(join(this.dir, 'tokens.json.tmp'), join(this.dir, 'tokens.json'));
  }
  public async returnRecord(label: string): Promise<ReturnRecord> {
    const id = this.entry(label).returnId;
    if (!id) throw new Error(`${label} has no planned return`);
    const r = await this.bridge.journal.ret(id);
    if (r === null) throw new Error(`${label}: return ${id} not journaled`);
    return r;
  }
}

/** The SDK aggregator through the gateway's /aggregator route, with a submit-then-poll that tolerates a busy route. */
class LaneAggregator {
  private readonly client: AggregatorClient;
  public constructor(url: string) {
    this.client = new AggregatorClient(url);
  }
  public async submit(request: Uint8Array): Promise<void> {
    const cd = CertificationData.fromCBOR(request);
    for (let attempt = 0; ; attempt++) {
      try {
        const r = await this.client.submitCertificationRequest(cd);
        if (!r.isAccepted && !r.isAlreadySubmitted && !r.isStateIdQueued) throw new WalletError('Reverted', `aggregator: ${r.status}`);
        return;
      } catch (e) {
        if (e instanceof WalletError || attempt >= 20) throw e;
        await sleep(1000 * (attempt + 1));
      }
    }
  }
  public async proof(request: Uint8Array, timeoutMs = 300_000): Promise<Uint8Array> {
    const cd = CertificationData.fromCBOR(request);
    const sid = await StateId.fromCertificationData(cd);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const resp = await this.client.getInclusionProof(sid, { waitMs: 2_000 });
        const p = resp.inclusionProof;
        if (p !== null) {
          if (!eq(p.certificationData.toCBOR(), request)) throw new WalletError('ProviderFault', 'the aggregator certified another request for this state');
          return p.toCBOR();
        }
      } catch (e) {
        if (e instanceof WalletError) throw e;
      }
      if (Date.now() > deadline) throw new WalletError('Unconfirmed', 'no inclusion proof in time');
      await sleep(1_000);
    }
  }
  public async certify(request: Uint8Array): Promise<Uint8Array> {
    await this.submit(request);
    return this.proof(request);
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

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function retry<T>(what: string, f: () => Promise<T>, tries = 120, ms = 2_000): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await f();
    } catch (e) {
      const reason = e instanceof WalletError ? e.reason : e instanceof Nb2Error ? e.rule : '';
      if (i >= tries || !['CompanionUnknown', 'Unconfirmed', 'NotPending', 'NoEntryForEpoch'].includes(reason)) throw e;
      if (i % 10 === 0) log(`  ${what}: ${reason}, retrying`);
      await sleep(ms);
    }
  }
}

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
  const w = await new Wallet('main').open(true); // the installation check: chain ID, config() == Γ, runtime code hash
  const res: Record<string, unknown> = { domain: hx(w.bridge.domain), K: test.K, B: test.B, build: pins.build, vault: hx(test.vault), verifier: hx(test.verifier) };
  if (lane.production) {
    const g = unhex(lane.production.gamma);
    const p = decodeConfig(g, buildParams('production'));
    res.production = { domain: hx(HU(g)), K: p.K, B: p.B, vault: hx(p.vault) };
  }
  out('gamma-check', res);
  log('Γ accepted by the plug-in; the installation check passed', res);
}

/** The operating envelope (section 12.5) from the pinned limits, by the plug-in's measured gas model (gas.ts MeasuredGasModel). */
function envelope(file: string): void {
  const m = MEASURED_VERIFIER;
  const K = cfg.K;
  const gp = BigInt(gapProofLen(K));
  // a part with `hops` further transfers and `levels` split levels, burned: the model's gas limit with P historical proofs, and its bytes
  const bytesOf = (hops: number, levels: number): number => m.baseBytes + m.bytesPerTransfer * hops + m.bytesPerSplitLevel * levels;
  const gasOf = (hops: number, levels: number, P: bigint, pendingBurn: boolean): bigint => {
    const evidence = bytesOf(hops, levels) + (pendingBurn ? burnPairBound(encodeReturnData({ d: new Uint8Array(32), asset: ASSET_UCT, recipient: new Uint8Array(20), amount: (1n << 255n), minIndex: (1n << 47n) }).length) - m.bytesPerTransfer : 0);
    const excess = BigInt(Math.max(0, evidence - bytesOf(hops, levels)));
    const extraSigs = pendingBurn ? BigInt(m.maxSignatures - m.measuredSignatures) : 0n;
    const verifier = m.base + m.perTransfer * BigInt(hops) + m.perSplitLevel * BigInt(levels) + m.perExcessByte * excess + m.perExtraSignature * extraSigs;
    const history = P === 0n ? 0n : 16n * (32n + P * gp);
    return verifier + m.vaultWorstCall + m.perSegment * P + history + MEASURED.gasReserve;
  };
  const sizeFits = (hops: number, levels: number, P: bigint, pending: boolean): boolean => {
    const lT = BigInt(bytesOf(hops, levels) + (pending ? burnPairBound(64) - m.bytesPerTransfer : 0));
    const mp = maxProofs(pins.maxEncodedTxBytes, lT, BigInt(otherBytes(Number(lT))), K);
    return mp.baseFits && P <= mp.pMax;
  };
  const reserve = pins.returnReserveSegments;
  const shapes: Record<string, unknown>[] = [];
  for (const levels of [0, 1, 2]) {
    // the largest history that passes the pre-burn preflight at P = returnReserveSegments (the burn counted at the decoder bounds)
    let hops = 0;
    while (gasOf(hops + 1, levels, reserve, true) <= pins.userGasLimit && sizeFits(hops + 1, levels, reserve, true)) hops++;
    const bytes = bytesOf(hops, levels);
    // and how many historical proofs fit beside it at redemption, by bytes and by gas
    const lT = BigInt(bytes);
    const byBytes = maxProofs(pins.maxEncodedTxBytes, lT, BigInt(otherBytes(bytes)), K).pMax;
    let byGas = 0n;
    while (gasOf(hops, levels, byGas + 1n, false) <= pins.userGasLimit) byGas++;
    shapes.push({ splitLevels: levels, maxTransfersPreBurn: hops, evidenceBytes: bytes, proofsByBytes: byBytes, proofsByGas: byGas, binding: byGas < byBytes ? 'gas' : 'bytes' });
  }
  // the reference part (one transfer, two split levels): the return delay its proofs support at stated rates
  const refHops = 1;
  const refLevels = 2;
  const refBytes = bytesOf(refHops, refLevels);
  const pBytes = maxProofs(pins.maxEncodedTxBytes, BigInt(refBytes), BigInt(otherBytes(refBytes)), K).pMax;
  let pGas = 0n;
  while (gasOf(refHops, refLevels, pGas + 1n, false) <= pins.userGasLimit) pGas++;
  const pMax = pGas < pBytes ? pGas : pBytes;
  const payments = pMax * K;
  const delay = (perSecond: number): number => Number(payments) / perSecond;
  const env = {
    model: 'native-bridge-plugins MeasuredGasModel (measured-nb2-05); bytes from MEASURED_VERIFIER',
    K, gapProofBytes: Number(gp), maxEncodedTxBytes: pins.maxEncodedTxBytes, userGasLimit: pins.userGasLimit, gasReserve: pins.gasReserve, returnReserveSegments: reserve,
    preBurnBurnBound: { bytes: burnPairBound(64), gas: gasOf(0, 0, 0n, true) - gasOf(0, 0, 0n, false) },
    largestToken: shapes,
    referencePart: {
      transfers: refHops, splitLevels: refLevels, evidenceBytes: refBytes, proofsByBytes: pBytes, proofsByGas: pGas, binding: pGas < pBytes ? 'gas' : 'bytes',
      interveningPayments: payments, returnDelaySeconds: { at1PerSecond: delay(1), at10PerSecond: delay(10), at100PerSecond: delay(100) },
    },
  };
  writeFileSync(file, JSON.stringify(env, (_k, x) => (typeof x === 'bigint' ? Number(x) : x), 2) + '\n');
  log('envelope', readFileSync(file, 'utf8'));
}

async function deposit(w: Wallet, label: string, units: bigint, mode: string | undefined): Promise<void> {
  if (mode === '--adopt') {
    const intent = big(w.entry(label).intent!);
    const r = await w.bridge.submitDeposit(intent, w.signer); // no send of its own: the lane's legacy deposit is found by its rho
    log(`  adopted deposit ${r.depositNumber} (tx ${hx(r.txHash)})`);
    return mintIntent(w, label, intent, r.txHash);
  }
  const plan = await w.bridge.planDeposit(units * UNIT, w.ownerPub(0));
  if (mode === '--plan-only') {
    w.keep(label, new Uint8Array(), 0, { intent: plan.intent.toString(), amount: (units * UNIT).toString(), note: 'planned' });
    out(`deposit-plan-${label}`, { intent: plan.intent, calldata: hx(plan.calldata), value: units * UNIT, vault: hx(cfg.vault) });
    log(`  planned intent ${plan.intent}`);
    return;
  }
  const r = await w.bridge.submitDeposit(plan, w.signer);
  log(`  deposit ${r.depositNumber} in block ${r.blockNumber} (tx ${hx(r.txHash)}, EIP-1559)`);
  w.keep(label, new Uint8Array(), 0, { intent: plan.intent.toString(), amount: (units * UNIT).toString() });
  return mintIntent(w, label, plan.intent, r.txHash);
}

async function mintIntent(w: Wallet, label: string, intent: bigint, tx: Uint8Array): Promise<void> {
  const p = await retry('the deposit proof', () => w.bridge.collectDepositProof(intent));
  const token = await w.bridge.mint(intent);
  const v = await w.bridge.verifyToken(token);
  w.keep(label, token, 0, { intent: intent.toString(), amount: v.amount.toString() });
  out(`deposit-${label}`, { intent, depositNumber: p.depositNumber, tx, amount: v.amount, tokenId: v.tokenId, reasonBytes: p.reason.length });
  log(`  minted ${label}: ${v.amount} wei, J ${p.reason.length} bytes`);
}

async function transfer(w: Wallet, from: string, to: string, owner: number): Promise<void> {
  const e = w.entry(from);
  const t = await w.bridge.transfer(w.token(from), w.owner(e.owner), w.ownerPub(owner));
  w.keep(to, t, owner, { amount: e.amount });
  log(`  ${from} -> ${to} (owner ${owner})`);
}

async function split(w: Wallet, from: string, owner: number, outs: string[]): Promise<void> {
  const e = w.entry(from);
  const parts = outs.map((s) => { const [l, a] = s.split('='); return { label: l, amount: big(a) * UNIT }; });
  const res = await w.bridge.split(w.token(from), w.owner(e.owner), parts.map((p) => ({ ownerKey: w.ownerPub(owner), amount: p.amount })));
  res.forEach((t, i) => w.keep(parts[i].label, t, owner, { amount: parts[i].amount.toString() }));
  log(`  split ${from} into ${outs.join(' + ')}`);
}

/** N transfers of FROM to the wallet's own keys, all requests built offline from the known states and certified together. */
async function chain(w: Wallet, from: string, to: string, n: number, rounds: boolean): Promise<void> {
  const agg = new LaneAggregator(lane.agg);
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
    for (let i = 0; i < pending.length; i += 32) await Promise.all(pending.slice(i, i + 32).map((p) => agg.submit(p.cd)));
    for (const p of pending) token = appendTransfer(token, p.tx, await agg.proof(p.cd));
  }
  const v = await w.bridge.verifyToken(token);
  w.keep(to, token, owner, { amount: v.amount.toString() });
  const ucs = new Set(decodeToken(token).proofs.map((p) => hx(HU(p.uc))));
  out(`chain-${to}`, { transfers: decodeToken(token).transfers.length, distinctCertificates: ucs.size, bytes: token.length });
  log(`  ${to}: ${decodeToken(token).transfers.length} transfers under ${ucs.size} certificates, ${token.length} bytes`);
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

async function burn(w: Wallet, label: string, recipient?: string): Promise<void> {
  const e = w.entry(label);
  const token = w.token(label);
  const plan = await w.bridge.planReturn(token, recipientOf(w, recipient), w.signer.address);
  w.update(label, { returnId: hx(plan.returnId) });
  const b = await retry('the burn', () => w.bridge.burn(plan.returnId, w.owner(e.owner)));
  const ev = evidenceOf(b.burned);
  mkdirSync(join(WORK, 'evidence'), { recursive: true });
  writeFileSync(evidenceFile(label), ev);
  out(`burn-${label}`, { a: plan.a, cObs: plan.cObs, pNow: plan.pNow, pMax: plan.pMax, marginSegments: plan.marginSegments, preflightGas: plan.gasLimit, eta: b.eta, amount: plan.amount,
    recipient: hx(plan.recipient), evidenceBytes: ev.length, warnings: plan.warnings });
  log(`  burned ${label} at index a = ${plan.a} (c observed ${plan.cObs}), ${ev.length} evidence bytes`);
}

async function verdicts(w: Wallet, labels: string[]): Promise<void> {
  const res: Record<string, unknown> = {};
  for (const l of labels) {
    const ev = Uint8Array.from(readFileSync(evidenceFile(l)));
    const ts = await tsVerdict(w, ev);
    const sol = await solidityVerdict(lane.verifier, pins.gamma, ev);
    res[l] = { ts, solidity: sol, equal: ts.verdict !== undefined && ts.verdict === sol.verdict, file: `evidence/${l}.cbor` };
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
    res.lowGas = { gasLimit: low, hash: sent.hash, status: sent.receipt.status, gasUsed: sent.receipt.gasUsed, stateAfter: mid, unchanged: JSON.stringify(mid) === JSON.stringify(before) };
    log(`  ${label}: redeem with gas ${low} -> status ${sent.receipt.status}; vault unchanged: ${(res.lowGas as Record<string, unknown>).unchanged}`);
  }
  const t0 = Date.now();
  let r = await w.bridge.submitRedeem(id, w.signer);
  for (let i = 0; r.state === 'pending' && i < 60; i++) {
    await sleep(3000);
    r = await w.bridge.reconcile(id);
  }
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
  if (evicted) {
    const forged = await forgedHistory(w, rec, eta, a, st.segment as bigint);
    res.forgedGapProof = await simulateRule(w.signer.address, redeemCalldata(evidence, eta, a, forged), 10_000_000n);
  }
  out(`replay-${label}${evicted ? '-evicted' : ''}`, res);
  log(`  replay of ${label} (${evicted ? 'evicted' : 'in the recent buffers'}):`, JSON.stringify(res));
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
    for (let i = 0; i < n; i++) {
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
    const r = await w.bridge.submitRedeem(id, w.signer);
    if (r.state !== 'paid') throw new Error(`small return ${l}: ${r.state}`);
    segs.push((await vaultState()).segment);
  }
  out(`rotate-${w.name}-${Date.now()}`, { paid: take, segmentsAfterEach: segs });
  log(`  ${w.name}: ${take.length} small returns paid; segment now ${segs[segs.length - 1]}`);
}

// ---- the capacity boundary ----------------------------------------------------------------------------------------------------------------

/** The wallet's section 12.5 pre-burn preflight of `token`, replayed outside the plug-in (the same functions and inputs as planReturn). */
async function predict(w: Wallet, token: Uint8Array): Promise<{ ok: boolean; gas: bigint | null; need: bigint; bytes: number; detail: string }> {
  const { capacityPreflight, burnIndex, lineageOf } = await import('../../../packages/native-bridge-plugin/src/nb2/index.js');
  const sr = await w.bridge.newestSealReceipt();
  const { a } = burnIndex(cfg, w.bridge.domain, sr?.receipt ?? null);
  const st = await w.bridge.evm.vaultState(cfg.vault);
  const cObs = st.segment > a ? st.segment : a;
  const R = encodeReturnData({ d: w.bridge.domain, asset: ASSET_UCT, recipient: w.signer.address, amount: 1n << 64n, minIndex: a });
  const lT = BigInt(evidenceOf(token).length + burnPairBound(R.length));
  const lO = BigInt(otherBytes(Number(lT)));
  const lineage = lineageOf(decodeToken(token));
  let gas: bigint | null = null;
  const gasAt = (p: bigint): bigint | null => (gas = w.bridge.gas.redeemGasLimit({ evidenceBytes: Number(lT), lineage, pendingTransactions: 1, proofs: p, K: cfg.K }));
  try {
    const r = capacityPreflight({ lMax: pins.maxEncodedTxBytes, lT, lO, K: cfg.K, a, cObs, reserve: pins.returnReserveSegments, gasAt, userGasLimit: pins.userGasLimit });
    return { ok: true, gas: r.gas, need: r.need, bytes: Number(lT), detail: 'fits' };
  } catch (e) {
    return { ok: false, gas, need: cObs - a + pins.returnReserveSegments, bytes: Number(lT), detail: String((e as Error).message) };
  }
}

/**
 * The largest transfer history whose return passes the wallet's preflight (the gas bound binds before L_max on this deployment), found on
 * live tokens: one held at the boundary (returned by the lane) and one a transfer above it (refused with CapacityPreflight). Each probe is a
 * fresh deposit chained to the predicted length, because a token checked one transfer further has spent the one below.
 */
async function boundary(w: Wallet, label: string, estimate: number): Promise<void> {
  const est = JSON.parse(readFileSync(join(WORK, 'out', `boundary-estimate-${label}e.json`), 'utf8'));
  const g16 = big(est.probeGas);
  const tries: { label: string; transfers: number; gas: bigint | null; real: string }[] = [];
  let pass: { label: string; transfers: number } | null = null;
  let fail: { label: string; transfers: number } | null = null;
  let k = estimate;
  for (let i = 0; i < 8; i++) {
    const l = `${label}${i}`;
    await deposit(w, l, 1n, undefined);
    await chain(w, l, `${l}c`, k, false);
    const t = w.token(`${l}c`);
    const p = await predict(w, t);
    // the real thing: planReturn's own preflight (it journals a plan; nothing irreversible)
    let real: string;
    try {
      await w.bridge.planReturn(t, w.signer.address, w.signer.address);
      real = 'passes';
    } catch (e) {
      real = e instanceof Nb2Error ? e.rule : e instanceof WalletError ? e.reason : String(e);
    }
    tries.push({ label: `${l}c`, transfers: k, gas: p.gas, real });
    log(`  ${l}c: ${k} transfers, ${evidenceOf(t).length} evidence bytes, preflight gas ${p.gas}: planReturn ${real}`);
    if (real === 'passes') { if (pass === null || k > pass.transfers) pass = { label: `${l}c`, transfers: k }; }
    else if (real === 'CapacityPreflight') { if (fail === null || k < fail.transfers) fail = { label: `${l}c`, transfers: k }; }
    else throw new Error(`the boundary probe was refused for another reason: ${real}`);
    if (pass !== null && fail !== null && fail.transfers === pass.transfers + 1) break;
    // the next length from the model's per-hop gas on these certificates
    const h = p.gas !== null && k > 16 ? (p.gas - g16) / BigInt(k - 16) : MEASURED_VERIFIER.perTransfer;
    const step = p.gas === null ? 1 : Number((pins.userGasLimit > p.gas ? pins.userGasLimit - p.gas : p.gas - pins.userGasLimit) / (h > 0n ? h : 1n));
    k = real === 'passes' ? k + Math.max(1, step) : k - Math.max(1, step);
    if (pass !== null && k <= pass.transfers) k = pass.transfers + 1;
    if (fail !== null && k >= fail.transfers) k = fail.transfers - 1;
  }
  out(`boundary-${label}`, { pass, fail, tries });
  if (pass === null || fail === null || fail.transfers !== pass.transfers + 1) throw new Error('no adjacent pass/refuse pair found');
}

/** The boundary estimate from a short live chain: the model's gas per further hop on this deployment's real certificates. */
async function boundaryEstimate(w: Wallet, label: string): Promise<void> {
  await deposit(w, label, 1n, undefined);
  await chain(w, label, `${label}c`, 16, false);
  const t16 = w.token(`${label}c`);
  const p16 = await predict(w, t16);
  const perHop = MEASURED_VERIFIER.perTransfer;
  const room = pins.userGasLimit - (p16.gas ?? 0n);
  const k = 16 + Number(room / (perHop + 2n * MEASURED_VERIFIER.perExtraSignature));
  out(`boundary-estimate-${label}`, { probeTransfers: 16, probeGas: p16.gas, perHop, estimate: k });
  log(`  boundary estimate: about ${k} transfers (probe ${p16.gas} gas at 16)`);
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
  // each certificate in check order: a byte of its seal signature flipped (an invalid claim at that position)
  proofs.forEach((p, i) => {
    const o = at(p.uc);
    if (o < 0) return;
    // the signatures are the last bytes of the UC (the seal's signature map closes the UC): flip one near the end
    ms.push({ name: `uc${i}-signature`, evidence: flipByte(ev, o + p.uc.length - 3) });
  });
  // the first certificate's mutations of the seal network, round and epoch fields: flipped bytes inside the UC (localised, not re-signed)
  const p0 = proofs[proofs.length - 1];
  const o0 = at(p0.uc);
  if (o0 >= 0) {
    ms.push({ name: 'uc-last-early-byte', evidence: flipByte(ev, o0 + 12) });
    ms.push({ name: 'uc-last-middle-byte', evidence: flipByte(ev, o0 + (p0.uc.length >> 1)) });
  }
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

// ---- fault injection by eth_simulateV1 (validator 1 directly: an operator check of the deployed bytecode, not a wallet path) -------------

async function simulate(calls: { to: string; data: string }[], overrides: Record<string, unknown>): Promise<{ ok: boolean; rule: string; returnData: string; gasUsed?: string }[]> {
  const r = await direct.call<{ calls: { status: string; returnData: string; gasUsed: string; error?: { message: string; data?: string } }[] }[]>('eth_simulateV1', [{
    blockStateCalls: [{ stateOverrides: overrides, calls: calls.map((c) => ({ ...c, gas: '0x3938700' })) }], validation: false,
  }, 'latest']);
  return r[0].calls.map((c) => ({ ok: c.status === '0x1', rule: c.status === '0x1' ? 'success' : ruleOf(unhex(c.error?.data ?? c.returnData ?? '0x')), returnData: c.returnData.slice(0, 74), gasUsed: c.gasUsed }));
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
  for (let i = 0; i < 10; i++) {
    const tx = await signTx(w.signer, { chainId: cfg.chainId, nonce, maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: 2n * base + 1_000_000_000n,
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
    case 'chain': return chain(await wallet(), pos[1], pos[2], Number(pos[3]), flag('--rounds'));
    case 'preflight': return preflight(await wallet(), pos[1]);
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
    default: throw new Error(`unknown command ${cmd}`);
  }
}

main().catch((e) => {
  console.error(e instanceof Nb2Error ? `Nb2Error ${e.rule}: ${e.message}` : e instanceof WalletError ? `WalletError ${e.reason}: ${e.message}` : e);
  process.exit(1);
});
