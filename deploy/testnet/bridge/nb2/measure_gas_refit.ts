/**
 * Measurement only (measure/nb2-gas-refit, bft-core#1179): the wallet's redeem gas bound (the plug-in's MeasuredGasModel, refit) against the
 * real redeem gas of live tokens of every shape. It runs like driver.ts (one command per container, this directory at tests/live/nb2lane/ of
 * the bridge image's plug-in checkout, GENERATION/bridge at /work; measure_gas_refit.py mounts the plug-in source under test over the image's)
 * and reuses driver.ts's wallet and commands. Every result is written to /work/nb2/out/g-<name>.json.
 *
 *   mk W LABEL N [--units U] [--groups G] [--keys]
 *                          deposit U units (default 1) and chain N transfers to LABEL: one aggregator batch, G consecutive groups (G distinct
 *                          certificates), and with --keys every transfer to a fresh owner key (N + 1 distinct keys) instead of four
 *   nest W FROM TO N1 [N2 ...]
 *                          split levels: FROM is split in two halves, the first chained N1 transfers; that again, N2 ...; the last is TO
 *   consolidate W FROM TO  the SDK's TokenProofClient on FROM (chunked above 256 outer proofs), as measure_consolidation.ts
 *   strip W FROM TO        every seal's signatures beyond the quorum removed (3 of 4), as measure_consolidation.ts
 *   judge W LABEL...       the preflight's bound on each held token (planReturn's inputs) and its terms; planReturn's verdict
 *   burn W LABEL [--permissive]
 *                          plan and burn LABEL (--permissive caps the bound's gas at userGasLimit, never the bytes, so a token past the
 *                          preflight can still be measured); its evidence is kept, then measured as below
 *   measure W LABEL... [--trace]
 *                          a burned return at the vault's current endpoint: the bound at redemption (P proofs) and its terms, the redeem's
 *                          eth_estimateGas, and with --trace the call tree (debug_traceCall callTracer, validator 1): the vault's own gas,
 *                          the verifier's, the helper's and each primitive's
 *   pay W LABEL            redeem LABEL live (driver.ts redeem): gasUsed beside the bound
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { ShardRouting } from '@unicitylabs/state-transition-sdk/lib/consolidation/ShardRouting.js';
import { TokenProofClient } from '@unicitylabs/state-transition-sdk/lib/consolidation/TokenProofClient.js';
import { ConsolidationError } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationError.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { PredicateVerifierService } from '@unicitylabs/state-transition-sdk/lib/predicate/verification/PredicateVerifierService.js';
import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { Token as SdkToken } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { MintJustificationVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { toHex } from '../../../packages/native-bridge-plugin/src/bytes.js';
import {
  MeasuredGasModel, Nb2Error, RpcError, WalletError, burnIndex, burnPairBound, capacityPreflight, decodeToken, encodeReturnData, encodeToken, evidenceOf,
  lineageOf, otherBytes, redeemFeatures, redeemGasTerms, revertDataOf, verifyHeld, ASSET_UCT, type RedeemShape,
} from '../../../packages/native-bridge-plugin/src/nb2/index.js';
import { appendTransfer, transferRequest, freshMask } from '../../../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { signaturePredicate, encodeProof } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { HU } from '../../../packages/native-bridge-plugin/src/nb2/crypto.js';
import { TAG } from '../../../packages/native-bridge-plugin/src/nb2/config.js';
import { GatewayAggregator, split as walletSplit } from '../../../wallet/core.js';
import { WORK, Wallet, cfg, deposit, direct, evidenceFile, hx, lane, log, out as driverOut, pins, redeem, rpc, ruleOf, unhex } from './driver.js';

const out = (name: string, v: unknown): void => driverOut(`g-${name}`, v);
const ms = (t0: number): number => Math.round(performance.now() - t0);
const js = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? hx(x) : x)));

// ---- tokens -------------------------------------------------------------------------------------------------------------------------------

/** N transfers of FROM kept as TO: owners cycle through four keys, or each a fresh key (KEYS); one batch, or G groups certified in turn. */
async function chainTo(w: Wallet, from: string, to: string, n: number, groups: number, keys: boolean): Promise<void> {
  const agg = new GatewayAggregator(lane.agg);
  let token = w.token(from);
  let owner = w.entry(from).owner;
  const pending: { tx: Uint8Array; cd: Uint8Array }[] = [];
  let virt = token;
  const placeholder = encodeProof(decodeToken(token).mintProof);
  const base = keys ? 1000 + Math.floor(Math.random() * 1e6) * 10 : 0;
  for (let k = 0; k < n; k++) {
    const next = keys ? base + k : (owner + 1) % 4;
    const req = await transferRequest(virt, w.owner(owner), { recipient: signaturePredicate(w.ownerPub(next)), mask: freshMask(), data: null, deadline: null });
    pending.push(req);
    virt = appendTransfer(virt, req.tx, placeholder);
    owner = next;
  }
  const g = Math.max(1, Math.min(groups, pending.length));
  for (let j = 0, at = 0; j < g; j++) {
    const group = pending.slice(at, (at = Math.round((pending.length * (j + 1)) / g)));
    for (let i = 0; i < group.length; i += 32) await Promise.all(group.slice(i, i + 32).map((p) => agg.submit(p.cd)));
    for (const p of group) token = appendTransfer(token, p.tx, await agg.proof(p.cd));
  }
  const v = await w.bridge.verifyToken(token);
  w.keep(to, token, owner, { amount: v.amount.toString() });
}

async function mk(w: Wallet, label: string, n: number, units: bigint, groups: number, keys: boolean): Promise<void> {
  const t0 = performance.now();
  await deposit(w, label, units, undefined);
  const t1 = performance.now();
  if (n > 0) await chainTo(w, label, label, n, groups, keys);
  out(`mk-${label}`, { label, transfers: n, units, groups, keys, depositMs: Math.round(t1 - t0), chainMs: ms(t1), anatomy: anatomy(w.token(label)) });
  log(`  ${label}: ${n} transfers (${groups} groups${keys ? ', fresh keys' : ''}), ${w.token(label).length} bytes`);
}

/** Split levels: at each, FROM is split into two halves and the first is chained Ni transfers. */
async function nest(w: Wallet, from: string, to: string, lengths: number[]): Promise<void> {
  let cur = from;
  for (let i = 0; i < lengths.length; i++) {
    const amount = BigInt(w.entry(cur).amount);
    const half = amount / 2n;
    const a = `${to}-l${i + 1}a`;
    const b = `${to}-l${i + 1}b`;
    await walletSplit(w, cur, w.entry(cur).owner, [{ label: a, amount: half }, { label: b, amount: amount - half }]);
    const next = i === lengths.length - 1 ? to : `${to}-l${i + 1}`;
    if (lengths[i] > 0) await chainTo(w, a, next, lengths[i], 1, false);
    else w.keep(next, w.token(a), w.entry(a).owner, { amount: w.entry(a).amount });
    cur = next;
  }
  out(`nest-${to}`, { from, to, lengths, anatomy: anatomy(w.token(to)) });
  log(`  ${to}: ${lengths.length} split levels (${lengths.join(', ')} transfers), ${w.token(to).length} bytes`);
}

// ---- consolidation and trimming (measure_consolidation.ts) --------------------------------------------------------------------------------

function nb2Justification(tag: bigint) {
  return {
    get tag(): bigint { return tag; },
    verify: async (): Promise<VerificationResult<VerificationStatus>> =>
      new VerificationResult('Nb2MintJustification', VerificationStatus.OK, 'judged by the NB2 plug-in (verifyHeld), not the SDK'),
  };
}

function sdkContext(w: Wallet): VerificationContext {
  const just = new MintJustificationVerifierService().register(nb2Justification(BigInt(TAG.receiptBacking))).register(nb2Justification(BigInt(TAG.splitJustification)));
  return new VerificationContext(
    w.trust.history as never,
    PredicateVerifierService.create(),
    new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 })),
    just,
    new TokenIssuanceVerifierService(false),
  );
}

async function consolidateBytes(w: Wallet, token: Uint8Array): Promise<{ token: Uint8Array; how: string; requests: number }> {
  const context = sdkContext(w);
  const client = new AggregatorClient(lane.agg);
  const tpc = new TokenProofClient({ routing: ShardRouting.single(client), verificationContext: context });
  const sdk = await SdkToken.fromCBOR(token);
  let r;
  for (let attempt = 0; ; attempt++) {
    try {
      r = await tpc.consolidate(sdk, { timeoutMs: 180_000 });
    } catch (e) {
      if (ConsolidationError.is(e) && e.retryable && attempt < 5) continue;
      throw e;
    }
    if (r.status === 'unavailable' && r.retryable && attempt < 10) {
      await new Promise((ok) => setTimeout(ok, 2000));
      continue;
    }
    break;
  }
  if (r.status === 'consolidated') return { token: r.token.toCBOR(), how: 'sdk', requests: r.summary.requests };
  if (r.reason !== 'limit_exceeded') throw new Error(`consolidation unavailable: ${r.reason}`);
  return chunked(sdk, client, context);
}

async function chunked(sdk: SdkToken, client: AggregatorClient, context: VerificationContext): Promise<{ token: Uint8Array; how: string; requests: number }> {
  const outer = [sdk.genesis, ...sdk.transactions].map((x) => x.inclusionProof);
  const sids = await Promise.all(outer.map((p) => StateId.fromCertificationData(p.certificationData)));
  const CH = 256;
  const order: number[][] = [];
  for (let end = sids.length; end > 0; end -= CH) order.push([...Array(Math.min(CH, end)).keys()].map((i) => end - Math.min(CH, end) + i));
  let requests = 0;
  const replaced: InclusionProof[] = new Array(outer.length);
  let target = null as UnicityCertificate | null;
  for (const idx of order) {
    const opts = target === null ? {} : { stateRoot: new DataHash(HashAlgorithm.SHA256, target.inputRecord.nullableHash!) };
    const batch = await client.getInclusionProofs(idx.map((i) => sids[i]), opts as never);
    requests++;
    for (const [k, resp] of batch.proofs.entries()) {
      const p = resp.inclusionProof;
      if (p === null) throw new Error(`chunked: no proof for outer proof ${idx[k]}`);
      if (target === null) target = p.unicityCertificate;
      else if (toHex(p.unicityCertificate.inputRecord.nullableHash!) !== toHex(target.inputRecord.nullableHash!)) throw new Error('chunked: another root');
      const orig = outer[idx[k]];
      replaced[idx[k]] = new InclusionProof(orig.certificationData, orig.referenceTime, p.inclusionCertificate, target!);
    }
  }
  const bytes = (TokenProofClient as unknown as { replaceOuterProofs(b: Uint8Array, p: InclusionProof[]): Uint8Array }).replaceOuterProofs(sdk.toCBOR(), replaced);
  const v = await (await SdkToken.fromCBOR(bytes)).verify(context);
  if (v.status !== VerificationStatus.OK) throw new Error('chunked: the rebuilt token does not verify');
  return { token: bytes, how: 'chunked', requests };
}

async function consolidateCmd(w: Wallet, from: string, to: string): Promise<void> {
  const src = w.token(from);
  const c = await consolidateBytes(w, src);
  const a = await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(src));
  const b = await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(c.token));
  if (a.amount !== b.amount || toHex(a.tokenId) !== toHex(b.tokenId)) throw new Error('the consolidated token is another token');
  const e = w.entry(from);
  w.keep(to, c.token, e.owner, { amount: e.amount });
  out(`consolidate-${to}`, { from, to, how: c.how, requests: c.requests, before: anatomy(src), after: anatomy(c.token) });
  log(`  ${from} -> ${to}: ${c.how}, ${c.requests} requests`);
}

function stripBytes(token: Uint8Array): Uint8Array {
  const t = decodeToken(token);
  const quorum = 3;
  const cache = new Map<string, Uint8Array>();
  const trim = (uc: Uint8Array): Uint8Array => {
    const k = hx(uc);
    if (cache.has(k)) return cache.get(k)!;
    const u = UnicityCertificate.fromCBOR(uc);
    const seal = u.unicitySeal as unknown as { _witnesses: Map<string, Uint8Array> | null };
    let r = uc;
    if (seal._witnesses !== null && seal._witnesses.size > quorum) {
      const keep = new Set([...seal._witnesses.keys()].sort().slice(0, quorum));
      seal._witnesses = new Map([...seal._witnesses.entries()].filter(([key]) => keep.has(key)));
      r = u.toCBOR();
    }
    cache.set(k, r);
    return r;
  };
  return encodeToken({ ...t, mintProof: { ...t.mintProof, uc: trim(t.mintProof.uc) }, proofs: t.proofs.map((p) => ({ ...p, uc: trim(p.uc) })) });
}

async function strip(w: Wallet, from: string, to: string): Promise<void> {
  const bytes = stripBytes(w.token(from));
  await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(bytes));
  const e = w.entry(from);
  w.keep(to, bytes, e.owner, { amount: e.amount });
  log(`  ${from} -> ${to}: ${w.token(from).length} -> ${bytes.length} token bytes`);
}

// ---- anatomy and the bound ------------------------------------------------------------------------------------------------------------------

function anatomy(token: Uint8Array): Record<string, unknown> {
  const t = decodeToken(token);
  const lineage = lineageOf(t);
  const proofs = lineage.flatMap((x) => [x.mintProof, ...x.proofs]);
  const ucs = new Set(proofs.map((p) => hx(HU(p.uc))));
  const keys = new Set(lineage.flatMap((x) => [x.mint.recipient, ...x.transfers.map((y) => y.recipient)]).filter((p) => p.type === 1n).map((p) => hx(p.params)));
  return {
    transfers: lineage.reduce((n, x) => n + x.transfers.length, 0), levels: lineage.length - 1, tokenBytes: token.length, evidenceBytes: evidenceOf(token).length,
    proofs: proofs.length, distinctCertificates: ucs.size, distinctOwnerKeys: keys.size,
    ucBytesPerProof: Math.round(proofs.reduce((n, p) => n + p.uc.length, 0) / proofs.length),
    siblingsPerProof: +(proofs.reduce((n, p) => n + p.siblings.length, 0) / proofs.length).toFixed(2),
  };
}

/** The preflight's shape of TOKEN (planReturn's inputs: the burn pair at its bound, 1 pending transaction, the proofs owed plus the reserve). */
async function preShape(w: Wallet, token: Uint8Array): Promise<{ shape: RedeemShape; need: bigint; lT: bigint }> {
  const sr = await w.bridge.newestSealReceipt();
  const { a } = burnIndex(cfg, w.bridge.domain, sr?.receipt ?? null);
  const st = await w.bridge.evm.vaultState(cfg.vault);
  const cObs = st.segment > a ? st.segment : a;
  const R = encodeReturnData({ d: w.bridge.domain, asset: ASSET_UCT, recipient: w.signer.address, amount: 1n << 64n, minIndex: a });
  const lT = BigInt(evidenceOf(token).length + burnPairBound(R.length));
  const need = cObs - a + pins.returnReserveSegments;
  return { shape: { evidenceBytes: Number(lT), lineage: lineageOf(decodeToken(token)), pendingTransactions: 1, proofs: need, K: cfg.K }, need, lT };
}

const termsOf = (s: RedeemShape): unknown => {
  const t = redeemGasTerms(s);
  const f = redeemFeatures(s);
  return js({ terms: t, features: f === null ? null : { ...f, claims: f.claims.length, evmUc: undefined } });
};

async function judge(w: Wallet, labels: string[]): Promise<void> {
  const res: Record<string, unknown> = {};
  for (const l of labels) {
    const t = w.token(l);
    const { shape, need, lT } = await preShape(w, t);
    let real: string;
    try {
      await w.bridge.planReturn(t, w.signer.address, w.signer.address);
      real = 'passes';
    } catch (e) {
      real = e instanceof Nb2Error ? `${e.rule}: ${e.message}` : e instanceof WalletError ? `${e.reason}: ${e.message}` : String(e);
    }
    let bytesFit = true;
    try {
      capacityPreflight({ lMax: pins.maxEncodedTxBytes, lT, lO: BigInt(otherBytes(Number(lT))), K: cfg.K, a: 0n, cObs: need - pins.returnReserveSegments, reserve: pins.returnReserveSegments, gasAt: () => 0n, userGasLimit: pins.userGasLimit });
    } catch {
      bytesFit = false;
    }
    res[l] = { anatomy: anatomy(t), need, preflightBytes: Number(lT), bytesFit, planReturn: real, bound: termsOf(shape) };
    log(`  ${l}: bound ${redeemGasTerms(shape)?.limit} (${bytesFit ? 'bytes fit' : 'bytes do not fit'}), planReturn ${real}`);
  }
  out(`judge-${labels.join('-')}`, res);
}

class Permissive extends MeasuredGasModel {
  public override redeemGasLimit(s: RedeemShape): bigint | null {
    const g = super.redeemGasLimit(s);
    return g !== null && s.pendingTransactions > 0 && g > pins.userGasLimit ? pins.userGasLimit : g;
  }
}

async function burnCmd(w: Wallet, label: string, permissive: boolean): Promise<void> {
  if (permissive) (w.bridge as unknown as { gas: unknown }).gas = new Permissive();
  const e = w.entry(label);
  const t = w.token(label);
  const pre = await preShape(w, t);
  const res: Record<string, unknown> = { label, permissive, anatomy: anatomy(t), preflight: termsOf(pre.shape), preflightNeed: pre.need };
  const prior = e.returnId ? await w.bridge.journal.ret(e.returnId) : null;
  if (prior === null || prior.status === 'planned') {
    const plan = await w.bridge.planReturn(t, w.signer.address, w.signer.address);
    w.update(label, { returnId: hx(plan.returnId), spent: `burn ${hx(plan.returnId)}` });
    res.plan = { a: plan.a, gasLimit: plan.gasLimit, marginSegments: plan.marginSegments };
    const b = await w.bridge.burn(plan.returnId, w.owner(e.owner));
    mkdirSync(join(WORK, 'evidence'), { recursive: true });
    writeFileSync(evidenceFile(label), evidenceOf(b.burned));
  }
  out(`burn-${label}`, res);
  log(`  ${label}: burned (preflight bound ${(res.plan as { gasLimit?: bigint } | undefined)?.gasLimit})`);
  await measure(w, [label], false);
}

interface Frame { type: string; to?: string; gasUsed: string; calls?: Frame[]; input?: string }

/** The call tree's gas by part: the vault's own, the verifier's own, the helper's, and each primitive's (calls and gas). */
function decompose(root: Frame): Record<string, unknown> {
  const used = (f: Frame): bigint => BigInt(f.gasUsed);
  const kids = (f: Frame): bigint => (f.calls ?? []).reduce((n, c) => n + used(c), 0n);
  const by: Record<string, { calls: number; gas: bigint }> = {};
  const add = (k: string, g: bigint): void => {
    by[k] = by[k] ?? { calls: 0, gas: 0n };
    by[k].calls++;
    by[k].gas += g;
  };
  const verifier = (root.calls ?? []).find((c) => c.to?.toLowerCase() === lane.verifier.toLowerCase());
  const walk = (f: Frame): void => {
    for (const c of f.calls ?? []) {
      const to = (c.to ?? '').toLowerCase();
      const name = to === lane.helper.toLowerCase() ? 'helper' : /^0x0{36}/.test(to) ? `p${to.slice(-4)}` : to;
      add(name, used(c));
      if (name === 'helper') walk(c);
    }
  };
  if (verifier) walk(verifier);
  return js({ total: used(root), vaultSelf: used(root) - kids(root), verifier: verifier ? used(verifier) : null, verifierSelf: verifier ? used(verifier) - kids(verifier) : null, by });
}

async function measure(w: Wallet, labels: string[], trace: boolean): Promise<void> {
  for (const l of labels) {
    const rec = await w.returnRecord(l);
    const id = unhex(rec.returnId);
    const ev = evidenceOf(unhex(rec.burned!));
    // a burn just certified may name a root seal the chain's registry has not imported yet (QuorumNotMet, #1125): wait for it
    let rtx;
    for (let i = 0; ; i++) {
      try {
        rtx = await w.bridge.buildRedeem(id);
        break;
      } catch (e) {
        if (!(e instanceof Nb2Error) || e.rule !== 'VerifierRefused' || i >= 60) throw e;
        await new Promise((ok) => setTimeout(ok, 3000));
      }
    }
    const shape: RedeemShape = { evidenceBytes: ev.length, lineage: lineageOf(decodeToken(unhex(rec.burned!))), pendingTransactions: 0, proofs: rtx.P, K: cfg.K };
    const call = { from: hx(unhex(rec.recipient)), to: hx(cfg.vault), data: hx(rtx.calldata) };
    let estimate: string;
    try {
      estimate = BigInt(await rpc.call<string>('eth_estimateGas', [{ ...call, gas: `0x${(200_000_000).toString(16)}` }, 'latest'])).toString();
    } catch (e) {
      estimate = e instanceof RpcError ? `refused: ${ruleOf(revertDataOf(e))}` : `error: ${String(e).slice(0, 160)}`;
    }
    const res: Record<string, unknown> = { label: l, P: rtx.P, endpoint: rtx.endpoint, calldataBytes: rtx.calldata.length, evidenceBytes: ev.length, anatomy: anatomy(unhex(rec.burned!)), estimate, bound: termsOf(shape) };
    if (trace) {
      try {
        const tr = await direct.call<Frame>('debug_traceCall', [{ ...call, gas: `0x${(100_000_000).toString(16)}` }, 'latest', { tracer: 'callTracer' }]);
        res.trace = decompose(tr);
      } catch (e) {
        res.trace = `error: ${String(e).slice(0, 200)}`;
      }
    }
    const t = redeemGasTerms(shape);
    out(`measure-${l}-P${rtx.P}`, res);
    log(`  ${l}: P ${rtx.P}, bound ${t?.limit} (without the reserve ${t ? t.limit - t.reserve : null}), estimate ${estimate}`);
  }
}

async function pay(w: Wallet, label: string): Promise<void> {
  await measure(w, [label], true);
  await redeem(w, label);
  const r = JSON.parse(readFileSync(join(WORK, 'out', `redeem-${label}.json`), 'utf8'));
  out(`pay-${label}`, r);
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  const opt = (name: string): string | undefined => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const valued = new Set(['--units', '--groups']);
  const pos = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && valued.has(args[i - 1])));
  const w = await new Wallet(pos[0]).open();
  switch (cmd) {
    case 'mk': return mk(w, pos[1], Number(pos[2]), BigInt(opt('--units') ?? '1'), Number(opt('--groups') ?? '1'), args.includes('--keys'));
    case 'nest': return nest(w, pos[1], pos[2], pos.slice(3).map(Number));
    case 'consolidate': return consolidateCmd(w, pos[1], pos[2]);
    case 'strip': return strip(w, pos[1], pos[2]);
    case 'judge': return judge(w, pos.slice(1));
    case 'burn': return burnCmd(w, pos[1], args.includes('--permissive'));
    case 'measure': return measure(w, pos.slice(1), args.includes('--trace'));
    case 'pay': return pay(w, pos[1]);
    default: throw new Error(`unknown command ${cmd}`);
  }
}

main().catch((e) => {
  console.error(e instanceof Nb2Error ? `Nb2Error ${e.rule}: ${e.message}` : e instanceof WalletError ? `WalletError ${e.reason}: ${e.message}` : e);
  process.exit(1);
});

void existsSync;
