/**
 * Measurement only (measure/nb2-consolidation): how much proof consolidation and token pre-processing change the cost of a native bridge v2
 * return. It runs like driver.ts (one command per container, this directory at tests/live/nb2lane/ of the bridge image's plug-in checkout,
 * GENERATION/bridge at /work) and reuses driver.ts's wallet and commands. Every result is written to /work/nb2/out/m-<name>.json.
 *
 *   mk W LABEL N                 deposit 1 unit and chain N transfers (one aggregator batch, the rounds it spans), kept as LABEL
 *   consolidate W FROM TO        the SDK's TokenProofClient (lib/consolidation) on FROM, kept as TO; above 256 outer proofs (the SDK's
 *                                one-batch limit) the same rebuild in chunks: one latest batch, the other chunks at its exact root
 *   judge W LABEL...             the wallet preflight on each token: the plug-in's gas model (predict, the inputs planReturn uses) and
 *                                planReturn itself; the token's anatomy (bytes per part, certificates, signatures, path lengths)
 *   burn3 W LABEL [--model permissive]
 *                                burn the consolidated LABELk (planReturn and burn; --model permissive lifts the model's gas bound, never
 *                                the byte bound, so a token past the preflight can still be measured), then three evidence files of the SAME
 *                                burn: raw (LABEL's original proofs + the burn), pre (consolidated before the burn: two seals), post (the burned
 *                                part consolidated again: one seal). Each: the plug-in's and the deployed verifier's verdicts, the verifier's
 *                                gas (eth_estimateGas of verifyReturn) and the vault redeem's (buildRedeem's estimate), or its refusal
 *   pay W LABEL VARIANT          redeem the burn of LABEL live with that variant's evidence (raw, pre or post)
 *                                and trim (post with every seal's signatures beyond the quorum removed)
 *   strip W FROM TO              pre-processing inside the current format: every seal's signatures beyond the quorum removed (validation
 *                                stays complete: the quorum is what the verifier checks)
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
  MeasuredGasModel, Nb2Error, SELECTOR, WalletError, decodeEvidence, decodeToken, encodeToken, evidenceOf, verifyHeld, verifyPart, type RedeemShape,
} from '../../../packages/native-bridge-plugin/src/nb2/index.js';
import { appendTransfer } from '../../../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { encodeProof, type InclusionProof as Nb2Proof, type Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { HU } from '../../../packages/native-bridge-plugin/src/nb2/crypto.js';
import { TAG } from '../../../packages/native-bridge-plugin/src/nb2/config.js';
import { decodeReceiptBacking } from '../../../packages/native-bridge-plugin/src/nb2/deposit.js';
import {
  WORK, Wallet, abiBytes2, cfg, chain, deposit, evidenceFile, hx, lane, log, out as driverOut, pins, predict, redeem, rpc, ruleOf, shapeOf, sleep, solidityVerdict,
  tsVerdict, unhex,
} from './driver.js';
import { RpcError, revertDataOf } from '../../../packages/native-bridge-plugin/src/nb2/index.js';

const out = (name: string, v: unknown): void => driverOut(`m-${name}`, v);
const ms = (t0: number): number => Math.round(performance.now() - t0);

// ---- the SDK side: a verification context the bridge tokens pass ----------------------------------------------------------------------

/**
 * The SDK has no verifier for the bridge's mint justifications (the deposit receipt backing, tag 39051; the split justification, 39044):
 * TokenProofClient verifies the whole token before and after it swaps the proofs, so a wallet must register one. Here they are accepted
 * as given and the plug-in's own lineage check (verifyHeld: the receipt backing under the EVM UC, the split sums, every seal) judges the
 * token before and after consolidation instead. Everything else (every outer inclusion proof, its seal's quorum under the epoch's entry,
 * the predicates and unlocks) is the SDK's stock verification.
 */
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

interface Consolidated { token: Uint8Array; how: string; ms: number; requests: number; summary?: Record<string, unknown>; unavailable?: Record<string, unknown> }

/** The SDK's consolidation of TOKEN (one attempt; the chunked rebuild when the token has more outer proofs than one batch carries). */
async function consolidateBytes(w: Wallet, token: Uint8Array): Promise<Consolidated> {
  const context = sdkContext(w);
  const client = new AggregatorClient(lane.agg);
  const tpc = new TokenProofClient({ routing: ShardRouting.single(client), verificationContext: context });
  const sdk = await SdkToken.fromCBOR(token);
  const t0 = performance.now();
  let r;
  for (let attempt = 0; ; attempt++) {
    try {
      r = await tpc.consolidate(sdk, { timeoutMs: 180_000 });
    } catch (e) {
      if (ConsolidationError.is(e) && e.retryable && attempt < 5) {
        log(`  consolidation: ${e.kind} (${e.message}), again`);
        continue;
      }
      throw e;
    }
    if (r.status === 'unavailable' && r.retryable && attempt < 10) {
      log(`  consolidation unavailable: ${r.reason}, again`);
      await new Promise((ok) => setTimeout(ok, 2000));
      continue;
    }
    break;
  }
  if (r.status === 'consolidated') {
    const s = r.summary;
    return { token: r.token.toCBOR(), how: 'sdk', ms: ms(t0), requests: s.requests, summary: { ...s, masterRound: s.masterRound.toString(), requiredRound: s.requiredRound.toString(), masterShard: s.masterShard.toString() } };
  }
  const unavailable = { reason: r.reason, detail: r.detail, retryable: r.retryable, ms: ms(t0) };
  if (r.reason !== 'limit_exceeded') throw new Error(`consolidation unavailable: ${JSON.stringify(unavailable)}`);
  const c = await chunked(w, sdk, client, context);
  return { ...c, unavailable };
}

/**
 * The consolidation of a token with more than 256 outer proofs (BATCH_MAX_STATE_IDS), which the SDK refuses as limit_exceeded rather than
 * chunk: one latest batch of the newest 256 states names the target certificate (unsharded: the served certificate itself, as the SDK's
 * authenticateDirect), every other chunk is asked at that exact state root, and each proof is rebuilt like ProofConsolidator.replace (the
 * original certification data and reference time, the new path, the one target certificate). The rebuilt token is then verified in full by
 * the SDK (every seal's quorum included) and by the plug-in, so nothing here is trusted: a wrong path or certificate fails verification.
 */
async function chunked(w: Wallet, sdk: SdkToken, client: AggregatorClient, context: VerificationContext): Promise<Consolidated> {
  const t0 = performance.now();
  const outer = [sdk.genesis, ...sdk.transactions].map((x) => x.inclusionProof);
  const sids = await Promise.all(outer.map((p) => StateId.fromCertificationData(p.certificationData)));
  const CH = 256;
  const order: number[][] = [];
  for (let end = sids.length; end > 0; end -= CH) order.push([...Array(Math.min(CH, end)).keys()].map((i) => end - Math.min(CH, end) + i));
  let requests = 0;
  let laterCertificates = 0;
  const replaced: InclusionProof[] = new Array(outer.length);
  let target = null as UnicityCertificate | null;
  let targetBytes = null as Uint8Array | null;
  for (const idx of order) {
    const opts = target === null ? {} : { stateRoot: new DataHash(HashAlgorithm.SHA256, target.inputRecord.nullableHash!) };
    const batch = await client.getInclusionProofs(idx.map((i) => sids[i]), opts as never);
    requests++;
    for (const [k, resp] of batch.proofs.entries()) {
      const p = resp.inclusionProof;
      if (p === null) throw new Error(`chunked: no proof for outer proof ${idx[k]}`);
      const ucb = p.unicityCertificate.toCBOR();
      if (target === null) {
        target = p.unicityCertificate;
        targetBytes = ucb;
      } else if (toHex(ucb) !== toHex(targetBytes!)) {
        // the exact root may be served under a later certificate of the same root (a round without new states): the path is the same
        // root's, so the one target certificate is used, as ProofConsolidator does for its exact-root peers (checkExactRoot)
        if (toHex(p.unicityCertificate.inputRecord.nullableHash!) !== toHex(target.inputRecord.nullableHash!)) {
          throw new Error(`chunked: outer proof ${idx[k]} came under another root (round ${p.unicityCertificate.unicitySeal.rootChainRoundNumber})`);
        }
        laterCertificates++;
      }
      const orig = outer[idx[k]];
      if (p.referenceTime !== orig.referenceTime) throw new Error(`chunked: outer proof ${idx[k]}: another reference time`);
      if (toHex(p.certificationData.toCBOR()) !== toHex(orig.certificationData.toCBOR())) throw new Error(`chunked: outer proof ${idx[k]}: another request`);
      replaced[idx[k]] = new InclusionProof(orig.certificationData, orig.referenceTime, p.inclusionCertificate, target!);
    }
  }
  const bytes = (TokenProofClient as unknown as { replaceOuterProofs(b: Uint8Array, p: InclusionProof[]): Uint8Array }).replaceOuterProofs(sdk.toCBOR(), replaced);
  const rebuilt = await SdkToken.fromCBOR(bytes);
  const v = await rebuilt.verify(context);
  if (v.status !== VerificationStatus.OK) throw new Error(`chunked: the rebuilt token does not verify: ${v.toString().slice(0, 400)}`);
  return { token: bytes, how: 'chunked', ms: ms(t0), requests, summary: { outerProofs: outer.length, sameRootLaterCertificates: laterCertificates, masterRound: target!.unicitySeal.rootChainRoundNumber.toString(), chunks: order.length } };
}

// ---- anatomy: where the bytes and the gas go ------------------------------------------------------------------------------------------

function sigCount(uc: Uint8Array): number | null {
  try {
    const wit = UnicityCertificate.fromCBOR(uc).unicitySeal.witnesses as unknown as Map<unknown, unknown> | null;
    return wit === null ? 0 : wit.size;
  } catch {
    return null;
  }
}

function anatomy(token: Uint8Array): Record<string, unknown> {
  const t = decodeToken(token);
  const proofs: Nb2Proof[] = [t.mintProof, ...t.proofs];
  const ucs = new Map<string, { bytes: number; sigs: number | null; round: string; n: number }>();
  let ucBytes = 0;
  let pathBytes = 0;
  let siblings = 0;
  let minSib = Infinity;
  let maxSib = 0;
  let proofBytes = 0;
  for (const p of proofs) {
    const k = hx(HU(p.uc));
    const e = ucs.get(k);
    if (e) e.n++;
    else ucs.set(k, { bytes: p.uc.length, sigs: sigCount(p.uc), round: UnicityCertificate.fromCBOR(p.uc).unicitySeal.rootChainRoundNumber.toString(), n: 1 });
    ucBytes += p.uc.length;
    pathBytes += p.bitmap.length + 32 * p.siblings.length;
    siblings += p.siblings.length;
    minSib = Math.min(minSib, p.siblings.length);
    maxSib = Math.max(maxSib, p.siblings.length);
    proofBytes += encodeProof(p).length;
  }
  const txBytes = t.transfersRaw.reduce((n, x) => n + x.length, 0);
  let evmUc: number | null = null;
  try {
    if (t.mint.justification !== null) evmUc = decodeReceiptBacking(t.mint.justification).proof.uc.length;
  } catch { /* not a root */ }
  const sigHist: Record<string, number> = {};
  for (const u of ucs.values()) sigHist[String(u.sigs)] = (sigHist[String(u.sigs)] ?? 0) + u.n;
  const n = t.transfers.length;
  return {
    transfers: n, tokenBytes: token.length, evidenceBytes: evidenceOf(token).length, distinctCertificates: ucs.size, proofs: proofs.length,
    ucBytesTotal: ucBytes, ucBytesDistinct: [...ucs.values()].reduce((a, u) => a + u.bytes, 0), ucBytesPerProof: Math.round(ucBytes / proofs.length),
    pathBytesPerProof: Math.round(pathBytes / proofs.length), siblingsPerProof: +(siblings / proofs.length).toFixed(2), siblingsMin: minSib, siblingsMax: maxSib,
    proofBytesPerProof: Math.round(proofBytes / proofs.length), txBytesPerTransfer: n ? Math.round(txBytes / n) : 0,
    bytesPerTransfer: n ? Math.round((token.length - t.mintRaw.length - encodeProof(t.mintProof).length) / n) : 0,
    signaturesPerProof: sigHist, evmUcBytes: evmUc, rounds: [...new Set([...ucs.values()].map((u) => u.round))].length,
  };
}

// ---- commands -------------------------------------------------------------------------------------------------------------------------

async function mk(w: Wallet, label: string, n: number): Promise<void> {
  const t0 = performance.now();
  await deposit(w, label, 1n, undefined);
  const t1 = performance.now();
  const c = await chain(w, label, label, n, false);
  out(`mk-${label}`, { label, transfers: c.transfers, certificates: c.certificates, depositMs: Math.round(t1 - t0), chainMs: ms(t1), anatomy: anatomy(w.token(label)) });
}

async function consolidateCmd(w: Wallet, from: string, to: string): Promise<void> {
  const src = w.token(from);
  const before = anatomy(src);
  const c = await consolidateBytes(w, src);
  // the plug-in's own lineage check on the result, and the same owner, amount and token as the original
  const t1 = performance.now();
  const a = await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(src));
  const b = await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(c.token));
  const pluginMs = ms(t1);
  if (a.amount !== b.amount || toHex(a.tokenId) !== toHex(b.tokenId)) throw new Error('the consolidated token is another token');
  const e = w.entry(from);
  w.keep(to, c.token, e.owner, { amount: e.amount });
  const after = anatomy(c.token);
  out(`consolidate-${to}`, { from, to, how: c.how, ms: c.ms, requests: c.requests, summary: c.summary, unavailable: c.unavailable, pluginVerifyMs: pluginMs, before, after });
  log(`  ${from} -> ${to}: ${c.how} in ${c.ms} ms, ${c.requests} requests; ${before.distinctCertificates} -> ${after.distinctCertificates} certificates, ${before.evidenceBytes} -> ${after.evidenceBytes} evidence bytes`);
}

async function judge(w: Wallet, labels: string[]): Promise<void> {
  const res: Record<string, unknown> = {};
  for (const l of labels) {
    const t = w.token(l);
    const p = await predict(w, t);
    const sh = await shapeOf(t, p.bytes);
    let real: string;
    try {
      await w.bridge.planReturn(t, w.signer.address, w.signer.address);
      real = 'passes';
    } catch (e) {
      real = e instanceof Nb2Error ? `${e.rule}: ${e.message}` : e instanceof WalletError ? `${e.reason}: ${e.message}` : String(e);
    }
    res[l] = { transfers: decodeToken(t).transfers.length, modelGas: p.gas, modelOk: p.ok, need: p.need, preflightBytes: p.bytes, detail: p.detail, planReturn: real, shape: sh.detail, up: sh.up, down: sh.down, anatomy: anatomy(t) };
    log(`  ${l}: ${decodeToken(t).transfers.length} transfers, model gas ${p.gas} (${p.ok ? 'fits' : p.detail}), planReturn ${real}`);
  }
  out(`judge-${labels.join('-')}`, res);
}

/** The deployed verifier's gas on EVIDENCE: eth_estimateGas of verifyReturn(Γ, evidence) (the call alone, its calldata included). */
async function verifierGas(evidence: Uint8Array): Promise<string> {
  const data = abiBytes2(SELECTOR.verifyReturn, pins.gamma, evidence);
  try {
    return await rpc.call<string>('eth_estimateGas', [{ to: lane.verifier, data: hx(data), gas: `0x${(200_000_000).toString(16)}` }, 'latest']).then((g) => BigInt(g).toString());
  } catch (e) {
    return e instanceof RpcError ? `refused: ${ruleOf(revertDataOf(e))} ${e.message.slice(0, 120)}` : `error: ${String(e).slice(0, 160)}`;
  }
}

class Permissive extends MeasuredGasModel {
  public override redeemGasLimit(s: RedeemShape): bigint | null {
    const g = super.redeemGasLimit(s);
    return g !== null && s.pendingTransactions > 0 && g > pins.userGasLimit ? pins.userGasLimit : g;
  }
}

const variants = ['raw', 'pre', 'post', 'trim'] as const;
type Variant = (typeof variants)[number];
const vfile = (label: string, v: Variant): string => evidenceFile(`${label}-${v}`);

async function setBurned(w: Wallet, label: string, burned: Uint8Array): Promise<void> {
  const id = w.entry(`${label}k`).returnId!;
  const rec = await w.bridge.journal.retForUpdate(id);
  if (rec === null) throw new Error('no return record');
  rec.burned = hx(burned);
  await w.bridge.journal.putReturn(rec);
}

async function burn3(w: Wallet, label: string, model?: string): Promise<void> {
  const res: Record<string, unknown> = { label, model: model ?? 'default' };
  const kl = `${label}k`;
  const e = w.entry(kl);
  const tk = w.token(kl);
  const t0 = performance.now();
  let returnId: Uint8Array;
  let pre: Uint8Array;
  const prior = e.returnId ? await w.bridge.journal.ret(e.returnId) : null;
  if (prior !== null && prior.status !== 'planned') {
    // resumed: the burn exists; its first certified form (consolidated before the burn) was kept beside the token
    returnId = unhex(prior.returnId);
    const kept = join(w.dir, 'tokens', `${label}-pre.cbor`);
    pre = existsSync(kept) ? Uint8Array.from(readFileSync(kept)) : Uint8Array.from(readFileSync(vfile(label, 'pre'))).subarray(2);
    res.resumed = prior.status;
  } else {
    const plan = await w.bridge.planReturn(tk, w.signer.address, w.signer.address);
    w.update(kl, { returnId: hx(plan.returnId) });
    const b = await w.bridge.burn(plan.returnId, w.owner(e.owner));
    returnId = plan.returnId;
    pre = b.burned;
    writeFileSync(join(w.dir, 'tokens', `${label}-pre.cbor`), pre);
    res.plan = { a: plan.a, gasLimit: plan.gasLimit, marginSegments: plan.marginSegments };
  }
  res.burnMs = ms(t0);
  const pt = decodeToken(pre);
  const burnTx = pt.transfersRaw[pt.transfersRaw.length - 1];
  const burnProof = encodeProof(pt.proofs[pt.proofs.length - 1]);
  const raw = appendTransfer(w.token(label), burnTx, burnProof);
  const t1 = performance.now();
  const post = await consolidateBytes(w, pre);
  res.postConsolidation = { how: post.how, ms: post.ms, requests: post.requests, consolidateAfterBurnMs: ms(t1) };
  // trim: the post form with every seal's signatures beyond the quorum removed (pre-processing inside the current format)
  const tokens: Record<Variant, Uint8Array> = { raw, pre, post: post.token, trim: stripBytes(post.token) };
  mkdirSync(join(WORK, 'evidence'), { recursive: true });
  const per: Record<string, unknown> = {};
  for (const v of variants) {
    const ev = evidenceOf(tokens[v]);
    writeFileSync(vfile(label, v), ev);
    const ts = await tsVerdict(w, ev);
    // a burn just certified may name a root seal the chain's registry has not imported yet (QuorumNotMet): wait for it, as driver.ts verdicts
    let sol = await solidityVerdict(lane.verifier, pins.gamma, ev);
    const tw = Date.now();
    while (sol.verdict === undefined && ts.verdict !== undefined && /QuorumNotMet/.test(sol.rule ?? '') && Date.now() - tw < 180_000) {
      await sleep(2000);
      sol = await solidityVerdict(lane.verifier, pins.gamma, ev);
    }
    const vg = await verifierGas(ev);
    await setBurned(w, label, tokens[v]);
    let redeemGas: string;
    let calldataBytes: number | null = null;
    try {
      const rtx = await w.bridge.buildRedeem(returnId);
      redeemGas = (rtx.gasLimit - pins.gasReserve).toString();
      calldataBytes = rtx.calldata.length;
    } catch (err) {
      redeemGas = err instanceof Nb2Error ? `refused: ${err.rule} ${err.message.slice(0, 120)}` : `error: ${String(err).slice(0, 160)}`;
    }
    per[v] = { registryWaitMs: Date.now() - tw, file: `evidence/${label}-${v}.cbor`, ts, solidity: sol, equal: ts.verdict !== undefined && ts.verdict === sol.verdict, verifierGas: vg, redeemGas, calldataBytes, anatomy: anatomy(tokens[v]) };
    log(`  ${label} ${v}: ${ev.length} evidence bytes, ${anatomy(tokens[v]).distinctCertificates} certificates; verifier gas ${vg}, redeem gas ${redeemGas}; plug-in ${ts.verdict ? 'accepts' : ts.rule}, verifier ${sol.verdict ? 'accepts' : sol.rule}`);
  }
  await setBurned(w, label, post.token);
  res.variants = per;
  out(`burn3-${label}`, res);
}

async function pay(w: Wallet, label: string, v: Variant): Promise<void> {
  const ev = readFileSync(vfile(label, v));
  await setBurned(w, label, Uint8Array.from(ev.subarray(2)));
  await redeem(w, `${label}k`);
  const r = JSON.parse(readFileSync(join(WORK, 'out', `redeem-${label}k.json`), 'utf8'));
  out(`pay-${label}`, { label, variant: v, ...r });
}

/**
 * Pre-processing inside the current format: drop every seal signature beyond the quorum. The seal's other fields and the signed bytes are
 * unchanged, so the quorum check is as complete as before; the SDK, the plug-in and the verifier count only valid signatures of the epoch's
 * members. The quorum is taken from the trust history's entry of the seal's epoch.
 */
function stripBytes(token: Uint8Array): Uint8Array {
  const t = decodeToken(token);
  const quorum = 3; // 4 root validators of equal weight: 2f + 1 with f = 1 (the lane's trust base; every verifier checks it again)
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

/** strip W FROM TO: stripBytes on a held token, checked by the plug-in. */
async function strip(w: Wallet, from: string, to: string): Promise<void> {
  const src = w.token(from);
  const bytes = stripBytes(src);
  await verifyHeld(cfg, w.bridge.domain, w.trust, decodeToken(bytes));
  const e = w.entry(from);
  w.keep(to, bytes, e.owner, { amount: e.amount });
  out(`strip-${to}`, { from, to, before: anatomy(src), after: anatomy(bytes) });
  log(`  ${from} -> ${to}: ${src.length} -> ${bytes.length} token bytes`);
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  const opt = (name: string): string | undefined => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const pos = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1] === '--model'));
  const model = opt('--model');
  const w = await new Wallet(pos[0]).open(false, model === 'permissive' ? new Permissive() : undefined);
  switch (cmd) {
    case 'mk': return mk(w, pos[1], Number(pos[2]));
    case 'consolidate': return consolidateCmd(w, pos[1], pos[2]);
    case 'judge': return judge(w, pos.slice(1));
    case 'burn3': return burn3(w, pos[1], model);
    case 'pay': return pay(w, pos[1], pos[2] as Variant);
    case 'strip': return strip(w, pos[1], pos[2]);
    default: throw new Error(`unknown command ${cmd}`);
  }
}

main().catch((e) => {
  console.error(e instanceof Nb2Error ? `Nb2Error ${e.rule}: ${e.message}` : e instanceof WalletError ? `WalletError ${e.reason}: ${e.message}` : e);
  process.exit(1);
});
