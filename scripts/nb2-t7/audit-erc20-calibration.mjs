import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , run, sdk, output] = process.argv;
assert(run && sdk && output, 'usage: node audit-erc20-calibration.mjs RUN SDK_LIB OUTPUT');
const load = (name) => import(pathToFileURL(join(sdk, 'nb2', name + '.js')));
const [{ decodeConfig, domainOf, PRODUCTION_PARAMS }, { decodeDepositProof, verifyReceiptLog, TOPIC },
  { decodeSignedTx }, { HE }, { checkSegmentLog, genesisHead }, { TrustInput }] = await Promise.all(
  ['config', 'deposit', 'evm', 'crypto', 'segment', 'trust'].map(load));
const read = (path) => readFileSync(join(run, path));
const json = (path) => JSON.parse(read(path));
const sha = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value) => '0x' + Buffer.from(value).toString('hex');
const bytes = (value) => Buffer.from(value.trim().replace(/^0x/, ''), 'hex');
const topic = (signature) => hex(HE(Buffer.from(signature)));
const progress = topic('NB2Progress11(bytes32,uint64,bytes32)');
const complete = topic('NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)');
const gap = topic('NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)');
const root = bytes(read('trust.pin').toString());
const gamma = read('fee/gamma.bin');
const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
const domain = domainOf(gamma);
const deployment = json('fee/deployment.json');
assert.equal(hex(domain), deployment.domain);
assert.equal(hex(cfg.vault), deployment.vault);
assert.equal(hex(cfg.executionGenesis), read('execution.pin').toString().trim());
const histories = ['trust.cbor', 'fee/verified-history.cbor', 'fee/load-history.cbor'];
const candidates = await Promise.all(histories.filter((file) => existsSync(join(run, file)))
  .map((file) => TrustInput.fromBundle(read(file), root)));
const trust = candidates.reduce((a, b) => a.history.tip.epoch >= b.history.tip.epoch ? a : b);
const result = json('fee/recovered/offline-result.json');
const archive = json('fee/offline-load/archive-result.json');
const reserve = json('fee/recovered/reserve-observations.json');
const limits = { submittedGas: 24_000_000, calldataBytes: 393_216, signedBytes: 524_288 };

async function receipt(prefix) {
  const encoded = read(prefix + '.cbor');
  const proof = decodeDepositProof(encoded);
  const loc = json(prefix + '.locator.json');
  const log = await verifyReceiptLog(cfg, trust, proof, bytes(loc.address));
  assert.equal(hex(HE(proof.header)), loc.blockHash, prefix);
  assert.equal(log.header.number, BigInt(loc.blockNumber), prefix);
  assert.equal(log.header.timestamp, BigInt(loc.blockTimestamp), prefix);
  assert.equal(proof.txIndex, BigInt(loc.transactionIndex), prefix);
  assert.equal(Number(proof.logIndex), loc.receiptLogIndex, prefix);
  assert.deepEqual(log.topics.map(hex), loc.topics, prefix);
  assert.equal(hex(log.data), loc.data, prefix);
  return { encoded, log, loc };
}

function signed(prefix, loc, gas, to) {
  const raw = read(prefix + '.signed');
  assert.equal(hex(HE(raw)), loc.transactionHash, prefix);
  const { from, request } = decodeSignedTx(raw);
  assert.equal(request.chainId, cfg.chainId, prefix);
  assert.equal(hex(request.to), to, prefix);
  assert(request.gas <= BigInt(limits.submittedGas) && raw.length <= limits.signedBytes &&
    request.data.length <= limits.calldataBytes && gas <= request.gas, prefix);
  return { from, request, raw };
}

async function measuredCall(prefix, kind, to, expectedEvent) {
  const { log, loc } = await receipt(prefix);
  assert.equal(log.topics[0] && hex(log.topics[0]), expectedEvent, prefix);
  const cost = json(prefix + '.cost.json');
  const bid = json(prefix + '.submitted.json');
  const state = json(prefix + '.signing-state.json');
  assert.equal(cost.tx, loc.transactionHash, prefix);
  assert.equal(bid.hash, loc.transactionHash, prefix);
  const gasUsed = BigInt(cost.gas);
  const { from, request, raw } = signed(prefix, loc, gasUsed, to);
  assert.deepEqual(Buffer.from(request.data), read(prefix + '.calldata'), prefix);
  assert.equal(request.gas, BigInt(bid.gasLimit), prefix);
  assert.equal(request.nonce, BigInt(bid.nonce), prefix);
  assert.equal(request.nonce, BigInt(state.pendingNonce), prefix);
  assert.equal(request.maxFeePerGas, BigInt(bid.maxFeePerGas), prefix);
  assert.equal(request.maxPriorityFeePerGas, BigInt(bid.maxPriorityFeePerGas), prefix);
  assert.equal(hex(from), bid.payer, prefix);
  const baseFee = log.header.baseFeePerGas;
  const tip = request.maxPriorityFeePerGas;
  const fullBid = baseFee + tip;
  const effectiveFeePerGas = fullBid < request.maxFeePerGas ? fullBid : request.maxFeePerGas;
  assert.equal(BigInt(cost.effectiveGasPrice), effectiveFeePerGas, prefix);
  assert.equal(BigInt(cost.paidFee), gasUsed * effectiveFeePerGas, prefix);
  const inclusionBlocks = Number(log.header.number - BigInt(state.finalizedBlockNumber));
  assert(Number.isSafeInteger(inclusionBlocks) && inclusionBlocks > 0, prefix);
  return { kind, prefix, txHash: loc.transactionHash, block: Number(log.header.number),
    blockTimestamp: Number(log.header.timestamp), payer: hex(from), nonce: Number(request.nonce),
    submittedGas: Number(request.gas), gasUsed: Number(gasUsed), signedBytes: raw.length,
    calldataBytes: request.data.length, includedBaseFeeWei: String(baseFee), tipWei: String(tip),
    maxFeePerGasWei: String(request.maxFeePerGas), paidFeeWei: cost.paidFee, inclusionBlocks, signingState: state };
}

const runCalls = [];
const count = Number(result.progressCalls);
for (let seq = 1; seq <= count; seq++) {
  const prefix = 'fee/recovered/offline-run-' + seq;
  const call = await measuredCall(prefix, seq === 1 ? 'Start' : 'Resume', deployment.recovery,
    seq === count ? complete : progress);
  const shape = json(prefix + '.shape.json');
  assert.equal(shape.calldataBytes, call.calldataBytes);
  runCalls.push({ ...call, shape });
}
const advances = [];
for (const step of result.advanceCalls) {
  const prefix = 'fee/recovered/' + step.label;
  const call = await measuredCall(prefix, 'AdvanceGaps', deployment.recovery, gap);
  const shape = json(prefix + '.shape.json');
  assert.equal(shape.gaps, step.verifiedGaps);
  assert.equal(shape.calldataBytes, call.calldataBytes);
  advances.push({ ...call, shape });
}
const recovered = await measuredCall('fee/recovered/offline-paid', 'recovered settlement', deployment.vault, hex(TOPIC.Paid));
const ordinary = await measuredCall('fee/ordinary-paid', 'ordinary settlement', deployment.vault, hex(TOPIC.Paid));
const retry = await measuredCall('fee/retry-paid', 'independent ordinary retry', deployment.vault, hex(TOPIC.Paid));
const fail = json('fee/payout-failure.receipt.json');
assert.equal(fail.status, '0x0');
assert(json('fee/payout-failure.custody.json').certifiedFailedReceipt);
const failed = signed('fee/payout-failure', fail, BigInt(fail.gasUsed), deployment.vault);
assert.deepEqual(Buffer.from(failed.request.data), read('fee/retry-paid.calldata'));
assert.notEqual(hex(failed.from), retry.payer);

let head = genesisHead(domain, cfg.K);
const sealTimes = [];
const seals = Number(archive.segments);
for (let i = 0; i < seals; i++) {
  const { log, loc } = await receipt('fee/offline-load/seal-' + i);
  assert.equal(loc.address, deployment.vault);
  assert.equal(loc.topics[0], hex(TOPIC.SegmentSealed));
  assert.equal(BigInt(loc.topics[1]), BigInt(i));
  const prefix = 'fee/offline-load/load-' + (i * Number(cfg.K) + Number(cfg.K) - 1);
  const cost = json(prefix + '.cost.json');
  assert.equal(cost.tx, loc.transactionHash);
  signed(prefix, loc, BigInt(cost.gas), deployment.vault);
  head = checkSegmentLog(domain, cfg.K, BigInt(i), head, log.data).after;
  sealTimes.push(Number(log.header.timestamp));
}
assert.equal(hex(head), archive.head);
assert.equal(hex(head), result.head);
assert.equal(result.finalBacklog, 0);
const exercisedReserve = seals >= result.initialBacklog + 64;

const window = (prefix) => {
  const row = json('fee/recovered/' + prefix + '.window.json');
  const { startMs, endMs } = row;
  const arrivals = Number(BigInt(row.endSegment) - BigInt(row.startSegment));
  assert(Number.isSafeInteger(arrivals) && arrivals >= 0 && endMs >= startMs, prefix);
  return { ...row, elapsedMs: endMs - startMs, arrivals };
};
const checkpoint = window('checkpoint-phase'), restored = window('resume-phase');
const final = window('final-settlement');
assert.equal(Number(final.endSegment), seals);
const finalEndpointToInclusionSeconds = recovered.blockTimestamp - sealTimes.at(-1);
assert(finalEndpointToInclusionSeconds >= 0);
const q = Math.max(...result.advanceCalls.map((a) => a.verifiedGaps));
assert.equal(q, 3);
const b = Math.max(...result.advanceCalls.map((a) => Number(a.arrivedDuringCall)));
const samples = result.advanceCalls.map((a) => a.proofMs).sort((a, b) => a - b);
const tauP99Ms = samples[Math.ceil(samples.length * 0.99) - 1];
const peakSeals30s = Math.max(...sealTimes.map((t) => sealTimes.filter((j) => j >= t && j < t + 30).length));
const peakSealsPerSecond = peakSeals30s / 30;
const mostSealsInSampledFinalWindow = Math.max(...sealTimes.map(
  (t) => sealTimes.filter((j) => j >= t && j <= t + finalEndpointToInclusionSeconds).length));
const duringProgress = Number(BigInt(restored.endSegment) - BigInt(checkpoint.startSegment));
const allAdvancesShrankBacklog = result.advanceCalls.every(
  (call) => BigInt(call.beforeBacklog) > BigInt(call.afterBacklog));
const observedCatchUp = q > b && q * 1000 * 30 >= 2 * peakSeals30s * tauP99Ms && allAdvancesShrankBacklog;

const path = [...runCalls, ...advances, recovered];
const payer = path[0].payer;
assert(path.every((call, i) => call.payer === payer && call.nonce === i));
assert(reserve.throughPayout.calls.length === path.length);
const bidAmounts = path.map((call) => BigInt(call.submittedGas) * BigInt(call.maxFeePerGasWei));
const exposure = bidAmounts.reduce((sum, bid) => sum + bid, 0n);
assert.equal(exposure, BigInt(reserve.throughPayout.upperBids));
assert.equal(path.reduce((sum, call) => sum + BigInt(call.paidFeeWei), 0n), BigInt(reserve.throughPayout.observedFees));
let remainingExposure = exposure;
const everySignatureFundedObservedPath = path.every(({ signingState }, index) => {
  const funded = remainingExposure <= BigInt(signingState.pendingBalance) &&
    remainingExposure <= BigInt(signingState.finalizedBalance);
  remainingExposure -= bidAmounts[index];
  return funded;
});
const max = (items) => items.reduce((a, b) => a > b ? a : b);
const inclusionSamples = [...path, ordinary, retry];
const maxInclusionBlocks = Math.max(...inclusionSamples.map((call) => call.inclusionBlocks));
const tip = max(inclusionSamples.map((call) => BigInt(call.tipWei)));
const boundBaseFee = (base, blocks) => {
  assert(Number.isSafeInteger(blocks) && blocks >= 0);
  for (let i = 0; i < blocks; i++) base += max([1n, base / 8n]);
  return base;
};
const candidateFee = boundBaseFee(
  max(inclusionSamples.map((call) => BigInt(call.signingState.finalizedBaseFee))), maxInclusionBlocks) + tip;
const coversSampledInclusion = inclusionSamples.every((call) => candidateFee >= BigInt(call.includedBaseFeeWei) + BigInt(call.tipWei));
const backlogAtProgressStart = Number(checkpoint.startSegment);
const d = backlogAtProgressStart + 64 + duringProgress;
const n = q > b ? Math.ceil(d / (q - b)) : null;
const candidateBudget = 10n ** 18n;
const candidateMaxNonce = 255;
const ordinaryAttempts = 2;
const recoveryCalls = n === null ? null : runCalls.length + n + 1;
const nonceCount = recoveryCalls === null ? null : recoveryCalls + ordinaryAttempts;
const perCall = candidateFee * BigInt(limits.submittedGas);
const recoveryCeiling = recoveryCalls === null ? null : BigInt(recoveryCalls) * perCall;
const ordinaryCeiling = BigInt(ordinaryAttempts + 1) * perCall;
const reserveCeiling = recoveryCeiling === null ? null : BigInt(nonceCount) * perCall;
const initial = path[0].signingState;
const observedPathBlocks = recovered.block - Number(initial.finalizedBlockNumber);
const fullPathFeeAtFullBlocks = boundBaseFee(BigInt(initial.finalizedBaseFee), observedPathBlocks) + tip;

writeFileSync(output, JSON.stringify({
  scope: 'Private lane observations and candidate reserve arithmetic',
  fundingQualified: false,
  chainId: String(cfg.chainId), executionGenesis: hex(cfg.executionGenesis), rootPin: hex(root), deployment,
  build: json('descriptors/erc20-build-index.json'), harnessRevision: read('builds.txt').toString().split('\n')[0],
  lanePins: json('pins.json'),
  releaseProfileSha256: sha(read('descriptors/semantic-profile-erc20.json')),
  slot: Number(read('slot.txt').toString()), limits,
  calls: { run: runCalls, advances, recovered, ordinary, retry, failed: {
    payer: hex(failed.from), gasUsed: Number(BigInt(fail.gasUsed)), signedBytes: failed.raw.length,
    calldataBytes: failed.request.data.length, submittedGas: Number(failed.request.gas), separatePayer: true,
  } },
  arrivals: { seals, initialBacklog: result.initialBacklog, q, b, tauP99Ms, sampleCount: samples.length,
    peakSeals30s, peakSealsPerSecond, duringProgress, finalEndpointToInclusionSeconds, mostSealsInSampledFinalWindow, final,
    observedCatchUp, exercisedReserve, allAdvancesShrankBacklog, backlogAtProgressStart,
    run: runCalls.map((call) => window(call.prefix.split('/').at(-1))),
    restore: window('restore'), checkpoint, resumed: restored, ordinaryBeforeFallbackExercised: false },
  funding: { payer, observedMaximumSignedExposureWei: String(exposure), candidateFeeWei: String(candidateFee),
    everySignatureFundedObservedPath, observedPaidFeesWei: reserve.throughPayout.observedFees,
    maxInclusionBlocks, coversSampledInclusion, tipWei: String(tip), d, n, ordinaryAttempts, nonceCount, candidateMaxNonce,
    observedPathBlocks, fullPathFeeAtFullBlocksWei: String(fullPathFeeAtFullBlocks),
    candidateBudgetWei: String(candidateBudget), signingState: initial,
    recoveryCeilingWei: recoveryCeiling?.toString() ?? null, ordinaryCeilingWei: String(ordinaryCeiling),
    reserveCeilingWei: reserveCeiling?.toString() ?? null,
    replacementCeilingPerNonceWei: String(perCall),
    passesCandidate: coversSampledInclusion && reserveCeiling !== null && reserveCeiling <= candidateBudget &&
      reserveCeiling <= BigInt(initial.pendingBalance) && reserveCeiling <= BigInt(initial.finalizedBalance) &&
      BigInt(initial.pendingNonce) + BigInt(nonceCount) <= BigInt(candidateMaxNonce + 1) },
}, null, 2) + '\n');
