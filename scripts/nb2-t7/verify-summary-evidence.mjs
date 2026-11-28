// Offline evidence checks using the freshly rebuilt, revision-pinned SDK.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [root, sdk] = process.argv.slice(2);
const load = name => import(pathToFileURL(join(sdk, 'nb2', name + '.js')).href);
const { decodeConfig, PRODUCTION_PARAMS } = await load('config');
const { decodeDepositProof, verifyReceiptLog } = await load('deposit');
const { decodeSignedTx } = await load('evm');
const { HE } = await load('crypto');
const { mptVerify } = await load('mpt');
const { rlpIndexKey } = await load('rlp');
const { encodeReceiptJson } = await load('rpc');
const { TrustInput } = await load('trust');

const read = path => JSON.parse(readFileSync(path, 'utf8'));
const hex = data => '0x' + Buffer.from(data).toString('hex');
const bytes = value => {
  assert.match(value, /^0x(?:[\da-f]{2})+$/i);
  return Buffer.from(value.slice(2), 'hex');
};
const sameBytes = (a, b) => assert(Buffer.from(a).equals(b), 'bytes do not match');
const verified = {};

async function verify(path, check) {
  try {
    verified[path] = await check();
  } catch (error) {
    if (error.code !== 'ENOENT') console.error(`${path}: ${error.message}`);
  }
}

async function proofContext(dir) {
  const pin = bytes(readFileSync(join(root, 'trust.pin'), 'utf8').trim());
  const config = decodeConfig(readFileSync(join(dir, 'gamma.bin')), PRODUCTION_PARAMS);
  assert.equal(hex(config.rootGenesis), hex(pin));
  assert.equal(hex(config.executionGenesis), readFileSync(join(root, 'execution.pin'), 'utf8').trim());
  let trust;
  for (const path of [join(root, 'trust.cbor'), join(dir, 'verified-history.cbor'), join(dir, 'load-history.cbor')]) {
    if (!existsSync(path)) continue;
    const candidate = await TrustInput.fromBundle(readFileSync(path), pin);
    if (!trust || candidate.history.tip.epoch > trust.history.tip.epoch) trust = candidate;
  }
  assert(trust, 'missing trust history');
  return { config, trust };
}

async function certify(path, receipt, { config, trust }, expectedEmitter) {
  const locator = read(path + '.locator.json');
  const proof = decodeDepositProof(readFileSync(path + '.cbor'));
  const log = await verifyReceiptLog(config, trust, proof, expectedEmitter ?? bytes(locator.address));
  assert.equal(hex(log.address), locator.address);
  assert.deepEqual(log.topics.map(hex), locator.topics);
  assert.equal(hex(log.data), locator.data);
  assert.equal(hex(HE(proof.header)), locator.blockHash);
  assert.equal(receipt.blockHash, locator.blockHash);
  assert.equal(receipt.transactionHash, locator.transactionHash);
  assert.equal(proof.txIndex, BigInt(locator.transactionIndex));
  assert.equal(proof.txIndex, BigInt(receipt.transactionIndex));
  assert.equal(proof.logIndex, BigInt(locator.receiptLogIndex));
  assert.equal(log.header.number, BigInt(locator.blockNumber));
  assert.equal(log.header.number, BigInt(receipt.blockNumber));
  assert.equal(log.header.timestamp, BigInt(locator.blockTimestamp));
  const receiptBytes = mptVerify(log.header.receiptsRoot, rlpIndexKey(proof.txIndex), proof.nodes);
  sameBytes(receiptBytes, encodeReceiptJson(receipt));
  return { header: log.header, locator };
}

function transaction(path, receipt, chainId) {
  const raw = readFileSync(path + '.signed');
  const { request, from, hash } = decodeSignedTx(raw);
  assert.equal(hex(hash), receipt.transactionHash);
  assert.equal(request.chainId, chainId);
  assert.equal(hex(from), receipt.from.toLowerCase());
  assert.equal(hex(request.to), receipt.to.toLowerCase());
  assert.equal(receipt.status, '0x1');
  sameBytes(request.data, readFileSync(path + '.calldata'));
  return { request, payer: hex(from) };
}

async function certifiedCall(path, context, emitter, signed) {
  await verify(path, async () => {
    const receipt = read(path + '.receipt.json');
    const { header, locator } = await certify(path, receipt, context, emitter);
    if (!signed) return { tx: receipt.transactionHash, locator };
    const { request, payer } = transaction(path, receipt, context.config.chainId);
    assert.equal(hex(request.to), locator.address);
    assert.equal(request.value, 0n);
    assert(request.maxFeePerGas >= header.baseFeePerGas && request.maxFeePerGas >= request.maxPriorityFeePerGas);
    const combined = header.baseFeePerGas + request.maxPriorityFeePerGas;
    const effective = combined < request.maxFeePerGas ? combined : request.maxFeePerGas;
    assert.equal(effective, BigInt(receipt.effectiveGasPrice));
    const used = BigInt(receipt.gasUsed), cumulative = BigInt(receipt.cumulativeGasUsed);
    assert(used > 0n && used <= request.gas && used <= cumulative);
    if (BigInt(receipt.transactionIndex) === 0n) assert.equal(used, cumulative);
    return { tx: receipt.transactionHash, locator, payer, nonce: String(request.nonce),
      paidFee: String(used * effective), upperBid: String(request.gas * request.maxFeePerGas) };
  });
}

for (const asset of ['', 'plain', 'fee']) {
  const dir = join(root, asset);
  if (!existsSync(join(dir, 'gamma.bin'))) continue;
  let context;
  try {
    context = await proofContext(dir);
  } catch (error) {
    console.error(`${dir}: ${error.message}`);
    continue;
  }
  if (!asset) {
    for (const name of ['ordinary', 'recovered']) {
      await certifiedCall(join(dir, name), context, context.config.vault, false);
    }
    continue;
  }

  const fund = join(dir, 'fund-relayer');
  await verify(fund, () => {
    const receipt = read(fund + '.receipt.json');
    const { request } = transaction(fund, receipt, context.config.chainId);
    assert.equal(request.data.length, 0);
    assert(request.value > 0n);
    return { tx: receipt.transactionHash, recipient: hex(request.to), value: String(request.value) };
  });
  for (const name of ['ordinary-paid', 'retry-paid', 'recovered/offline-paid']) {
    await certifiedCall(join(dir, name), context, context.config.vault, true);
  }
  const recovered = join(dir, 'recovered');
  if (existsSync(recovered)) {
    for (const file of readdirSync(recovered)) {
      if (/^offline-(run|advance)-\d+\.locator\.json$/.test(file)) {
        await certifiedCall(join(recovered, file.slice(0, -'.locator.json'.length)), context, undefined, true);
      }
    }
  }
}
process.stdout.write(JSON.stringify(verified));
