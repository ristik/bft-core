import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { concat, fromHex, toHex } from './sdk/bytes.js';
import { depositCalldata, redeemCalldata } from './sdk/nb2/abi.js';
import { SdkAggregator } from './sdk/nb2/aggregator.js';
import { ascii, raw, scanNative, u16, u256 } from './sdk/nb2/cbor.js';
import { ASSET_UCT, deriveCoin, deriveType, domainOf, encodeConfig, PRODUCTION_PARAMS, type Config } from './sdk/nb2/config.js';
import { HE, HU } from './sdk/nb2/crypto.js';
import { depositSalt, depositedData, encodeReceiptBacking, firstOwnerOf, rhoOf, TOPIC, verifyReceiptLog } from './sdk/nb2/deposit.js';
import { Nb2Error } from './sdk/nb2/errors.js';
import { LocalKeySigner, signTx } from './sdk/nb2/evm.js';
import { RecoveryAuthority, RecoverySession } from './sdk/nb2/recovery.js';
import { EvmReader, HttpJsonRpc } from './sdk/nb2/rpc.js';
import { genesisHead } from './sdk/nb2/segment.js';
import { burnPredicate, decodeToken, encodeProof, lineageOf, signaturePredicate, valueData } from './sdk/nb2/token.js';
import { appendTransfer, certifyChecked, childMint, localOwner, mintRequest, splitPlan, tokenOfChild, tokenOfMint, transferRequest } from './sdk/nb2/tokenops.js';
import { decodeUc, TrustInput } from './sdk/nb2/trust.js';
import { encodeReturnData, verifyReturn, verifySplit } from './sdk/nb2/verify.js';
import { firstAvailableReceipt, receiptArchive } from './receipt.js';

const [out, rpc, aggregator, chain, artifacts, createTool, keys] = process.argv.slice(2);
const registry = '0xff00000000000000000000000000000000000002';
const funded = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const hex = (raw: Uint8Array) => '0x' + toHex(raw);
const bytes = (value: string) => fromHex(value.trim().replace(/^0x/, ''))!;
const text = (name: string) => readFileSync(join(out, name), 'utf8').trim();
let evidenceDir = out;
const json = (name: string, data: unknown) => writeFileSync(join(evidenceDir, name), JSON.stringify(
  data, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n');
const h = (label: string, ...fields: Uint8Array[]) => HE(HE(ascii('UNICITY/NB2/CONT/1.1/' + label)), ...fields);
const reader = new EvmReader(new HttpJsonRpc(rpc));
const agg = new SdkAggregator(aggregator, { allowInsecure: true });
const signer = new LocalKeySigner(bytes(readFileSync(join(keys, 'send-key'), 'utf8')));
assert.equal(hex(signer.address), funded);

function option(name: string, fallback: number, min: number, max: number) {
  const n = Number(process.env[name] ?? fallback);
  assert(Number.isSafeInteger(n) && n >= min && n <= max, name);
  return n;
}
const transfers = option('NB2_TRANSFERS', 1, 0, 600);
const route = process.env.NB2_ROUTE ?? 'both';
assert(route === 'both' || route === 'recovered', 'NB2_ROUTE');
const depth = route === 'both' ? option('NB2_SPLIT_DEPTH', 1, 1, 20) : option('NB2_SPLIT_DEPTH', 0, 0, 20);
const qualify = process.env.NB2_QUALIFY_COSTS === '1';
const packetMax = option('NB2_PACKET_OPERATIONS', qualify ? 16 : 2, 1, 16);
const receiptReaders = [process.env.NB2_RECEIPT_PRIMARY_RPC ?? rpc, ...(process.env.NB2_RECEIPT_ALT_RPC?.split(',') ?? [])].map((url) => {
  assert.equal(new URL(url).hostname, '127.0.0.1', 'disposable loopback archive required');
  return receiptArchive(new HttpJsonRpc(url, { timeoutMs: 3000, retries: 0 }));
});

function command(name: string, args: string[], input?: string) {
  const r = spawnSync(name, args, { input, encoding: 'utf8', timeout: 180_000, maxBuffer: 8 << 20 });
  if (r.status !== 0) throw new Error(`${name} failed: ${(r.stderr || r.error?.message || r.stdout).slice(-1600)}`);
  return r.stdout.trim();
}
const abi = (signature: string, ...args: string[]) => command('cast', ['abi-encode', signature, ...args]);
const codeHash = async (address: string) => HE(await reader.code(bytes(address)));

interface Receipt {
  status: string; transactionHash: string; blockNumber: string; blockHash: string; transactionIndex: string;
  gasUsed: string; effectiveGasPrice: string; contractAddress: string; logs: { address: string; topics: string[]; data: string }[];
}
async function record(name: string, receipt: Receipt, started: number, signedBytes?: number) {
  assert.equal(receipt.status, '0x1', name);
  signedBytes ??= bytes(await reader.rpc.call<string>('eth_getRawTransactionByHash', [receipt.transactionHash])).length;
  json(name + '.receipt.json', receipt);
  json(name + '.cost.json', { tx: receipt.transactionHash, block: BigInt(receipt.blockNumber),
    gas: BigInt(receipt.gasUsed), effectiveGasPrice: BigInt(receipt.effectiveGasPrice),
    paidFee: BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice), signedBytes, inclusionMs: Date.now() - started });
  return receipt;
}

async function send(name: string, target: string, calldata: Uint8Array, value = 0n) {
  writeFileSync(join(evidenceDir, name + '.calldata'), calldata);
  const started = Date.now();
  const { baseFee, priority } = await reader.fees();
  const nonce = await reader.nonce(signer.address);
  const tx = await signTx(signer, { chainId: BigInt(chain), nonce, maxPriorityFeePerGas: priority,
    maxFeePerGas: baseFee * 2n + priority, gas: 24_000_000n, to: bytes(target), data: calldata, value });
  assert(tx.raw.length <= 524_288, 'signed transaction cap');
  json(name + '.submitted.json', { hash: hex(tx.hash), nonce, gasLimit: 24_000_000n,
    maxFeePerGas: baseFee * 2n + priority, maxPriorityFeePerGas: priority });
  assert.equal(hex(await reader.sendRaw(tx.raw)), hex(tx.hash));
  for (let i = 0; i < 120; ++i) {
    const receipt = await reader.receipt(tx.hash) as Receipt | null;
    if (receipt) return record(name, receipt, started, tx.raw.length);
    await delay(500);
  }
  throw new Error(`no receipt for ${name} ${hex(tx.hash)}`);
}

const pinsFile = JSON.parse(text('pins.json')) as { registryRuntimeKeccak: string; artifactKeccak: Record<string, string[]> };
const artifactBytes = new Map<string, string>();
for (const [name, hashes] of Object.entries(pinsFile.artifactKeccak)) {
  const a = JSON.parse(readFileSync(join(artifacts, name + '.sol', name + '.json'), 'utf8'));
  assert.deepEqual([a.bytecode.object, a.deployedBytecode.object].map((x: string) => hex(HE(bytes(x)))), hashes, name);
  artifactBytes.set(name, hex(bytes(a.bytecode.object)));
}

async function deploy(name: string, args = '0x') {
  const init = artifactBytes.get(name)! + args.slice(2);
  writeFileSync(join(out, name + '.initcode'), bytes(init));
  const started = Date.now();
  const lines = command('python3', [createTool, rpc, keys, name], init).split('\n');
  for (const line of lines.slice(0, -1)) console.log(line);
  const receipt = await record(name, JSON.parse(lines.at(-1)!), started);
  return receipt.contractAddress.toLowerCase();
}

const genesis = await reader.headerByNumber(0n);
assert(genesis);
const executionGenesis = bytes(text('execution.pin'));
assert.equal(hex(genesis.hash), hex(executionGenesis));
assert.equal(await reader.chainId(), BigInt(chain));
assert(await reader.balance(bytes(funded)) > 0n);

const descriptorNames = ['cert-batch-v2', 'rsmt-member-v1', 'registry-layout', 'execution', 'build-index', 'primitive-vectors'];
const descriptor = (name: string) => HU(readFileSync(join(out, 'descriptors', name + '.json')));
const descriptors = descriptorNames.map(descriptor);
const profile = descriptor('semantic-profile');
const receipts = await deploy('FlatReceipts');
const receiptsHash = await codeHash(receipts);
assert.equal(hex(receiptsHash), pinsFile.artifactKeccak.FlatReceipts[1]);
const lineage = await deploy('FlatLineage', abi('f(address)', receipts));
const lineageHash = await codeHash(lineage);
const registryHash = await codeHash(registry);
assert.equal(hex(registryHash), pinsFile.registryRuntimeKeccak);
const ordinary = await deploy('NativeBridgeVerifier11',
  abi('f(address,bytes32,bytes32,bytes32)', lineage, hex(lineageHash), hex(profile), hex(registryHash)));
const ordinaryHash = await codeHash(ordinary);
// One sender, with the recovery construction at nonce n and the vault at n+1.
const vault = command('cast', ['compute-address', '--nonce',
  String(1n + await reader.nonce(bytes(funded), 'latest')), funded]).split(/\s+/).at(-1)!.toLowerCase();
const rootGenesis = bytes(text('trust.pin'));
const chainId = BigInt(chain);
const c: Config = {
  network: 3, rootGenesis, executionGenesis, chainId, evmPartition: 8, evmShard: Uint8Array.of(0x80),
  aggregatorPartition: 7, vault: bytes(vault), asset: ASSET_UCT, ty: deriveType(3, rootGenesis, executionGenesis, chainId),
  aid: deriveCoin(3, rootGenesis, executionGenesis, chainId), semanticProfileHash: profile, verifier: bytes(ordinary),
  verifierCodeHash: ordinaryHash, K: 64n, B: 16n, Qmax: 10n ** 30n,
};
const gamma = encodeConfig(c), domain = domainOf(gamma);
const pinRecord = (role: number, addr: string, digest: Uint8Array) => concat(u16(role), bytes(addr), digest);
const records = concat(
  pinRecord(1, ordinary, ordinaryHash), pinRecord(2, receipts, receiptsHash),
  pinRecord(3, '0000000000000000000000000000000000000100', descriptors[0]),
  pinRecord(4, '0000000000000000000000000000000000000102', descriptors[1]),
  pinRecord(5, registry, h('REGISTRY', registryHash, descriptors[2])), pinRecord(256, lineage, lineageHash));
const release = h('RELEASE', ...descriptors), pins = h('PINS', release, u16(6), records);
const salt = randomBytes(32);
const recovery = await deploy('NativeBridgeRecovery11',
  abi('f(bytes,address,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes32)',
    hex(gamma), ordinary, hex(salt), '(' + descriptors.map(hex).join(',') + ')', hex(pins)));
const recoveryHash = await codeHash(recovery);
assert.equal(await deploy('NativeBridgeVault11', abi('f(bytes,address,bytes32,bytes32)',
  hex(gamma), recovery, hex(recoveryHash), hex(profile))), vault);
const vaultHash = await codeHash(vault);
assert.equal(hex(await reader.vaultConfig(c.vault)), hex(gamma));
writeFileSync(join(out, 'gamma.bin'), gamma);
writeFileSync(join(out, 'pin-records.bin'), records);
json('deployment.json', { chainId, rootGenesis: hex(rootGenesis), executionGenesis: hex(executionGenesis),
  ordinary, recovery, vault, receipts, lineage, registry, profile: hex(profile), release: hex(release),
  salt: hex(salt), pins: hex(pins), domain: hex(domain), creationAndTemplateHashes: pinsFile.artifactKeccak,
  runtimeHashes: { ordinary: hex(ordinaryHash), recovery: hex(recoveryHash), vault: hex(vaultHash),
    receipts: hex(receiptsHash), lineage: hex(lineageHash), registry: hex(registryHash) },
  routes: { rpc, aggregator }, route, transfers, depth, packetMax });
// T6 can exercise its own wallet and load script against this fresh, pinned vault.
if (process.env.NB2_SCENARIO_DRIVER) process.exit(0);

const history = await TrustInput.fromBundle(readFileSync(join(out, 'trust.cbor')), rootGenesis);
const registrySlot = (name: string) => hex(HE(ascii('unicity.seal-registry/' + name)));
async function trustFor(ucs: Uint8Array[]) {
  const round = ucs.map((uc) => decodeUc(uc).unicitySeal.rootChainRoundNumber)
    .reduce((max, n) => n > max ? n : max, 0n);
  for (let i = 0; i < 120; ++i) {
    // The locally enrolled execution client is the authority for this test lane.
    const head = await reader.rpc.call<{ hash: string }>('eth_getBlockByNumber', ['finalized', false]);
    const at = { blockHash: head.hash, requireCanonical: true };
    const readSlot = async (name: string) => BigInt(await reader.rpc.call<string>('eth_getStorageAt', [registry, registrySlot(name), at]));
    const [usableEpoch, rootRound] = await Promise.all([readSlot('origin.rootEpoch'), readSlot('clock.rootRound')]);
    if (usableEpoch > 0n && rootRound >= round) {
      json('origin.json', { blockHash: head.hash, registry, usableEpoch, rootRound });
      return history.withAuthenticatedOrigin({ usableEpoch, rootRound });
    }
    await delay(500);
  }
  throw new Error(`execution origin did not reach certified root round ${round}`);
}

const authenticatedArchives = new Set<EvmReader>();
type ExpectedLog = { topics: Uint8Array[]; data: Uint8Array };
async function certifyReceipt(name: string, receipt: Receipt, emitter: Uint8Array, expected: ExpectedLog) {
  const fields = (log: { address: string; topics: string[]; data: string }) =>
    ({ address: log.address.toLowerCase(), topics: log.topics.map((t) => t.toLowerCase()), data: log.data.toLowerCase() });
  const wanted = { address: hex(emitter), topics: expected.topics.map(hex), data: hex(expected.data) };
  assert.deepEqual(receipt.logs.map(fields), [wanted], name);
  const tx = bytes(receipt.transactionHash);
  const started = Date.now();
  for (let attempt = 0; attempt < 60; ++attempt) {
    const result = await firstAvailableReceipt(receiptReaders, async (archive, source) => {
      if (!authenticatedArchives.has(archive)) {
        const remote = await archive.headerByNumber(0n);
        assert(remote && hex(remote.hash) === hex(executionGenesis), 'archive belongs to another generation');
        authenticatedArchives.add(archive);
      }
      const proof = await archive.receiptProof(tx, emitter, expected.topics[0], true);
      const trust = await trustFor([proof.proof.uc]);
      const log = await verifyReceiptLog(c, trust, proof.proof, emitter);
      assert.deepEqual({ address: hex(log.address), topics: log.topics.map(hex), data: hex(log.data) }, wanted);
      assert.equal(hex(proof.blockHash), receipt.blockHash.toLowerCase());
      assert.equal(proof.proof.txIndex, BigInt(receipt.transactionIndex));
      assert.equal(proof.receiptLogIndex, 0);
      writeFileSync(join(evidenceDir, name + '.cbor'), proof.encoded);
      json(name + '.locator.json', { transactionHash: receipt.transactionHash, blockHash: hex(proof.blockHash),
        blockNumber: proof.blockNumber, transactionIndex: proof.proof.txIndex, receiptLogIndex: proof.receiptLogIndex,
        source, attempts: attempt + 1, acquisitionMs: Date.now() - started, ...wanted });
      return { proof: proof.proof, encoded: proof.encoded, trust };
    });
    if (result) return result;
    await delay(1000);
  }
  throw new Error(`no certified receipt for ${name}`);
}

if (qualify) await runQualificationCosts();
else await runSmoke();

async function runSmoke() {
  const rootOwner = localOwner(randomBytes(32));
  const secret = randomBytes(32), ownerWire = firstOwnerOf(rootOwner.publicKey), rho = rhoOf(domain, secret);
  const ordinaryRecipient = bytes('0000000000000000000000000000000000000011');
  const recoveredRecipient = bytes('0000000000000000000000000000000000000012');
  const baseline = await Promise.all([reader.balance(ordinaryRecipient), reader.balance(recoveredRecipient)]);
  const depositAmount = 100n;
  const dep = await certifyReceipt('deposit', await send('deposit', vault, depositCalldata(ownerWire, rho), depositAmount), c.vault,
    { topics: [TOPIC.Deposited, u256(1)], data: depositedData(domain, depositAmount, rho, ownerWire) });

  async function custody(name: string, population: bigint, outstanding: bigint) {
    const state = await reader.vaultState(c.vault);
    const balance = await reader.balance(c.vault);
    assert.equal(state.deposits, 1n);
    assert.equal(state.segment, 0n);
    assert.equal(state.population, population);
    assert.equal(state.outstanding, outstanding);
    assert.equal(balance, outstanding);
    assert.equal(hex(state.head), hex(genesisHead(domain, c.K)));
    assert.equal(hex(state.previousHead), hex(u256(0)));
    json(name + '.custody.json', { ...state, head: hex(state.head), previousHead: hex(state.previousHead), balance });
  }
  await custody('deposit', 0n, depositAmount);

  type Owner = ReturnType<typeof localOwner>;
  async function spend(token: Uint8Array, owner: Owner, transfer: Parameters<typeof transferRequest>[2]) {
    const request = await transferRequest(token, owner, transfer);
    return appendTransfer(token, request.tx, await certifyChecked(agg, request.cd));
  }
  function trustForToken(token: Uint8Array) {
    const levels = lineageOf(decodeToken(token));
    return trustFor([dep.proof.uc, ...levels.flatMap((l) => [l.mintProof.uc, ...l.proofs.map((p) => p.uc)])]);
  }
  const root = mintRequest({ network: c.network, recipient: signaturePredicate(rootOwner.publicKey),
    salt: depositSalt(domain, 1n, secret), type: c.ty, justification: encodeReceiptBacking({ d: domain, n: 1n, r: secret, proof: dep.proof }),
    data: valueData(c.aid, depositAmount), deadline: null });
  const parent = tokenOfMint(root.tx, await certifyChecked(agg, root.cd));

  async function splitToken(token: Uint8Array, signer: Owner, amounts: bigint[]) {
    const owners = amounts.map(() => localOwner(randomBytes(32)));
    const plan = splitPlan(decodeToken(token), owners.map((owner, i) => ({
      ownerKey: owner.publicKey, amount: amounts[i], salt: randomBytes(32),
    })), c.ty, c.aid, randomBytes(32));
    const burned = await spend(token, signer, plan.burn);
    const verified = await verifySplit(c, domain, await trustForToken(burned), decodeToken(burned));
    const children = [];
    for (const [i, template] of plan.children.entries()) {
      const child = childMint(verified.link, plan.tree, template);
      const mint = mintRequest(child.mint);
      const token = tokenOfChild(burned, child.allocation, mint.tx, await certifyChecked(agg, mint.cd));
      children.push({ token, owner: owners[i] });
    }
    return children;
  }

  async function returned(name: string, part: { token: Uint8Array; owner: Owner }, recipient: Uint8Array, amount: bigint) {
    const data = encodeReturnData({ d: domain, asset: c.asset, recipient, amount, minIndex: 0n });
    const evidence = await spend(part.token, part.owner, { recipient: burnPredicate(HU(data)), mask: randomBytes(32), data, deadline: null });
    const trust = await trustForToken(evidence);
    const verdict = await verifyReturn(gamma, evidence, trust, PRODUCTION_PARAMS);
    assert.equal(verdict.amount, amount);
    assert.equal(hex(verdict.recipient), hex(recipient));
    writeFileSync(join(evidenceDir, name + '.evidence'), evidence);
    return { evidence, verdict, trust, paid: { topics: [TOPIC.Paid, verdict.eta, concat(new Uint8Array(12), recipient)], data: u256(amount) } };
  }

  let recoveredPart = { token: parent, owner: rootOwner };
  let recoveredAmount = depositAmount;
  let ordinaryAmount = 0n;
  if (route === 'both') {
    const [ordinaryPart, otherPart] = await splitToken(parent, rootOwner, [40n, 60n]);
    ordinaryAmount = 40n;
    recoveredPart = otherPart;
    recoveredAmount -= ordinaryAmount;
    const a = await returned('ordinary', ordinaryPart, ordinaryRecipient, ordinaryAmount);
    await certifyReceipt('ordinary', await send('ordinary', vault,
      redeemCalldata(a.evidence, a.verdict.eta, a.verdict.minSegment, new Uint8Array())), c.vault, a.paid);
    await custody('ordinary', 1n, recoveredAmount);
  }
  for (let i = 0; i < transfers; ++i) {
    const next = localOwner(randomBytes(32));
    recoveredPart = { token: await spend(recoveredPart.token, recoveredPart.owner, {
      recipient: signaturePredicate(next.publicKey), mask: randomBytes(32), data: null, deadline: null,
    }), owner: next };
  }
  for (let i = Number(route === 'both'); i < depth; ++i) {
    [recoveredPart] = await splitToken(recoveredPart.token, recoveredPart.owner, [recoveredAmount - 1n, 1n]);
    --recoveredAmount;
  }

  const b = await returned('recovered', recoveredPart, recoveredRecipient, recoveredAmount);
  const result = await executeRecovery(b);
  const remaining = depositAmount - ordinaryAmount - recoveredAmount;
  await custody('recovered', route === 'both' ? 2n : 1n, remaining);
  assert.equal(await reader.balance(ordinaryRecipient), baseline[0] + ordinaryAmount);
  assert.equal(await reader.balance(recoveredRecipient), baseline[1] + recoveredAmount);
  json('result.json', { deposit: depositAmount, ordinary: ordinaryAmount, recovered: recoveredAmount,
    vaultBalance: remaining, ...result, route, transfers, depth, packetMax });
  console.log('PASS NB2 v1.1 deposit and certified payout');
}
type Burn = { evidence: Uint8Array; trust: TrustInput; paid: ExpectedLog };
async function executeRecovery(b: Burn) {
  const authority = new RecoveryAuthority(b.trust, async (next) => json('authority.json', next.origin));
  const session = await RecoverySession.create(gamma, b.evidence, authority, PRODUCTION_PARAMS,
    { salt, recovery: bytes(recovery), runtimeHash: recoveryHash, pins, vaultRuntimeHash: vaultHash });
  let trust = b.trust;
  let prior: { seq: bigint; receipt: Uint8Array } | undefined;
  let from = 0;
  while (from < session.operationCount) {
    let count = Math.min(packetMax, session.operationCount - from);
    let packet;
    for (;;) {
      try {
        packet = await session.run(from, count, trust, prior);
        break;
      } catch (e) {
        if (count === 1 || !(e instanceof Nb2Error && e.rule === 'InputTooLarge'
          && ['run pages', 'cold calldata'].includes(e.detail ?? ''))) throw e;
        --count;
      }
    }
    const seq = (prior?.seq ?? 0n) + 1n;
    const name = 'run-' + seq;
    const cert = await certifyReceipt(name, await send(name, recovery, packet.calldata), bytes(recovery), packet.event);
    await session.verifyEvent(cert.trust, cert.encoded, packet.event);
    if (packet.state) writeFileSync(join(evidenceDir, name + '.state'), packet.state);
    json(name + '.shape.json', packet.shape);
    prior = { seq, receipt: cert.encoded };
    trust = cert.trust;
    from = packet.end;
  }
  assert(prior);
  const payment = await session.gaps('redeemRecovered', trust, prior.receipt, { seq: prior.seq }, []);
  await certifyReceipt('recovered', await send('recovered', vault, payment.calldata), c.vault, b.paid);
  return { session: hex(session.id), packets: prior.seq, operations: session.operationCount };
}

async function runQualificationCosts() {
  const walletCore = await import('./wallet/core.js');
  const originPath = join(out, 'wallet-origin.json');
  const deploymentBlock = Number(BigInt(JSON.parse(text('NativeBridgeVault11.receipt.json')).blockNumber));
  const releasePath = join(out, 'wallet-measurement-input.json');
  json('wallet-measurement-input.json', {
    purpose: 'Test-value workload generation; no qualified return envelope',
    pins: { gamma: hex(gamma), build: 'production', vaultRuntimeCodeHash: hex(vaultHash),
      maxEncodedTxBytes: 524288, userGasLimit: '24000000', gasReserve: '500000',
      returnReserveSegments: 64, deploymentBlock, stateReadOnly: false },
  });
  async function publishOrigin(ucs: Uint8Array[] = []) {
    const trust = await trustFor(ucs);
    writeFileSync(originPath, JSON.stringify(trust.origin, (_, v) => typeof v === 'bigint' ? String(v) : v));
    return trust;
  }
  await publishOrigin();
  const walletAgg = new walletCore.GatewayAggregator(aggregator);
  // Authenticate the execution origin at or beyond each newly certified wallet
  // source before handing that proof to the wallet's normal verification path.
  const advancingAgg = { async certify(cd: Uint8Array) {
    const proof = await walletAgg.certify(cd);
    await publishOrigin([raw(proof, scanNative(proof).kids[0].kids[4])]);
    return proof;
  } };
  // The measurement wallet uses the disposable lane's funded key. Its private state
  // stays in the driver's scratch directory and is removed when the lane stops.
  const wallet = await new walletCore.Wallet(join(keys, 'workload-wallet'), bytes(readFileSync(join(keys, 'send-key'), 'utf8')), {
    release: releasePath, trustBundle: join(out, 'trust.cbor'), trustPin: join(out, 'trust.pin'),
    trustOrigin: originPath, rpc, aggregator,
  }).open({ aggregator: advancingAgg });
  const recipient = bytes('0000000000000000000000000000000000000012');
  const cases = [
    { label: 'split-20', transfers: 0, depth: 20, txTarget: 8, gasTarget: 50_000_000 },
    { label: 'transfer-600', transfers: 600, depth: 0, txTarget: 44, gasTarget: 390_000_000 },
    { label: 'transfer-600-split-1', transfers: 600, depth: 1, txTarget: 46, gasTarget: 395_000_000 },
  ];
  const selected = process.env.NB2_QUALIFY_CASE;
  assert(selected === undefined || cases.some(({ label }) => label === selected), 'NB2_QUALIFY_CASE');
  const failures: { label: string; message: string }[] = [];
  for (const { label, transfers, depth, txTarget, gasTarget } of cases) {
    if (selected && selected !== label) continue;
    evidenceDir = join(out, label);
    mkdirSync(evidenceDir, { mode: 0o700 });
    console.log('Starting', label);
    const start = Date.now();
    const initial = await reader.vaultState(c.vault);
    const initialBalance = await reader.balance(c.vault);
    const recipientBefore = await reader.balance(recipient);
    const value = 100n;
    try {
      const plan = await walletCore.planDeposit(wallet, label, value);
      const deposit = await walletCore.sendDeposit(wallet, label);
      const receipt = await reader.receipt(deposit.txHash) as Receipt;
      const firstOwner = firstOwnerOf(wallet.ownerPub(0));
      const rho = rhoOf(domain, wallet.bridge.secretOf(plan.intent));
      const certified = await certifyReceipt('deposit', await record('deposit', receipt, start),
        c.vault, { topics: [TOPIC.Deposited, u256(deposit.depositNumber)], data: depositedData(domain, value, rho, firstOwner) });
      await publishOrigin([certified.proof.uc]);
      await wallet.refreshAuthority();
      await walletCore.mint(wallet, label);
      let held = label;
      let amount = value;
      if (transfers > 0) {
        let token = wallet.token(held);
        let owner = wallet.entry(held).owner;
        // As in the existing wallet lane, sign batches against the deterministic next
        // state. The placeholder proof is used only for signing. Store and verify
        // only the complete token built with the actual certificates.
        const placeholder = encodeProof(decodeToken(token).mintProof);
        for (let at = 0; at < transfers; at += 16) {
          const requests = [];
          let nextToken = token;
          for (let n = at; n < Math.min(transfers, at + 16); n++) {
            const next = (owner + 1) % 4;
            const request = await transferRequest(nextToken, wallet.owner(owner), {
              recipient: signaturePredicate(wallet.ownerPub(next)), mask: randomBytes(32), data: null, deadline: null,
            });
            requests.push(request);
            nextToken = appendTransfer(nextToken, request.tx, placeholder);
            owner = next;
          }
          await Promise.all(requests.map(({ cd }) => walletAgg.submit(cd)));
          for (const { tx, cd } of requests) token = appendTransfer(token, tx, await walletAgg.proof(cd));
        }
        const nextLabel = label + '-transferred';
        const ucs = tokenUcs(token);
        await publishOrigin(ucs);
        await wallet.refreshAuthority();
        await walletCore.receive(wallet, nextLabel, token, owner);
        wallet.update(held, { spent: 'transferred as ' + nextLabel });
        held = nextLabel;
        console.log(label, 'certified transfers', transfers);
      }
      for (let i = 0; i < depth; i++) {
        const nextLabel = label + '-child-' + i;
        await publishOrigin();
        await wallet.refreshAuthority();
        const [next] = await walletCore.split(wallet, held, 0, [
          { label: nextLabel, amount: amount - 1n }, { label: label + '-sibling-' + i, amount: 1n },
        ]);
        held = nextLabel;
        --amount;
        await publishOrigin(tokenUcs(next));
        await wallet.refreshAuthority();
      }
      console.log(label, 'held lineage ready', wallet.token(held).length);
      // Keep the fail-closed admission result separate from the manually
      // authorised test-value return used to obtain the first measurements.
      try {
        await walletCore.planReturn(wallet, held, recipient);
        json('wallet-admission.json', { accepted: true });
      } catch (error) {
        if (walletCore.reasonOf(error) !== 'CapacityPreflight') throw error;
        json('wallet-admission.json', { accepted: false, detail: String(error) });
      }
      const token = wallet.token(held);
      const data = encodeReturnData({ d: domain, asset: c.asset, recipient, amount, minIndex: 0n });
      const request = await transferRequest(token, wallet.owner(wallet.entry(held).owner), {
        recipient: burnPredicate(HU(data)), mask: randomBytes(32), data, deadline: null,
      });
      const evidence = appendTransfer(token, request.tx, await certifyChecked(agg, request.cd));
      const trust = await publishOrigin(tokenUcs(evidence));
      const verdict = await verifyReturn(gamma, evidence, trust, PRODUCTION_PARAMS);
      assert.equal(verdict.amount, amount);
      assert.equal(hex(verdict.recipient), hex(recipient));
      const levels = lineageOf(decodeToken(evidence));
      json('workload.json', { transfers, depth, flatBytes: evidence.length,
        signedSourceBytes: levels.reduce((sum, l) => sum + l.mintRaw.length +
          l.transfersRaw.reduce((n, tx) => n + tx.length, 0), 0),
        sourceOps: levels.reduce((sum, l) => sum + 1 + l.transfers.length, 0),
        distinctCertificatePresentations: new Set(tokenUcs(evidence).map(uc => hex(HU(uc)))).size,
        generationMs: Date.now() - start, txTarget, gasTarget });
      const paid = { topics: [TOPIC.Paid, verdict.eta, concat(new Uint8Array(12), recipient)], data: u256(amount) };
      const result = await executeRecovery({ evidence, trust, paid });
      const final = await reader.vaultState(c.vault);
      const vaultBalance = await reader.balance(c.vault);
      const recipientAfter = await reader.balance(recipient);
      assert.equal(final.deposits, initial.deposits + 1n);
      assert.equal(final.outstanding, initial.outstanding + value - amount);
      assert.equal(vaultBalance, initialBalance + value - amount);
      assert.equal(recipientAfter, recipientBefore + amount);
      json('result.json', { ...result, paid: amount, liability: final.outstanding, vaultBalance,
        recipientBefore, recipientAfter, elapsedMs: Date.now() - start });
      console.log('Completed', label, result);
    } catch (error) {
      const message = String(error);
      json('error.json', { message, elapsedMs: Date.now() - start });
      failures.push({ label, message });
      console.error(label, error);
    }
  }
  evidenceDir = out;
  json('scenario.json', { failures });
  if (failures.length) throw new Error(failures.map(({ label, message }) => label + ': ' + message).join('\n'));
}

function tokenUcs(token: Uint8Array) {
  return lineageOf(decodeToken(token)).flatMap(l => [l.mintProof.uc, ...l.proofs.map(p => p.uc)]);
}
