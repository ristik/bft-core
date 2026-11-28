import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { concat, fromHex, toHex } from './sdk/bytes.js';
import { abiEncode, depositCalldata, redeemCalldata } from './sdk/nb2/abi.js';
import { SdkAggregator } from './sdk/nb2/aggregator.js';
import { ascii, cBytes, head, raw, scanNative, u16, u256 } from './sdk/nb2/cbor.js';
import { ASSET_UCT, decodeConfig, deriveCoin, deriveType, domainOf, encodeConfig, PRODUCTION_PARAMS, type Config } from './sdk/nb2/config.js';
import { HE, HU } from './sdk/nb2/crypto.js';
import { decodeDepositProof, decodeReceiptBacking, depositSalt, depositedData, encodeReceiptBacking, firstOwnerOf, rhoOf, TOPIC, verifyReceiptLog } from './sdk/nb2/deposit.js';
import { Nb2Error, WalletError } from './sdk/nb2/errors.js';
import { LocalKeySigner, signTx } from './sdk/nb2/evm.js';
import { RecoveryAuthority, RecoverySession } from './sdk/nb2/recovery.js';
import { EvmReader, HttpJsonRpc, RpcError } from './sdk/nb2/rpc.js';
import { checkSegmentLog, encodeHistory, GapTree, genesisHead, nextHead, type Segment } from './sdk/nb2/segment.js';
import { burnPredicate, decodeToken, encodeProof, encodeToken, lineageOf, stateId, signaturePredicate, valueData } from './sdk/nb2/token.js';
import { appendTransfer, certifyChecked, childMint, headOf, localOwner, mintRequest, splitPlan, tokenOfChild, tokenOfMint, transferRequest } from './sdk/nb2/tokenops.js';
import { decodeUc, TrustInput } from './sdk/nb2/trust.js';
import { burnTransitionId, encodeReturnData, redemptionId, verifyReturn, verifySplit } from './sdk/nb2/verify.js';
import { firstAvailableReceipt, receiptArchive } from './receipt.js';

const [laneOut, rpc, aggregator, chain, artifacts, createTool, keys] = process.argv.slice(2);
const erc20Mode = process.env.NB2_ERC20_MODE;
const erc20 = erc20Mode === 'plain' || erc20Mode === 'fee';
const releaseCalibration = erc20Mode === 'fee' && process.env.NB2_ERC20_CALIBRATE === '1';
const out = erc20 ? join(laneOut, erc20Mode) : laneOut;
const resumeStage = process.env.NB2_RESUME_STAGE;
const offline = process.env.NB2_QUALIFY_OFFLINE === '1';
const registry = '0xff00000000000000000000000000000000000002';
const funded = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const hex = (raw: Uint8Array) => '0x' + toHex(raw);
const bytes = (value: string) => fromHex(value.trim().replace(/^0x/, ''))!;
const text = (name: string) => readFileSync(join(laneOut, name), 'utf8').trim();
let evidenceDir = out;
const json = (name: string, data: unknown) => writeFileSync(join(evidenceDir, name), JSON.stringify(
  data, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n');
const h = (label: string, ...fields: Uint8Array[]) => HE(HE(ascii('UNICITY/NB2/CONT/1.1/' + label)), ...fields);
const reader = new EvmReader(new HttpJsonRpc(rpc));
const agg = new SdkAggregator(aggregator, { allowInsecure: true });
const keyFile = resumeStage === 'load' ? 'load-key' : resumeStage ? 'relayer-key' : erc20 ? 'holder-key' : 'send-key';
const signer = new LocalKeySigner(bytes(readFileSync(join(keys, keyFile), 'utf8')));
if (!resumeStage && !erc20) assert.equal(hex(signer.address), funded);

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
const qualifyCustody = process.env.NB2_QUALIFY_CUSTODY === '1';
const archiveSegments = option('NB2_ARCHIVE_SEGMENTS', 2, 2, 4096);
const peakRestore = process.env.NB2_OFFLINE_PEAK === '1';
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
const callData = (signature: string, ...args: string[]) => bytes(command('cast', ['calldata', signature, ...args]));
const codeHash = async (address: string) => HE(await reader.code(bytes(address)));

type Receipt = NonNullable<Awaited<ReturnType<EvmReader['receipt']>>> & { effectiveGasPrice: string; contractAddress?: string };
async function record(name: string, receipt: Receipt, started: number, signedBytes?: number, expectedStatus: string | null = '0x1') {
  if (expectedStatus !== null) assert.equal(receipt.status, expectedStatus, name);
  else assert(['0x0', '0x1'].includes(receipt.status), name);
  assert(receipt.gasUsed, name + ' gasUsed');
  if (erc20Mode || signedBytes === undefined) {
    const raw = erc20Mode
      ? await reader.rpc.call<string>('eth_getRawTransactionByBlockHashAndIndex', [receipt.blockHash, receipt.transactionIndex])
      : await reader.rpc.call<string>('eth_getRawTransactionByHash', [receipt.transactionHash]);
    const wire = bytes(raw);
    if (signedBytes !== undefined) assert.equal(signedBytes, wire.length);
    assert.equal(hex(HE(wire)), receipt.transactionHash.toLowerCase());
    signedBytes = wire.length;
    if (erc20Mode) writeFileSync(join(evidenceDir, name + '.signed'), wire);
  }
  json(name + '.receipt.json', receipt);
  json(name + '.cost.json', { tx: receipt.transactionHash, block: BigInt(receipt.blockNumber),
    blockHash: receipt.blockHash, transactionIndex: BigInt(receipt.transactionIndex),
    gas: BigInt(receipt.gasUsed), effectiveGasPrice: BigInt(receipt.effectiveGasPrice),
    paidFee: BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice), signedBytes, inclusionMs: Date.now() - started });
  return receipt;
}

async function send(name: string, target: string, calldata: Uint8Array, value = 0n,
  expectedStatus: string | null = '0x1', payer = signer, gas = 24_000_000n, requiredEpoch?: bigint) {
  writeFileSync(join(evidenceDir, name + '.calldata'), calldata);
  const importGate = requiredEpoch === undefined ? undefined : await waitForImport(requiredEpoch);
  const estimate = erc20Mode && expectedStatus === '0x1'
    ? await reader.estimateGas({ from: payer.address, to: bytes(target), data: calldata, value }) : undefined;
  if (estimate) assert('gas' in estimate && estimate.gas <= gas, name + ': ' + JSON.stringify(estimate, (_, v) => typeof v === 'bigint' ? String(v) : v));
  const started = Date.now();
  const { baseFee, priority } = await reader.fees();
  const nonce = await reader.nonce(payer.address);
  const signingState = releaseCalibration && /^(offline-|ordinary-paid$|payout-failure$|retry-paid$)/.test(name)
    ? await payerSigningState(payer.address, baseFee, nonce) : undefined;
  const tx = await signTx(payer, { chainId: BigInt(chain), nonce, maxPriorityFeePerGas: priority,
    maxFeePerGas: baseFee * 2n + priority, gas, to: bytes(target), data: calldata, value });
  assert(tx.raw.length <= 524_288, 'signed transaction cap');
  json(name + '.submitted.json', { hash: hex(tx.hash), nonce, gasLimit: gas, payer: hex(payer.address),
    maxFeePerGas: baseFee * 2n + priority, maxPriorityFeePerGas: priority, importGate,
    estimatedGas: estimate && 'gas' in estimate ? estimate.gas : undefined });
  if (signingState) json(name + '.signing-state.json', { ...signingState, submittedAtMs: Date.now() });
  assert.equal(hex(await reader.sendRaw(tx.raw)), hex(tx.hash));
  for (let i = 0; i < 120; ++i) {
    const receipt = await reader.receipt(tx.hash) as Receipt | null;
    if (receipt) return record(name, receipt, started, tx.raw.length, expectedStatus);
    await delay(500);
  }
  throw new Error(`no receipt for ${name} ${hex(tx.hash)}`);
}

async function payerSigningState(payer: Uint8Array, quotedBaseFee: bigint, pendingNonce: bigint) {
  const block = await reader.rpc.call<{ hash: string; number: string; baseFeePerGas: string }>(
    'eth_getBlockByNumber', ['finalized', false]);
  const number = BigInt(block.number);
  const [finalizedBalance, finalizedNonce, pendingBalance] = await Promise.all([
    reader.balance(payer, number), reader.nonce(payer, number), reader.balance(payer, 'pending'),
  ]);
  return { finalizedBlock: block.hash, finalizedBlockNumber: number, finalizedBaseFee: BigInt(block.baseFeePerGas),
    finalizedBalance, finalizedNonce, pendingBalance, pendingNonce, quotedBaseFee };
}

async function startCalibrationWindow() {
  if (releaseCalibration) return { startMs: Date.now(), startSegment: (await reader.vaultState(c.vault)).segment };
}

async function finishCalibrationWindow(name: string, start: Awaited<ReturnType<typeof startCalibrationWindow>>) {
  if (!start) return;
  const endSegment = (await reader.vaultState(c.vault)).segment;
  json(name + '.window.json', { ...start, endMs: Date.now(), endSegment });
}

const pinsFile = JSON.parse(text('pins.json')) as { registryRuntimeKeccak: string; artifactKeccak: Record<string, string[]> };
const artifactBytes = new Map<string, string>();
for (const [name, hashes] of Object.entries(erc20Mode ? {} : pinsFile.artifactKeccak)) {
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
  assert(receipt.contractAddress, name);
  return receipt.contractAddress.toLowerCase();
}

const genesis = await reader.headerByNumber(0n);
assert(genesis);
const executionGenesis = bytes(text('execution.pin'));
assert.equal(hex(genesis.hash), hex(executionGenesis));
assert.equal(await reader.chainId(), BigInt(chain));
assert(await reader.balance(bytes(funded)) > 0n);

const chainId = BigInt(chain);
if (erc20Mode === 'deploy') {
  await deployErc20Graphs();
  process.exit(0);
}
const { c, gamma, domain, salt, pins, vault, vaultHash, recovery, recoveryHash, rootGenesis } =
  resumeStage || erc20 ? loadGraph() : await deployGraph();
const tokenAddress = c.erc20 && hex(c.erc20.token);

async function deployGraph() {
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
  return { c, gamma, domain, salt, pins, vault, vaultHash, recovery, recoveryHash, rootGenesis };
}

function loadGraph() {
  const deployment = JSON.parse(readFileSync(join(out, 'deployment.json'), 'utf8'));
  const gamma = readFileSync(join(out, 'gamma.bin'));
  const c = decodeConfig(gamma, PRODUCTION_PARAMS);
  return { c, gamma, domain: domainOf(gamma), salt: bytes(deployment.salt), pins: bytes(deployment.pins),
    vault: deployment.vault as string, vaultHash: bytes(deployment.runtimeHashes.vault),
    recovery: deployment.recovery as string, recoveryHash: bytes(deployment.runtimeHashes.recovery), rootGenesis: c.rootGenesis };
}

async function deployErc20Graphs() {
  const { ERC20_PROFILE_HASH } = await import('./sdk/nb2/bridge.js');
  const uct = JSON.parse(text('deployment.json'));
  const build = process.env.NB2_ERC20_ARTIFACTS!;
  const tokenArtifact = process.env.NB2_ERC20_TOKEN_ARTIFACT!;
  const graphDir = join(laneOut, 'erc20-graph');
  mkdirSync(graphDir);
  evidenceDir = graphDir;
  for (const name of ['ERC20FlatLineage', 'ERC20BridgeVerifier', 'ERC20BridgeFactory',
    'ERC20BridgeVault', 'ERC20BridgeRecovery', 'QualificationToken']) {
    const file = name === 'QualificationToken' ? tokenArtifact : join(build, name + '.sol', name + '.json');
    const artifact = JSON.parse(readFileSync(file, 'utf8'));
    artifactBytes.set(name, hex(bytes(artifact.bytecode.object)));
    json(name + '.artifact.json', {
      artifactSha256: hex(HU(readFileSync(file))), template: hex(HE(bytes(artifact.bytecode.object))),
      runtimeTemplate: hex(HE(bytes(artifact.deployedBytecode.object))),
    });
  }
  async function create(name: string, args: string, label = name) {
    const init = artifactBytes.get(name)! + args.slice(2);
    writeFileSync(join(graphDir, label + '.initcode'), bytes(init));
    const started = Date.now();
    const lines = command('python3', [createTool, rpc, keys, label], init).split('\n');
    const r = await record(label, JSON.parse(lines.at(-1)!), started);
    assert(r.contractAddress, label);
    return r.contractAddress.toLowerCase();
  }
  const lineage = await create('ERC20FlatLineage', abi('f(address)', uct.receipts));
  const profile = '0x' + ERC20_PROFILE_HASH;
  const ordinary = await create('ERC20BridgeVerifier',
    abi('f(address,bytes32,bytes32,bytes32)', lineage, hex(await codeHash(lineage)), profile, uct.runtimeHashes.registry));
  const descriptors = ['cert-batch-v2', 'rsmt-member-v1', 'registry-layout', 'execution', 'erc20-build-index', 'primitive-vectors']
    .map(name => hex(HU(readFileSync(join(laneOut, 'descriptors', name + '.json')))));
  const generation = hex(randomBytes(32));
  const vaultCode = artifactBytes.get('ERC20BridgeVault')!;
  const recoveryCode = artifactBytes.get('ERC20BridgeRecovery')!;
  const vaultInitcodeHash = hex(HE(bytes(vaultCode)));
  const recoveryInitcodeHash = hex(HE(bytes(recoveryCode)));
  const factory = await create('ERC20BridgeFactory', abi(
    'f((uint16,bytes32,bytes32,uint32,bytes,uint32,uint144),(address,bytes32,bytes32,bytes32,bytes32,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)))',
    `(3,${uct.rootGenesis},${uct.executionGenesis},8,0x80,7,${10n ** 30n})`,
    `(${ordinary},${hex(await codeHash(ordinary))},${profile},${generation},${vaultInitcodeHash},${recoveryInitcodeHash},(${descriptors.join(',')}))`,
  ));
  const factoryRuntimeHash = hex(await codeHash(factory));
  const assets = [];
  for (const kind of ['plain', 'fee']) {
    const token = await create('QualificationToken', abi('f(bool)', String(kind === 'fee')), kind + '-token');
    evidenceDir = join(laneOut, kind);
    mkdirSync(evidenceDir);
    const activation = await send('activation', factory, callData('activate(address,bytes,bytes)', token, vaultCode, recoveryCode));
    assert.equal(activation.logs.length, 1);
    const log = activation.logs[0];
    const [vault, recovery] = log.topics.slice(2).map(t => '0x' + t.slice(-40).toLowerCase());
    const gamma = await reader.vaultConfig(bytes(vault));
    const config = decodeConfig(gamma, PRODUCTION_PARAMS);
    const domain = hex(domainOf(gamma));
    assert.equal(hex(config.erc20!.token), token);
    assert.equal(hex(config.erc20!.generation), generation);
    const vaultRuntimeCodeHash = hex(await codeHash(vault));
    const recoveryRuntimeHash = hex(await codeHash(recovery));
    const graphPins = hex(config.erc20!.pins);
    writeFileSync(join(evidenceDir, 'gamma.bin'), gamma);
    json('deployment.json', { token, vault, recovery, factory, lineage, ordinary, receipts: uct.receipts,
      salt: generation, pins: graphPins, domain, asset: hex(config.asset),
      runtimeHashes: { vault: vaultRuntimeCodeHash, recovery: recoveryRuntimeHash,
        token: hex(await codeHash(token)), factory: factoryRuntimeHash,
        ordinary: hex(await codeHash(ordinary)), lineage: hex(await codeHash(lineage)), receipts: uct.runtimeHashes.receipts,
        registry: uct.runtimeHashes.registry } });
    json('wallet-measurement-input.json', {
      status: 'testnet-provisional', purpose: 'Private disposable test assets',
      pins: { gamma: hex(gamma), build: 'production', vaultRuntimeCodeHash, maxEncodedTxBytes: 524_288,
        userGasLimit: '24000000', gasReserve: '500000', returnReserveSegments: 64, deploymentBlock: Number(BigInt(activation.blockNumber)),
        stateReadOnly: false, erc20: { factory, factoryRuntimeHash, vaultInitcodeHash, recoveryInitcodeHash,
          activationTx: activation.transactionHash, fundingQualified: false } },
    });
    assets.push({ token, vault, recovery, domain, asset: hex(config.asset) });
    evidenceDir = graphDir;
  }
  for (const field of ['token', 'vault', 'recovery', 'domain', 'asset'] as const) assert.notEqual(assets[0][field], assets[1][field]);
  assert(assets.every(a => a.domain !== uct.domain && a.vault !== uct.vault));
  json('assets.json', { chainId, executionGenesis: hex(executionGenesis), factory, assets, uct: { vault: uct.vault, domain: uct.domain } });
}
// T6 can exercise its own wallet and load script against this fresh, pinned vault.
if (!erc20 && process.env.NB2_SCENARIO_DRIVER && !resumeStage) process.exit(0);

const history = await TrustInput.fromBundle(readFileSync(join(laneOut, 'trust.cbor')), rootGenesis);
const verifiedHistory = join(out, resumeStage === 'load' ? 'load-history.cbor' : 'verified-history.cbor');
if (existsSync(verifiedHistory)) await extendHistory(verifiedHistory);
const historyUrl = process.env.NB2_HISTORY_URL;
assert(historyUrl && new URL(historyUrl).hostname === '127.0.0.1', 'loopback UTB history required');
let refreshingHistory: Promise<void> | undefined;

function signerEpoch(ucs: Uint8Array[]) {
  return ucs.reduce((tip, raw) => {
    const { epoch } = decodeUc(raw).unicitySeal;
    return epoch > tip ? epoch : tip;
  }, history.history.entries[0].epoch);
}

async function extendHistory(file: string) {
  const candidate = await TrustInput.fromBundle(readFileSync(file), rootGenesis);
  for (const entry of candidate.history.entries) await history.history.append(entry);
}

async function refreshHistory() {
  const candidate = join(keys, 'history-candidate-' + process.pid + '.cbor');
  command(join(out, 'utb-evidence'), ['fetch', '--url', historyUrl!, '--out', candidate]);
  await extendHistory(candidate);
  writeFileSync(candidate, await history.history.toBundle());
  renameSync(candidate, verifiedHistory);
}

async function trustFor(ucs: Uint8Array[]) {
  const required = signerEpoch(ucs);
  for (let i = 0; i < 120; ++i) {
    if (history.history.tip!.epoch >= required) return history.snapshot();
    await (refreshingHistory ??= refreshHistory().finally(() => { refreshingHistory = undefined; }));
    if (history.history.tip!.epoch < required) await delay(500);
  }
  throw new Error(`verified wallet history did not reach signer epoch ${required}`);
}

async function waitForImport(required: bigint) {
  const started = Date.now();
  for (let i = 0; i < 120; ++i) {
    try {
      await reader.checkReturnImport(c, required);
      return { signerEpoch: required, attempts: i + 1, elapsedMs: Date.now() - started };
    } catch (error) {
      if (!(error instanceof WalletError && error.reason === 'ImportLag') || i === 119) throw error;
      await delay(500);
    }
  }
}

const authenticatedArchives = new Set<EvmReader>();
type ExpectedLog = { topics: Uint8Array[]; data: Uint8Array };
async function certifyReceipt(name: string, receipt: Receipt, emitter: Uint8Array, expected: ExpectedLog, index = 0, count = 1) {
  const fields = (log: { address: string; topics: string[]; data: string }) =>
    ({ address: log.address.toLowerCase(), topics: log.topics.map((t) => t.toLowerCase()), data: log.data.toLowerCase() });
  const wanted = { address: hex(emitter), topics: expected.topics.map(hex), data: hex(expected.data) };
  assert.equal(receipt.logs.length, count, name);
  assert.deepEqual(fields(receipt.logs[index]), wanted, name);
  const tx = bytes(receipt.transactionHash);
  const started = Date.now();
  for (let attempt = 0; attempt < 60; ++attempt) {
    const result = await firstAvailableReceipt(receiptReaders, async (archive, source) => {
      if (!authenticatedArchives.has(archive)) {
        const remote = await archive.headerByNumber(0n);
        assert(remote && hex(remote.hash) === hex(executionGenesis), 'archive belongs to another generation');
        authenticatedArchives.add(archive);
      }
      const proof = await archive.receiptProof(tx, emitter, expected.topics[0], true, expected);
      const trust = await trustFor([proof.proof.uc]);
      const log = await verifyReceiptLog(c, trust, proof.proof, emitter);
      assert.deepEqual({ address: hex(log.address), topics: log.topics.map(hex), data: hex(log.data) }, wanted);
      assert.equal(hex(proof.blockHash), receipt.blockHash.toLowerCase());
      assert.equal(proof.proof.txIndex, BigInt(receipt.transactionIndex));
      assert.equal(proof.receiptLogIndex, index);
      writeFileSync(join(evidenceDir, name + '.cbor'), proof.encoded);
      json(name + '.locator.json', { transactionHash: receipt.transactionHash, blockHash: hex(proof.blockHash),
        blockNumber: proof.blockNumber, blockTimestamp: log.header.timestamp,
        transactionIndex: proof.proof.txIndex, receiptLogIndex: proof.receiptLogIndex,
        source, attempts: attempt + 1, acquisitionMs: Date.now() - started, ...wanted });
      return { proof: proof.proof, encoded: proof.encoded, trust };
    });
    if (result) return result;
    await delay(1000);
  }
  throw new Error(`no certified receipt for ${name}`);
}

if (resumeStage) await runOfflineRelayer(resumeStage);
else if (erc20) await runErc20Holder();
else if (qualify) await runQualificationCosts();
else if (qualifyCustody) await runQualificationCustody();
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
      redeemCalldata(a.evidence, a.verdict.eta, a.verdict.minSegment, new Uint8Array()),
      0n, '0x1', signer, 24_000_000n, signerEpoch(tokenUcs(a.evidence))), c.vault, a.paid);
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

async function assetBalance(address: Uint8Array): Promise<bigint> {
  if (!c.erc20) return reader.balance(address);
  return BigInt(hex(await reader.call(c.erc20.token, callData('balanceOf(address)', hex(address)))));
}

async function lockAsset(name: string, amount: bigint, firstOwner: Uint8Array, rho: Uint8Array) {
  if (!c.erc20) return send(name, vault, depositCalldata(firstOwner, rho), amount);
  const requested = amount + BigInt(erc20Mode === 'fee');
  const { depositErc20Calldata, approveCalldata } = await import('./sdk/nb2/abi.js');
  await send(name + '-approve', tokenAddress!, approveCalldata(c.vault, requested));
  return send(name, vault, depositErc20Calldata(requested, amount, firstOwner, rho));
}

async function certifyDeposit(name: string, mined: Receipt, nonce: bigint, amount: bigint, rho: Uint8Array, owner: Uint8Array) {
  const data = depositedData(domain, amount, rho, owner);
  if (!c.erc20) return certifyReceipt(name, mined, c.vault, { topics: [TOPIC.Deposited, u256(nonce)], data });
  const log = { topics: [TOPIC.ERC20Deposited, u256(nonce), concat(new Uint8Array(12), c.erc20.token)], data };
  const index = erc20Mode === 'fee' ? 2 : 1;
  return certifyReceipt(name, mined, c.vault, log, index, index + 1);
}

async function custodySnapshot() {
  const state = await reader.vaultState(c.vault);
  return { ...state, head: hex(state.head), previousHead: hex(state.previousHead), balance: await assetBalance(c.vault) };
}

async function verifyIsolation(label: string) {
  const otherKind = erc20Mode === 'plain' ? 'fee' : 'plain';
  const address = (dir: string) => bytes(JSON.parse(readFileSync(join(dir, 'deployment.json'), 'utf8')).vault);
  const [uct, other] = await Promise.all([reader.vaultState(address(laneOut)), reader.vaultState(address(join(laneOut, otherKind)))]);
  const state = [uct, other].map(s => ({ ...s, head: hex(s.head), previousHead: hex(s.previousHead) }));
  const file = join(out, 'isolation-before.json');
  if (label === 'after') {
    const before = JSON.parse(readFileSync(file, 'utf8'));
    assert.deepEqual(state.map(s => Object.fromEntries(Object.entries(s).map(([k, v]) =>
      [k, typeof v === 'bigint' ? String(v) : v]))), before);
  }
  json('isolation-' + label + '.json', state);
}

async function runErc20Holder() {
  const core = await import('./wallet/core.js');
  const deployment = JSON.parse(readFileSync(join(out, 'deployment.json'), 'utf8'));
  const manifest = JSON.parse(readFileSync(join(out, 'wallet-measurement-input.json'), 'utf8'));
  const activation = JSON.parse(readFileSync(join(out, 'activation.receipt.json'), 'utf8')) as Receipt;
  const paddedAddress = (address: string) => concat(new Uint8Array(12), bytes(address));
  await certifyReceipt('activation', activation, bytes(deployment.factory), {
    topics: [TOPIC.ERC20Activated, paddedAddress(tokenAddress!), paddedAddress(vault), paddedAddress(recovery)],
    data: concat(domain, vaultHash, recoveryHash),
  });
  await verifyIsolation('before');
  const wallet = await new core.Wallet(join(keys, 'app-wallet'), bytes(readFileSync(join(keys, 'holder-key'), 'utf8')), {
    release: join(out, 'wallet-measurement-input.json'), trustBundle: join(laneOut, 'trust.cbor'),
    trustPin: join(laneOut, 'trust.pin'), rpc, aggregator,
  }).open();
  assert.equal(manifest.pins.erc20.fundingQualified, false);
  const initial = await custodySnapshot();
  const amount = 1_000n;
  const requested = amount + BigInt(erc20Mode === 'fee');
  const holder = hex(wallet.signer.address);
  const operator = new LocalKeySigner(bytes(readFileSync(join(keys, 'operator-key'), 'utf8')));
  const loadPayer = new LocalKeySigner(bytes(readFileSync(join(keys, 'load-key'), 'utf8')));
  const relayer = new LocalKeySigner(bytes(readFileSync(join(keys, 'relayer-key'), 'utf8')));
  await send('mint-test-holder', tokenAddress!, callData('mint(address,uint256)', holder, String(requested)), 0n, '0x1', operator);
  const loadAmount = BigInt(archiveSegments) * c.K + BigInt(archiveSegments) + 1n;
  await send('mint-test-load', tokenAddress!, callData('mint(address,uint256)', hex(loadPayer.address), String(loadAmount)), 0n, '0x1', operator);
  await send('fund-holder', holder, new Uint8Array(), 10n ** 18n, '0x1', operator);
  await send('fund-load', hex(loadPayer.address), new Uint8Array(), 10n ** 18n, '0x1', operator);
  const relayerFunding = 10n ** 18n;
  const funding = await send('fund-relayer', hex(relayer.address), new Uint8Array(), relayerFunding, '0x1', operator);
  assert.equal(await reader.balance(relayer.address), relayerFunding);
  json('relayer-funding.json', { tx: funding.transactionHash, payer: hex(relayer.address), balance: relayerFunding });
  const plan = await core.planDeposit(wallet, 'root', requested, amount);
  await assert.rejects(core.sendDeposit(wallet, 'root'), e => core.reasonOf(e) === 'CapacityPreflight');
  const firstOwner = firstOwnerOf(wallet.ownerPub(0));
  const mined = await lockAsset('deposit', amount, firstOwner, plan.rho);
  await certifyDeposit('deposit', mined, 1n, amount, plan.rho, firstOwner);
  await core.sendDeposit(wallet, 'root');
  assert.equal((await core.mint(wallet, 'root')).amount, amount);
  const deposited = await custodySnapshot();
  assert.equal(deposited.outstanding - initial.outstanding, amount);
  assert.equal(deposited.balance - initial.balance, amount);
  json('deposit-custody.json', { requested, credit: amount, before: initial, after: deposited, qDelta: amount });
  await core.split(wallet, 'root', 0, [{ label: 'ordinary', amount: 40n }, { label: 'branch', amount: 960n }]);
  await core.split(wallet, 'branch', 0, [{ label: 'retry', amount: 50n }, { label: 'recovered', amount: 910n }]);
  let recoveryLabel = 'recovered';
  const descendants = erc20Mode === 'fee' ? 32 : 2;
  for (let i = 0; i < descendants; i++) {
    const next = 'recovery-child-' + i;
    await core.transfer(wallet, recoveryLabel, next, 0);
    recoveryLabel = next;
  }
  const claims = [
    { name: 'ordinary', amount: 40n, recipient: '0x' + '11'.repeat(20) },
    { name: 'retry', amount: 50n, recipient: '0x' + '12'.repeat(20) },
    { name: 'recovered', amount: 910n, recipient: '0x' + '13'.repeat(20) },
  ];
  await assert.rejects(core.planReturn(wallet, recoveryLabel, bytes(claims[2].recipient)),
    e => core.reasonOf(e) === 'CapacityPreflight');
  json('wallet-admission.json', { deposit: 'CapacityPreflight', return: 'CapacityPreflight', fundingQualified: false });
  for (const claim of claims) {
    const recipient = bytes(claim.recipient);
    const token = wallet.token(claim.name === 'recovered' ? recoveryLabel : claim.name);
    const data = encodeReturnData({ d: domain, asset: c.asset, recipient, amount: claim.amount, minIndex: 0n });
    const request = await transferRequest(token, wallet.owner(0), {
      recipient: burnPredicate(HU(data)), mask: randomBytes(32), data, deadline: null,
    });
    const backup = { label: claim.name, token: hex(token), signedBurn: hex(request.tx), certification: hex(request.cd),
      amount: String(claim.amount), recipient: claim.recipient, initialBalance: String(initial.balance),
      recipientBefore: String(await assetBalance(recipient)), value: String(amount), holderPID: process.pid };
    const file = claim.name === 'recovered' ? 'offline-burn.private.json' : claim.name + '.private.json';
    core.writeDurable(join(keys, file), JSON.stringify(backup));
    json(claim.name + '-backup.json', { bytes: readFileSync(join(keys, file)).length, sha256: hex(HU(readFileSync(join(keys, file)))), holderPID: process.pid });
  }
  mkdirSync(join(out, 'recovered'), { mode: 0o700 });
  console.log('Signed ERC20 burns backed up before holder exit', erc20Mode);
}

type Burn = { evidence: Uint8Array; trust: TrustInput; paid: ExpectedLog };
type Checkpoint = { from: number; seq: string; receipt: Receipt; event: { topics: string[]; data: string } };
async function completeRecovery(b: Burn, name = 'run', restore?: Checkpoint, saveAt = Infinity, maxOperations = packetMax) {
  const authority = new RecoveryAuthority(b.trust, async (next) => writeFileSync(join(evidenceDir, 'authority.cbor'), await next.history.toBundle()));
  const session = await RecoverySession.create(gamma, b.evidence, authority, PRODUCTION_PARAMS,
    { salt, recovery: bytes(recovery), runtimeHash: recoveryHash, pins, vaultRuntimeHash: vaultHash });
  const admissionCheck = erc20 && process.env.NB2_ERC20_ADMISSION === '1';
  const plan = admissionCheck ? await (async () => {
    const { ERC20_RESUME_OPERATIONS, quoteRecovery } = await import('./sdk/nb2/recovery-cost.js');
    const limits = { chainId: BigInt(chain), signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n,
      maxNonce: 256n, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n,
      balance: 10n ** 18n, feeBudget: 10n ** 18n, worstCaseEnvelope: true };
    const range = (operations: number, minReceiptBytes: number, receiptBytes: number) => ({
      minReceiptBytes, execution: 14_000_000n,
      max: { entry: 'run' as const, operations, pages: 32, calldataBytes: 393_216, receiptBytes, gaps: 0, openingBytes: 393_216 },
    });
    // Trial bounds for the disposable workload. Calibration tries the full Start.
    const calibration = { pins, runtimeHash: recoveryHash, vaultRuntimeHash: vaultHash,
      ranges: [...Array.from({ length: releaseCalibration ? 16 : 1 }, (_, i) => range(i + 1, 0, 0)),
        ...Array.from({ length: 16 }, (_, i) => range(i + 1, 1, 65_536))] };
    const calls = session.planRuns(calibration, limits);
    if (!restore) json('admission-run-plan.json', { scope: 'trial bounds for disposable test value', calls });
    if (erc20Mode === 'fee') assert(calls.slice(1).some((call) => call.shape.operations === ERC20_RESUME_OPERATIONS));
    return { calls, limits, calibration, quoteRecovery };
  })() : undefined;
  let trust = b.trust;
  let prior: { seq: bigint; receipt: Uint8Array } | undefined;
  let from = 0;
  if (restore) {
    const restoreWindow = await startCalibrationWindow();
    // Fetch the actual prior Progress from the configured reader list, even
    // though the first relayer also kept a local proof.
    const cert = await certifyReceipt('restored-predecessor', restore.receipt, bytes(recovery),
      { topics: restore.event.topics.map(bytes), data: bytes(restore.event.data) });
    from = restore.from;
    prior = { seq: BigInt(restore.seq), receipt: cert.encoded };
    trust = cert.trust;
    json('restored.json', { consumedOperations: from, seq: restore.seq,
      restoreTx: restore.receipt.transactionHash, segment: (await reader.vaultState(c.vault)).segment });
    await finishCalibrationWindow('restore', restoreWindow);
  }
  while (from < session.operationCount) {
    const seq = (prior?.seq ?? 0n) + 1n;
    const runWindow = await startCalibrationWindow();
    const planned = plan?.calls[Number(seq - 1n)];
    let count = planned?.shape.operations ?? Math.min(maxOperations, session.operationCount - from);
    if (plan && !planned) throw new Error('missing cut in admitted schedule');
    let packet;
    for (;;) {
      try {
        packet = await session.run(from, count, trust, prior);
        break;
      } catch (e) {
        if (planned || count === 1 || !(e instanceof Nb2Error && e.rule === 'InputTooLarge'
          && ['run pages', 'cold calldata'].includes(e.detail ?? ''))) throw e;
        --count;
      }
    }
    if (plan && planned) {
      const exact = plan.quoteRecovery(packet.shape, plan.calibration, plan.limits, true);
      assert(exact && exact.gas <= planned.gas && exact.signedBytes <= planned.signedBytes);
      assert(packet.shape.receiptBytes <= planned.shape.receiptBytes && packet.shape.openingBytes <= planned.shape.openingBytes);
    }
    const label = name + '-' + seq;
    const mined = await send(label, recovery, packet.calldata, 0n, '0x1', signer, planned?.gas ?? 24_000_000n, packet.requiredSignerEpoch);
    const cert = await certifyReceipt(label, mined, bytes(recovery), packet.event);
    await session.verifyEvent(cert.trust, cert.encoded, packet.event);
    await finishCalibrationWindow(label, runWindow);
    if (packet.state) writeFileSync(join(evidenceDir, label + '.state'), packet.state);
    json(label + '.shape.json', packet.shape);
    prior = { seq, receipt: cert.encoded };
    trust = cert.trust;
    from = packet.end;
    if (packet.state && from >= saveAt) {
      json('offline-checkpoint.json', { from, receipt: mined, seq: String(seq),
        event: { topics: packet.event.topics.map(hex), data: hex(packet.event.data) } } satisfies Checkpoint);
      break;
    }
  }
  assert(prior);
  return { session, prior, trust };
}

async function executeRecovery(b: Burn) {
  const singleton = process.env.NB2_COMPARE_SINGLE_SOURCE === '1'
    ? await completeRecovery(b, 'single-source', undefined, Infinity, 1)
    : undefined;
  const { session, prior, trust } = await completeRecovery(b);
  if (singleton) {
    assert.equal(hex(singleton.session.id), hex(session.id));
    const readComplete = (prefix: string, seq: bigint) =>
      JSON.parse(readFileSync(join(evidenceDir, prefix + '-' + seq + '.locator.json'), 'utf8'));
    const one = readComplete('single-source', singleton.prior.seq);
    const packed = readComplete('run', prior.seq);
    assert.deepEqual(one.topics, packed.topics);
    assert.equal(one.data.slice(66), packed.data.slice(66));
    json('same-evidence-comparison.json', { session: hex(session.id), evidenceSha256: hex(HU(b.evidence)),
      singleSourceProgress: singleton.prior.seq, packedProgress: prior.seq });
  }
  const payment = await session.gaps('redeemRecovered', trust, prior.receipt, { seq: prior.seq }, []);
  await certifyReceipt('recovered', await send('recovered', vault, payment.calldata, 0n, '0x1', signer, 24_000_000n, payment.requiredSignerEpoch), c.vault, b.paid);
  return { session: hex(session.id), packets: prior.seq, operations: session.operationCount };
}

async function runQualificationCosts() {
  const walletCore = await import('./wallet/core.js');
  const deploymentBlock = Number(BigInt(JSON.parse(text('NativeBridgeVault11.receipt.json')).blockNumber));
  const releasePath = join(out, 'wallet-measurement-input.json');
  json('wallet-measurement-input.json', {
    purpose: 'Test-value workload generation; no qualified return envelope',
    pins: { gamma: hex(gamma), build: 'production', vaultRuntimeCodeHash: hex(vaultHash),
      maxEncodedTxBytes: 524288, userGasLimit: '24000000', gasReserve: '500000',
      returnReserveSegments: 64, deploymentBlock, stateReadOnly: false },
  });
  const walletAgg = new walletCore.GatewayAggregator(aggregator);
  // The measurement wallet uses the disposable lane's funded key. Its private state
  // stays in the driver's scratch directory and is removed when the lane stops.
  const walletKey = offline ? randomBytes(32) : bytes(readFileSync(join(keys, 'send-key'), 'utf8'));
  if (offline) {
    await send('holder-funding', hex(new LocalKeySigner(walletKey).address), new Uint8Array(), 10n ** 18n);
    const { baseFee, priority } = await reader.fees();
    const loadFunding = BigInt(archiveSegments) * c.K * 12_000_000n * (2n * baseFee + priority);
    for (const role of ['relayer', 'load']) {
      const key = bytes(readFileSync(join(keys, role + '-key'), 'utf8'));
      const funding = role === 'load' ? loadFunding + 10n ** 18n : 10n ** 18n;
      await send(role + '-funding', hex(new LocalKeySigner(key).address), new Uint8Array(), funding);
    }
  }
  const wallet = await new walletCore.Wallet(join(keys, 'workload-wallet'), walletKey, {
    release: releasePath, trustBundle: join(out, 'trust.cbor'), trustPin: join(out, 'trust.pin'),
    rpc, aggregator,
  }).open({ aggregator: walletAgg });
  const recipient = bytes('0000000000000000000000000000000000000012');
  const cases = [
    { label: 'split-20', transfers: 0, depth: 20, txTarget: 8, gasTarget: 50_000_000 },
    { label: 'transfer-600', transfers: 600, depth: 0, txTarget: 44, gasTarget: 390_000_000 },
    { label: 'transfer-600-split-1', transfers: 600, depth: 1, txTarget: 46, gasTarget: 395_000_000 },
  ];
  if (offline) cases.push({ label: 'archive-only', transfers: 0, depth: 0, txTarget: 0, gasTarget: 0 });
  const selected = process.env.NB2_QUALIFY_CASE;
  assert(selected === undefined || cases.some(({ label }) => label === selected), 'NB2_QUALIFY_CASE');
  assert(!offline || selected === 'archive-only' || selected?.startsWith('transfer-600'),
    'offline requires archive-only or a 600-transfer workload');
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
      const receipt = await reader.receipt(deposit.txHash) as Receipt | null;
      assert(receipt, label);
      const firstOwner = firstOwnerOf(wallet.ownerPub(0));
      const rho = rhoOf(domain, wallet.bridge.secretOf(plan.intent));
      await certifyReceipt('deposit', await record('deposit', receipt, start),
        c.vault, { topics: [TOPIC.Deposited, u256(deposit.depositNumber)], data: depositedData(domain, value, rho, firstOwner) });
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
        await wallet.refreshAuthority();
        await walletCore.receive(wallet, nextLabel, token, owner);
        wallet.update(held, { spent: 'transferred as ' + nextLabel });
        held = nextLabel;
        console.log(label, 'certified transfers', transfers);
      }
      for (let i = 0; i < depth; i++) {
        const nextLabel = label + '-child-' + i;
        await wallet.refreshAuthority();
        await walletCore.split(wallet, held, 0, [
          { label: nextLabel, amount: amount - 1n }, { label: label + '-sibling-' + i, amount: 1n },
        ]);
        held = nextLabel;
        --amount;
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
      if (offline) {
        walletCore.writeDurable(join(keys, 'offline-burn.private.json'), JSON.stringify({
          label, token: hex(token), signedBurn: hex(request.tx), certification: hex(request.cd),
          amount: String(amount), recipient: hex(recipient), initialBalance: String(initialBalance),
          recipientBefore: String(recipientBefore), value: String(value), holderPID: process.pid,
        }));
        console.log('Holder saved the signed burn and exited before certification');
        return;
      }
      const evidence = appendTransfer(token, request.tx, await certifyChecked(agg, request.cd));
      const trust = await trustFor(tokenUcs(evidence));
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
  const levels = lineageOf(decodeToken(token));
  const backing = decodeReceiptBacking(levels[0].mint.justification!);
  return [backing.proof.uc, ...levels.flatMap(l => [l.mintProof.uc, ...l.proofs.map(p => p.uc)])];
}

function anotherPresentation(evidence: Uint8Array) {
  const token = decodeToken(evidence);
  const terminal = token.proofs.at(-1)!;
  const uc = terminal.uc;
  const witnesses = scanNative(uc).kids[0].kids[6].kids[0].kids[7];
  assert(witnesses.major === 5 && witnesses.arg < 16n);
  const label = ascii('t7-nonmember-witness');
  assert(!decodeUc(uc).unicitySeal.witnesses?.has(Buffer.from(label).toString()));
  const entries: { key: Uint8Array; signature: Uint8Array }[] = [];
  for (let i = 0; i < witnesses.kids.length; i += 2) {
    entries.push({ key: raw(uc, witnesses.kids[i]), signature: raw(uc, witnesses.kids[i + 1]) });
  }
  // The extra witness contributes zero weight, and every original signature is unchanged.
  entries.push({ key: concat(head(3, label.length), label), signature: cBytes(new Uint8Array(65)) });
  entries.sort((a, b) => a.key.length - b.key.length || Buffer.compare(a.key, b.key));
  terminal.uc = concat(uc.subarray(0, witnesses.start), head(5, entries.length),
    ...entries.flatMap(({ key, signature }) => [key, signature]), uc.subarray(witnesses.end));
  return encodeToken(token);
}

async function createLoadClaims(label: string, count: number, recipient: Uint8Array, minIndex: bigint,
  skew: boolean, captureBeforeCertification = false) {
  const { GatewayAggregator } = await import('./wallet/core.js');
  const walletAgg = new GatewayAggregator(aggregator);
  const amount = BigInt(count);
  const owner = localOwner(randomBytes(32));
  const secret = randomBytes(32);
  const firstOwner = firstOwnerOf(owner.publicKey);
  const rho = rhoOf(domain, secret);
  const depositNumber = (await reader.vaultState(c.vault)).deposits + 1n;
  const deposit = await lockAsset(label, amount, firstOwner, rho);
  const dep = await certifyDeposit(label, deposit, depositNumber, amount, rho, firstOwner);
  const beforeCertification = captureBeforeCertification
    ? await reader.rpc.call<{ hash: string; number: string }>('eth_getBlockByNumber', ['finalized', false])
    : undefined;
  if (beforeCertification) assert(BigInt(beforeCertification.number) >= BigInt(deposit.blockNumber));
  const root = mintRequest({ network: c.network, recipient: signaturePredicate(owner.publicKey),
    salt: depositSalt(domain, depositNumber, secret), type: c.ty,
    justification: encodeReceiptBacking({ d: domain, n: depositNumber, r: secret, proof: dep.proof }),
    data: valueData(c.aid, amount), deadline: null });
  const token = tokenOfMint(root.tx, await certifyChecked(agg, root.cd));
  const plan = splitPlan(decodeToken(token), Array.from({ length: count }, () => ({
    ownerKey: owner.publicKey, amount: 1n, salt: randomBytes(32),
  })), c.ty, c.aid, randomBytes(32));
  const split = await transferRequest(token, owner, plan.burn);
  const parent = appendTransfer(token, split.tx, await certifyChecked(agg, split.cd));
  const verified = await verifySplit(c, domain, await trustFor(tokenUcs(parent)), decodeToken(parent));

  async function certifyBatch<T extends { cd: Uint8Array }>(requests: readonly T[]) {
    for (let at = 0; at < requests.length; at += 16) {
      await Promise.all(requests.slice(at, at + 16).map(({ cd }) => walletAgg.submit(cd)));
    }
    const proofs: Uint8Array[] = [];
    for (const { cd } of requests) proofs.push(await walletAgg.proof(cd));
    return proofs;
  }
  const children = plan.children.map(template => {
    const child = childMint(verified.link, plan.tree, template);
    return { ...mintRequest(child.mint), allocation: child.allocation };
  });
  const childProofs = await certifyBatch(children);
  const tokens = children.map((m, i) => tokenOfChild(parent, m.allocation, m.tx, childProofs[i]));
  const data = encodeReturnData({ d: domain, asset: c.asset, recipient, amount: 1n, minIndex });
  const burns: Awaited<ReturnType<typeof transferRequest>>[] = [];
  for (const [i, token] of tokens.entries()) {
    const source = headOf(decodeToken(token));
    const sid = stateId(source.owner, source.state);
    for (;;) {
      const request = await transferRequest(token, owner, {
        recipient: burnPredicate(HU(data)), mask: randomBytes(32), data, deadline: null,
      });
      const eta = redemptionId(domain, burnTransitionId(sid, HU(request.tx)));
      if (!skew || (captureBeforeCertification && i === count - 1) || (eta[0] >> 4) === 0) {
        burns.push(request);
        break;
      }
    }
  }
  const burnProofs = await certifyBatch(burns);
  const evidence = tokens.map((t, i) => appendTransfer(t, burns[i].tx, burnProofs[i]));
  const trust = await trustFor(evidence.flatMap(tokenUcs));
  const claims = await Promise.all(evidence.map(async e => {
    const verdict = await verifyReturn(gamma, e, trust, PRODUCTION_PARAMS);
    assert.equal(verdict.amount, 1n);
    assert.equal(hex(verdict.recipient), hex(recipient));
    return { evidence: e, verdict, paid: { topics: [TOPIC.Paid, verdict.eta,
      concat(new Uint8Array(12), recipient)], data: u256(1) } };
  }));
  assert.equal(new Set(claims.map(({ verdict }) => hex(verdict.eta))).size, count);
  return { claims, trust, beforeCertification };
}

async function runQualificationCustody() {
  const startTime = Date.now();
  const loadSegments = option('NB2_LOAD_SEGMENTS', 2, 2, 1024);
  const skew = process.env.NB2_LOAD_SKEW === '1';
  const n = Number(c.K) * loadSegments;
  const amount = BigInt(n + 1);
  const recipient = bytes('0000000000000000000000000000000000000013');
  const initialRecipient = await reader.balance(recipient);
  const initial = await reader.vaultState(c.vault);
  const initialBalance = await reader.balance(c.vault);
  assert.equal(initial.segment, 0n);
  assert.equal(initial.population, 0n);
  const { claims, trust, beforeCertification } = await createLoadClaims('deposit', n + 1, recipient, 0n, skew, true);
  const target = claims[0], late = claims[n];
  const ordinaryCall = (claim: typeof target, history: Uint8Array = new Uint8Array()) =>
    redeemCalldata(claim.evidence, claim.verdict.eta, claim.verdict.minSegment, history);
  assert(beforeCertification);
  const at = { blockHash: beforeCertification.hash, requireCanonical: true };
  const readRegistry = async (name: string) => {
    const slot = hex(HE(ascii('unicity.seal-registry/' + name)));
    return BigInt(await reader.rpc.call<string>('eth_getStorageAt', [registry, slot, at]));
  };
  const importedTip = await readRegistry('b1.importedTipEpoch');
  const formerClock = await readRegistry('clock.rootRound');
  const terminalSeal = decodeUc(decodeToken(target.evidence).proofs.at(-1)!.uc).unicitySeal;
  assert.equal(terminalSeal.epoch, importedTip);
  assert(terminalSeal.rootChainRoundNumber > formerClock);
  await reader.rpc.call('eth_call', [{ from: funded, to: vault, data: hex(ordinaryCall(target)),
    gas: '0x16e3600' }, at]);
  json('authority-open-tip.json', { ...beforeCertification, importedTip, formerClock,
    round: terminalSeal.rootChainRoundNumber, eta: hex(target.verdict.eta), calldata: 'paid-target.calldata' });
  const recovered = await completeRecovery({ ...target, trust }, 'eviction-run');
  const recoveredPacket = await recovered.session.gaps('redeemRecovered', recovered.trust,
    recovered.prior.receipt, { seq: recovered.prior.seq }, []);
  const altEvidence = anotherPresentation(target.evidence);
  assert.deepEqual(await verifyReturn(gamma, altEvidence, trust, PRODUCTION_PARAMS), target.verdict);
  const alternative = await completeRecovery({ evidence: altEvidence, trust, paid: target.paid }, 'same-eta-run');
  assert.notEqual(hex(alternative.session.id), hex(recovered.session.id));
  const alternativePacket = await alternative.session.gaps('redeemRecovered', alternative.trust,
    alternative.prior.receipt, { seq: alternative.prior.seq }, []);
  const replayReceipt = await send('paid-target', vault, ordinaryCall(target),
    0n, '0x1', signer, 24_000_000n, signerEpoch(tokenUcs(target.evidence)));
  await certifyReceipt('paid-target', replayReceipt, c.vault, target.paid);

  async function evmRefusal(name: string, calldata: Uint8Array, signature: string, ...args: Uint8Array[]) {
    const expected = hex(concat(HE(ascii(signature)).subarray(0, 4), ...args));
    await assert.rejects(reader.rpc.call('eth_call', [{ from: funded, to: vault, data: hex(calldata),
      gas: '0x16e3600' }, 'latest']), error => {
      assert(error instanceof RpcError, String(error));
      assert.equal(error.data, expected, name);
      return true;
    });
    json(name + '.refusal.json', { expected, signature });
  }
  await evmRefusal('before-ordinary', ordinaryCall(target), 'AlreadyPaid(bytes32)', target.verdict.eta);
  await evmRefusal('before-recovered', recoveredPacket.calldata, 'AlreadyPaid(bytes32)', target.verdict.eta);
  await evmRefusal('before-recovered-other-session', alternativePacket.calldata, 'AlreadyPaid(bytes32)', target.verdict.eta);
  json('same-eta-sessions.json', { eta: hex(target.verdict.eta), sessions: [hex(recovered.session.id), hex(alternative.session.id)],
    completeLocators: ['eviction-run-' + recovered.prior.seq, 'same-eta-run-' + alternative.prior.seq] });
  const segments: Segment[] = [];
  const sealEvidence: Uint8Array[] = [];
  const h0 = genesisHead(domain, c.K);
  let head = h0;
  let ids = [target.verdict.eta];
  const sealTopic = HE(ascii('SegmentSealed(uint64,bytes32,bytes32,bytes)'));
  const windows = [];
  const batchOffers = [];
  const catchUpMeasurements: { calls: string; verifiedGaps: number; submittedAtMs: number; proofMs: number;
    arrivedDuringCall: bigint; beforeBacklog: bigint; afterBacklog: bigint }[] = [];
  const loadPayer = new LocalKeySigner(randomBytes(32));
  await send('catch-up-funding', hex(loadPayer.address), new Uint8Array(), 10n ** 18n);
  const lateRecovery = await completeRecovery({ ...late, trust }, 'late-run');
  type AdvanceCursor = { seq: bigint; receipt: Uint8Array; next: bigint; head: Uint8Array; trust: TrustInput };
  let lateCursor: AdvanceCursor = { ...lateRecovery.prior, next: 0n, head: h0, trust: lateRecovery.trust };
  let pending: Promise<AdvanceCursor> | undefined;
  let resultReady = false;
  const batchGaps = 3;
  async function advance(suffix: Uint8Array[], cursor: AdvanceCursor, name: string): Promise<AdvanceCursor> {
    const gapTrust = await trustFor(suffix.map(e => decodeDepositProof(e).uc));
    const gaps = await lateRecovery.session.certifiedGaps(gapTrust, cursor.next, cursor.head, suffix);
    const opened = cursor.next === 0n ? undefined : { next: cursor.next, head: cursor.head };
    const packet = await lateRecovery.session.gaps('advanceGaps', gapTrust, cursor.receipt,
      { seq: cursor.seq, cursor: opened }, gaps, opened === undefined ? h0 : undefined);
    const before = await reader.vaultState(c.vault);
    const start = Date.now();
    const certified = await certifyReceipt(name, await send(name, recovery, packet.calldata, 0n, '0x1', loadPayer, 24_000_000n, packet.requiredSignerEpoch),
      bytes(recovery), packet.event!);
    await lateRecovery.session.verifyEvent(certified.trust, certified.encoded, packet.event!);
    const after = await reader.vaultState(c.vault);
    catchUpMeasurements.push({ calls: name, verifiedGaps: gaps.length, submittedAtMs: start, proofMs: Date.now() - start,
      arrivedDuringCall: after.segment - before.segment, beforeBacklog: before.segment - cursor.next, afterBacklog: after.segment - packet.next });
    return { seq: cursor.seq + 1n, receipt: certified.encoded, next: packet.next, head: packet.head!, trust: certified.trust };
  }
  const eligibleHistory = (claim: typeof target, count: number) => count === 0 ? new Uint8Array() :
    encodeHistory(h0, segments.slice(0, count).map(segment => {
      const gap = GapTree.build(segment.z)!.prove(claim.verdict.eta);
      assert(gap, 'load eta appears in an already sealed archive');
      return gap;
    }));

  // Offer batches to the pool without waiting for each transaction's receipt.
  const size = loadSegments > 2 ? 32 : 16;
  for (let i = 1; i < n; i += size) {
    if (pending && resultReady) {
      lateCursor = await pending;
      pending = undefined;
    }
    if (loadSegments > 2 && !pending && sealEvidence.length >= Number(lateCursor.next) + batchGaps) {
      const next = Number(lateCursor.next);
      resultReady = false;
      pending = advance(sealEvidence.slice(next, next + batchGaps), lateCursor, 'loaded-advance-' + next);
      void pending.then(() => { resultReady = true; }, () => { resultReady = true; });
    }
    const first = Date.now();
    const nonce = await reader.nonce(signer.address);
    const { baseFee, priority } = await reader.fees();
    const batch = claims.slice(i, Math.min(n, i + size));
    await waitForImport(signerEpoch(batch.flatMap(claim => tokenUcs(claim.evidence))));
    const endpoint = segments.length;
    const submitted = [];
    for (const [j, claim] of batch.entries()) {
      const data = ordinaryCall(claim, eligibleHistory(claim, endpoint));
      const tx = await signTx(signer, { chainId, nonce: nonce + BigInt(j), gas: 12_000_000n,
        maxFeePerGas: 2n * baseFee + priority, maxPriorityFeePerGas: priority, to: c.vault,
        value: 0n, data });
      assert.equal(hex(await reader.sendRaw(tx.raw)), hex(tx.hash));
      submitted.push(tx);
    }
    batchOffers.push({ atMs: first, calls: batch.length, dispatchedMs: Date.now() - first, endpoint });
    for (const [j, tx] of submitted.entries()) {
      const claim = batch[j];
      const name = 'load-' + (i + j);
      let receipt;
      for (let attempt = 0; attempt < 120; attempt++) {
        receipt = await reader.receipt(tx.hash);
        if (receipt) break;
        await delay(500);
      }
      assert(receipt, name);
      const mined = await record(name, receipt as Receipt, first, tx.raw.length);
      ids.push(claim.verdict.eta);
      const sealing = ids.length === Number(c.K);
      await certifyReceipt(name, mined, c.vault, claim.paid, 0, sealing ? 2 : 1);
      if (sealing) {
        ids.sort(Buffer.compare);
        const tree = GapTree.build(ids)!;
        const index = BigInt(segments.length);
        const after = nextHead(domain, index, head, tree.root);
        const seal = { topics: [sealTopic, u256(index)], data: abiEncode([
          { word: head }, { word: after }, { bytes: concat(...ids) },
        ]) };
        sealEvidence.push((await certifyReceipt('seal-' + index, mined, c.vault, seal, 1, 2)).encoded);
        segments.push(checkSegmentLog(domain, c.K, index, head, seal.data));
        const buckets = Array.from({ length: Number(c.B) }, (_, b) => ids.filter(id => (id[0] >> 4) === b).length);
        windows.push({ segment: index, block: mined.blockNumber, buckets, observedMs: Date.now(), batchStartMs: first });
        head = after;
        ids = [];
      }
    }
  }
  const evicted = await reader.vaultState(c.vault);
  assert.equal(evicted.segment, BigInt(loadSegments));
  assert.equal(evicted.population, 0n);
  assert.equal(evicted.outstanding, initial.outstanding + 1n);
  assert.equal(await reader.balance(c.vault), initialBalance + 1n);
  assert.equal(hex(evicted.head), hex(head));
  assert.equal(await reader.balance(recipient), initialRecipient + BigInt(n));
  assert.equal(GapTree.build(segments[0].z)!.prove(target.verdict.eta), null);
  assert.equal(GapTree.build(segments[1].z)!.prove(target.verdict.eta) !== null, true);
  await evmRefusal('evicted-ordinary-stale', ordinaryCall(target), 'StaleEndpoint(uint64,uint64)', u256(0), u256(BigInt(loadSegments)));
  await evmRefusal('evicted-recovered-stale', recoveredPacket.calldata, 'StaleEndpoint(uint64,uint64)', u256(0), u256(BigInt(loadSegments)));
  // Use a genuine opening for a distinct unpaid eta as the control. It proves
  // a gap at the correct archive endpoint, but cannot exclude the paid eta.
  const replayGaps = segments.slice(0, loadSegments - 1).map(segment => GapTree.build(segment.z)!.prove(late.verdict.eta)!);
  const history = encodeHistory(h0, replayGaps);
  const ordinaryReplay = ordinaryCall(target, history);
  // Preserve the exact certified Complete and substitute only the gap suffix.
  const proofEnd = 68 + 42 + 1 + 4 + recovered.prior.receipt.length;
  const payload = concat(recoveredPacket.calldata.subarray(68, proofEnd), u16(replayGaps.length), h0, ...replayGaps);
  const replay = concat(recoveredPacket.calldata.subarray(0, 4), abiEncode([{ bytes: payload }]));
  await evmRefusal('evicted-ordinary', ordinaryReplay, 'BadGapProof(uint256)', u256(0));
  await evmRefusal('evicted-recovered', replay, 'BadGapProof(uint256)', u256(0));

  const failed = await send('evicted-recovered-mined', vault, replay,
    0n, '0x0', signer, 24_000_000n, recoveredPacket.requiredSignerEpoch);
  assert.deepEqual(failed.logs, []);
  const gatewayChecks = [];
  for (const url of laneGateways()) {
    const gateway = new EvmReader(new HttpJsonRpc(url, { retries: 0, timeoutMs: 3000 }));
    const started = Date.now();
    let authenticated = false;
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        await gateway.verifyFailedReceipt(bytes(failed.transactionHash), c, await trustFor([]),
          failed);
        authenticated = true;
        break;
      } catch (error) {
        if (attempt === 19) throw error;
        await delay(1000);
      }
    }
    assert(authenticated);
    gatewayChecks.push({ url, exactFailedTransactionReceipt: true, elapsedMs: Date.now() - started });
  }
  json('gateway-checks.json', gatewayChecks);
  const before = Date.now();
  if (pending) lateCursor = await pending;
  if (lateCursor.next < BigInt(sealEvidence.length)) {
    lateCursor = await advance(sealEvidence.slice(Number(lateCursor.next)), lateCursor, 'late-advance');
  }
  assert.equal(lateCursor.next, BigInt(loadSegments));
  const settlement = await lateRecovery.session.gaps('redeemRecovered', lateCursor.trust, lateCursor.receipt,
    { seq: lateCursor.seq, cursor: { next: lateCursor.next, head: lateCursor.head } }, []);
  const gaps = await lateRecovery.session.certifiedGaps(lateCursor.trust, 0n, h0, sealEvidence);
  const bidder = new LocalKeySigner(randomBytes(32));
  await send('race-bidder-funding', hex(bidder.address), new Uint8Array(), 10n ** 18n);
  const race = [
    { name: 'race-ordinary', payer: signer, data: ordinaryCall(late, encodeHistory(h0, gaps)),
      requiredEpoch: signerEpoch(tokenUcs(late.evidence)) },
    { name: 'race-recovered', payer: bidder, data: settlement.calldata,
      requiredEpoch: settlement.requiredSignerEpoch },
  ];
  const quotes = await Promise.all(race.map(async leg => {
    const estimate = BigInt(await reader.rpc.call<string>('eth_estimateGas', [
      { from: hex(leg.payer.address), to: vault, data: hex(leg.data), gas: '0x16e3600' },
    ]));
    const gas = (estimate * 6n + 4n) / 5n + 500_000n;
    assert(gas <= 24_000_000n, leg.name);
    return { ...leg, estimate, gas };
  }));
  const attempts = await Promise.all(quotes.map(({ name, payer, data, gas, requiredEpoch }) =>
    send(name, vault, data, 0n, null, payer, gas, requiredEpoch)));
  const winner = attempts.findIndex(r => r.status === '0x1');
  assert(winner >= 0 && attempts.filter(r => r.status === '0x1').length === 1, 'one race winner');
  await certifyReceipt('late-paid', attempts[winner], c.vault, late.paid);
  assert.deepEqual(attempts[1 - winner].logs, []);
  await evmRefusal('race-refused', quotes[1 - winner].data, 'AlreadyPaid(bytes32)', late.verdict.eta);
  json('race.json', { winner: quotes[winner].name, attempts: quotes.map(({ name, payer, estimate, gas }, i) => ({
    name, payer: hex(payer.address), estimate, submittedGas: gas, status: attempts[i].status,
    transactionHash: attempts[i].transactionHash,
  })) });
  const final = await reader.vaultState(c.vault);
  assert.equal(final.segment, BigInt(loadSegments));
  assert.equal(final.population, 1n);
  assert.equal(final.outstanding, initial.outstanding);
  assert.equal(await reader.balance(c.vault), initialBalance);
  assert.equal(await reader.balance(recipient), initialRecipient + amount);
  assert.equal(hex(final.head), hex(head));
  json('custody-result.json', { payments: amount, evicted: hex(target.verdict.eta), liability: final.outstanding,
    recipientBefore: initialRecipient, recipientAfter: initialRecipient + amount, head: hex(head), windows, batchOffers, skew,
    lateGaps: gaps.length, lateAdvanceMs: Date.now() - before, catchUpMeasurements,
    segment: final.segment, elapsedMs: Date.now() - startTime });
}

function laneGateways() {
  const base = new URL(rpc);
  return Array.from({ length: 4 }, (_, n) => {
    const url = new URL(base);
    url.port = String(Number(base.port) + n);
    return url.href;
  });
}

async function sealOfflineArchive() {
  const recipient = bytes('0000000000000000000000000000000000000013');
  const initial = await reader.vaultState(c.vault);
  const initialBalance = await assetBalance(c.vault);
  const initialRecipient = await assetBalance(recipient);
  assert.equal(initial.segment, 0n);
  assert.equal(initial.population, 0n);
  const sealTopic = HE(ascii('SegmentSealed(uint64,bytes32,bytes32,bytes)'));
  const started = Date.now();
  const windows: { observedMs: number; segment: bigint; block: string }[] = [];
  const batchOffers: { atMs: number; calls: number; dispatchedMs: number; endpoint: bigint }[] = [];
  let head = initial.head;
  const windowSize = option('NB2_ARCHIVE_WINDOW', 12, 1, 16);
  const K = Number(c.K);
  for (let start = 0; start < archiveSegments; start += windowSize) {
    const end = Math.min(start + windowSize, archiveSegments);
    const startHead = head;
    const trees: NonNullable<ReturnType<typeof GapTree.build>>[] = [];
    const window = await createLoadClaims('deposit-' + start, (end - start) * K, recipient, BigInt(start),
      process.env.NB2_LOAD_SKEW === '1');
    for (let index = start; index < end; ++index) {
      const number = BigInt(index);
      const claims = window.claims.slice((index - start) * K, (index - start + 1) * K);
      const ids = claims.map(({ verdict }) => verdict.eta).sort(Buffer.compare);
      const tree = GapTree.build(ids)!;
      const next = nextHead(domain, number, head, tree.root);
      const seal = { topics: [sealTopic, u256(number)], data: abiEncode([
        { word: head }, { word: next }, { bytes: concat(...ids) },
      ]) };
      const historyFor = (eta: Uint8Array, previous: boolean) => {
        const gaps = previous ? trees.slice(0, -1) : trees;
        return gaps.length === 0 ? new Uint8Array() : encodeHistory(startHead, gaps.map(tree => {
          const gap = tree.prove(eta);
          assert(gap, 'duplicate eta in load window');
          return gap;
        }));
      };
      for (let offset = 0; offset < claims.length; offset += 16) {
        const batch = claims.slice(offset, offset + 16);
        const required = signerEpoch(batch.flatMap(claim => tokenUcs(claim.evidence)));
        await waitForImport(required);
        const first = Date.now();
        const nonce = await reader.nonce(signer.address);
        const { baseFee, priority } = await reader.fees();
        const txs = await Promise.all(batch.map(({ evidence, verdict }, i) => {
          // The closing payment in each later ERC20 segment uses the previous
          // endpoint so both matching tag buffers are scanned before sealing.
          const previous = erc20 && trees.length > 0 && offset + i === claims.length - 1;
          return signTx(signer, {
            chainId, nonce: nonce + BigInt(i), gas: 12_000_000n,
            maxFeePerGas: 2n * baseFee + priority, maxPriorityFeePerGas: priority, to: c.vault, value: 0n,
            data: redeemCalldata(evidence, verdict.eta, verdict.minSegment, historyFor(verdict.eta, previous)),
          });
        }));
        for (const tx of txs) {
          assert(tx.raw.length <= 524_288, 'archive load signed transaction cap');
          assert.equal(hex(await reader.sendRaw(tx.raw)), hex(tx.hash));
        }
        batchOffers.push({ atMs: first, calls: batch.length, dispatchedMs: Date.now() - first, endpoint: number });
        for (const [i, tx] of txs.entries()) {
          let receipt: Awaited<ReturnType<EvmReader['receipt']>> = null;
          for (let attempt = 0; attempt < 120; ++attempt) {
            receipt = await reader.receipt(tx.hash);
            if (receipt) break;
            await delay(500);
          }
          const name = 'load-' + (index * Number(c.K) + offset + i);
          assert(receipt, name);
          const mined = await record(name, receipt as Receipt, first, tx.raw.length);
          const sealing = offset + i + 1 === claims.length;
          const logCount = (sealing ? 2 : 1) + Number(erc20);
          await certifyReceipt(name, mined, c.vault, batch[i].paid, 0, logCount);
          if (erc20) json(name + '.q.json', { qDelta: -1, verifiedPaid: true });
          if (sealing) {
            await certifyReceipt('seal-' + index, mined, c.vault, seal, 1, logCount);
            windows.push({ observedMs: Date.now(), segment: number, block: mined.blockNumber });
          }
        }
      }
      trees.push(tree);
      head = next;
      console.log('Certified archive segment', index);
    }
  }
  const final = await reader.vaultState(c.vault);
  const payments = BigInt(archiveSegments) * c.K;
  assert.equal(final.segment, BigInt(archiveSegments));
  assert.equal(final.population, 0n);
  assert.equal(hex(final.head), hex(head));
  assert.equal(final.outstanding, initial.outstanding);
  assert.equal(await assetBalance(c.vault), initialBalance);
  assert.equal(await assetBalance(recipient) - initialRecipient, payments);
  json('archive-result.json', { payments, segments: final.segment, head: hex(head),
    elapsedMs: Date.now() - started, skew: process.env.NB2_LOAD_SKEW === '1', windows, batchOffers });
}

async function runOfflineRelayer(stage: string) {
  assert(stage === 'checkpoint' || stage === 'settle' || stage === 'load');
  assert.equal(hex(await reader.vaultConfig(c.vault)), hex(gamma), 'resuming the deployed generation');
  assert.equal(hex(await codeHash(recovery)), hex(recoveryHash));
  assert.equal(hex(await codeHash(vault)), hex(vaultHash));
  const load = join(out, 'offline-load');
  if (stage === 'load') {
    evidenceDir = load;
    mkdirSync(evidenceDir, { mode: 0o700 });
    await sealOfflineArchive();
    return;
  }
  const backup = JSON.parse(readFileSync(join(keys, 'offline-burn.private.json'), 'utf8'));
  evidenceDir = join(out, backup.label);
  const phaseWindow = await startCalibrationWindow();
  const recipient = bytes(backup.recipient);
  const amount = BigInt(backup.amount);
  if (stage === 'checkpoint') {
    assert.notEqual(backup.holderPID, process.pid);
    // This process has the existing signed request, with no invocation of
    // a holder signing API. The EVM sender belongs to the test relayer.
    const proof = await certifyChecked(agg, bytes(backup.certification));
    writeFileSync(join(keys, 'burn.certified'), appendTransfer(bytes(backup.token), bytes(backup.signedBurn), proof));
  }
  const certified = readFileSync(join(keys, 'burn.certified'));
  const trust = await trustFor(tokenUcs(certified));
  const verdict = await verifyReturn(gamma, certified, trust, PRODUCTION_PARAMS);
  assert.equal(verdict.amount, amount);
  assert.equal(hex(verdict.recipient), hex(recipient));
  const paid = { topics: [TOPIC.Paid, verdict.eta, concat(new Uint8Array(12), recipient)], data: u256(amount) };
  const saveAt = releaseCalibration ? 16 : backup.label === 'archive-only' || erc20 ? 1 : 336;
  if (stage === 'checkpoint') {
    await completeRecovery({ evidence: certified, trust, paid }, 'offline-run', undefined, saveAt, saveAt === 1 ? 1 : packetMax);
    await finishCalibrationWindow('checkpoint-phase', phaseWindow);
    return;
  }
  const checkpoint: Checkpoint = JSON.parse(readFileSync(join(evidenceDir, 'offline-checkpoint.json'), 'utf8'));
  assert(checkpoint.from >= saveAt, 'checkpoint has too few consumed source operations');
  async function awaitLoadFile(name: string, timeoutMs = 600_000) {
    const path = join(load, name);
    const deadline = Date.now() + timeoutMs;
    while (!existsSync(path) && Date.now() < deadline) {
      await delay(500);
    }
    assert(existsSync(path), `archive did not publish ${name}`);
  }
  if (peakRestore) {
    assert(archiveSegments >= 6 && archiveSegments < 1026, 'use a finite peak restore window');
    await awaitLoadFile('seal-2.locator.json');
  }
  const initialBacklog = Number((await reader.vaultState(c.vault)).segment);
  const completed = await completeRecovery({ evidence: certified, trust, paid }, 'offline-run', checkpoint);
  await finishCalibrationWindow('resume-phase', phaseWindow);
  assert.equal(verdict.minSegment, 0n);
  let cursor = { ...completed.prior, next: 0n, head: genesisHead(domain, c.K), trust: completed.trust };
  const ordinaryGaps: Uint8Array[] = [];
  const advanceCalls = [];
  const started = Date.now();
  const stride = peakRestore ? 3 : 1024;
  const queuedProofsAtStart = releaseCalibration ? 64 : undefined;
  if (queuedProofsAtStart !== undefined) {
    assert(archiveSegments >= queuedProofsAtStart, 'calibration needs 64 queued seal proofs');
    await awaitLoadFile(`seal-${queuedProofsAtStart - 1}.locator.json`, 3_600_000);
  }
  for (let index = 0; index < archiveSegments;) {
    const reserveBoundary = erc20 && index < 64 ? 64 - index : Infinity;
    const count = Math.min(stride, archiveSegments - index, reserveBoundary);
    if (peakRestore) await awaitLoadFile('seal-' + (index + count - 1) + '.locator.json');
    // Start when the last input is available, before reading, authenticating or packing it.
    const before = Date.now();
    const beforeSegment = (await reader.vaultState(c.vault)).segment;
    const proofs = Array.from({ length: count }, (_, i) => readFileSync(join(load, 'seal-' + (index + i) + '.cbor')));
    const gapTrust = await trustFor(proofs.map(proof => decodeDepositProof(proof).uc));
    const gaps = await completed.session.certifiedGaps(gapTrust, cursor.next, cursor.head, proofs);
    assert.equal(cursor.next, BigInt(index));
    for (const proof of gaps) ordinaryGaps.push(proof);
    const opened = index ? { next: cursor.next, head: cursor.head } : undefined;
    const advance = await completed.session.gaps('advanceGaps', gapTrust, cursor.receipt,
      { seq: cursor.seq, cursor: opened }, gaps, opened ? undefined : cursor.head);
    assert.equal(advance.next, cursor.next + BigInt(count));
    const label = 'offline-advance-' + index;
    const gap = await certifyReceipt(label, await send(label, recovery, advance.calldata,
      0n, '0x1', signer, 24_000_000n, advance.requiredSignerEpoch), bytes(recovery), advance.event!);
    await completed.session.verifyEvent(gap.trust, gap.encoded, advance.event!);
    const usableProofAtMs = Date.now();
    const afterSegment = (await reader.vaultState(c.vault)).segment;
    if (releaseCalibration) json(label + '.shape.json', advance.shape);
    advanceCalls.push({ verifiedGaps: count, verifiedThrough: String(advance.next), label,
      inputsAvailableAtMs: before, usableProofAtMs, proofMs: usableProofAtMs - before, arrivedDuringCall: afterSegment - beforeSegment,
      beforeBacklog: beforeSegment - cursor.next, afterBacklog: afterSegment - advance.next });
    cursor = { receipt: gap.encoded, seq: cursor.seq + 1n, next: advance.next, head: advance.head!, trust: gap.trust };
    index += count;
  }
  const signedOrdinaryBytes = [];
  const { baseFee, priority } = await reader.fees();
  const nonce = await reader.nonce(signer.address);
  for (const count of [archiveSegments - 1, archiveSegments]) {
    const data = redeemCalldata(certified, verdict.eta, verdict.minSegment,
      encodeHistory(genesisHead(domain, c.K), ordinaryGaps.slice(0, count)));
    const tx = await signTx(signer, { chainId, nonce, data, to: c.vault, value: 0n, gas: 24_000_000n,
      maxFeePerGas: 2n * baseFee + priority, maxPriorityFeePerGas: priority });
    signedOrdinaryBytes.push(tx.raw.length);
  }
  if (archiveSegments >= 1026) {
    assert(signedOrdinaryBytes.every(length => length > 524_288), 'both ordinary endpoints must exceed the signed byte cap');
  }
  if (peakRestore) await awaitLoadFile('archive-result.json');
  const beforePayout = erc20 ? await custodySnapshot() : undefined;
  const finalWindow = await startCalibrationWindow();
  const packet = await completed.session.gaps('redeemRecovered', cursor.trust, cursor.receipt,
    { seq: cursor.seq, cursor: { next: cursor.next, head: cursor.head } }, []);
  await certifyReceipt('offline-paid', await send('offline-paid', vault, packet.calldata, 0n, '0x1', signer, 24_000_000n, packet.requiredSignerEpoch),
    c.vault, paid, 0, 1 + Number(erc20));
  await finishCalibrationWindow('final-settlement', finalWindow);
  if (releaseCalibration) json('offline-paid.shape.json', packet.shape);
  const final = await reader.vaultState(c.vault);
  assert.equal(await assetBalance(c.vault), BigInt(backup.initialBalance) + BigInt(backup.value) - amount);
  assert.equal(await assetBalance(recipient), BigInt(backup.recipientBefore) + amount);
  assert.equal(final.outstanding, BigInt(backup.initialBalance) + BigInt(backup.value) - amount);
  assert.equal(final.segment, cursor.next);
  assert.equal(final.population, 1n);
  assert.equal(hex(final.head), hex(cursor.head));
  json('offline-result.json', { eta: hex(verdict.eta), holderPID: backup.holderPID, relayerPID: process.pid,
    relayerOS: process.platform,
    consumedOperationsAtRestore: checkpoint.from, session: hex(completed.session.id), progressCalls: completed.prior.seq,
    amount, liability: final.outstanding, head: hex(final.head), segment: final.segment,
    verifiedGapCount: ordinaryGaps.length, certifiedAdvanceMs: Date.now() - started, advanceCalls, queuedProofsAtStart,
    signedOrdinaryBytes, initialBacklog, finalBacklog: Number(final.segment - cursor.next) });
  if (erc20) {
    const after = await custodySnapshot();
    assert.equal(after.outstanding - beforePayout!.outstanding, -amount);
    json('offline-paid.custody.json', { before: beforePayout, after, qDelta: -amount,
      recipientBefore: backup.recipientBefore, recipientAfter: await assetBalance(recipient) });
    const funding = JSON.parse(readFileSync(join(out, 'relayer-funding.json'), 'utf8'));
    assert.equal(funding.payer, hex(signer.address));
    const runCalls = Array.from({ length: Number(completed.prior.seq) }, (_, i) => 'offline-run-' + (i + 1));
    const path = [...runCalls, ...advanceCalls.map(a => a.label), 'offline-paid'];
    const costs = path.map((label, index) => {
      const limit = JSON.parse(readFileSync(join(evidenceDir, label + '.submitted.json'), 'utf8'));
      const used = JSON.parse(readFileSync(join(evidenceDir, label + '.cost.json'), 'utf8'));
      assert.equal(limit.hash, used.tx);
      assert.equal(limit.payer, funding.payer);
      assert.equal(BigInt(limit.nonce), BigInt(index));
      return { observedFee: BigInt(used.paidFee), upperBid: BigInt(limit.gasLimit) * BigInt(limit.maxFeePerGas) };
    });
    const totals = (count: number, throughGaps: bigint) => ({
      throughGaps, calls: path.slice(0, count),
      observedFees: costs.slice(0, count).reduce((total, cost) => total + cost.observedFee, 0n),
      upperBids: costs.slice(0, count).reduce((total, cost) => total + cost.upperBid, 0n),
    });
    const boundary = advanceCalls.findIndex(a => a.verifiedThrough === '64');
    json('reserve-observations.json', {
      checkpoint64: boundary < 0 ? null : totals(runCalls.length + boundary + 1, 64n),
      throughPayout: totals(path.length, cursor.next),
      fundedRelayer: funding.tx, funded: funding.balance, wholePathBoundQualified: false,
    });
    await settleErc20Siblings(cursor.next, genesisHead(domain, c.K));
  }
}

async function settleErc20Siblings(segment: bigint, h0: Uint8Array) {
  evidenceDir = out;
  const seals = Array.from({ length: Number(segment) }, (_, i) => {
    const path = join(out, 'offline-load', 'seal-' + i + '.locator.json');
    const log = JSON.parse(readFileSync(path, 'utf8'));
    // The authenticated SegmentSealed data contains ABI(headBefore, headAfter, bytes IDs).
    const data = bytes(log.data);
    const packed = data.subarray(128);
    assert.equal(packed.length, Number(c.K) * 32);
    return GapTree.build(Array.from({ length: Number(c.K) }, (_, j) => packed.subarray(j * 32, (j + 1) * 32)))!;
  });
  for (const label of ['ordinary', 'retry']) {
    const backup = JSON.parse(readFileSync(join(keys, label + '.private.json'), 'utf8'));
    assert.notEqual(process.pid, backup.holderPID);
    const recipient = bytes(backup.recipient);
    const evidence = appendTransfer(bytes(backup.token), bytes(backup.signedBurn),
      await certifyChecked(agg, bytes(backup.certification)));
    const trust = await trustFor(tokenUcs(evidence));
    const v = await verifyReturn(gamma, evidence, trust, PRODUCTION_PARAMS);
    const amount = BigInt(backup.amount);
    assert.equal(v.amount, amount);
    assert.equal(hex(v.recipient), hex(recipient));
    assert.equal(v.minSegment, 0n);
    const gaps = seals.map(tree => {
      const proof = tree.prove(v.eta);
      assert(proof, 'test burn already paid');
      return proof;
    });
    const calldata = redeemCalldata(evidence, v.eta, v.minSegment, encodeHistory(h0, gaps));
    const required = signerEpoch(tokenUcs(evidence));
    const before = await custodySnapshot();
    const balanceBefore = await assetBalance(recipient);
    const operator = new LocalKeySigner(bytes(readFileSync(join(keys, 'operator-key'), 'utf8')));
    if (label === 'retry') {
      await send('block-recipient', tokenAddress!, callData('setBlocked(address)', hex(recipient)), 0n, '0x1', operator);
      const estimate = await reader.estimateGas({ to: c.vault, from: operator.address, data: calldata, value: 0n });
      assert(!('gas' in estimate));
      assert(estimate.revert);
      assert.equal(hex(estimate.revert.subarray(0, 4)), hex(HE(ascii('TokenCallFailed()')).subarray(0, 4)));
      const failure = await send('payout-failure', vault, calldata, 0n, '0x0', operator, 24_000_000n, required);
      assert.deepEqual(failure.logs, []);
      for (let attempt = 0; ; attempt++) {
        try {
          const archive = receiptReaders.at(-1)!;
          await archive.verifyFailedReceipt(bytes(failure.transactionHash), c, trust, failure);
          break;
        } catch (error) {
          if (attempt === 29) throw error;
          await delay(1000);
        }
      }
      assert.deepEqual(await custodySnapshot(), before);
      assert.equal(await assetBalance(recipient), balanceBefore);
      json('payout-failure.custody.json', { before, after: before, qDelta: 0, payer: hex(operator.address),
        certifiedFailedReceipt: true, estimate, signedRecipient: hex(recipient) });
      await send('unblock-recipient', tokenAddress!,
        callData('setBlocked(address)', '0x' + '00'.repeat(20)), 0n, '0x1', operator);
      assert.notEqual(hex(signer.address), hex(operator.address));
    }
    const mined = await send(label + '-paid', vault, calldata, 0n, '0x1', signer, 24_000_000n, required);
    await certifyReceipt(label + '-paid', mined, c.vault, { topics: [TOPIC.Paid, v.eta,
      concat(new Uint8Array(12), recipient)], data: u256(amount) }, 0, 2);
    const after = await custodySnapshot();
    const balanceAfter = await assetBalance(recipient);
    assert.equal(after.outstanding - before.outstanding, -amount);
    assert.equal(after.balance - before.balance, -amount);
    assert.equal(balanceAfter - balanceBefore, amount);
    json(label + '-paid.custody.json', { before, after, qDelta: -amount, balanceBefore, balanceAfter,
      recipient: hex(recipient), payer: hex(signer.address), eta: hex(v.eta), sealCount: segment });
  }
  assert.equal((await custodySnapshot()).outstanding, 0n);
  await verifyIsolation('after');
}
