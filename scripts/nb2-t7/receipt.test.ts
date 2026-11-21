import assert from 'node:assert/strict';
import test from 'node:test';
import { buildTrie } from './sdk/nb2/mpt.js';
import { rlpIndexKey } from './sdk/nb2/rlp.js';
import { encodeReceiptJson, HttpJsonRpc, WalletError, type ReceiptJson } from './sdk/nb2/rpc.js';
import type { Header } from './sdk/nb2/header.js';
import { firstAvailableReceipt, receiptArchive } from './receipt.js';

const receipt: ReceiptJson = {
  status: '0x1', cumulativeGasUsed: '0x5208', logsBloom: '0x' + '00'.repeat(256), logs: [],
  blockHash: '0x' + '11'.repeat(32), blockNumber: '0x37', transactionIndex: '0x0',
  transactionHash: '0x' + '22'.repeat(32),
};
const trie = buildTrie([[rlpIndexKey(0n), encodeReceiptJson(receipt)]], rlpIndexKey(0n));
const header = { number: 55n, receiptsRoot: trie.root } as Header;
const hash = new Uint8Array(32);

test('a size-limited receipt gateway falls through to a verified alternate', async () => {
  const calls: string[] = [];
  const archive = (name: string, status: number) => receiptArchive(new HttpJsonRpc('http://127.0.0.1:1', {
    fetch: async (_url, init) => {
      calls.push(name + ':' + JSON.parse(String(init?.body)).method);
      return new Response(JSON.stringify(status === 413 ? { error: 'too large' } : { result: [receipt] }), { status });
    },
  }));
  const archives = [archive('primary', 413), archive('alternate', 200)];
  const found = await firstAvailableReceipt(archives, async (reader, source) =>
    ({ source, path: await reader.receiptPath(header, hash, 0n) }));
  assert.deepEqual(found, { source: 1, path: trie.path });
  assert.deepEqual(calls, ['primary:eth_getBlockReceipts', 'alternate:eth_getBlockReceipts']);

  calls.length = 0;
  const badHeader = { ...header, receiptsRoot: new Uint8Array(32) };
  await assert.rejects(firstAvailableReceipt([archives[1], archives[0]], reader =>
    reader.receiptPath(badHeader, hash, 0n)), (e: unknown) =>
    e instanceof WalletError && e.reason === 'ProviderFault' && /receiptsRoot/.test(e.message));
  assert.deepEqual(calls, ['alternate:eth_getBlockReceipts']);
});
