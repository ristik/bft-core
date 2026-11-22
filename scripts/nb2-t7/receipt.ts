import { Nb2Error } from './sdk/nb2/errors.js';
import { EvmReader, RpcError, WalletError, type JsonRpc } from './sdk/nb2/rpc.js';

class BlockReceiptsTooLarge extends Error {}

export function receiptArchive(rpc: JsonRpc): EvmReader {
  return new EvmReader({
    async call<T>(method: string, params: unknown[]): Promise<T> {
      try {
        return await rpc.call<T>(method, params);
      } catch (e) {
        // Preserve this method-specific availability error before receiptPath converts it
        // to ProviderFault, which also covers fatal receipt-root mismatches.
        if (method === 'eth_getBlockReceipts' && e instanceof RpcError && e.status === 413) {
          throw new BlockReceiptsTooLarge(e.message);
        }
        throw e;
      }
    },
  });
}

export async function firstAvailableReceipt<T>(
  archives: readonly EvmReader[], acquire: (archive: EvmReader, source: number) => Promise<T>,
): Promise<T | undefined> {
  for (const [source, archive] of archives.entries()) {
    try {
      return await acquire(archive, source);
    } catch (e) {
      const unavailable = e instanceof BlockReceiptsTooLarge
        || (e instanceof WalletError && ['CompanionUnknown', 'EvidenceMissing'].includes(e.reason))
        || (e instanceof Nb2Error && e.rule === 'EvidencePruned')
        || (e instanceof RpcError && (e.status === 429 || e.status >= 500))
        || (e instanceof TypeError && e.message === 'fetch failed')
        || (e instanceof Error && e.name === 'AbortError');
      if (!unavailable) throw e;
    }
  }
}
