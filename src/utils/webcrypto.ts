import { webcrypto as nodeWebcrypto } from 'node:crypto';

function resolveWebcrypto(): Crypto {
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  return nodeWebcrypto as unknown as Crypto;
}

export const webcrypto = resolveWebcrypto();
