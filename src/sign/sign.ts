const webcrypto = globalThis.crypto;
import { SIGNING_ALGORITHM_CONFIG, isSigningAlgorithm } from '../algorithms';

export async function sign(
  data: string,
  privateKey: CryptoKey,
  algorithm: keyof typeof SIGNING_ALGORITHM_CONFIG
): Promise<string> {
  // verify that the algorithm is supported
  if (!isSigningAlgorithm(algorithm)) {
    throw new Error(`Algorithm ${algorithm as string} is not supported`);
  }

  const encoder = new TextEncoder();
  const bufferData = encoder.encode(data);

  const signature = await webcrypto.subtle.sign(
    SIGNING_ALGORITHM_CONFIG[algorithm],
    privateKey,
    bufferData
  );

  const uint8Array = new Uint8Array(signature);
  return Array.from(uint8Array, byte =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}
