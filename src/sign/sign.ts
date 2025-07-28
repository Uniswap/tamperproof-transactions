import { webcrypto } from 'crypto';
import { SIGNING_ALGORITHM_CONFIG, isSigningAlgorithm } from '../algorithms';

export async function sign(
  data: string,
  privateKey: webcrypto.CryptoKey,
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
  return Buffer.from(signature).toString('hex');
}
