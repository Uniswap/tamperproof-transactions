const webcrypto = globalThis.crypto;
import {
  SIGNING_ALGORITHM_CONFIG,
  SIGNING_ALGORITHM_IMPORT_PARAMS,
} from '../algorithms';
import { toHex, fromHex } from '../utils/hex';

const encoder = new TextEncoder();

export async function sign(
  data: string,
  privateKey: string,
  algorithm: keyof typeof SIGNING_ALGORITHM_CONFIG
): Promise<string> {
  if (
    typeof algorithm !== 'string' ||
    !Object.prototype.hasOwnProperty.call(SIGNING_ALGORITHM_CONFIG, algorithm)
  ) {
    throw new Error(`Algorithm is not supported: ${String(algorithm)}`);
  }

  const bufferData = encoder.encode(data);

  const key = await webcrypto.subtle.importKey(
    'pkcs8',
    fromHex(privateKey),
    SIGNING_ALGORITHM_IMPORT_PARAMS[algorithm],
    false,
    ['sign']
  );

  const signature = await webcrypto.subtle.sign(
    SIGNING_ALGORITHM_CONFIG[algorithm],
    key,
    bufferData
  );

  return toHex(signature);
}
