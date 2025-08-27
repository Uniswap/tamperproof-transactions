const webcrypto = globalThis.crypto;
import {
  SIGNING_ALGORITHM_CONFIG,
  SIGNING_ALGORITHM_IMPORT_PARAMS,
} from './algorithms';
import { toHex, fromHex } from './utils/hex';
import { serializeRequestPayload } from './utils/canonicalJson';
import { ERROR_ALGORITHM_NOT_SUPPORTED } from './constants/errors';

const encoder = new TextEncoder();
const PRIVATE_KEY_FORMAT = 'pkcs8';

export async function sign(
  data: string | object,
  privateKey: string,
  algorithm: keyof typeof SIGNING_ALGORITHM_CONFIG
): Promise<string> {
  if (
    typeof algorithm !== 'string' ||
    !Object.prototype.hasOwnProperty.call(SIGNING_ALGORITHM_CONFIG, algorithm)
  ) {
    throw new Error(ERROR_ALGORITHM_NOT_SUPPORTED(algorithm));
  }

  const bufferData =
    typeof data === 'string'
      ? encoder.encode(data)
      : serializeRequestPayload(data);

  const key = await webcrypto.subtle.importKey(
    PRIVATE_KEY_FORMAT,
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

  return `0x${toHex(signature)}`;
}
