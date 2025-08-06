const webcrypto = globalThis.crypto;
import {
  SigningAlgorithmName,
  isSigningAlgorithm,
  SIGNING_ALGORITHM_CONFIG,
} from '../algorithms';
import { fromHex } from '../utils/hex';
import doh from 'dohjs';

export const PREFIX = 'TWIST=';
const resolver = new doh.DohResolver('https://1.1.1.1/dns-query');

export async function verifyAsyncDns(
  calldata: string,
  signature: string,
  host: string,
  id?: number
): Promise<boolean> {
  // Use DNS over HTTPS to resolve TXT records
  const response = await resolver.query(host, 'TXT');

  if (!response.answers || response.answers.length === 0) {
    throw new Error(`No TXT records found for host ${host}`);
  }

  let twistRecord: string | undefined;

  // Search through all TXT record answers for one that starts with the prefix
  for (const answer of response.answers) {
    const recordData = answer.data.toString();
    if (recordData.startsWith(PREFIX)) {
      twistRecord = recordData.slice(PREFIX.length);
      break;
    }
  }

  if (!twistRecord) {
    throw new Error(
      `No TXT record found with prefix ${PREFIX} for host ${host}`
    );
  }

  return await verifyAsyncJson(calldata, signature, twistRecord, id);
}

export async function verifyAsyncJson(
  calldata: string,
  signature: string,
  url: string,
  id?: number
): Promise<boolean> {
  // Fetch and parse the public keys from the URL, selecting either the specified key by ID or the first key
  const response = await fetch(url);
  const publicKeys = (await response.json()) as Array<{
    algorithm: string;
    key: string;
  }>;
  const publicKey = id ? publicKeys[id] : publicKeys[0];

  if (!isSigningAlgorithm(publicKey.algorithm)) {
    throw new Error(`Unsupported algorithm: ${publicKey.algorithm}`);
  }

  const publicKeyObject = await webcrypto.subtle.importKey(
    'raw',
    fromHex(publicKey.key),
    { name: publicKey.algorithm },
    false,
    ['verify']
  );

  return await verify(
    calldata,
    signature,
    publicKey.algorithm,
    publicKeyObject
  );
}

export async function verify(
  calldata: string,
  signature: string,
  algorithm: SigningAlgorithmName,
  publicKey: CryptoKey
): Promise<boolean> {
  const encoder = new TextEncoder();
  const bufferData = encoder.encode(calldata);

  const signatureUint8Array = fromHex(signature);

  return await webcrypto.subtle.verify(
    SIGNING_ALGORITHM_CONFIG[algorithm],
    publicKey,
    signatureUint8Array,
    bufferData
  );
}
