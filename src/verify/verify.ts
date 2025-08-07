const webcrypto = globalThis.crypto;
import { isSigningAlgorithm, SIGNING_ALGORITHM_CONFIG } from '../algorithms';
import { fromHex } from '../utils/hex';
import { DohResolver } from 'dohjs';

export const PREFIX = 'TWIST=';
const quadOneResolver = new DohResolver('https://1.1.1.1/dns-query');
const TIMEOUT = 1000;

export async function verifyAsyncDns(
  calldata: string,
  signature: string,
  host: string,
  id?: number,
  thisResolver: DohResolver = quadOneResolver
): Promise<boolean> {
  // Use DNS over HTTPS to resolve TXT records
  const response = await thisResolver.query(host, 'TXT', 'GET', {}, TIMEOUT);

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

  const url = new URL(`https://${host}/${twistRecord}`);

  return await verifyAsyncJson(calldata, signature, url, id);
}

export async function verifyAsyncJson(
  calldata: string,
  signature: string,
  url: URL,
  id?: number
): Promise<boolean> {
  // Fetch and parse the public keys from the URL, selecting either the specified key by ID or the first key
  const response = await fetch(url);
  const publicKeys = (await response.json()) as Array<{
    algorithm: string;
    key: string;
  }>;
  const publicKey = id ? publicKeys[id] : publicKeys[0];

  const publicKeyObject = await webcrypto.subtle.importKey(
    'raw',
    fromHex(publicKey.key),
    { name: publicKey.algorithm },
    false,
    ['verify']
  );

  return await verify(calldata, signature, publicKeyObject);
}

export async function verify(
  calldata: string,
  signature: string,
  publicKey: CryptoKey
): Promise<boolean> {
  if (!isSigningAlgorithm(publicKey.algorithm.name)) {
    throw new Error(`Unsupported algorithm: ${publicKey.algorithm.name}`);
  }

  const encoder = new TextEncoder();
  const bufferData = encoder.encode(calldata);

  const signatureUint8Array = fromHex(signature);

  return await webcrypto.subtle.verify(
    SIGNING_ALGORITHM_CONFIG[publicKey.algorithm.name],
    publicKey,
    signatureUint8Array,
    bufferData
  );
}
