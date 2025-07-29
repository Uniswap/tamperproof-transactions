import { webcrypto } from 'crypto';
import {
  SigningAlgorithmName,
  isSigningAlgorithm,
  SIGNING_ALGORITHM_CONFIG,
} from '../algorithms';

import dns from 'dns';
const dnsPromises = dns.promises;

export const PREFIX = 'TWIST=';

export async function verifyAsyncDns(
  calldata: string,
  signature: string,
  host: string,
  id?: number
): Promise<boolean> {
  // Convert callback-style to Promise
  const records = await dnsPromises.resolveTxt(host);

  if (!records || records.length === 0) {
    throw new Error(`No TXT records found for host ${host}`);
  }

  const [address] = records;
  let twistRecord: string | undefined;

  // return the first record that starts with the prefix
  for (const record of address) {
    if (record.startsWith(PREFIX)) {
      twistRecord = record.slice(PREFIX.length);
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
    Buffer.from(publicKey.key, 'hex'),
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
  publicKey: webcrypto.CryptoKey
): Promise<boolean> {
  const encoder = new TextEncoder();
  const bufferData = encoder.encode(calldata);

  const signatureBuffer = Buffer.from(signature, 'hex');
  const signatureUint8Array = new Uint8Array(signatureBuffer);

  return await verifyInternal(
    bufferData,
    signatureUint8Array,
    algorithm,
    publicKey
  );
}

export async function verifyInternal(
  calldata: ArrayBufferView | ArrayBuffer,
  signature: ArrayBufferView | ArrayBuffer,
  algorithm: SigningAlgorithmName,
  publicKey: webcrypto.CryptoKey
): Promise<boolean> {
  return await webcrypto.subtle.verify(
    SIGNING_ALGORITHM_CONFIG[algorithm],
    publicKey,
    signature,
    calldata
  );
}
