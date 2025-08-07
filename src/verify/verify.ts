const webcrypto = globalThis.crypto;
import { isSigningAlgorithm, SIGNING_ALGORITHM_CONFIG } from '../algorithms';
import { fromHex } from '../utils/hex';
import { processTxtRecordData } from '../utils/txtRecord';
import { DohResolver } from 'dohjs';

export const PREFIX = 'TWIST=';
const quadOneResolver = new DohResolver('https://1.1.1.1/dns-query');
const TIMEOUT = 1000;

export async function verifyAsyncDns(
  calldata: string,
  signature: string,
  host: string,
  id: string,
  thisResolver: DohResolver = quadOneResolver
): Promise<boolean> {
  // Use DNS over HTTPS to resolve TXT records
  const response = await thisResolver.query(
    host,
    'TXT',
    'GET',
    {
      Accept: 'application/dns-message',
    },
    TIMEOUT
  );

  if (!response.answers || response.answers.length === 0) {
    throw new Error(`No TXT records found for host ${host}`);
  }

  let twistRecord: string | undefined;

  // Search through all TXT record answers for the first one that starts with the prefix
  for (const answer of response.answers) {
    const recordData = processTxtRecordData(answer.data);

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
  id: string
): Promise<boolean> {
  const response = await fetch(url, { redirect: 'error' });
  const data = (await response.json()) as {
    publicKeys: Array<{
      id: string;
      alg: string;
      publicKey: string;
    }>;
  };
  const matchingKeys = data.publicKeys.filter(pk => pk.id === id.toString());

  if (matchingKeys.length === 0) {
    throw new Error(`Public key with id ${id} not found`);
  }

  if (matchingKeys.length > 1) {
    throw new Error(
      `Multiple public keys found with id ${id}. Key IDs must be unique.`
    );
  }

  const publicKey = matchingKeys[0];

  const publicKeyObject = await webcrypto.subtle.importKey(
    'raw',
    fromHex(publicKey.publicKey),
    { name: publicKey.alg },
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
