const webcrypto = globalThis.crypto;
import {
  SigningAlgorithmConfig,
  SIGNING_ALGORITHM_CONFIG,
  SIGNING_ALGORITHM_IMPORT_PARAMS,
} from '../algorithms';
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
  if (url.protocol !== 'https:') {
    throw new Error('Manifest must be fetched over HTTPS');
  }

  const response = await fetch(url, { redirect: 'error' });

  const ct = response.headers.get('content-type') || '';
  if (!/^application\/json(?:;|$)/i.test(ct)) {
    throw new Error('Manifest Content-Type must be application/json');
  }

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

  if (!Object.hasOwn(SIGNING_ALGORITHM_IMPORT_PARAMS, publicKey.alg)) {
    throw new Error(`Algorithm is not supported: ${String(publicKey.alg)}`);
  }
  const algorithmKey =
    publicKey.alg as keyof typeof SIGNING_ALGORITHM_IMPORT_PARAMS;

  const publicKeyObject = await webcrypto.subtle.importKey(
    'spki',
    fromHex(publicKey.publicKey),
    SIGNING_ALGORITHM_IMPORT_PARAMS[algorithmKey],
    false,
    ['verify']
  );

  return await verify(calldata, signature, publicKeyObject, algorithmKey);
}

export async function verify(
  calldata: string,
  signature: string,
  publicKey: CryptoKey,
  alg: keyof typeof SIGNING_ALGORITHM_CONFIG
): Promise<boolean> {
  const encoder = new TextEncoder();
  const bufferData = encoder.encode(calldata);

  const signatureBytes = fromHex(signature);

  if (!Object.hasOwn(SIGNING_ALGORITHM_CONFIG, alg)) {
    throw new Error(`Algorithm is not supported: ${String(alg)}`);
  }
  const algConfig: SigningAlgorithmConfig = SIGNING_ALGORITHM_CONFIG[alg];

  // Use algorithm params directly from configuration
  const verifyParams = algConfig as unknown as
    | Algorithm
    | EcdsaParams
    | RsaPssParams;

  let signatureForVerify: Uint8Array = signatureBytes;
  if (algConfig.name === 'ECDSA') {
    // Only accept raw r||s for ECDSA signatures and pass raw to verify
    const coordLen = algConfig.ecdsaCoordinateLength!;
    if (signatureBytes.length !== coordLen * 2) {
      return false;
    }
    signatureForVerify = signatureBytes;
  }

  const verified = await webcrypto.subtle.verify(
    verifyParams,
    publicKey,
    signatureForVerify,
    bufferData
  );
  return verified;
}
