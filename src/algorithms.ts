export type SigningAlgorithmConfig = {
  name: string;
  hash?: { name: string };
  saltLength?: number;
  namedCurve?: string;
  ecdsaCoordinateLength?: number;
};

export const SIGNING_ALGORITHM_IMPORT_PARAMS = {
  ES256: {
    name: 'ECDSA',
    namedCurve: 'P-256',
  } as EcKeyImportParams,
  ES384: {
    name: 'ECDSA',
    namedCurve: 'P-384',
  } as EcKeyImportParams,
  ES512: {
    name: 'ECDSA',
    namedCurve: 'P-521',
  } as EcKeyImportParams,
  EdDSA: {
    name: 'Ed25519',
  } as Algorithm,
  PS256: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-256' },
  } as RsaHashedImportParams,
  PS384: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-384' },
  } as RsaHashedImportParams,
  PS512: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-512' },
  } as RsaHashedImportParams,
  RS256: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-256' },
  } as RsaHashedImportParams,
  RS384: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-384' },
  } as RsaHashedImportParams,
  RS512: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-512' },
  } as RsaHashedImportParams,
};

export const SIGNING_ALGORITHM_CONFIG = {
  ES256: {
    name: 'ECDSA',
    hash: { name: 'SHA-256' },
    namedCurve: 'P-256',
    ecdsaCoordinateLength: 32,
  },
  ES384: {
    name: 'ECDSA',
    hash: { name: 'SHA-384' },
    namedCurve: 'P-384',
    ecdsaCoordinateLength: 48,
  },
  ES512: {
    name: 'ECDSA',
    hash: { name: 'SHA-512' },
    namedCurve: 'P-521',
    ecdsaCoordinateLength: 66,
  },
  EdDSA: {
    name: 'Ed25519',
  },
  PS256: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-256' },
    saltLength: 32,
  },
  PS384: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-384' },
    saltLength: 48,
  },
  PS512: {
    name: 'RSA-PSS',
    hash: { name: 'SHA-512' },
    saltLength: 64,
  },
  RS256: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-256' },
  },
  RS384: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-384' },
  },
  RS512: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-512' },
  },
} satisfies Record<string, SigningAlgorithmConfig>;

export function getVerifyParamsForPublicKey(
  publicKey: CryptoKey
): Algorithm | EcdsaParams | RsaPssParams {
  const algoName = (publicKey.algorithm as Algorithm).name;
  if (algoName === 'ECDSA') {
    const curve = (publicKey.algorithm as EcKeyAlgorithm).namedCurve;
    const hashName =
      curve === 'P-256' ? 'SHA-256' : curve === 'P-384' ? 'SHA-384' : 'SHA-512';
    return { name: 'ECDSA', hash: { name: hashName } } as EcdsaParams;
  }
  if (algoName === 'RSA-PSS') {
    const hashName = (publicKey.algorithm as RsaHashedKeyAlgorithm).hash?.name;
    const saltLength = ((): number => {
      if (hashName === 'SHA-256') return 32;
      if (hashName === 'SHA-384') return 48;
      if (hashName === 'SHA-512') return 64;
      const match = /SHA-(\d+)/.exec(hashName ?? '');
      if (match) {
        const bits = Number(match[1]);
        if (!Number.isNaN(bits)) return Math.floor(bits / 8);
      }
      return 32;
    })();
    return { name: 'RSA-PSS', saltLength } as RsaPssParams;
  }
  if (algoName === 'RSASSA-PKCS1-v1_5') {
    return { name: 'RSASSA-PKCS1-v1_5' } as Algorithm;
  }
  return { name: algoName } as Algorithm;
}
