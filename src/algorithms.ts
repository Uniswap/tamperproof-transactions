export type SigningAlgorithmConfig = {
  name: string;
  hash?: { name: string };
  saltLength?: number;
};

export enum SigningAlgorithmName {
  ECDSA = 'ECDSA',
  Ed25519 = 'Ed25519',
  RSA_PSS = 'RSA-PSS',
  RSASSA_PKCS1_v1_5 = 'RSASSA-PKCS1-v1_5',
  Ed448 = 'Ed448',
}

export const SIGNING_ALGORITHM_CONFIG: Record<
  SigningAlgorithmName,
  SigningAlgorithmConfig
> = {
  ECDSA: {
    name: 'ECDSA',
    hash: { name: 'SHA-256' },
  },
  Ed25519: { name: 'Ed25519' },
  'RSA-PSS': {
    name: 'RSA-PSS',
    hash: { name: 'SHA-256' },
    saltLength: 32,
  },
  'RSASSA-PKCS1-v1_5': {
    name: 'RSASSA-PKCS1-v1_5',
  },
  Ed448: {
    name: 'Ed448',
  },
} as const;

export function isSigningAlgorithm(
  maybe: string
): maybe is SigningAlgorithmName {
  return maybe in SIGNING_ALGORITHM_CONFIG;
}
