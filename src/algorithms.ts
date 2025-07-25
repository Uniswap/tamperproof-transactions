export type SigningAlgorithm = {
  name: string;
  hash?: { name: string };
  saltLength?: number;
};

export const SIGNING_ALGORITHM_NAMES: Record<string, string> = {
  ECDSA: 'ECDSA',
  Ed25519: 'Ed25519',
  RSA_PSS: 'RSA-PSS',
  RSASSA_PKCS1_v1_5: 'RSASSA-PKCS1-v1_5',
  Ed448: 'Ed448',
} as const;

export const SIGNING_ALGORITHMS: Record<string, SigningAlgorithm> = {
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
): maybe is keyof typeof SIGNING_ALGORITHMS {
  return maybe in SIGNING_ALGORITHMS;
}
