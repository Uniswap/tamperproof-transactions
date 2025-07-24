export const SIGNING_ALGORITHMS = {
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
