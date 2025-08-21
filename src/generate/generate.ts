import { SIGNING_ALGORITHM_CONFIG } from '../algorithms';
import { normalizeHex } from '../utils/hex';
export type PublicKey = {
  key: string; // hex string
  algorithm: keyof typeof SIGNING_ALGORITHM_CONFIG;
};

export function generate(...publicKeys: PublicKey[]): string {
  const pubKeys: object[] = publicKeys.map((publicKey, index) => {
    if (!Object.keys(SIGNING_ALGORITHM_CONFIG).includes(publicKey.algorithm)) {
      throw new Error(
        `Unsupported signing algorithm: ${String(publicKey.algorithm)}`
      );
    }

    return {
      // EIP states 1-indexed string
      id: (index + 1).toString(),
      alg: publicKey.algorithm,
      publicKey: normalizeHex(publicKey.key),
    };
  });

  return JSON.stringify({
    publicKeys: pubKeys,
  });
}
