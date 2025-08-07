import { SigningAlgorithmName, isSigningAlgorithm } from '../algorithms';
export type PublicKey = {
  key: string;
  algorithm: SigningAlgorithmName;
};

export function generate(...publicKeys: PublicKey[]): string {
  const pubKeys: object[] = publicKeys.map((publicKey, index) => {
    if (!isSigningAlgorithm(publicKey.algorithm)) {
      throw new Error(
        `Unsupported signing algorithm: ${String(publicKey.algorithm)}`
      );
    }

    return {
      // EIP states 1-indexed string
      id: (index + 1).toString(),
      alg: publicKey.algorithm,
      publicKey: publicKey.key.startsWith('0x')
        ? publicKey.key
        : `0x${publicKey.key}`,
    };
  });

  return JSON.stringify({
    publicKeys: pubKeys,
  });
}
