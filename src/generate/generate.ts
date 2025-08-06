import { SigningAlgorithmName } from '../algorithms';
export type PublicKey = {
  key: string;
  algorithm: SigningAlgorithmName;
};

export function generate(...publicKeys: PublicKey[]): string {
  const pubKeys: object[] = publicKeys.map((publicKey, index) => {
    return {
      // EIP states 1-indexed string
      id: (index + 1).toString(),
      alg: publicKey.algorithm,
      publicKey: `0x${publicKey.key}`, // Add 0x prefix
    };
  });
  return JSON.stringify({
    publicKeys: pubKeys,
  });
}
