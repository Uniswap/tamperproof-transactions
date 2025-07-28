import { SigningAlgorithmConfig } from '../algorithms';
export type PublicKey = {
  key: string;
  algorithm: SigningAlgorithmConfig;
};

export function generate(...publicKeys: PublicKey[]): string {
  const pubKeys: object[] = publicKeys.map((publicKey, index) => {
    return {
      id: index,
      alg: publicKey.algorithm,
      publicKey: publicKey.key,
    };
  });
  return JSON.stringify({
    publicKeys: pubKeys,
  });
}
