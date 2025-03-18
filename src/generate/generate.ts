import { SigningAlgorithm } from "../algorithms";
export type PublicKey = {
    key: string,
    algorithm: SigningAlgorithm
}

export function generate(...publicKeys: PublicKey[]): string {
    let pubKeys: object[] = publicKeys.map((publicKey, index) => {
        return {
            id: index,
            alg: publicKey.algorithm,
            publicKey: publicKey.key
        }
    });
    return JSON.stringify(
        {
            publicKeys: pubKeys
        }
    )
}