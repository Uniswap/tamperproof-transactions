import { SigningAlgorithm } from "../algorithms";
export type PublicKey = {
    key: string,
    algorithm: string
}

export function generate(...publicKeys: PublicKey[]): string {
    let pubKeys: object[] = publicKeys.map((publicKey, index) => {
        if (publicKey.algorithm in SigningAlgorithm) {
            return {
                id: index,
                alg: publicKey.algorithm,
                key: publicKey.key
            }
        } else {
            throw "Invalid algorithm";
        }

    });
    return JSON.stringify(
        {
            publicKeys: pubKeys
        }
    )
}