import { createSign, getHashes } from "crypto";

export enum SigningAlgorithm {
    RSA = "RSA-SHA256",
    RSA_PSS = "RSA-PSS",
    ECDSA = "SHA256"
}


export function sign(
    { data, privateKey, algorithm }: { data: string, privateKey: string, algorithm: SigningAlgorithm }
): string {
    // verify that the algorithm is supported
    if (!getHashes().includes(algorithm)) {
        throw new Error(`Algorithm ${algorithm} is not supported`);
    }
    const signer = createSign(algorithm);
    signer.update(data);
    return signer.sign(privateKey, "hex");
}