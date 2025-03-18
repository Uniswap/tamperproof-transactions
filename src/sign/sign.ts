import { createSign, getHashes, KeyObject } from "crypto";
import { SigningAlgorithm } from "../algorithms";

export function sign(
    { data, privateKey, algorithm }: { data: string, privateKey: KeyObject, algorithm: SigningAlgorithm }
): string {
    // verify that the algorithm is supported
    if (!getHashes().includes(algorithm)) {
        throw new Error(`Algorithm ${algorithm} is not supported`);
    }
    const signer = createSign(algorithm);
    signer.update(data);
    return signer.sign(privateKey, "hex");
}