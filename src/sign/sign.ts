import { webcrypto } from "crypto";
import { SIGNING_ALGORITHMS, isSigningAlgorithm } from "../algorithms";

export async function sign(
    data: string, privateKey: webcrypto.CryptoKey, algorithm: keyof typeof SIGNING_ALGORITHMS
): Promise<string> {
    // verify that the algorithm is supported
    if (!isSigningAlgorithm(algorithm)) {
        throw new Error(`Algorithm ${algorithm} is not supported`);
    }

    const encoder = new TextEncoder();
    const bufferData = encoder.encode(data);

    const signature = await webcrypto.subtle.sign(SIGNING_ALGORITHMS[algorithm], privateKey, bufferData);
    return Buffer.from(signature).toString('hex');
}