import { createSign, createVerify, KeyObject } from "crypto";
import { SigningAlgorithm } from "../algorithms";

export async function verifyAsync(
    {
        calldata, signature, algorithm, url
    }: {
        calldata: string, signature: string, algorithm: SigningAlgorithm, url?: string
    }
): Promise<boolean> {
    return false
    // const publicKey = await fetch(url).then(res => res.json());

    // // using public key, verify the signature
    // const verify = createVerify(algorithm);
    // verify.update(calldata);
    // verify.end();
    // return verify.verify(publicKey, signature, "hex");
}

export function verifySync(
    {
        calldata, signature, algorithm, publicKey
    }: {
        calldata: string, signature: string, algorithm: SigningAlgorithm, publicKey: KeyObject
    }
): boolean {
    const verify = createVerify(algorithm);
    verify.update(calldata);
    verify.end();
    return verify.verify(publicKey, signature, "hex");
}