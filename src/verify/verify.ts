import { createSign, createVerify, KeyObject } from "crypto";
import { SigningAlgorithm } from "../algorithms";

import { resolveTxt } from "dns";


export const PREFIX = "TWIT=";

export async function verifyAsyncDns(
    calldata: string, signature: string, host: string, id?: number
): Promise<boolean> {
    let txtRecords: string[] = [];
    resolveTxt(
        host,
        res => {
            txtRecords = res as string[];
        }
    );

    let twistRecord: string | undefined;
    txtRecords.forEach(record => {
        if (record.startsWith(PREFIX)) {
            twistRecord = record;
        }
    });

    if (!twistRecord) {
        throw new Error(`No TXT record found for host ${host}`);
    }

    return verifyAsyncJson(calldata, signature, twistRecord.slice(PREFIX.length)[0], id);

    // const publicKey = await fetch(url).then(res => res.json());
    // return verifySync(calldata, signature, publicKey.algorithm, publicKey.key);
}

export async function verifyAsyncJson(
    calldata: string, signature: string, url: string, id?: number
): Promise<boolean> {
    const publicKeys = await fetch(url).then(res => res.publicKeys);
    const publicKey = id ? publicKeys[id] : publicKeys[0];

    return verifySync(calldata, signature, publicKey.algorithm, publicKey.key);
}

export function verifySync(
    calldata: string, signature: string, algorithm: SigningAlgorithm, publicKey: KeyObject
): boolean {
    const verify = createVerify(algorithm);
    verify.update(calldata);
    verify.end();
    return verify.verify(publicKey, signature, "hex");
}