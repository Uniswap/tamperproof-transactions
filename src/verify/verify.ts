import { createVerify, KeyObject } from "crypto";
import { SigningAlgorithm } from "../algorithms";

import dns from "dns";
const dnsPromises = dns.promises;


export const PREFIX = "TWIST=";

export async function verifyAsyncDns(
    calldata: string, signature: string, host: string, id?: number
): Promise<boolean> {
    // Convert callback-style to Promise
    const records = await dnsPromises.resolveTxt(host);

    if (!records || records.length === 0) {
        throw new Error(`No TXT records found for host ${host}`);
    }

    const [address] = records;
    let twistRecord: string | undefined;

    // return the first record that starts with the prefix
    for (const record of address) {
        if (record.startsWith(PREFIX)) {
            twistRecord = record.slice(PREFIX.length);
            break;
        }
    }

    if (!twistRecord) {
        throw new Error(`No TXT record found with prefix ${PREFIX} for host ${host}`);
    }

    return await verifyAsyncJson(calldata, signature, twistRecord, id);
}

export async function verifyAsyncJson(
    calldata: string, signature: string, url: string, id?: number
): Promise<boolean> {
    // Fetch and parse the public keys from the URL, selecting either the specified key by ID or the first key
    const response = await fetch(url);
    const publicKeys = await response.json() as Array<{ algorithm: SigningAlgorithm, key: KeyObject }>;
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