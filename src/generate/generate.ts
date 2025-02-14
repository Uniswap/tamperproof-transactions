export type PublicKey = {
    key: string,
    algorithm: string
}

export function generate(...publicKeys: PublicKey[]): string {
    return "Not implemented";
}