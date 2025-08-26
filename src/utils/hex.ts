import {
  ERROR_INVALID_HEX_LENGTH_EVEN,
  ERROR_INVALID_HEX_STRING,
  ERROR_NO_BASE64_DECODER,
} from '../constants/errors';
export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/i, '').replace(/\s/g, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error(ERROR_INVALID_HEX_LENGTH_EVEN);
  }
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new Error(ERROR_INVALID_HEX_STRING(cleanHex));
  }
  const out = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    out[i / 2] = Number.parseInt(cleanHex.slice(i, i + 2), 16);
  }
  return out;
}

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
  const uint8Array =
    buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  return Array.from(uint8Array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function normalizeHex(input: string, with0x = true): string {
  const cleaned = input.replace(/^0x/i, '').replace(/\s/g, '');
  const padded = cleaned.length % 2 === 1 ? `0${cleaned}` : cleaned;
  const bytes = fromHex(padded);
  const hex = toHex(bytes);
  return with0x ? `0x${hex}` : hex;
}

export function fromBase64(base64: string): Uint8Array {
  const clean = base64.replace(/\s/g, '');
  // Browser: use atob when available
  if (typeof globalThis.atob === 'function') {
    const binaryString = globalThis.atob(clean);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  // Node: use Buffer when available without forcing bundler polyfills
  const NodeBuffer = (
    globalThis as unknown as {
      Buffer?: typeof Buffer;
    }
  ).Buffer;
  if (NodeBuffer && typeof NodeBuffer.from === 'function') {
    return new Uint8Array(NodeBuffer.from(clean, 'base64'));
  }
  throw new Error(ERROR_NO_BASE64_DECODER);
}
