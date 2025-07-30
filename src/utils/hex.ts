export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.replace(/\s/g, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: length must be even');
  }

  const bytes = [];
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.slice(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex string: ${cleanHex}`);
    }
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
}

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
  const uint8Array =
    buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  return Array.from(uint8Array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromBase64(base64: string): Uint8Array {
  const cleanBase64 = base64.replace(/\s/g, '');

  const binaryString = atob(cleanBase64);
  const bytes = new Uint8Array(binaryString.length);

  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}
