export function parseTxtRecord(buffer: Buffer): string {
  let result = '';
  let offset = 0;

  while (offset < buffer.length) {
    const length = buffer.readUInt8(offset);
    offset += 1;

    if (offset + length > buffer.length) {
      throw new Error('Invalid TXT record format: length exceeds buffer size');
    }

    const stringData = buffer
      .subarray(offset, offset + length)
      .toString('utf8');
    result += stringData;
    offset += length;
  }

  return result;
}

export function processTxtRecordData(data: unknown): string {
  if (typeof data === 'string') {
    return data;
  } else if (Buffer.isBuffer(data)) {
    return parseTxtRecord(data);
  } else {
    // Fallback for other types - cast to unknown first to avoid type errors
    return (data as { toString(): string }).toString();
  }
}
