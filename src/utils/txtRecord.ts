import { ERROR_INVALID_TXT_RECORD_FORMAT } from '../constants/errors';

export function parseTxtRecord(buffer: ArrayBuffer | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const decoder = new TextDecoder();
  let result = '';
  let offset = 0;

  while (offset < view.length) {
    const length = view[offset];
    offset += 1;

    if (offset + length > view.length) {
      throw new Error(ERROR_INVALID_TXT_RECORD_FORMAT);
    }

    const slice = view.subarray(offset, offset + length);
    result += decoder.decode(slice);
    offset += length;
  }

  return result;
}

export function processTxtRecordData(data: unknown): string {
  if (typeof data === 'string') {
    return data;
  }
  if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
    return parseTxtRecord(data);
  }
  // Fallback for other types
  return data as string;
}
