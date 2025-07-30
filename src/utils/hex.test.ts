import { fromHex, toHex } from './hex';

describe('fromHex', () => {
  describe('valid hex strings', () => {
    it('should convert empty hex string to empty Uint8Array', () => {
      const result = fromHex('');
      expect(result).toEqual(new Uint8Array([]));
    });

    it('should convert simple hex string to Uint8Array', () => {
      const result = fromHex('48656c6c6f');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    it('should handle uppercase hex string', () => {
      const result = fromHex('48656C6C6F');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    it('should handle mixed case hex string', () => {
      const result = fromHex('48656c6C6F');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    it('should handle hex string with all byte values', () => {
      const result = fromHex('00ff8001');
      expect(result).toEqual(new Uint8Array([0x00, 0xff, 0x80, 0x01]));
    });

    it('should clean whitespace from hex string', () => {
      const result = fromHex('48 65 6c 6c 6f');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    it('should clean tabs and newlines from hex string', () => {
      const result = fromHex('48\t65\n6c\r6c\n6f');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });
  });

  describe('invalid hex strings', () => {
    it('should throw error for odd length hex string', () => {
      expect(() => fromHex('48656c6c6')).toThrow(
        'Invalid hex string: length must be even'
      );
    });

    it('should throw error for odd length hex string after cleaning whitespace', () => {
      expect(() => fromHex('48 65 6c 6c 6')).toThrow(
        'Invalid hex string: length must be even'
      );
    });

    it('should handle partially invalid hex characters (parseInt behavior)', () => {
      // Note: parseInt('4g', 16) returns 4, so this doesn't throw
      const result = fromHex('48656g6c6f');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6, 0x6c, 0x6f]));
    });

    it('should throw error for completely non-hex characters', () => {
      expect(() => fromHex('hello!')).toThrow('Invalid hex string: hello!');
    });

    it('should handle mixed valid/invalid hex characters (parseInt behavior)', () => {
      // Note: parseInt('6x', 16) returns 6, so this doesn't throw
      const result = fromHex('48656c6x6f');
      expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6, 0x6f]));
    });
  });
});

describe('toHex', () => {
  describe('Uint8Array input', () => {
    it('should convert empty Uint8Array to empty string', () => {
      const result = toHex(new Uint8Array([]));
      expect(result).toBe('');
    });

    it('should convert Uint8Array to hex string', () => {
      const result = toHex(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
      expect(result).toBe('48656c6c6f');
    });

    it('should handle all byte values', () => {
      const result = toHex(new Uint8Array([0x00, 0xff, 0x80, 0x01]));
      expect(result).toBe('00ff8001');
    });

    it('should pad single digit hex values with leading zero', () => {
      const result = toHex(new Uint8Array([0x01, 0x02, 0x0f]));
      expect(result).toBe('01020f');
    });
  });

  describe('ArrayBuffer input', () => {
    it('should convert empty ArrayBuffer to empty string', () => {
      const buffer = new ArrayBuffer(0);
      const result = toHex(buffer);
      expect(result).toBe('');
    });

    it('should convert ArrayBuffer to hex string', () => {
      const buffer = new ArrayBuffer(5);
      const view = new Uint8Array(buffer);
      view.set([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const result = toHex(buffer);
      expect(result).toBe('48656c6c6f');
    });

    it('should handle all byte values in ArrayBuffer', () => {
      const buffer = new ArrayBuffer(4);
      const view = new Uint8Array(buffer);
      view.set([0x00, 0xff, 0x80, 0x01]);
      const result = toHex(buffer);
      expect(result).toBe('00ff8001');
    });
  });
});

describe('round-trip conversion', () => {
  it('should convert hex to bytes and back to hex', () => {
    const originalHex = '48656c6c6f776f726c64';
    const bytes = fromHex(originalHex);
    const resultHex = toHex(bytes);
    expect(resultHex).toBe(originalHex);
  });

  it('should normalize case in round-trip conversion', () => {
    const mixedCaseHex = '48656C6C6F576F726C64';
    const bytes = fromHex(mixedCaseHex);
    const resultHex = toHex(bytes);
    expect(resultHex).toBe(mixedCaseHex.toLowerCase());
  });

  it('should handle round-trip with all byte values', () => {
    const originalHex =
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
    const bytes = fromHex(originalHex);
    const resultHex = toHex(bytes);
    expect(resultHex).toBe(originalHex);
  });

  it('should handle round-trip with whitespace in original hex', () => {
    const hexWithSpaces = '48 65 6c 6c 6f';
    const expectedHex = '48656c6c6f';
    const bytes = fromHex(hexWithSpaces);
    const resultHex = toHex(bytes);
    expect(resultHex).toBe(expectedHex);
  });

  it('should convert bytes to hex and back to equivalent bytes', () => {
    const originalBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    const hex = toHex(originalBytes);
    const resultBytes = fromHex(hex);
    expect(resultBytes).toEqual(originalBytes);
  });

  it('should handle empty data in round-trip', () => {
    const emptyHex = '';
    const bytes = fromHex(emptyHex);
    const resultHex = toHex(bytes);
    expect(resultHex).toBe(emptyHex);
  });
});
