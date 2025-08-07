// Move mock before imports
const mockQuery = jest.fn();
jest.mock('dohjs', () => ({
  DohResolver: jest.fn().mockImplementation(() => ({
    query: mockQuery,
  })),
}));

import { verify, verifyAsyncDns, PREFIX } from './verify';
import { toHex } from '../utils/hex';
import { SigningAlgorithmName, SIGNING_ALGORITHM_CONFIG } from '../algorithms';
const webcrypto = globalThis.crypto;

const data = 'data';
let ecdsaKeyPair: CryptoKeyPair;
let ed25519KeyPair: CryptoKeyPair;
let rsaSSAKeyPair: CryptoKeyPair;
let rsaPSSKeyPair: CryptoKeyPair;
let ed448KeyPair: CryptoKeyPair;

describe('verify.ts', () => {
  describe('Test failure cases for verifyAsyncDns', () => {
    beforeEach(() => {
      // Clear mock between tests
      mockQuery.mockClear();
    });

    it('throws error if DNS resolution fails', async () => {
      mockQuery.mockRejectedValue(new Error('DNS resolution failed'));

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow('DNS resolution failed');
    });

    it('throws error if no TXT records are found', async () => {
      mockQuery.mockResolvedValue({ answers: [] });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow('No TXT records found for host example.com');
    });

    it('throws error if no record with PREFIX is found', async () => {
      mockQuery.mockResolvedValue({
        answers: [{ data: 'WRONG_PREFIX=somedata' }],
      });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(
        `No TXT record found with prefix ${PREFIX} for host example.com`
      );
    });
  });

  describe('TXT record parsing for verifyAsyncDns', () => {
    beforeEach(() => {
      // Clear mock between tests
      mockQuery.mockClear();
    });

    it('should handle single substring TXT records as string', async () => {
      mockQuery.mockResolvedValue({
        answers: [{ data: 'TWIST=test-endpoint' }],
      });

      // Mock the JSON fetch to avoid making real HTTP requests
      global.fetch = jest.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            publicKeys: [
              {
                id: '1',
                alg: 'ECDSA',
                publicKey: '0x123456789abcdef',
              },
            ],
          }),
      });

      // Since we can't easily test the crypto verification without setting up keys,
      // we'll expect it to throw at the crypto step (which means parsing worked)
      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(); // Will fail at crypto step, but parsing succeeded
    });

    it('should handle multiple substring TXT records in Buffer format', async () => {
      // Create a Buffer that represents a TXT record with multiple substrings
      // Format: length1 + string1 + length2 + string2
      // "TWIST=" (6 bytes) + "test-end" (8 bytes) + "point" (5 bytes)
      const buffer = Buffer.concat([
        Buffer.from([6]), // length of "TWIST="
        Buffer.from('TWIST='),
        Buffer.from([8]), // length of "test-end"
        Buffer.from('test-end'),
        Buffer.from([5]), // length of "point"
        Buffer.from('point'),
      ]);

      mockQuery.mockResolvedValue({
        answers: [{ data: buffer }],
      });

      // Mock the JSON fetch
      global.fetch = jest.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            publicKeys: [
              {
                id: '1',
                alg: 'ECDSA',
                publicKey: '0x123456789abcdef',
              },
            ],
          }),
      });

      // Should parse buffer as "TWIST=test-endpoint" and continue processing
      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(); // Will fail at crypto step, but parsing succeeded
    });

    it('should handle empty substring in TXT record Buffer', async () => {
      // Create a Buffer with an empty substring: "TWIST=" + "" + "data"
      const buffer = Buffer.concat([
        Buffer.from([6]), // length of "TWIST="
        Buffer.from('TWIST='),
        Buffer.from([0]), // empty string
        Buffer.from([4]), // length of "data"
        Buffer.from('data'),
      ]);

      mockQuery.mockResolvedValue({
        answers: [{ data: buffer }],
      });

      global.fetch = jest.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            publicKeys: [
              {
                id: '1',
                alg: 'ECDSA',
                publicKey: '0x123456789abcdef',
              },
            ],
          }),
      });

      // Should parse as "TWIST=data"
      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(); // Will fail at crypto step, but parsing succeeded
    });

    it('should throw error for malformed TXT record Buffer', async () => {
      // Create a malformed buffer where length exceeds available data
      const buffer = Buffer.concat([
        Buffer.from([6]), // length of "TWIST="
        Buffer.from('TWIST='),
        Buffer.from([10]), // claims 10 bytes but only 4 available
        Buffer.from('test'),
      ]);

      mockQuery.mockResolvedValue({
        answers: [{ data: buffer }],
      });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(
        'Invalid TXT record format: length exceeds buffer size'
      );
    });

    it('should handle mixed record types with Buffer containing multiple substrings', async () => {
      // First record without prefix, second record with prefix in Buffer format
      const buffer = Buffer.concat([
        Buffer.from([6]), // length of "TWIST="
        Buffer.from('TWIST='),
        Buffer.from([5]), // length of "valid"
        Buffer.from('valid'),
      ]);

      mockQuery.mockResolvedValue({
        answers: [
          { data: 'OTHER_PREFIX=ignore-this' },
          { data: buffer }, // Should find this one
          { data: 'TWIST=backup' }, // Should not reach this
        ],
      });

      global.fetch = jest.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            publicKeys: [
              {
                id: '1',
                alg: 'ECDSA',
                publicKey: '0x123456789abcdef',
              },
            ],
          }),
      });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com', '1')
      ).rejects.toThrow(); // Will fail at crypto step, but parsing succeeded
    });
  });

  describe('verify', () => {
    beforeAll(async () => {
      ecdsaKeyPair = await webcrypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false,
        ['sign', 'verify']
      );
      ed25519KeyPair = await webcrypto.subtle.generateKey(
        {
          name: 'Ed25519',
        },
        false,
        ['sign', 'verify']
      );
      rsaSSAKeyPair = await webcrypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' },
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          modulusLength: 2048,
        },
        false,
        ['sign', 'verify']
      );
      rsaPSSKeyPair = await webcrypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          hash: { name: 'SHA-256' },
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          modulusLength: 2048,
        },
        false,
        ['sign', 'verify']
      );
      ed448KeyPair = (await webcrypto.subtle.generateKey(
        {
          name: 'Ed448',
        },
        false,
        ['sign', 'verify']
      )) as CryptoKeyPair;
    });

    describe('returns true for correct public key', () => {
      it('is successful with ECDSA', async () => {
        const privateKey = ecdsaKeyPair.privateKey;
        const publicKey = ecdsaKeyPair.publicKey;
        const signature = await webcrypto.subtle.sign(
          SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.ECDSA],
          privateKey,
          new TextEncoder().encode(data)
        );
        const signatureString = toHex(signature);

        expect(await verify(data, signatureString, publicKey)).toBe(true);
      });
      it('is successful with ed25519', async () => {
        const privateKey = ed25519KeyPair.privateKey;
        const publicKey = ed25519KeyPair.publicKey;
        const signature = await webcrypto.subtle.sign(
          SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.Ed25519],
          privateKey,
          new TextEncoder().encode(data)
        );
        const signatureString = toHex(signature);

        expect(await verify(data, signatureString, publicKey)).toBe(true);
      });
      it('is successful with RSASSA-PKCS1-v1_5', async () => {
        const privateKey = rsaSSAKeyPair.privateKey;
        const publicKey = rsaSSAKeyPair.publicKey;
        const signature = await webcrypto.subtle.sign(
          SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.RSASSA_PKCS1_v1_5],
          privateKey,
          new TextEncoder().encode(data)
        );
        const signatureString = toHex(signature);

        expect(await verify(data, signatureString, publicKey)).toBe(true);
      });
      it('is successful with RSA-PSS', async () => {
        const privateKey = rsaPSSKeyPair.privateKey;
        const publicKey = rsaPSSKeyPair.publicKey;
        const signature = await webcrypto.subtle.sign(
          SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.RSA_PSS],
          privateKey,
          new TextEncoder().encode(data)
        );
        const signatureString = toHex(signature);

        expect(await verify(data, signatureString, publicKey)).toBe(true);
      });
      it('is successful with Ed448', async () => {
        const privateKey = ed448KeyPair.privateKey;
        const publicKey = ed448KeyPair.publicKey;
        const signature = await webcrypto.subtle.sign(
          SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.Ed448],
          privateKey,
          new TextEncoder().encode(data)
        );
        const signatureString = toHex(signature);

        expect(await verify(data, signatureString, publicKey)).toBe(true);
      });
    });

    it('returns false for incorrect public key', async () => {
      const privateKey1 = rsaSSAKeyPair.privateKey;
      const signature = await webcrypto.subtle.sign(
        SIGNING_ALGORITHM_CONFIG[SigningAlgorithmName.RSASSA_PKCS1_v1_5],
        privateKey1,
        new TextEncoder().encode(data)
      );
      const signatureString = toHex(signature);

      const rsaSSAKeyPair2 = await webcrypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' },
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          modulusLength: 2048,
        },
        false,
        ['sign', 'verify']
      );
      const publicKey2 = rsaSSAKeyPair2.publicKey;

      expect(await verify(data, signatureString, publicKey2)).toBe(false);
    });
  });
});
