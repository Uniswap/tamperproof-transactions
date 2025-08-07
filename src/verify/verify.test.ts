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
        verifyAsyncDns('data', 'signature', 'example.com')
      ).rejects.toThrow('DNS resolution failed');
    });

    it('throws error if no TXT records are found', async () => {
      mockQuery.mockResolvedValue({ answers: [] });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com')
      ).rejects.toThrow('No TXT records found for host example.com');
    });

    it('throws error if no record with PREFIX is found', async () => {
      mockQuery.mockResolvedValue({
        answers: [{ data: 'WRONG_PREFIX=somedata' }],
      });

      await expect(
        verifyAsyncDns('data', 'signature', 'example.com')
      ).rejects.toThrow(
        `No TXT record found with prefix ${PREFIX} for host example.com`
      );
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
