// Move mock before imports
jest.mock('dns', () => ({
    promises: {
        resolveTxt: jest.fn()
    }
}));

import { PREFIX, verifyAsyncDns, verifyAsyncJson, verifySync } from './verify';
import { SigningAlgorithm } from '../algorithms';
import { generateKeyPairSync } from 'crypto';
import { sign } from '../sign/sign';
import dns from 'dns';

describe('verify', () => {
    describe('verifyAsyncDns', () => {
        beforeEach(() => {
            // Clear mock between tests
            (dns.promises.resolveTxt as jest.Mock).mockClear();
        });

        it('throws error if DNS resolution fails', async () => {
            (dns.promises.resolveTxt as jest.Mock).mockRejectedValue(
                new Error('DNS resolution failed')
            );

            await expect(verifyAsyncDns(
                'data',
                'signature',
                'example.com'
            )).rejects.toThrow('DNS resolution failed');
        });

        it('throws error if no TXT records are found', async () => {
            (dns.promises.resolveTxt as jest.Mock).mockResolvedValue([]);

            await expect(verifyAsyncDns(
                'data',
                'signature',
                'example.com'
            )).rejects.toThrow('No TXT records found for host example.com');
        });

        it('throws error if no record with PREFIX is found', async () => {
            (dns.promises.resolveTxt as jest.Mock).mockResolvedValue([
                ['WRONG_PREFIX=somedata']
            ]);

            await expect(verifyAsyncDns(
                'data',
                'signature',
                'example.com'
            )).rejects.toThrow(`No TXT record found with prefix ${PREFIX} for host example.com`);
        });
    });

    describe('verifySync', () => {
        it('returns true for correct public key', () => {
            const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        const data = 'data';
        const result = sign(data, privateKey, SigningAlgorithm.RSA);
        expect(verifySync(
            data,
            result,
            SigningAlgorithm.RSA,
            publicKey
        )).toBe(true);
        });

        it('returns false for incorrect public key', () => {
            // Generate first key pair
            const { privateKey: privateKey1 } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        // Generate second key pair (different from first)
        const { publicKey: privateKey2 } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        const data = 'data';
        // Sign the data with the first key pair
        const result = sign(data, privateKey1, SigningAlgorithm.RSA);

        // Verify the signature with the different public key
        expect(verifySync(
                data,
                result,
                SigningAlgorithm.RSA,
                privateKey2
            )).toBe(false);
        });
    });
});