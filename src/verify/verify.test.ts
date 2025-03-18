import { verifyAsync, verifySync } from './verify';
import { SigningAlgorithm } from '../algorithms';
import { generateKeyPairSync } from 'crypto';
import { sign } from '../sign/sign';


describe('verify', () => {
    it.skip('verify returns false', async () => {
        expect(await verifyAsync({
            calldata: '0x',
            signature: '0x',
            algorithm: SigningAlgorithm.RSA,
            url: 'https://example.com',
        })).toBe(false);
    });

    it('verify returns true', () => {
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

    it('verify returns false for incorrect public key', () => {
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