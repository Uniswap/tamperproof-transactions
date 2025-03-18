import { generateKeyPairSync } from 'crypto';
import { SigningAlgorithm } from '../algorithms';
import { generate } from './generate';

describe('generate', () => {
    it('should return a string', () => {
        const { publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        expect(typeof generate(
            {
                key: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
                algorithm: SigningAlgorithm.RSA
            }
        )).toBe("string");
    });
});