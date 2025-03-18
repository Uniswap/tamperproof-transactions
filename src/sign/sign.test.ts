import { sign } from './sign';
import { SigningAlgorithm } from '../algorithms';

const {
    generateKeyPairSync,
    createSign,
    createVerify,
} = require('node:crypto');

describe('sign', () => {
    it('should return a string', () => {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        const data = 'data';
        const result = sign(data, privateKey, SigningAlgorithm.RSA);
        expect(typeof result).toBe("string");
    });
});

