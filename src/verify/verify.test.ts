import { verify } from './verify';
import { SigningAlgorithm } from '../algorithms';


describe('verify', () => {
    test('verify returns false', () => {
        expect(verify({
            calldata: '0x',
            signature: '0x',
            url: 'https://example.com',
        })).toBe(false);
    });

    test('verify returns false', () => {
        expect(verify({
            calldata: '0x',
            signature: '0x',
            publickey: '0x'
        })).toBe(false);
    });
});