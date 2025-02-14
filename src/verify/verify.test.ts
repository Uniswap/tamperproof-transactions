import { verify } from './verify';

describe('verify', () => {
    test('verify returns false', () => {
        expect(verify({
            calldata: '0x',
            signature: '0x',
            url: 'https://example.com',
            publickey: '0x'
        })).toBe(false);
    });
});