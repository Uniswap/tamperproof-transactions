import { sign } from './sign';

describe('sign', () => {
    it('should return a string', () => {
        const data = 'data';
        const privateKey = 'privateKey';
        const result = sign({ data, privateKey });
        expect(typeof result).toBe("string");
    });
});