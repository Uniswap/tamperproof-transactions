import { generate } from './generate';

describe('generate', () => {
    it('should return a string', () => {
        expect(typeof generate(
            {
                key: 'key',
                algorithm: 'algorithm'
            }
        )).toBe("string");
    });
});