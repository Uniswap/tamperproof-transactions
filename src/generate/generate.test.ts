import { generateKeyPairSync } from 'crypto';
import { SigningAlgorithmConfig, SIGNING_ALGORITHM_CONFIG } from '../algorithms';
import { generate } from './generate';

describe('generate', () => {
  it('should return a string', () => {
    const { publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
    expect(
      typeof generate({
        key: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
        algorithm: SIGNING_ALGORITHM_CONFIG['RSASSA-PKCS1-v1_5'],
      })
    ).toBe('string');
  });
});
