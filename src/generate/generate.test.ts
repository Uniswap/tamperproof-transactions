import { SigningAlgorithmName } from '../algorithms';
import { generate } from './generate';

interface ParsedResult {
  publicKeys: {
    id: string;
    alg: string;
    publicKey: string;
  }[];
}

describe('generate', () => {
  const testKeys = {
    rsassa:
      '30820122300d06092a864886f70d01010105000382010f003082010a02820101009d36845018ef5dc07a3097055a5657404be931644c98350ad86918ac3873dad2b3950ab8913856d1f47281a48eeec17737a0c7dd02f3dda3e1d86bfd72932968efee7b6d2a73e9b72a1eb741d3016b212a41f000936e0e7b9bc9726b7522447b8059a3263020c0685896f2d597a6b25dc8255c34c8ac12c3f6410d8200a8aa880f93cda8e7085550dba93ddb2623325094ef2fff466057998bf9da851c4ff7064a719cde40882ccec5c1c32ecc5918b63fb46416f1d3761aab4a2249737b5700e9e65df075a91cb33846e4efafccb45bfa622af11a6ff9ca6fcf7d3140d6227652b63337a90db79461957bb0390934454530292f243e9a2ace92d0375136e3f10203010001',
    rsaPss:
      '30820122300d06092a864886f70d01010105000382010f003082010a0282010100a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef010203010001',
    ecdsa:
      '3059301306072a8648ce3d020106082a8648ce3d030107034200041234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    ed25519:
      '302a300506032b6570032100abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    ed448:
      '3043300506032b6571033a00abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  };

  describe('single algorithm tests', () => {
    describe('RSASSA-PKCS1-v1_5', () => {
      it('should generate correct JSON for single key', () => {
        const result = generate({
          key: testKeys.rsassa,
          algorithm: SigningAlgorithmName.RSASSA_PKCS1_v1_5,
        });

        const parsed = JSON.parse(result) as ParsedResult;
        expect(parsed.publicKeys).toHaveLength(1);
        expect(parsed.publicKeys[0]).toEqual({
          id: '1',
          alg: 'RSASSA-PKCS1-v1_5',
          publicKey: `0x${testKeys.rsassa}`,
        });
      });
    });

    describe('RSA-PSS', () => {
      it('should generate correct JSON for single key', () => {
        const result = generate({
          key: testKeys.rsaPss,
          algorithm: SigningAlgorithmName.RSA_PSS,
        });

        const parsed = JSON.parse(result) as ParsedResult;
        expect(parsed.publicKeys).toHaveLength(1);
        expect(parsed.publicKeys[0]).toEqual({
          id: '1',
          alg: 'RSA-PSS',
          publicKey: `0x${testKeys.rsaPss}`,
        });
      });
    });

    describe('ECDSA', () => {
      it('should generate correct JSON for single key', () => {
        const result = generate({
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        });

        const parsed = JSON.parse(result) as ParsedResult;
        expect(parsed.publicKeys).toHaveLength(1);
        expect(parsed.publicKeys[0]).toEqual({
          id: '1',
          alg: 'ECDSA',
          publicKey: `0x${testKeys.ecdsa}`,
        });
      });
    });

    describe('Ed25519', () => {
      it('should generate correct JSON for single key', () => {
        const result = generate({
          key: testKeys.ed25519,
          algorithm: SigningAlgorithmName.Ed25519,
        });

        const parsed = JSON.parse(result) as ParsedResult;
        expect(parsed.publicKeys).toHaveLength(1);
        expect(parsed.publicKeys[0]).toEqual({
          id: '1',
          alg: 'Ed25519',
          publicKey: `0x${testKeys.ed25519}`,
        });
      });
    });

    describe('Ed448', () => {
      it('should generate correct JSON for single key', () => {
        const result = generate({
          key: testKeys.ed448,
          algorithm: SigningAlgorithmName.Ed448,
        });

        const parsed = JSON.parse(result) as ParsedResult;
        expect(parsed.publicKeys).toHaveLength(1);
        expect(parsed.publicKeys[0]).toEqual({
          id: '1',
          alg: 'Ed448',
          publicKey: `0x${testKeys.ed448}`,
        });
      });
    });
  });

  describe('multiple algorithms tests', () => {
    it('should generate correct JSON for two different algorithms', () => {
      const result = generate(
        {
          key: testKeys.rsassa,
          algorithm: SigningAlgorithmName.RSASSA_PKCS1_v1_5,
        },
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(2);
      expect(parsed.publicKeys[0]).toEqual({
        id: '1',
        alg: 'RSASSA-PKCS1-v1_5',
        publicKey: `0x${testKeys.rsassa}`,
      });
      expect(parsed.publicKeys[1]).toEqual({
        id: '2',
        alg: 'ECDSA',
        publicKey: `0x${testKeys.ecdsa}`,
      });
    });

    it('should generate correct JSON for three different algorithms', () => {
      const result = generate(
        {
          key: testKeys.rsassa,
          algorithm: SigningAlgorithmName.RSASSA_PKCS1_v1_5,
        },
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        },
        {
          key: testKeys.ed25519,
          algorithm: SigningAlgorithmName.Ed25519,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(3);
      expect(parsed.publicKeys[0]).toEqual({
        id: '1',
        alg: 'RSASSA-PKCS1-v1_5',
        publicKey: `0x${testKeys.rsassa}`,
      });
      expect(parsed.publicKeys[1]).toEqual({
        id: '2',
        alg: 'ECDSA',
        publicKey: `0x${testKeys.ecdsa}`,
      });
      expect(parsed.publicKeys[2]).toEqual({
        id: '3',
        alg: 'Ed25519',
        publicKey: `0x${testKeys.ed25519}`,
      });
    });

    it('should generate correct JSON for all five algorithms', () => {
      const result = generate(
        {
          key: testKeys.rsassa,
          algorithm: SigningAlgorithmName.RSASSA_PKCS1_v1_5,
        },
        {
          key: testKeys.rsaPss,
          algorithm: SigningAlgorithmName.RSA_PSS,
        },
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        },
        {
          key: testKeys.ed25519,
          algorithm: SigningAlgorithmName.Ed25519,
        },
        {
          key: testKeys.ed448,
          algorithm: SigningAlgorithmName.Ed448,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(5);
      expect(parsed.publicKeys[0]).toEqual({
        id: '1',
        alg: 'RSASSA-PKCS1-v1_5',
        publicKey: `0x${testKeys.rsassa}`,
      });
      expect(parsed.publicKeys[1]).toEqual({
        id: '2',
        alg: 'RSA-PSS',
        publicKey: `0x${testKeys.rsaPss}`,
      });
      expect(parsed.publicKeys[2]).toEqual({
        id: '3',
        alg: 'ECDSA',
        publicKey: `0x${testKeys.ecdsa}`,
      });
      expect(parsed.publicKeys[3]).toEqual({
        id: '4',
        alg: 'Ed25519',
        publicKey: `0x${testKeys.ed25519}`,
      });
      expect(parsed.publicKeys[4]).toEqual({
        id: '5',
        alg: 'Ed448',
        publicKey: `0x${testKeys.ed448}`,
      });
    });

    it('should handle duplicate algorithms with different keys', () => {
      const alternateEcdsaKey =
        '3059301306072a8648ce3d020106082a8648ce3d030107034200040987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba';

      const result = generate(
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        },
        {
          key: alternateEcdsaKey,
          algorithm: SigningAlgorithmName.ECDSA,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(2);
      expect(parsed.publicKeys[0]).toEqual({
        id: '1',
        alg: 'ECDSA',
        publicKey: `0x${testKeys.ecdsa}`,
      });
      expect(parsed.publicKeys[1]).toEqual({
        id: '2',
        alg: 'ECDSA',
        publicKey: `0x${alternateEcdsaKey}`,
      });
    });
  });

  describe('edge cases', () => {
    it('should handle empty input gracefully', () => {
      const result = generate();

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(0);
      expect(parsed.publicKeys).toEqual([]);
    });

    it('should preserve key order in output', () => {
      const result = generate(
        {
          key: testKeys.ed448,
          algorithm: SigningAlgorithmName.Ed448,
        },
        {
          key: testKeys.rsassa,
          algorithm: SigningAlgorithmName.RSASSA_PKCS1_v1_5,
        },
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(3);
      expect(parsed.publicKeys[0].alg).toBe('Ed448');
      expect(parsed.publicKeys[1].alg).toBe('RSASSA-PKCS1-v1_5');
      expect(parsed.publicKeys[2].alg).toBe('ECDSA');
    });

    it('should assign sequential IDs regardless of algorithm type', () => {
      const result = generate(
        {
          key: testKeys.ed25519,
          algorithm: SigningAlgorithmName.Ed25519,
        },
        {
          key: testKeys.rsaPss,
          algorithm: SigningAlgorithmName.RSA_PSS,
        },
        {
          key: testKeys.ed448,
          algorithm: SigningAlgorithmName.Ed448,
        },
        {
          key: testKeys.ecdsa,
          algorithm: SigningAlgorithmName.ECDSA,
        }
      );

      const parsed = JSON.parse(result) as ParsedResult;
      expect(parsed.publicKeys).toHaveLength(4);
      expect(parsed.publicKeys.map(key => key.id)).toEqual([
        '1',
        '2',
        '3',
        '4',
      ]);
    });
  });
});
