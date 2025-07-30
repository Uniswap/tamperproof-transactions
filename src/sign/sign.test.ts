import { sign } from './sign';
import { webcrypto } from 'crypto';
import { SigningAlgorithmName } from '../algorithms';
import { fromHex, fromBase64 } from '../utils/hex';

let data: string;
let privateKeyRSA!: webcrypto.CryptoKey;
let privateKeyRSA_PSS!: webcrypto.CryptoKey;
let privateKeyECDSA!: webcrypto.CryptoKey;
let privateKeyEd25519!: webcrypto.CryptoKey;
let privateKeyEd448!: webcrypto.CryptoKey;

describe('sign', () => {
  beforeAll(async () => {
    const privateKeyBuffer = fromBase64(
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdNoRQGO9dwHowlwVaVldAS+kxZEyYNQrYaRisOHPa0rOVCriROFbR9HKBpI7uwXc3oMfdAvPdo+HYa/1ykylo7+57bSpz6bcqHrdB0wFrISpB8ACTbg57m8lya3UiRHuAWaMmMCDAaFiW8tWXprJdyCVcNMisEsP2QQ2CAKiqiA+TzajnCFVQ26k92yYjMlCU7y//RmBXmYv52oUcT/cGSnGc3kCILM7FwcMuzFkYtj+0ZBbx03Yaq0oiSXN7VwDp5l3wdakcszhG5O+vzLRb+mIq8Rpv+cpvz30xQNYidlK2MzepDbeUYZV7sDkJNEVFMDkvJD6aKs6S0DdRNuPxAgMBAAECggEABIbqhiCZr/JCx9MUITb67zaLDKmN4mol7ve5G/3KKZhx+bjjz1wMdUzxM9YoaYFNAgnmshtg01aMl9NQP97d9+VvfBgM0Lv/qBOsr5VjD+craiz+OetBjoH8vzHknxZ9ae5AL5wo1/GJRNt8QWWC8wa4O1tSa1C6Wi/NsvB66uIm5sH1rfrMCqcli0PD7k9vcwgt4G5Yg0Y3dDLtLMZOKRwf0oZbj/zFGRK5nPlN2Q0OS9yG0o7kqSjQZiqzXPYfO7ioEcf5EB95ioa95a5XtHubfomp+k7Ep/zBvWby63BZKsDS7NRf+mvZY05ZKbbKGoTodb83vNlb8xJ3OTuo+QKBgQDKqZT2P1phjl6iqgjHwxpSKGCcEhKn/KAWK6mUOe5WEWqUjzCwavYP/0iW/7vGCyGn5MuZXw2m9rDBfZn0rzBl+C6OtM9SKsASAskKnpiR21P8k5/ZXv37V7XzlZs2Qqg5osBkaA+yIM6gtICPbpGu3S3cNMarXTX5dpF+64R0FQKBgQDGlsS5FYoAUH3brYgBFLvlODj+PbRfQp3AFkMFxSxkyIXA+cH9UDJqVHVTkGg1OS7xFPYFX4jNqfCCljPMWLB+KWsmDze2i4EFNjYb2+HPDem03FIcd2nfrU6uxyp/jw4comfQKILraT4bwd0ZZXcuQCu9fysdQY4xaLJv/9ZbbQKBgQCooZr1m5mU+2X7bAiKT+mi2z4oH1GuviJm0EX2tI2AyFUq8ErPQPEmNoEsQ/b2v2Rt048mO1WczEAfgGeOlgdrkasLy5+G+1N+qRqn33eMRjgIPr4PnV8wuLcJzD6uU6Cu9KGp6nzE9093oTooHxTRr/Ds/m0hQhobTXGbblV0UQKBgGMpo9/bzoYrqz0HoNMRXGWwNl1VyHyM0iK5uwvlki5dJtTeoixwYExSEigBAtgYzsTZN6QlOTWhNxSuFf1jB/ZnjjZ6ANLpRCqrEEfG+zGd++Yw4duPEVH8wz5o+2Kot147BmWd5QnSCo5ntpTY4rM4nd7I4mmAc5Ved0OP16TdAoGALJIutHGuM76XJNy2vbMvVHmH2Vin2ZXQAwdaD18+0AawWviWRpO6OTphSkbTr1GcWoRbFro34mqU03dY/vuCOrv20TXLfDRAlNZ9VRyXfbEZY0VfW5rywblN5fvHe3Zauxz2yrbTQ1YK9NPR8lOHF1hNEHsh5Pi/7Zx2kPEC/2k='
    );
    data = 'test data';

    privateKeyRSA = await webcrypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      false,
      ['sign']
    );
    privateKeyRSA_PSS = await webcrypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'RSA-PSS',
        hash: { name: 'SHA-256' },
      },
      false,
      ['sign']
    );

    const ecdsaKeyPair = await webcrypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['sign', 'verify']
    );
    privateKeyECDSA = ecdsaKeyPair.privateKey;

    const ed25519PrivateKeyBuffer = fromHex(
      '302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842'
    );
    privateKeyEd25519 = await webcrypto.subtle.importKey(
      'pkcs8',
      ed25519PrivateKeyBuffer,
      {
        name: 'Ed25519',
      },
      false,
      ['sign']
    );

    const ed448PrivateKeyBuffer = fromHex(
      '3047020100300506032b6571043b0439d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842a69b9dc13ee02a4b9dc13ee02a4b9dc13ee02a4b9dc13ee02a40'
    );
    privateKeyEd448 = await webcrypto.subtle.importKey(
      'pkcs8',
      ed448PrivateKeyBuffer,
      {
        name: 'Ed448',
      },
      false,
      ['sign']
    );
  });

  describe('RSASSA-PKCS1-v1_5', () => {
    it('should return expected signature', async () => {
      const result = await sign(
        data,
        privateKeyRSA,
        SigningAlgorithmName.RSASSA_PKCS1_v1_5
      );

      expect(result).toBe(
        '487f06a3dfdd4fc57dd3f60e3534b7853238bf57cf8f41fb12542bd4427a3f9569c2a11a6db68e170ceed85f9786bef12156aa6b2574601ce62b27417bbae8e7c405aae0a8d33efa940c09b1b7af024313f1b9cd9e0d7c59c9fc71433898224d16a53787fc1d74182adaed049b9bfe6d44605597691f0e7db223feca52ac5a31be13c654c4d0c4a5e0430dd24493f2cbd454308dae3cd1f06adacb7ae00427784adde34f5d02d117780851e11f675f1402ca70b6fe8c36c8a542442b0563e91357d1b929140f1394876a46f4f5c8d0b86a4d9083aefb1c739bb8e1ba175f0b9245704907aa74c7b6520e967f24f08402fb3eee3e73c609168a4325080b428f01'
      );
    });
  });

  describe('RSA-PSS', () => {
    it('should be 512 byte string', async () => {
      const result = await sign(
        data,
        privateKeyRSA_PSS,
        SigningAlgorithmName.RSA_PSS
      );

      expect(typeof result).toBe('string');
      expect(result).toHaveLength(512);
    });
    it('should be non-deterministic', async () => {
      const result1 = await sign(
        data,
        privateKeyRSA_PSS,
        SigningAlgorithmName.RSA_PSS
      );
      const result2 = await sign(
        data,
        privateKeyRSA_PSS,
        SigningAlgorithmName.RSA_PSS
      );

      expect(result1).not.toBe(result2);
    });
  });

  describe('ECDSA', () => {
    it('should be 128 byte string', async () => {
      const result = await sign(
        data,
        privateKeyECDSA,
        SigningAlgorithmName.ECDSA
      );

      expect(typeof result).toBe('string');
      expect(result).toHaveLength(128);
    });
    it('should be non-deterministic', async () => {
      const result1 = await sign(
        data,
        privateKeyECDSA,
        SigningAlgorithmName.ECDSA
      );
      const result2 = await sign(
        data,
        privateKeyECDSA,
        SigningAlgorithmName.ECDSA
      );

      expect(result1).not.toBe(result2);
    });
  });

  describe('Ed25519', () => {
    it('should return expected signature', async () => {
      const result = await sign(
        data,
        privateKeyEd25519,
        SigningAlgorithmName.Ed25519
      );

      expect(result).toBe(
        '0804a2a72f52d7afdaf18b78e1a48891a729be1bdde2b30366fd00a128bc37243aa75c36e8b0a93b71fe7dfd7b67bee0838e25acd26b8a81ad7074ae38f84102'
      );
    });
  });

  describe('Ed448', () => {
    it('should return expected signature', async () => {
      const result = await sign(
        data,
        privateKeyEd448,
        SigningAlgorithmName.Ed448
      );

      expect(result).toBe(
        '5b8538163d88064b524ad596292eed220621ca41c17f4c8cef31e2ee7ca497f0d0533acdb31a441f007ac5f9f6e1143b3197b5d5b306066400dfab50dcab37e2e9f9a6b1468d60dd922f5edbae8661627423fb4d60448f7f0a06e59e1d1426f773a7c4ae3c07599fad6cc71464e8dbb20400'
      );
    });
  });

  describe('Error handling', () => {
    it('should throw error for unsupported algorithm', async () => {
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any
        sign(data, privateKeyRSA, 'INVALID_ALGO' as any)
      ).rejects.toThrow();
    });

    it('should throw error for key-algorithm mismatch', async () => {
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any
        sign(data, privateKeyRSA, 'RSA-PSS' as any)
      ).rejects.toThrow();
    });
  });
});
