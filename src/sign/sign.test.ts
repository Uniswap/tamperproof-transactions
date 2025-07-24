import { sign } from './sign';
import { webcrypto } from 'crypto';

describe('sign', () => {
  describe('RSASSA-PKCS1-v1_5', () => {
    it('should return expected signature', async () => {
      // Fixed private key for deterministic testing (pre-processed base64)
      const privateKeyBase64 =
        'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdNoRQGO9dwHowlwVaVldAS+kxZEyYNQrYaRisOHPa0rOVCriROFbR9HKBpI7uwXc3oMfdAvPdo+HYa/1ykylo7+57bSpz6bcqHrdB0wFrISpB8ACTbg57m8lya3UiRHuAWaMmMCDAaFiW8tWXprJdyCVcNMisEsP2QQ2CAKiqiA+TzajnCFVQ26k92yYjMlCU7y//RmBXmYv52oUcT/cGSnGc3kCILM7FwcMuzFkYtj+0ZBbx03Yaq0oiSXN7VwDp5l3wdakcszhG5O+vzLRb+mIq8Rpv+cpvz30xQNYidlK2MzepDbeUYZV7sDkJNEVFMDkvJD6aKs6S0DdRNuPxAgMBAAECggEABIbqhiCZr/JCx9MUITb67zaLDKmN4mol7ve5G/3KKZhx+bjjz1wMdUzxM9YoaYFNAgnmshtg01aMl9NQP97d9+VvfBgM0Lv/qBOsr5VjD+craiz+OetBjoH8vzHknxZ9ae5AL5wo1/GJRNt8QWWC8wa4O1tSa1C6Wi/NsvB66uIm5sH1rfrMCqcli0PD7k9vcwgt4G5Yg0Y3dDLtLMZOKRwf0oZbj/zFGRK5nPlN2Q0OS9yG0o7kqSjQZiqzXPYfO7ioEcf5EB95ioa95a5XtHubfomp+k7Ep/zBvWby63BZKsDS7NRf+mvZY05ZKbbKGoTodb83vNlb8xJ3OTuo+QKBgQDKqZT2P1phjl6iqgjHwxpSKGCcEhKn/KAWK6mUOe5WEWqUjzCwavYP/0iW/7vGCyGn5MuZXw2m9rDBfZn0rzBl+C6OtM9SKsASAskKnpiR21P8k5/ZXv37V7XzlZs2Qqg5osBkaA+yIM6gtICPbpGu3S3cNMarXTX5dpF+64R0FQKBgQDGlsS5FYoAUH3brYgBFLvlODj+PbRfQp3AFkMFxSxkyIXA+cH9UDJqVHVTkGg1OS7xFPYFX4jNqfCCljPMWLB+KWsmDze2i4EFNjYb2+HPDem03FIcd2nfrU6uxyp/jw4comfQKILraT4bwd0ZZXcuQCu9fysdQY4xaLJv/9ZbbQKBgQCooZr1m5mU+2X7bAiKT+mi2z4oH1GuviJm0EX2tI2AyFUq8ErPQPEmNoEsQ/b2v2Rt048mO1WczEAfgGeOlgdrkasLy5+G+1N+qRqn33eMRjgIPr4PnV8wuLcJzD6uU6Cu9KGp6nzE9093oTooHxTRr/Ds/m0hQhobTXGbblV0UQKBgGMpo9/bzoYrqz0HoNMRXGWwNl1VyHyM0iK5uwvlki5dJtTeoixwYExSEigBAtgYzsTZN6QlOTWhNxSuFf1jB/ZnjjZ6ANLpRCqrEEfG+zGd++Yw4duPEVH8wz5o+2Kot147BmWd5QnSCo5ntpTY4rM4nd7I4mmAc5Ved0OP16TdAoGALJIutHGuM76XJNy2vbMvVHmH2Vin2ZXQAwdaD18+0AawWviWRpO6OTphSkbTr1GcWoRbFro34mqU03dY/vuCOrv20TXLfDRAlNZ9VRyXfbEZY0VfW5rywblN5fvHe3Zauxz2yrbTQ1YK9NPR8lOHF1hNEHsh5Pi/7Zx2kPEC/2k=';

      const privateKey = await webcrypto.subtle.importKey(
        'pkcs8',
        Buffer.from(privateKeyBase64, 'base64'),
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' },
        },
        false,
        ['sign']
      );

      const data = 'test data';
      const result = await sign(data, privateKey, 'RSASSA-PKCS1-v1_5');

      expect(typeof result).toBe('string');
      expect(result).toHaveLength(512); // 2048-bit key = 256 bytes = 512 hex chars

      expect(result).toBe(
        '487f06a3dfdd4fc57dd3f60e3534b7853238bf57cf8f41fb12542bd4427a3f9569c2a11a6db68e170ceed85f9786bef12156aa6b2574601ce62b27417bbae8e7c405aae0a8d33efa940c09b1b7af024313f1b9cd9e0d7c59c9fc71433898224d16a53787fc1d74182adaed049b9bfe6d44605597691f0e7db223feca52ac5a31be13c654c4d0c4a5e0430dd24493f2cbd454308dae3cd1f06adacb7ae00427784adde34f5d02d117780851e11f675f1402ca70b6fe8c36c8a542442b0563e91357d1b929140f1394876a46f4f5c8d0b86a4d9083aefb1c739bb8e1ba175f0b9245704907aa74c7b6520e967f24f08402fb3eee3e73c609168a4325080b428f01'
      );
    });
  });
});
