# tamperproof-transactions
Implementation of EIP-7754

## Installation

```bash
yarn add @uniswap/tamperproof-transactions
# or
npm install @uniswap/tamperproof-transactions
```

## API

### SigningAlgorithm

```ts
export enum SigningAlgorithm {
  RSA = "RSA-SHA256",
  RSA_PSS = "RSA-PSS",
  ECDSA = "SHA256"
}
```

---

### `sign(data: string, privateKey: KeyObject, algorithm: SigningAlgorithm): string`

Signs a string using the provided private key and algorithm.

#### Example

```ts
import { sign, SigningAlgorithm } from '@uniswap/tamperproof-transactions';
import { generateKeyPairSync } from 'crypto';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const data = 'hello world';
const signature = sign(data, privateKey, SigningAlgorithm.RSA);
```

---

### `verifySync(calldata: string, signature: string, algorithm: SigningAlgorithm, publicKey: KeyObject): boolean`

Verifies a signature synchronously.

#### Example

```ts
import { sign, verifySync, SigningAlgorithm } from '@uniswap/tamperproof-transactions';
import { generateKeyPairSync } from 'crypto';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const data = 'hello world';
const signature = sign(data, privateKey, SigningAlgorithm.RSA);

const isValid = verifySync(data, signature, SigningAlgorithm.RSA, publicKey);
```

---

### `verifyAsyncDns(calldata: string, signature: string, host: string, id?: number): Promise<boolean>`

Verifies a signature by fetching a public key from a DNS TXT record.

#### Example

```ts
import { verifyAsyncDns } from '@uniswap/tamperproof-transactions';

const isValid = await verifyAsyncDns('data', 'signature', 'example.com');
```

---

### `verifyAsyncJson(calldata: string, signature: string, url: string, id?: number): Promise<boolean>`

Verifies a signature by fetching a public key from a JSON endpoint.

#### Example

```ts
import { verifyAsyncJson } from '@uniswap/tamperproof-transactions';

const isValid = await verifyAsyncJson('data', 'signature', 'https://example.com/keys.json');
```

---

### `generate(...publicKeys: PublicKey[]): string`

Generates a JSON string containing an array of public keys.

#### Types

```ts
type PublicKey = {
  key: string;
  algorithm: SigningAlgorithm;
};
```

#### Example

```ts
import { generate, SigningAlgorithm } from '@uniswap/tamperproof-transactions';

const publicKey = {
  key: 'hex-encoded-key',
  algorithm: SigningAlgorithm.RSA
};

const json = generate(publicKey);
```

---

## License

MIT

