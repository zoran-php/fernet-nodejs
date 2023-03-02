import {
  aes128cbcDecrypt,
  aes128cbcEncrypt,
  compareBuffers,
  computeHmac,
  fromBase64Url,
  generateIv,
  randomBytes,
  toBase64Url,
  ts8byteBuffer,
} from './utils/index';

export class Fernet {
  version: Buffer = Buffer.from([0x80]);
  constructor(private key: string) {
    try {
      const buffer = fromBase64Url(key);
      if (buffer.length !== 32) {
        throw new Error('Key must be 32-byte long base64url encoded string.');
      }
    } catch (error) {
      throw new Error('Key must be 32-byte long base64url encoded string.');
    }
  }

  static generateKey() {
    return toBase64Url(randomBytes(32));
  }

  encrypt(text: string): string {
    try {
      const keyBuffer = fromBase64Url(this.key);
      const signingKey = keyBuffer.subarray(0, 16);
      const encryptionKey = keyBuffer.subarray(16, 32);
      const version = this.version;
      console.log(version);
      const timestamp = ts8byteBuffer();
      const iv = generateIv();
      const cipherText = aes128cbcEncrypt(text, encryptionKey, iv);
      const hmacInput = Buffer.concat([version, timestamp, iv, cipherText]);
      const hmac = computeHmac(hmacInput, signingKey);
      const token = Buffer.concat([version, timestamp, iv, cipherText, hmac]);
      return toBase64Url(token);
    } catch (err) {
      throw err;
    }
  }

  decrypt(token: string): string {
    try {
      const keyBuffer = fromBase64Url(this.key);
      const signingKey = keyBuffer.subarray(0, 16);
      const encryptionKey = keyBuffer.subarray(16, 32);
      const tokenBuffer = fromBase64Url(token);
      const version = tokenBuffer.subarray(0, 1);
      if (!compareBuffers(version, this.version)) {
        throw new Error('Fernet version must be 0x80');
      }
      const timestamp = tokenBuffer.subarray(1, 9);
      const iv = tokenBuffer.subarray(9, 25);
      const cipherText = tokenBuffer.subarray(25, tokenBuffer.length - 32);
      const hmac = tokenBuffer.subarray(
        tokenBuffer.length - 32,
        tokenBuffer.length
      );
      const toVerify = tokenBuffer.subarray(0, tokenBuffer.length - 32);
      const computedHmac = computeHmac(toVerify, signingKey);
      const isVerified = compareBuffers(hmac, computedHmac);
      if (!isVerified) {
        throw new Error('Invalid signature. Signature did not match digest.');
      }
      const decrypted = aes128cbcDecrypt(cipherText, encryptionKey, iv);
      return decrypted;
    } catch (err) {
      throw err;
    }
  }
}
