import {
  aesDecrypt,
  aesEncrypt,
  compareBuffers,
  computeHmac,
  fromBase64Url,
  generateIv,
  hash,
  randomBytes,
  toBase64Url,
  ts8byteBuffer,
} from './utils/index';

export class Fernet {
  static readonly version: Buffer = Buffer.from([0x80]);

  constructor(private key: string) {
    Fernet.checkKey(this.key);
  }

  /**
   * Checks if the key is encoded as base64url, and if the length of the key is 32 bytes.
   *
   * @remarks
   * This method checks if the key is valid for Fernet cipher.
   * Throws error if the key is not in base64url format or it's not 32 bytes long.
   *
   * @returns void
   *
   */
  static checkKey(key: string): void {
    try {
      const buffer = fromBase64Url(key);
      if (buffer.length !== 32) {
        throw new Error('Key must be 32-byte long base64url encoded string.');
      }
    } catch (error) {
      throw new Error('Key must be 32-byte long base64url encoded string.');
    }
  }

  /**
   * Returns 32-byte long base64url encoded string.
   *
   * @remarks
   * This method generates random 32 bytes.
   * The generated random bytes are encoded as base64url encoded string.
   * First 16 bytes are used as signing key for computing 256-bit SHA256 HMAC.
   * Last 16 bytes are user as encryption key.
   *
   * @returns 32-byte long key encoded as base64url string.
   *
   */
  static generateKey(): string {
    return toBase64Url(randomBytes(32));
  }

  /**
   * Returns Fernet token as base64url encoded string.
   *
   * @remarks
   * This method encrypts the input text with the given key.
   * It returns Fernet token that contains encrypted input text.
   * The Fernet token is encoded as base64url encoded string.
   *
   * @param text - The input text
   * @returns Fernet token encoded as base64url encoded string.
   *
   */
  encrypt(text: string): string {
    return Fernet.encrypt(text, this.key);
  }

  /**
   * Returns decrypted plain text from provided Fernet token.
   *
   * @remarks
   * This method decrypts Fernet token with the given key.
   * Returns decrypted string as plain text.
   * The decrypted string is encoded as utf-8 encoded string.
   *
   * @param token - Fernet token
   * @returns Decrypted utf-8 encoded string.
   *
   */
  decrypt(token: string): string {
    return Fernet.decrypt(token, this.key);
  }

  /**
   * Returns decrypted plain text from provided Fernet token.
   *
   * @remarks
   * This method decrypts Fernet token with the given key.
   * Returns decrypted string as plain text.
   * The decrypted string is encoded as utf-8 encoded string.
   *
   * @param token - Fernet token
   * @param key - The provided 32-byte long base64url encoded key
   * @returns Decrypted utf-8 encoded string.
   *
   */
  static decrypt(token: string, key: string): string {
    try {
      Fernet.checkKey(key);
      const keyBuffer = fromBase64Url(key);
      const signingKey = keyBuffer.subarray(0, 16);
      const encryptionKey = keyBuffer.subarray(16, 32);
      const tokenBuffer = fromBase64Url(token);
      const version = tokenBuffer.subarray(0, 1);
      if (!compareBuffers(version, Fernet.version)) {
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
      const decrypted = aesDecrypt(cipherText, encryptionKey, iv);
      return decrypted.toString('utf-8');
    } catch (err) {
      throw err;
    }
  }

  /**
   * Returns Fernet token as base64url encoded string.
   *
   * @remarks
   * This method encrypts the input text with the given key.
   * It returns Fernet token that contains encrypted input text.
   * The Fernet token is encoded as base64url encoded string.
   *
   * @param text - The input text
   * @returns Fernet token encoded as base64url encoded string.
   *
   */
  static encrypt(text: string, key: string): string {
    try {
      Fernet.checkKey(key);
      const keyBuffer = fromBase64Url(key);
      const signingKey = keyBuffer.subarray(0, 16);
      const encryptionKey = keyBuffer.subarray(16, 32);
      const version = Fernet.version;
      const timestamp = ts8byteBuffer();
      const iv = generateIv();
      const cipherText = aesEncrypt(text, encryptionKey, iv);
      const hmacInput = Buffer.concat([version, timestamp, iv, cipherText]);
      const hmac = computeHmac(hmacInput, signingKey);
      const token = Buffer.concat([version, timestamp, iv, cipherText, hmac]);
      return toBase64Url(token);
    } catch (err) {
      throw err;
    }
  }

  /**
   * Returns SHA256 hashed input as base64url encoded string
   *
   * @remarks
   * This method is useful for deriving Fernet key from arbitrary input string.
   *
   * @param input - The input string
   * @returns SHA256 hashed input as base64url encoded string
   *
   */
  static deriveKey(input: string): string {
    const inputBuff = Buffer.from(input, 'utf-8');
    const sha256 = hash(inputBuff, 'sha256');
    return toBase64Url(sha256);
  }
}
