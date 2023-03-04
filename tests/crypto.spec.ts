import * as crypto from 'crypto';
import { randomBytes, generateIv, computeHmac, hash, compareBuffers, aesEncrypt, aesDecrypt } from "../src/utils/crypto";

describe('randomBytes', () => {
  it('returns a Buffer of the correct length', () => {
    const length = 10;
    const result = randomBytes(length);
    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBe(length);
  });
});

describe('randomBytes', () => {
  it('returns a Buffer with the length of 16 bytes', () => {
    const length = 16;
    const result = generateIv();
    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBe(length);
  });
});

describe('computeHmac', () => {
  const input = Buffer.from('hello');
  const key = Buffer.from('world');

  it('returns the expected HMAC', () => {
    const expected = crypto.createHmac('sha256', key).update(input).digest();
    const result = computeHmac(input, key);

    expect(result).toEqual(expected);
  });

  it('uses the specified algorithm', () => {
    const algo = 'sha512';
    const expected = crypto.createHmac(algo, key).update(input).digest();
    const result = computeHmac(input, key, algo);

    expect(result).toEqual(expected);
  });
});

describe('hash', () => {
  const input = Buffer.from('hello');

  it('returns the expected hash', () => {
    const expected = crypto.createHash('sha256').update(input).digest();
    const result = hash(input);

    expect(result).toEqual(expected);
  });

  it('uses the specified algorithm', () => {
    const algorithm = 'sha512';
    const expected = crypto.createHash(algorithm).update(input).digest();
    const result = hash(input, algorithm);

    expect(result).toEqual(expected);
  });
});

describe('compareBuffers', () => {
  const a = Buffer.from('hello');
  const b = Buffer.from('world');

  it('returns true for equal buffers', () => {
    const result = compareBuffers(a, a);

    expect(result).toBe(true);
  });

  it('returns false for different buffers', () => {
    const result = compareBuffers(a, b);

    expect(result).toBe(false);
  });

  it('returns true for empty buffers', () => {
    const result = compareBuffers(Buffer.alloc(0), Buffer.alloc(0));

    expect(result).toBe(true);
  });
});

describe('aes', () => {
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const plainText = 'hello world';

  it('correctly encrypts and decrypts the plain text', () => {
    const encrypted = aesEncrypt(plainText, key, iv);
    const decrypted = aesDecrypt(encrypted, key, iv);

    expect(decrypted.toString('utf8')).toEqual(plainText);
  });

  it('returns a different cipher text for different plain texts', () => {
    const plainText2 = 'goodbye world';
    const encrypted1 = aesEncrypt(plainText, key, iv);
    const encrypted2 = aesEncrypt(plainText2, key, iv);

    expect(encrypted1.equals(encrypted2)).toBe(false);
  });

  it('returns a different cipher text for different keys', () => {
    const key2 = crypto.randomBytes(16);
    const encrypted1 = aesEncrypt(plainText, key, iv);
    const encrypted2 = aesEncrypt(plainText, key2, iv);

    expect(encrypted1.equals(encrypted2)).toBe(false);
  });

  it('returns a different cipher text for different ivs', () => {
    const iv2 = crypto.randomBytes(16);
    const encrypted1 = aesEncrypt(plainText, key, iv);
    const encrypted2 = aesEncrypt(plainText, key, iv2);

    expect(encrypted1.equals(encrypted2)).toBe(false);
  });
});