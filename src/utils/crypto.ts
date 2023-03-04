import * as crypto from 'crypto';

const randomBytes = (length: number): Buffer => {
  return crypto.randomBytes(length);
};

const generateIv = () => {
  return randomBytes(16);
};

const aesEncrypt = (
  plainText: string,
  key: Buffer,
  iv: Buffer,
  algo = 'aes-128-cbc'
): Buffer => {
  const cipher = crypto.createCipheriv(algo, key, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return Buffer.from(encrypted, 'hex');
};

const aesDecrypt = (
  cipherText: Buffer,
  key: Buffer,
  iv: Buffer,
  algo = 'aes-128-cbc'
): Buffer => {
  const decipher = crypto.createDecipheriv(algo, key, iv);
  let decrypted = decipher.update(cipherText);
  return Buffer.concat([decrypted, decipher.final()]);
};

const computeHmac = (input: Buffer, key: Buffer, algo = 'sha256'): Buffer => {
  return crypto.createHmac(algo, key).update(input).digest();
};

const compareBuffers = (a: Buffer, b: Buffer): boolean => {
  return crypto.timingSafeEqual(a, b);
};

const hash = (input: Buffer, algorithm = 'sha256'): Buffer => {
  return crypto.createHash(algorithm).update(input).digest();
};

export {
  randomBytes,
  generateIv,
  aesEncrypt,
  aesDecrypt,
  computeHmac,
  compareBuffers,
  hash,
};
