import * as crypto from 'crypto';

const randomBytes = (length: number): Buffer => {
  return crypto.randomBytes(length);
};

const generateIv = () => {
  return randomBytes(16);
};

const aes128cbcEncrypt = (
  plainText: string,
  key: Buffer,
  iv: Buffer
): Buffer => {
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return Buffer.from(encrypted, 'hex');
};

const aes128cbcDecrypt = (
  cipherText: Buffer,
  key: Buffer,
  iv: Buffer
): string => {
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let decrypted = decipher.update(cipherText, null, 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const computeHmac = (input: Buffer, key: Buffer, algo = 'sha256'): Buffer => {
  return crypto.createHmac(algo, key).update(input).digest();
};

const compareBuffers = (a: Buffer, b: Buffer): boolean => {
  return crypto.timingSafeEqual(a, b);
};

export {
  randomBytes,
  generateIv,
  aes128cbcEncrypt,
  aes128cbcDecrypt,
  computeHmac,
  compareBuffers,
};
