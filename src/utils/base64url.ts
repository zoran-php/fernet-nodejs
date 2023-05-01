const toBase64Url = (buffer: Buffer) => {
  const b64 = buffer.toString('base64url');
  const leftover = b64.length % 4;
  const lengthByFour = b64.length - leftover;
  const length =
    lengthByFour === b64.length ? b64.length : b64.length + (4 - leftover);
  return b64.padEnd(length, '=');
};

const fromBase64Url = (base64url: string) => {
  const unpadded = base64url.replace(/\=/g, '');
  if (Buffer.from(unpadded, 'base64url').toString('base64url') !== unpadded) {
    throw new Error(
      'Invalid encoding. String must be base64url encoded string.'
    );
  }
  const buff = Buffer.from(unpadded, 'base64url');
  return buff;
};

export { toBase64Url, fromBase64Url };
