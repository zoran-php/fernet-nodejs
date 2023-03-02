const toBase64Url = (buffer: Buffer) => {
  const b64 = buffer.toString('base64url');
  const leftover = b64.length % 4;
  const lengthByFour = b64.length - leftover;
  const length =
    lengthByFour === b64.length ? b64.length : b64.length + (4 - leftover);
  return b64.padEnd(length, '=');
};

const fromBase64Url = (base64url: string) => {
  try {
    const buff = Buffer.from(base64url.replace(/\=/g, ''), 'base64url');
    return buff;
  } catch (err) {
    throw new Error('Invalid encoding. String must be base64url encoded.');
  }
};

export { toBase64Url, fromBase64Url };
