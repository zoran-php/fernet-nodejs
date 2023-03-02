const ts8byteBuffer = (): Buffer => {
  const now = Math.trunc(Date.now() / 1000);
  const nowHex = now.toString(16);
  const timestamp = Buffer.from(nowHex, 'hex');
  const initLength = timestamp.length;
  const totalLength = 8;
  const add = totalLength - initLength;
  const pad = Buffer.alloc(add, 0);
  const result = Buffer.concat([pad, timestamp]);
  return result;
};

export { ts8byteBuffer };
