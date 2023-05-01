const ts8byteBuffer = (): Buffer => {
  const now = Math.trunc(Date.now() / 1000);
  const result = Buffer.alloc(8, 0);
  result.writeUInt32BE(now, 4);
  return result;
};

export { ts8byteBuffer };
