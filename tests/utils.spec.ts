import { ts8byteBuffer } from '../src/utils/utils';

describe('ts8byteBuffer', () => {
  test('returns a buffer of length 8', () => {
    const result = ts8byteBuffer();
    expect(result.length).toBe(8);
  });

  test('returns a buffer with 4 leading zeroes', () => {
    const expected = Buffer.alloc(4, 0);
    const result = ts8byteBuffer();
    expect(result.subarray(0, 4)).toEqual(expected);
  });
});