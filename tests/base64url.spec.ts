import { toBase64Url, fromBase64Url } from '../src/utils/base64url';

describe('toBase64Url', () => {
  test('returns a base64url encoded string with pad', () => {
    const buffer = Buffer.from('hello world');
    const expected = 'aGVsbG8gd29ybGQ=';
    const result = toBase64Url(buffer);
    expect(result).toEqual(expected);
  });

  test('pads the result string with "=" characters if necessary', () => {
    const buffer = Buffer.from('a');
    const expected = 'YQ==';
    const result = toBase64Url(buffer);
    expect(result).toEqual(expected);
  });

  test('does not pad the result string if length is already a multiple of 4', () => {
    const buffer = Buffer.from('base64');
    const expected = 'YmFzZTY0';
    const result = toBase64Url(buffer);
    expect(result).toEqual(expected);
  });
});

describe('fromBase64Url', () => {
  test('decodes a base64url-encoded string with padding', () => {
    const base64url = 'YWJjZA==';
    const expected = Buffer.from('abcd');
    const result = fromBase64Url(base64url);
    expect(result).toEqual(expected);
  });

  test('decodes a base64url-encoded string without padding', () => {
    const base64url = 'YWJjZA';
    const expected = Buffer.from('abcd');
    const result = fromBase64Url(base64url);
    expect(result).toEqual(expected);
  });

  test('throws an error for an invalid base64url-encoded string', () => {
    const base64url = '%%invalid*string!@#$';
    expect(() => fromBase64Url(base64url)).toThrow('Invalid encoding. String must be base64url encoded string.');
  });
});