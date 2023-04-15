import CryptoJS from 'crypto-js';
import ciphers from '../logic';

test('AES cipher', () => {
  const key = CryptoJS.enc.Utf8.parse('1234567890123456');
  const plaintext = 'Hello World!';
  const encrypted = ciphers.encryptAES(plaintext, key);

  expect(encrypted).toEqual('CIkluy7Bh0b2w77xypv+8A==');

  const decrypted = ciphers.decryptAES(encrypted, key);

  expect(decrypted).toEqual('Hello World!');
});

test('MD5 cipher', () => {
  const plaintext = 'MD5 TEST!!!';
  const encrypt = ciphers.encryptMD5(plaintext);

  expect(encrypt).toEqual('7032351dd287de8b85f1ae05c184f99f');
});

test('SHA512 cipher', () => {
  const plaintext = 'SHA512 TEST!!!';
  const encrypted = ciphers.encryptSHA512(plaintext);

  expect(encrypted).toEqual('39a455ab8f28b907c2fe3714ad22fd27589602a39fb9bcc17274ed66a988dd6f8e68a6182350fbd0d982be318d6b90f8a371b86b19c3635152700f7db714056e');
});

test('DES cipher', () => {
  const plaintext = 'DES TEST!!!';
  const key = CryptoJS.enc.Utf8.parse('1234567890123456');
  const encrypted = ciphers.encryptDES(plaintext, key);

  expect(encrypted).toEqual('7/JYvZFHV5TwkybUR1kiFw==');

  const decrypted = ciphers.decryptDES(encrypted, key);

  expect(decrypted).toEqual(plaintext);
});

test('RC4 cipher', () => {
  const plaintext = 'RC4 TEST!!!';
  const key = CryptoJS.enc.Utf8.parse('1234567890123456');
  const encrypted = ciphers.encryptRC4(plaintext, key);

  expect(encrypted).toEqual('cvOnkXCgn90y4D4=');

  const decrypted = ciphers.decryptRC4(encrypted, key);

  expect(decrypted).toEqual(plaintext);
});

test('Base64', () => {
  const plaintext = 'test1234';
  const encoded = ciphers.toBase64(plaintext);
  expect(encoded).toEqual('dGVzdDEyMzQ=');

  const decoded = ciphers.fromBase64ToUtf8(encoded);
  expect(decoded).toEqual(plaintext);

  const decodedWrong = ciphers.fromBase64ToUtf8('test');
  expect(decodedWrong).toEqual('provide base64 text');
});
