import CryptoJS from 'crypto-js';

import ciphers from '../logic';

test('AES cipher and decipher', () => {
  const key = CryptoJS.enc.Utf8.parse('1234567890123456');
  //   const iv = CryptoJS.enc.Utf8.parse('abcdefghijklmnop');
  const plaintext = 'Hello World!';

  const cipher = ciphers.cipherAES(plaintext, key);
  //  console.log(cipher);
  expect(cipher).toEqual('CIkluy7Bh0b2w77xypv+8A==');
  const decipher = ciphers.decipherAES(cipher, key);
  expect(decipher).toEqual('Hello World!');
});
