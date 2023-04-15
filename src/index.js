// import webInit from './dom';
// import './style.scss';

// document.addEventListener('DOMContentLoaded', () => {
//   webInit();
// });

import CryptoJS from 'crypto-js';

const key = CryptoJS.enc.Utf8.parse('1234567890123456');
const iv = CryptoJS.enc.Utf8.parse('abcdefghijklmnop');

const plaintext = 'Hello World!';

// Szyfruj wiadomość za pomocą AES w trybie CBC
const ciphertext = CryptoJS.AES.encrypt(plaintext, key, {
  iv,
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7,
});

console.log('Wiadomość zaszyfrowana:', ciphertext.toString());

// Dekoduj i odszyfruj wiadomość
const bytes = CryptoJS.AES.decrypt(ciphertext.toString(), key, {
  iv,
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7,
});

const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
console.log('Wiadomość odszyfrowana:', decryptedText);
