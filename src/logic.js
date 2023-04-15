import CryptoJS from 'crypto-js';

// Szyfruj wiadomość za pomocą AES w trybie CBC
const ciphers = (() => {
  const iv = CryptoJS.enc.Utf8.parse('abcdefghijklmnop');
  const cipherAES = (plaintext, key) => {
    const ciphertext = CryptoJS.AES.encrypt(plaintext, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return ciphertext.toString();
  };

  const decipherAES = (ciphertext, key) => {
    const bytes = CryptoJS.AES.decrypt(ciphertext.toString(), key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  };

  return { cipherAES, decipherAES };
})();

export default ciphers;
// console.log('Wiadomość zaszyfrowana:', ciphertext.toString());

// Dekoduj i odszyfruj wiadomość
