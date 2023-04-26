import CryptoJS from 'crypto-js';

const ciphers = (() => {
  // Encrypt Decrypt functions (AES, DES, RC4)

  const iv = CryptoJS.enc.Utf8.parse('abcdefghijklmnop');
  const encryptAES = (plaintext, key) => {
    const encryptedText = CryptoJS.AES.encrypt(plaintext, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return encryptedText.toString();
  };

  const decryptAES = (encryptedText, key) => {
    const bytes = CryptoJS.AES.decrypt(encryptedText.toString(), key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  };

  const encryptDES = (plaintext, key) => {
    const encryptedText = CryptoJS.DES.encrypt(plaintext, key, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });
    return encryptedText.toString();
  };

  const decryptDES = (encryptedText, key) => {
    const bytes = CryptoJS.DES.decrypt(encryptedText.toString(), key, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  };

  const encryptRC4 = (plaintext, key) => {
    const encryptedText = CryptoJS.RC4.encrypt(plaintext, key);
    return encryptedText.toString();
  };

  const decryptRC4 = (encryptedText, key) => {
    const bytes = CryptoJS.RC4.decrypt(encryptedText.toString(), key);
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  };

  // MD5, SHA-256, and SHA-512 hash functions
  const encryptMD5 = (plaintext) => {
    const encryptedText = CryptoJS.MD5(plaintext).toString();
    return encryptedText;
  };

  const encryptSHA256 = (plaintext) => {
    const encryptedText = CryptoJS.SHA256(plaintext).toString();
    return encryptedText;
  };

  const encryptSHA512 = (plaintext) => {
    const encryptedText = CryptoJS.SHA512(plaintext).toString();
    return encryptedText;
  };

  return {
    encryptAES,
    decryptAES,
    encryptMD5,
    encryptSHA256,
    encryptSHA512,
    encryptDES,
    decryptDES,
    encryptRC4,
    decryptRC4,
  };
})();

export default ciphers;
