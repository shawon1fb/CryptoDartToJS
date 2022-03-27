import * as CryptoJS from "crypto-js";

// Encrypt
const ciphertext = CryptoJS.AES.encrypt('my message2', 'secret key 123').toString();
console.log(ciphertext);
// Decrypt
const bytes = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
const originalText = bytes.toString(CryptoJS.enc.Utf8);

console.log(originalText); // 'my message'