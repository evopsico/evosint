const crypto = require('crypto');

/**
 * Encode text in various formats
 * @param {string} text - Text to encode
 * @param {string} type - Encoding type (base64, hex, binary, morse)
 * @returns {string} - Encoded text
 */
function encodeText(text, type) {
  switch (type.toLowerCase()) {
    case 'base64':
      return Buffer.from(text).toString('base64');
    case 'hex':
      return Buffer.from(text).toString('hex');
    case 'binary':
      return text.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
    case 'morse':
      const morseMap = {
        A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....',
        I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.',
        Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
        Y: '-.--', Z: '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
        '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
        ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
        '"': '.-..-.', '$': '...-..-', '@': '.--.-.', ' ': '/'
      };

      return text
        .toUpperCase()
        .split('')
        .map(c => morseMap[c] || c)
        .join(' ');
    default:
      throw new Error(`Invalid encoding type: ${type}`);
  }
}

/**
 * Decode text from various formats
 * @param {string} text - Text to decode
 * @param {string} type - Encoding type (base64, hex, binary, morse)
 * @returns {string} - Decoded text
 */
function decodeText(text, type) {
  switch (type.toLowerCase()) {
    case 'base64':
      return Buffer.from(text, 'base64').toString('utf8');
    case 'hex':
      return Buffer.from(text, 'hex').toString('utf8');
    case 'binary':
      return text.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
    case 'morse':
      const morseMap = {
        A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....',
        I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.',
        Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
        Y: '-.--', Z: '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
        '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
        ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
        '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
      };

      const morseReverse = Object.fromEntries(
        Object.entries(morseMap).map(([k, v]) => [v, k])
      );

      return text
        .split(' ')
        .map(c => (c === '/' ? ' ' : morseReverse[c] || c))
        .join('');
    default:
      throw new Error(`Invalid decoding type: ${type}`);
  }
}

/**
 * Generate hash of text
 * @param {string} text - Text to hash
 * @param {string} algorithm - Hash algorithm (md5, sha1, sha256, sha512)
 * @returns {string} - Hexadecimal hash
 */
function hashText(text, algorithm) {
  const hash = crypto.createHash(algorithm.toLowerCase());
  hash.update(text);
  return hash.digest('hex');
}

/**
 * Generate secure password
 * @param {number} length - Password length (default: 16)
 * @param {boolean} includeSymbols - Whether to include symbols (default: true)
 * @returns {string} - Generated password
 */
function generatePassword(length = 16, includeSymbols = true) {
  const len = Math.min(Math.max(Math.floor(length) || 16, 8), 128);
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const pool = includeSymbols ? chars + symbols : chars;

  let password = '';
  for (let i = 0; i < len; i++) {
    password += pool[crypto.randomInt(pool.length)]; // CSPRNG — Math.random is NOT safe for passwords
  }

  return password;
}

module.exports = {
  encodeText,
  decodeText,
  hashText,
  generatePassword
};