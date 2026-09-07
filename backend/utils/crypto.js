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
  generatePassword,
  base32Encode,
  totpCode,
  totpVerify,
  newBackupCodes,
  sha256hex,
};

// ---------- TOTP (RFC 6238, SHA-1, dependency-free) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const byte of buf) {
    val = (val << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function base32Decode(s) {
  const clean = String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, val = 0;
  const bytes = [];
  for (const ch of clean) {
    val = (val << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}
function totpCode(secretB32, timeMs, step = 30, digits = 6) {
  const counter = Math.floor((timeMs || Date.now()) / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secretB32)).update(msg).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
  return String(code % (10 ** digits)).padStart(digits, '0');
}
function totpVerify(secretB32, code, window = 1, nowMs) {
  const now = nowMs || Date.now();
  const want = String(code || '').replace(/\D/g, '');
  if (want.length !== 6) return false;
  for (let w = -window; w <= window; w++) {
    const got = totpCode(secretB32, now + w * 30000);
    if (got.length === want.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want))) return true;
  }
  return false;
}
function sha256hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}
// 8 single-use backup codes (caller stores only the hashes).
function newBackupCodes() {
  const pool = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const out = [];
  for (let i = 0; i < 8; i++) {
    let c = '';
    for (let j = 0; j < 10; j++) c += pool[crypto.randomInt(pool.length)];
    out.push(c.slice(0, 4) + '-' + c.slice(4));
  }
  return out;
}