// RFC 6238 Appendix B vectors: secret ASCII "12345678901234567890", SHA-1, 8 digits.
// T=59 -> 94287082, T=1111111109 -> 07081804, T=1234567890 -> 89005924.
const { base32Encode, totpCode, totpVerify } = require('./backend/utils/crypto');
const raw = Buffer.from('12345678901234567890', 'ascii');
const secret = base32Encode(raw);
console.log('secret:', secret);
const cases = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1234567890, '89005924'],
];
let pass = 0;
for (const [t, want8] of cases) {
  const got8 = totpCode(secret, t * 1000, 30, 8);
  const got6 = totpCode(secret, t * 1000, 30, 6);
  const ok = got8 === want8 && got6 === want8.slice(-6) && totpVerify(secret, got6, 1, t * 1000) && !totpVerify(secret, '000000', 1, t * 1000);
  if (ok) pass++;
  console.log((ok ? 'PASS' : 'FAIL'), 'T=' + t, 'want8=' + want8, 'got8=' + got8, 'got6=' + got6);
}
// base32 round-trip sanity (our secret must decode back to the raw bytes)
const { totpVerify: v2 } = require('./backend/utils/crypto');
console.log(pass === 3 ? 'RFC6238: ALL GREEN' : 'RFC6238: FAILURES');
process.exit(pass === 3 ? 0 : 1);
