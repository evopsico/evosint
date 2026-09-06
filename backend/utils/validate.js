const validator = require('validator');

// Shared validation helpers — strict but correct (fixes broken regexes in v1).

function isValidIP(ip) {
  return typeof ip === 'string' && validator.isIP(ip.trim(), 4) || validator.isIP((ip || '').trim(), 6);
}

function isPrivateIP(ip) {
  const v = (ip || '').trim();
  if (!validator.isIP(v, 4)) return false;
  const parts = v.split('.').map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 0) return true;
  return false;
}

// Accepts bare domains AND subdomains, multi-level TLDs, punycode. Rejects URLs/paths/ports.
function isValidDomain(input) {
  if (typeof input !== 'string') return false;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').split('/')[0].split('?')[0].split('#')[0].split('@').pop();
  d = d.replace(/:\d+$/, '').replace(/\.$/, '');
  if (d.length < 3 || d.length > 253) return false;
  return validator.isFQDN(d, { require_tld: true, allow_underscores: false });
}

function normalizeDomain(input) {
  let d = String(input || '').trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').split('/')[0].split('?')[0].split('#')[0].split('@').pop();
  d = d.replace(/:\d+$/, '').replace(/\.$/, '');
  return d;
}

function isValidEmail(email) {
  return typeof email === 'string' && validator.isEmail(email.trim(), { allow_utf8_local_part: false });
}

function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9._-]{1,39}$/.test(u.trim());
}

function isValidGitHubUsername(u) {
  // GitHub rules: 1-39 chars, alnum + hyphen, no leading/trailing hyphen, no consecutive hyphens
  if (typeof u !== 'string') return false;
  const s = u.trim();
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(s) && !s.includes('--');
}

function isValidHash(h) {
  if (typeof h !== 'string') return null;
  const s = h.trim().toLowerCase();
  if (/^[a-f0-9]{32}$/.test(s)) return 'md5';
  if (/^[a-f0-9]{40}$/.test(s)) return 'sha1';
  if (/^[a-f0-9]{64}$/.test(s)) return 'sha256';
  if (/^[a-f0-9]{128}$/.test(s)) return 'sha512';
  return null;
}

const SUPPORTED_HASHES = ['md5', 'sha1', 'sha256', 'sha512', 'sha384', 'ripemd160'];

function ok(res, data, extra = {}) {
  return res.json({ success: true, data, timestamp: new Date().toISOString(), ...extra });
}

function fail(res, status, message) {
  return res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

// Production error hygiene: only messages we curated (thrown with a numeric
// `status`) ever reach the client. Raw system/upstream errors (timeouts, DNS,
// TLS, axios internals) collapse to a generic fallback — they can carry
// hostnames, paths, or provider metadata that must never leak.
function clientError(err, fallback = 'Request failed') {
  if (err && Number.isInteger(err.status) && typeof err.message === 'string') return err.message;
  return fallback;
}

// Tighten free-text fields: single line, no control chars, hard length cap.
function oneLine(s, max = 120) {
  return String(s ?? '').replace(/[\u0000-\u001F\u007F]+/g, ' ').trim().slice(0, max);
}

// Map axios errors to clean API errors (never leak stacks).
function axiosError(res, error, fallback = 'Upstream OSINT service error') {
  if (error.response) {
    const status = error.response.status;
    const upstream = error.response.data;
    const msg = typeof upstream === 'string' ? upstream.slice(0, 500)
      : (upstream && (upstream.message || upstream.error)) || error.message || fallback;
    if (status === 404) return fail(res, 404, typeof msg === 'string' ? msg : 'Not found');
    if (status === 429) return fail(res, 502, 'Upstream rate limit reached — try again in a minute');
    return fail(res, status >= 500 ? 502 : status, typeof msg === 'string' ? msg : fallback);
  }
  if (error.request || error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
    return fail(res, 504, 'No response from OSINT service (timeout)');
  }
  return fail(res, 500, error.message || fallback);
}

module.exports = {
  isValidIP, isPrivateIP, isValidDomain, normalizeDomain,
  isValidEmail, isValidUsername, isValidGitHubUsername,
  isValidHash, SUPPORTED_HASHES, ok, fail, axiosError, clientError, oneLine,
};
