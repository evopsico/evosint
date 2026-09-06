const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { http } = require('../utils/http');
const { isValidHash, SUPPORTED_HASHES, ok, fail } = require('../utils/validate');

function makeHash(algorithm, text) {
  const h = crypto.createHash(algorithm);
  h.update(text, 'utf8');
  return h.digest('hex');
}

// ---- Specific routes FIRST (v1 bug: /:algorithm/:text shadowed /check/* and /file) ----
router.get('/test', (req, res) => res.json({ success: true, message: 'Hash service OK' }));

/** GET /api/hash/check/:hash — honest malware lookup (MalwareBazaar, no key). */
router.get('/check/:hash', async (req, res) => {
  const hash = String(req.params.hash || '').trim().toLowerCase();
  const algo = isValidHash(hash);
  if (!algo) return fail(res, 400, 'Invalid hash (MD5/SHA1/SHA256/SHA512 hex expected)');

  // Real lookup: MalwareBazaar (abuse.ch, no key). VT only if key configured.
  let verdict = { is_malicious: null, threat_level: 'unknown', sources_checked: [], details: '' };
  try {
    const r = await http.post('https://mb-api.abuse.ch/api/v1/', new URLSearchParams({ query: 'get_info', hash }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000,
    });
    verdict.sources_checked.push('MalwareBazaar');
    if (r.status === 200 && r.data?.query_status === 'ok') {
      const d = r.data.data?.[0] || {};
      verdict = {
        is_malicious: true, threat_level: 'high', sources_checked: verdict.sources_checked,
        details: `Known malware: ${d.signature || 'unknown'} (${d.file_type || 'file'}) — first seen ${d.first_seen || '?'}`,
        file_info: { signature: d.signature || null, file_type: d.file_type || null, file_size: d.file_size ?? null, tags: d.tags || [] },
      };
    } else {
      verdict = { is_malicious: false, threat_level: 'none', sources_checked: verdict.sources_checked, details: 'Not found in MalwareBazaar' };
    }
  } catch {
    verdict = { is_malicious: null, threat_level: 'unknown', sources_checked: [], details: 'MalwareBazaar unreachable — verdict inconclusive' };
  }

  if (process.env.VIRUSTOTAL_API_KEY) {
    verdict.sources_checked.push('VirusTotal');
    verdict.details += ' (VT key configured — query vt-cli or gui for full report)';
  } else {
    verdict.details += ' (set VIRUSTOTAL_API_KEY for VT enrichment)';
  }
  return ok(res, { hash, algorithm: algo, ...verdict });
});

/** POST /api/hash/file — disallow (no uploads by design); explicit message. */
router.post('/file', (req, res) => fail(res, 501, 'File upload hashing is disabled in server mode — use the text endpoint or hash locally'));

/** POST /api/hash — body-based (avoids URL-length/slash bugs of GET). */
router.post('/', (req, res) => {
  const { algorithm = 'sha256', text = '' } = req.body || {};
  if (typeof text !== 'string' || !text) return fail(res, 400, 'Body { algorithm, text } required, text must be non-empty');
  if (text.length > 100000) return fail(res, 413, 'Text too large (max 100k chars)');
  const algo = String(algorithm).toLowerCase();
  if (!SUPPORTED_HASHES.includes(algo)) return fail(res, 400, `Unsupported algorithm. Use: ${SUPPORTED_HASHES.join(', ')}`);
  try {
    return ok(res, { algorithm: algo, text_length: text.length, hash: makeHash(algo, text) });
  } catch (e) { return fail(res, 500, e.message); }
});

/** GET /api/hash/:algorithm/:text — kept for backwards compat (short texts only). */
router.get('/:algorithm/:text', (req, res) => {
  // NOTE: Express already URL-decodes params — v1 double-decoded and broke on % and /.
  const algo = String(req.params.algorithm || '').toLowerCase();
  const text = String(req.params.text ?? '');
  if (!SUPPORTED_HASHES.includes(algo)) return fail(res, 400, `Unsupported algorithm. Use: ${SUPPORTED_HASHES.join(', ')}`);
  if (!text) return fail(res, 400, 'Text is required');
  if (text.length > 4000) return fail(res, 413, 'Text too long for GET (max ~4k chars) — use POST /api/hash');
  try {
    return ok(res, { algorithm: algo, text, hash: makeHash(algo, text) });
  } catch (e) { return fail(res, 500, e.message); }
});

module.exports = router;
