const express = require('express');
const tls = require('tls');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, ok, fail } = require('../utils/validate');

function fetchDirectCert(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        socket.end();
        if (!cert || !Object.keys(cert).length) return resolve({ error: 'No certificate presented' });
        resolve({
          subject: cert.subject, issuer: cert.issuer,
          valid_from: cert.valid_from, valid_to: cert.valid_to,
          days_remaining: Math.max(0, Math.ceil((new Date(cert.valid_to) - Date.now()) / 86400000)),
          expired: Date.now() > new Date(cert.valid_to).getTime(),
          fingerprint: cert.fingerprint, fingerprint256: cert.fingerprint256,
          serialNumber: cert.serialNumber, subjectaltname: cert.subjectaltname || null,
          cipher: cipher ? `${cipher.name} (${cipher.version})` : null,
          tls_version: protocol, _source: 'direct-tls',
        });
      } catch (e) { try { socket.destroy(); } catch {} resolve({ error: e.message }); }
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'TLS handshake timed out' }); });
    socket.on('error', (e) => resolve({ error: e.message }));
    setTimeout(() => { try { socket.destroy(); } catch {} resolve({ error: 'TLS handshake timed out' }); }, timeoutMs + 1000).unref?.();
  });
}

/**
 * GET /api/ssl/:domain[?fresh=1] — instant direct-TLS cert + optional SSL Labs grade.
 * v1 flaw fixed: always triggered a NEW SSL Labs scan (slow, rate-limited, often IN_PROGRESS).
 */
router.get('/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);

  try {
    const { data, cached } = await getOrSet(`ssl:${domain}`, 3600, async () => fetchDirectCert(domain));
    if (data.error) return ok(res, { direct: data, labs: null }, { cached, note: `Direct TLS failed (${data.error}). Use ?fresh=1 for SSL Labs deep scan.` });

    let labs = null;
    if (String(req.query.fresh || '') === '1') {
      // Cached SSL Labs assessment, never force a new scan by default
      const r = await http.get(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&fromCache=on&all=done&maxAge=24`, { timeout: 20000 });
      labs = r.data;
    }
    return ok(res, { direct: data, labs }, { cached, note: labs ? 'SSL Labs from cache (≤24h).' : 'Direct TLS result. Add ?fresh=1 for SSL Labs grade (slow, cached).' });
  } catch (e) {
    return fail(res, 500, e.message || 'SSL analysis failed');
  }
});

module.exports = router;
