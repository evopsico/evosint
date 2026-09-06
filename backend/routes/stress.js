const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { ok, fail } = require('../utils/validate');

// LOAD STRESS TESTER — k6-lite for YOUR OWN sites.
// Hard caps (server-enforced, non-negotiable): ≤500 requests, ≤10 concurrency,
// ≤60s wall time, GET/HEAD only, one run at a time, private targets blocked,
// explicit ownership confirmation required. This is a measurement tool, not a flooder.

const CAPS = { max_requests: 500, max_concurrency: 10, max_seconds: 60, methods: ['GET', 'HEAD'] };
let busy = false;

function blockedHost(h) {
  h = String(h || '').toLowerCase();
  return !h || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')
    || ['169.254.169.254', 'metadata.google.internal'].includes(h)
    || /^(127\.|10\.|0\.)/.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    || /^169\.254\./.test(h) || h === '::1';
}

// GET /api/lab/limits — published caps
router.get('/limits', (req, res) => ok(res, { ...CAPS, concurrent_runs: 1, per_request_timeout_ms: 15000 }));

// POST /api/lab/stress { url, requests?, concurrency?, method?, confirm? }
// Set DISABLE_STRESS=1 to turn this endpoint off (recommended on public instances).
router.post('/stress', async (req, res) => {
  if (process.env.DISABLE_STRESS === '1') return fail(res, 404, 'Load tester disabled on this instance');
  let u;
  try {
    u = new URL(String(req.body?.url || ''));
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s)');
    if (blockedHost(u.hostname)) throw new Error('Private/internal targets blocked');
    if (u.username || u.password) throw new Error('Credentials in URL not allowed');
  } catch (e) { return fail(res, 400, `Invalid target: ${e.message}`); }
  if (req.body?.confirm !== true) return fail(res, 400, 'Ownership confirmation required — tick the box confirming you own / are authorized to test this target');
  const total = Math.min(Math.max(parseInt(req.body?.requests, 10) || 50, 1), CAPS.max_requests);
  const conc = Math.min(Math.max(parseInt(req.body?.concurrency, 10) || 5, 1), CAPS.max_concurrency);
  const method = String(req.body?.method || 'GET').toUpperCase();
  if (!CAPS.methods.includes(method)) return fail(res, 400, 'Method must be GET or HEAD');
  if (busy) return fail(res, 429, 'A stress run is already in progress — one at a time');
  busy = true;
  const t0 = Date.now();
  const deadline = t0 + CAPS.max_seconds * 1000;
  const lat = [], hist = {};
  let okN = 0, failN = 0, sent = 0;
  let idx = 0;
  try {
    const worker = async () => {
      while (idx < total && Date.now() < deadline) {
        const n = idx++;
        sent++;
        const s = Date.now();
        try {
          const r = await http.request({ url: u.toString(), method, timeout: 15000, maxRedirects: 2,
            headers: { 'User-Agent': 'Evosint-LoadTest/2.4 (authorized-owner-testing)' } });
          lat.push(Date.now() - s);
          hist[r.status] = (hist[r.status] || 0) + 1;
          if (r.status < 500) okN++; else failN++;
        } catch (e) {
          lat.push(Date.now() - s);
          hist.network_error = (hist.network_error || 0) + 1;
          failN++;
        }
        void n;
      }
    };
    await Promise.all(Array.from({ length: Math.min(conc, total) }, worker));
    const dur = (Date.now() - t0) / 1000;
    lat.sort((a, b) => a - b);
    const pct = (p) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((p / 100) * lat.length))] : 0);
    const avg = lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : 0;
    const errRate = sent ? failN / sent : 0;
    return ok(res, {
      target: u.origin + u.pathname, method, requested: total, sent,
      ok: okN, failed: failN, error_rate: +errRate.toFixed(3),
      status_histogram: hist,
      ms: { avg, p50: pct(50), p95: pct(95), max: lat.length ? lat[lat.length - 1] : 0 },
      rps: +(sent / Math.max(dur, 0.01)).toFixed(1), duration_s: +dur.toFixed(1),
      truncated_by_deadline: sent < total,
      verdict: errRate >= 0.5 ? 'FAILING under load — error rate ≥50%' : errRate >= 0.1 ? 'DEGRADED — 10%+ errors, investigate before shipping' : `HEALTHY — absorbed ${(sent / Math.max(dur, 0.01)).toFixed(0)} rps with <10% errors`,
    }, { source: 'evosint-stress' });
  } finally { busy = false; }
});

module.exports = router;
