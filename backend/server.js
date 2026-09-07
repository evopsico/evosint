const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 3001;

// Trust proxy (REQUIRED when sharing via tunnel/reverse proxy so each visitor
// gets their own IP-based guest bucket + rate limits; leave unset for localhost).
// Values: 1 (one proxy hop, e.g. local cloudflared) or true (trust all).
if (process.env.TRUST_PROXY) {
  const v = String(process.env.TRUST_PROXY).trim();
  app.set('trust proxy', /^\d+$/.test(v) ? Number(v) : true);
}

// ---------- Security & performance ----------
app.disable('x-powered-by');
// Flat query strings only (?a=1&a=2 stays a string, never an array/object):
// kills an entire class of parser-differential and prototype-pollution bugs.
app.set('query parser', 'simple');
app.use(helmet({
  // HSTS is ignored by browsers over plain HTTP (localhost/LAN) and enforced
  // the moment the app sits behind HTTPS — safe to always send, no preload pin.
  strictTransportSecurity: { maxAge: 31536000 },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // No inline <script> anywhere (all handlers are addEventListener/delegated).
      scriptSrc: ["'self'"],
      // Inline style="" attributes are used for dynamic result rendering.
      styleSrc: ["'self'", 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
      fontSrc: ["'self'", 'https://cdn.jsdelivr.net', 'data:'],
      // Favicons, avatars, logos load cross-origin by design.
      imgSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
    },
  },
  frameguard: { action: 'sameorigin' },
  // COEP require-corp would break cross-origin favicons/avatars (no CORP headers
  // on google/gravatar/clearbit) — intentionally off, documented here.
  crossOriginEmbedderPolicy: false,
  // OPSEC: external sites opened from results never learn our URL via Referer
  // (belt + suspenders alongside rel="noopener noreferrer" on every link).
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use(compression());
// (request logging is registered below with secret-redaction — do NOT add another morgan here)

const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors(corsOrigin ? { origin: corsOrigin.split(',').map((s) => s.trim()) } : {}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

// ---------- No client-side caching, ever (local tool: edits must appear instantly) ----------
// + noindex: if this ever hangs off a public tunnel, search engines stay out.
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use((req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex, nofollow'); next(); });

// Redacted request log: API keys/tokens/passwords must never land in log files,
// even when passed as query params (?key= / ?api_key= / ?token= / ?password=).
// The (?<![a-z_]) guard keeps innocent params (?monkey=, ?donkey=) intact.
const SENSITIVE_PARAM = /([?&])((?:api_?key|key|token|password|passwd|secret)=)[^&\s]*/gi;
function redactUrl(url) { return String(url || '').replace(SENSITIVE_PARAM, '$1$2[REDACTED]'); }
app.use(morgan((tokens, req, res) =>
  `${tokens.method(req, res)} ${redactUrl(tokens.url(req, res))} ${tokens.status(req, res)} ${tokens['response-time'](req, res)}ms`
));

// ---------- Rate limiting (prevents abuse + upstream bans) ----------
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests — slow down and try again shortly' },
});
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 90,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, error: 'Scan rate limit reached — try again in a few minutes' },
});
app.use('/api/', globalLimiter);
app.use(['/api/username', '/api/social', '/api/ssl', '/api/network', '/api/threat', '/api/archive', '/api/people', '/api/oauth', '/api/breacher', '/api/recon', '/api/lab'], scanLimiter);

// ---------- Auth (mounted before quota so login/signup/me never cost scans) ----------
const { router: authRouter, quotaMiddleware, ensureSeed } = require('./routes/auth');
app.use('/api/auth', authRouter);
app.use('/api', quotaMiddleware);
ensureSeed().catch((e) => console.error('auth seed failed:', e.message));

// ---------- Route registry ----------
// NOTE ON DEPLOY SAFETY: every route file is required with a STATIC string
// literal. Vercel's file tracer (nft) only bundles statically-analyzable
// requires — a `require(variable)` loop once shipped a function with NO route
// files in it (health + auth worked, everything else 404'd). This explicit
// form also makes the README's "no dynamic require" claim literally true.
function safeMount(mountPath, load) {
  try {
    app.use(mountPath, load());
    console.log(`✓ ${mountPath} loaded`);
  } catch (error) {
    console.error(`✗ Failed to load ${mountPath}:`, error.message);
  }
}
safeMount('/api/ip', () => require('./routes/ip'));
safeMount('/api/domain', () => require('./routes/domain'));
safeMount('/api/dns', () => require('./routes/dns'));
safeMount('/api/email', () => require('./routes/email'));
safeMount('/api/phone', () => require('./routes/phone'));
safeMount('/api/username', () => require('./routes/username'));
safeMount('/api/github', () => require('./routes/github'));
safeMount('/api/social', () => require('./routes/social'));
safeMount('/api/ssl', () => require('./routes/ssl'));
safeMount('/api/cve', () => require('./routes/cve'));
safeMount('/api/hash', () => require('./routes/hash'));
safeMount('/api/utils', () => require('./routes/utils'));
safeMount('/api/network', () => require('./routes/network'));
safeMount('/api/threat', () => require('./routes/threat'));
safeMount('/api/archive', () => require('./routes/archive'));
safeMount('/api/geo', () => require('./routes/geo'));
safeMount('/api/crypto', () => require('./routes/blockchain'));
safeMount('/api/people', () => require('./routes/people'));
safeMount('/api/bgp', () => require('./routes/bgp'));
safeMount('/api/verify', () => require('./routes/verify'));
safeMount('/api/forensics', () => require('./routes/forensics'));
safeMount('/api/company', () => require('./routes/company'));
safeMount('/api/oauth', () => require('./routes/oauth'));
safeMount('/api/breacher', () => require('./routes/breacher'));
safeMount('/api/recon', () => require('./routes/recon'));
safeMount('/api/lab', () => require('./routes/stress'));

// ---------- Static + pages (no-store: a cached UI is a stale UI) ----------
const NO_STORE = (res) => res.setHeader('Cache-Control', 'no-store');
app.use('/public', express.static(path.join(__dirname, '..', 'public'), {
  etag: false, lastModified: false, maxAge: 0,
  setHeaders: (res) => NO_STORE(res),
}));
const APP_VERSION = (() => { try { return require('../package.json').version || 'dev'; } catch { return 'dev'; } })();
const fs = require('fs');
app.get('/', (req, res) => {
  try {
    const html = fs.readFileSync(path.resolve(__dirname, '..', 'index.html'), 'utf8').split('__APPV__').join(APP_VERSION);
    NO_STORE(res);
    res.type('html').send(html);
  } catch (e) {
    res.status(500).send('console failed to load');
  }
});

app.get(['/health', '/api/health'], (req, res) => {
  res.json({
    status: 'OK',
    version: '2.11.0',
    uptime_seconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// ---------- 404 + errors (never leak stacks) ----------
app.use((req, res) => res.status(404).json({ success: false, error: 'Route not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err);
  const status = err && Number.isInteger(err.status) ? err.status : 500;
  res.status(status).json({ success: false, error: status === 500 ? 'Internal server error' : (err.message || 'Request failed') });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`OSINT API server running on http://localhost:${PORT}`));
}

module.exports = app;
