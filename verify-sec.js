const { spawn } = require('child_process');
const http = require('http');
function req(m, p, b, headers, timeout) {
  timeout = timeout || 30000;
  return new Promise((resolve) => {
    const pl = b ? JSON.stringify(b) : null;
    const r = http.request({ hostname: '127.0.0.1', port: 3001, path: p, method: m, timeout,
      headers: { ...(pl ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(pl) } : {}), ...(headers || {}) } },
      (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ s: res.statusCode, h: res.headers, b: d })); });
    r.on('timeout', () => { r.destroy(); resolve({ s: -1, b: 'TIMEOUT' }); });
    r.on('error', (e) => resolve({ s: -1, b: e.message }));
    if (pl) r.write(pl);
    r.end();
  });
}
let pass = 0, total = 0;
function check(name, cond, extra = '') {
  total++;
  if (cond) pass++;
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name + (extra ? ' | ' + extra : ''));
}
function boot(extraEnv) {
  const srv = spawn('node', ['backend/server.js'], { cwd: process.cwd(), env: { ...process.env, PORT: '3001', ...(extraEnv || {}) } });
  const logs = [];
  srv.stdout.on('data', (d) => logs.push(String(d)));
  srv.stderr.on('data', (d) => logs.push(String(d)));
  return { srv, logs };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  // ---------- PHASE A: headers, timing, validation, redaction, 404 ----------
  let { srv, logs } = boot();
  await sleep(3500);
  let r = await req('GET', '/');
  const h = r.h;
  check('HSTS max-age>=1yr', /max-age=31536000/.test(h['strict-transport-security'] || ''), h['strict-transport-security']);
  check('CSP script-src self only', /script-src 'self'/.test(h['content-security-policy'] || ''));
  check('CSP worker-src self+blob (map workers)', /worker-src 'self' blob:/.test(h['content-security-policy'] || ''));
  check('CSP connect allows tile host', (h['content-security-policy'] || '').includes('https://tiles.openfreemap.org'));
  check('CSP frame-ancestors self', /frame-ancestors 'self'/.test(h['content-security-policy'] || ''));
  check('CSP object-src none', /object-src 'none'/.test(h['content-security-policy'] || ''));
  check('X-Frame-Options SAMEORIGIN', h['x-frame-options'] === 'SAMEORIGIN');
  check('nosniff', h['x-content-type-options'] === 'nosniff');
  check('no-referrer', h['referrer-policy'] === 'no-referrer');
  check('robots noindex', /noindex/.test(h['x-robots-tag'] || ''));
  check('no x-powered-by', !h['x-powered-by']);

  async function timeLogin(u) {
    const t0 = Date.now();
    await req('POST', '/api/auth/login', { username: u, password: 'WrongPass1!' });
    return Date.now() - t0;
  }
  const un = 'timeprobe' + Date.now().toString(36);
  await req('POST', '/api/auth/signup', { username: un, password: 'TimeProbe1!', repeat: 'TimeProbe1!', dob: '1990-01-01' });
  const tu = [], tk = [];
  for (let i = 0; i < 3; i++) { tu.push(await timeLogin('definitely-not-here-' + i)); tk.push(await timeLogin(un)); }
  const avg = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const ratio = Math.max(avg(tu), avg(tk)) / Math.max(1, Math.min(avg(tu), avg(tk)));
  check('login timing parity (ratio<3)', ratio < 3, `unknown=${Math.round(avg(tu))}ms known=${Math.round(avg(tk))}ms`);

  r = await req('POST', '/api/auth/signup', { username: 'secprobe', password: 'x'.repeat(201), repeat: 'x'.repeat(201), dob: '1990-01-01' });
  check('201-char pw signup 400', r.s === 400);
  r = await req('POST', '/api/auth/login', { username: 'zzlenprobe', password: 'y'.repeat(500) });
  check('500-char pw login generic 401', r.s === 401, 'got ' + r.s);

  await req('GET', '/api/utils/timestamp?value=1&key=SUPERSECRETVOID999&api_key=ALSOVOID&token=TOKVOID&password=PWVOID');
  await sleep(500);
  const logText = logs.join('\n');
  check('secrets absent from logs', !/SUPERSECRETVOID999|ALSOVOID|TOKVOID|PWVOID/.test(logText));
  check('redaction marker present', logText.includes('[REDACTED]'));

  const un2 = 'nfprobe' + Date.now().toString(36);
  r = await req('POST', '/api/auth/signup', { username: un2, password: 'NfProbe12!', repeat: 'NfProbe12!', dob: '1991-02-02' });
  let nfTok = '';
  try { nfTok = JSON.parse(r.b).data.token; } catch {}
  r = await req('GET', '/api/definitely-missing', null, { Authorization: 'Bearer ' + nfTok });
  check('404 shape clean', r.s === 404 && !/stack|at [A-Za-z_]+\(/.test(r.b), r.s + ' ' + r.b.slice(0, 90));
  srv.kill();
  await sleep(1000);

  // ---------- PHASE B: fresh limiter bucket → 10x401 then 429 ----------
  ({ srv } = boot());
  await sleep(3500);
  const codes = [];
  for (let i = 0; i < 11; i++) {
    r = await req('POST', '/api/auth/login', { username: 'nosuchuser', password: 'WrongPass1!' });
    codes.push(r.s);
  }
  check('login 10x401 then 429', codes.slice(0, 10).every((c) => c === 401) && codes[10] === 429, codes.join(','));
  srv.kill();

  console.log(`\nSEC PASS ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})().catch((e) => { console.error('HARNESS FAIL', e); process.exit(1); });
