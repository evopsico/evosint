const { spawn } = require('child_process');
const http = require('http');
const PORT = 3001;

const server = spawn('node', ['backend/server.js'], { cwd: __dirname, env: { ...process.env, PORT: String(PORT) } });
server.stdout.on('data', () => {});
server.stderr.on('data', () => {});

function call(path, method = 'GET', body = null, headers = {}, timeout = 45000) {
  return new Promise((resolve) => {
    const p = body ? JSON.stringify(body) : null;
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path, method, timeout,
      headers: { ...(p ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(p) } : {}), ...headers } },
      (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d })); });
    req.on('timeout', () => { req.destroy(); resolve({ status: -1, body: 'TIMEOUT' }); });
    req.on('error', (e) => resolve({ status: -1, body: 'ERR ' + e.message }));
    if (p) req.write(p);
    req.end();
  });
}

(async () => {
  await new Promise((r) => setTimeout(r, 3500));
  const J = (r) => { try { return JSON.parse(r.body); } catch { return {}; } };
  // sign up a fresh user for quota
  const uname = 'smoke' + Date.now().toString(36);
  let r = await call('/api/auth/signup', 'POST', { username: uname, password: 'SmokePass1!', repeat: 'SmokePass1!', dob: '1995-06-06' });
  const tok = J(r).data && J(r).data.token;
  console.log('signup ->', r.status, tok ? 'token ok' : r.body);
  const H = tok ? { Authorization: 'Bearer ' + tok } : {};
  const tests = [
    ['GET', '/health', null, {}],
    ['GET', '/api/health', null, {}],
    ['GET', '/api/utils/timestamp?value=1710000000', null, H],
    ['GET', '/api/ip/999.999.999.999', null, H],
    ['GET', '/api/ip/8.8.8.8', null, H],
    ['GET', '/api/dns/google.com?type=MX', null, H],
    ['GET', '/api/hash/test', null, H],
    ['POST', '/api/hash', { algorithm: 'sha256', text: 'hello' }, H],
    ['POST', '/api/utils/encode', { text: 'hi', type: 'base64' }, H],
    ['GET', '/api/utils/password?length=16', null, H],
    ['POST', '/api/utils/jwt', { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln' }, H],
    ['GET', '/api/phone/+14155552671', null, H],
    ['GET', '/api/github/octocat', null, H],
    ['GET', '/api/ssl/google.com', null, H],
    ['GET', '/api/network/blacklist/8.8.8.8', null, H],
    ['GET', '/api/bgp/ptr/8.8.8.8', null, H],
    ['POST', '/api/forensics/hash-id', { hash: '5d41402abc4b2a76b9719d911017c592' }, H],
    ['GET', '/api/auth/me', null, H],
    ['GET', '/nope-missing', null, H],
  ];
  let pass = 0;
  for (const [m, p, b, h] of tests) {
    const t0 = Date.now();
    r = await call(p, m, b, h);
    const bad = r.status === -1 || r.status >= 500 || r.status === 402;
    if (!bad) pass++;
    console.log(`${m} ${p} -> ${r.status} (${Date.now() - t0}ms)${r.headers['x-searches-left'] !== undefined ? ` [left=${r.headers['x-searches-left']}]` : ''} | ${r.body.replace(/\s+/g, ' ').slice(0, 200)}`);
  }
  console.log(`\nPASS ${pass}/${tests.length}`);
  server.kill();
  setTimeout(() => process.exit(0), 500);
})();
