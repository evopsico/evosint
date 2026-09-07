const { spawn } = require('child_process');
const http = require('http');
// Own port: never collides with a dev server on :3001 or other suites.
const PORT = 3002;

const server = spawn('node', ['backend/server.js'], { cwd: __dirname, env: { ...process.env, PORT: String(PORT), KITTY_PER: '40' } });
server.stdout.on('data', () => {});
server.stderr.on('data', () => {});

function call(path, method = 'GET', body = null, headers = {}, timeout = 45000) {
  return new Promise((resolve) => {
    const p = body ? JSON.stringify(body) : null;
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path, method, timeout,
      headers: { ...(p ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(p) } : {}), ...headers } },
      (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d })); });
    req.on('timeout', () => { req.destroy(); resolve({ status: -1, headers: {}, body: 'TIMEOUT' }); });
    req.on('error', (e) => resolve({ status: -1, headers: {}, body: 'ERR ' + e.message }));
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
  console.log(`\nPASS ${pass}/${tests.length} (base)`);
  // kitty (KITTY_PER=40 here): legit-shaped taps to the award -> +20, balance agrees
  const meBefore = J(await call('/api/auth/me', 'GET', null, H)).data.searches_left;
  let prevTap = 0;
  const humanBatch = async (n) => {
    const now = Date.now();
    const taps = [prevTap ? [Math.min(10000, now - prevTap), 70, 60] : [80, 70, 60]];
    for (let i = 1; i < n; i++) taps.push([Math.round(60 + Math.random() * 80), Math.round(60 + Math.random() * 50), Math.round(55 + Math.random() * 40)]);
    prevTap = now;
    const rr = await call('/api/kitty/click', 'POST', { taps }, H);
    return J(rr).data;
  };
  let earn = null;
  earn = await humanBatch(30);
  await new Promise((s) => setTimeout(s, 3200));
  earn = await humanBatch(30);
  const kittyOk = earn && earn.per === 40 && earn.earned === 1 && earn.scans_added === 20 && earn.challenged !== true && earn.clicks === 20;
  if (kittyOk) pass++;
  console.log(`kitty legit award -> earned=${earn && earn.earned} added=${earn && earn.scans_added} c=${earn && earn.clicks} challenged=${earn && earn.challenged} | ${kittyOk ? 'AWARD OK' : 'AWARD FAIL'}`);
  r = await call('/api/auth/me', 'GET', null, H);
  const balOk = J(r).data.searches_left === meBefore + 20;
  if (balOk) pass++;
  console.log(`kitty balance ${meBefore} -> ${J(r).data.searches_left} | ${balOk ? 'OK' : 'FAIL'}`);
  // fair play: metronome bot gets challenged…
  const bot = 'bot' + Date.now().toString(36);
  r = await call('/api/auth/signup', 'POST', { username: bot, password: 'BotTest12!', repeat: 'BotTest12!', dob: '1995-06-06' });
  const HB = { Authorization: 'Bearer ' + J(r).data.token };
  const metro = Array.from({ length: 20 }, () => [100, 80, 60]);
  let ch = null;
  for (let i = 0; i < 3; i++) {
    r = await call('/api/kitty/click', 'POST', { taps: metro }, HB);
    ch = J(r).data;
    await new Promise((s) => setTimeout(s, 1600));
  }
  const metroOk = ch && ch.challenged === true && typeof ch.cooldown_ms === 'number';
  if (metroOk) pass++;
  console.log(`fair-play metronome -> challenged=${ch && ch.challenged} cooldown=${ch && ch.cooldown_ms} | ${metroOk ? 'OK' : 'FAIL'}`);
  // …and a machine-gun burst trips it in a single batch
  const gun = 'gun' + Date.now().toString(36);
  r = await call('/api/auth/signup', 'POST', { username: gun, password: 'GunTest12!', repeat: 'GunTest12!', dob: '1995-06-06' });
  const HG = { Authorization: 'Bearer ' + J(r).data.token };
  r = await call('/api/kitty/click', 'POST', { taps: Array.from({ length: 60 }, () => [5, 80, 60]) }, HG);
  const mg = J(r).data;
  const mgOk = r.status === 200 && mg && mg.challenged === true;
  if (mgOk) pass++;
  console.log(`fair-play machine-gun -> ${r.status} challenged=${mg && mg.challenged} | ${mgOk ? 'OK' : 'FAIL'}`);
  r = await call('/api/world/geo?q=Berlin', 'GET', null, H);
  const geoOk = r.status === 200 && ((J(r).data || [])[0] || {}).name === 'Berlin';
  if (geoOk) pass++;
  console.log(`world geo Berlin -> ${r.status} | ${geoOk ? 'OK' : String(r.body).slice(0, 120)}`);
  console.log(`\nPASS ${pass}/${tests.length + 5}`);
  server.kill();
  setTimeout(() => process.exit(pass === tests.length + 5 ? 0 : 1), 500);
})();
