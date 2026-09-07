const { spawn, execSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const PORT = 4781;
const USERS = 'backend/data/users.json';
const BACKUP = 'C:/Users/gamer/AppData/Local/Temp/opencode/users.json.bak';
try { execSync(`powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort ${PORT} -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }"`, { timeout: 15000 }); } catch {}
function call(method, p, body, headers) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path: p, method, timeout: 30000,
      headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}), ...(headers || {}) } }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch {} resolve({ s: res.statusCode, j }); });
    }).on('timeout', () => resolve({ s: -1 })).on('error', (e) => resolve({ s: -1, b: e.message }));
    if (payload) req.write(payload);
    req.end();
  });
}
let pass = 0, total = 0;
function check(n, c, x) { total++; if (c) pass++; console.log((c ? 'PASS' : 'FAIL') + ' ' + n + (x ? ' | ' + x : '')); }
(async () => {
  fs.copyFileSync(USERS, BACKUP);
  const strip = () => {
    const u = JSON.parse(fs.readFileSync(USERS, 'utf8'));
    for (const [id, x] of Object.entries(u)) if (x.tier === 'super') delete u[id];
    fs.writeFileSync(USERS, JSON.stringify(u, null, 2));
  };
  const restore = () => { try { fs.copyFileSync(BACKUP, USERS); console.log('(users.json restored)'); } catch (e) { console.log('RESTORE FAILED:', e.message); } };
  const srv = spawn('node', ['backend/server.js'], { cwd: process.cwd(), env: { ...process.env, PORT: String(PORT), EVOSINT_DEBUG_AUTH: '1' } });
  srv.stdout.on('data', (d) => { const t = String(d); if (t.includes('[authdbg]')) process.stdout.write(t); });
  await new Promise((r) => setTimeout(r, 6000));
  try {
    strip();
    const un = 'claim' + Date.now().toString(36);
    let r = await call('POST', '/api/auth/signup', { username: un, password: 'ClaimMe12!', repeat: 'ClaimMe12!', dob: '1991-01-01' });
    check('first signup with no super claims super', r.s === 200 && r.j.data.tier === 'super' && r.j.data.searches_left === 'infinite', 'tier=' + ((r.j || {}).data || {}).tier);
    const tok = r.j.data.token;
    const H = { Authorization: 'Bearer ' + tok };
    r = await call('GET', '/api/auth/backup', null, H);
    check('backup exports (has users/keys keys)', r.s === 200 && r.j.data && r.j.data.users && Array.isArray(r.j.data.keys) && r.j.data.version === 1, 'users=' + Object.keys((r.j.data || {}).users || {}).length);
    const snap = r.j.data;
    r = await call('POST', '/api/auth/backup/restore', { data: 'nope' }, H);
    console.log('  garbage-restore raw ->', r.s, JSON.stringify(r.j).slice(0, 150));
    check('restore rejects garbage', r.s === 400);
    r = await call('POST', '/api/auth/backup/restore', { data: snap }, H);
    check('restore roundtrip ok', r.s === 200 && r.j && r.j.data && r.j.data.restored === true, 'status=' + r.s);
    r = await call('GET', '/api/auth/me', null, H);
    check('still super after restore', r.s === 200 && r.j.data.tier === 'super');
  } finally {
    srv.kill();
    restore();
  }
  console.log(`CLAIM/BACKUP ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})();
