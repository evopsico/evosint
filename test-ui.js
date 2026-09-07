// Headless UI boot test: serves the real app, runs app.js in jsdom, asserts render + auth flow.
// Usage: node test-ui.js  (spawns server on :3999, exits 0/1)
const { spawn } = require('child_process');
const http = require('http');
const { JSDOM, VirtualConsole } = require('jsdom');

const PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;
let failures = 0;
function check(name, cond, extra = '') {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name + (extra ? ' | ' + extra : ''));
  if (!cond) failures++;
}
function get(path, timeout = 20000) {
  return new Promise((resolve) => {
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path, method: 'GET', timeout }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: -1, body: 'TIMEOUT' }); });
    req.on('error', (e) => resolve({ status: -1, body: e.message }));
    req.end();
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const srv = spawn('node', ['backend/server.js'], { cwd: process.cwd(), env: { ...process.env, PORT: String(PORT) } });
  await sleep(3500);

  // 1) cache headers = the actual "lock" fix
  let r = await get('/');
  check('GET / 200, no-store', r.status === 200 && String(r.headers['cache-control']).includes('no-store'), r.headers['cache-control']);
  check('version stamped, no tokens left', r.body.includes('/public/app.js?v=') && !r.body.includes('__APPV__'));
  const ver = (r.body.match(/Evosint v([\d.]+)/) || [])[1];
  r = await get('/public/app.js');
  check('app.js no-store', String(r.headers['cache-control']).includes('no-store'), r.headers['cache-control']);
  const appJs = r.body;
  check('app.js served', r.status === 200 && appJs.length > 50000, appJs.length + ' bytes');
  r = await get('/api/health');
  check('api no-store', String(r.headers['cache-control']).includes('no-store'));
  check('health version = footer version', JSON.parse(r.body).version === ver, JSON.parse(r.body).version + ' vs ' + ver);

  // 2) boot UI in jsdom with live fetch
  r = await get('/');
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => errors.push('jsdomError: ' + (e.detail?.stack || e.message || e)));
  vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));
  const dom = new JSDOM(r.body.replace(/<script src="\/public\/app\.js[^"]*"><\/script>/, ''), {
    url: BASE + '/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
  });
  dom.window.fetch = (u, o) => globalThis.fetch(new URL(u, dom.window.location.href).toString(), o);
  dom.window.AbortController = AbortController; // native controller: undici rejects jsdom-realm signals
  dom.window.eval(appJs + '\n;window.__T={openAuth,show,TOOLS,AUTH,S,apiGet,addEntity,buildReport,LM,lmDetect,lmMk,lmReset,renderLinkMap,GLOBE,globeDots,globeProject,globeInvert,globeTapPx,wGetMode,STREETS};');
  const T = () => dom.window.__T;
  const q = (s) => dom.window.document.querySelector(s);
  const qa = (s) => [...dom.window.document.querySelectorAll(s)];
  for (let i = 0; i < 30 && !((q('[data-v="modules"] .n') || {}).textContent || '').match(/^\d+$/); i++) await sleep(500);

  check('no uncaught JS errors', errors.length === 0, errors.slice(0, 2).join(' ;; ').slice(0, 300));
  check('nav rendered (15+ buttons)', qa('#nav button').length >= 15, qa('#nav button').length + ' buttons');
  check('18 views mounted', qa('.view').length === 18, qa('.view').length + ' views');
  check('tool cards mounted (60+)', qa('.card[data-card]').length >= 60, qa('.card[data-card]').length + ' cards');
  check('account chip injected', !!q('#acctChip'), (q('#acctChip') || { textContent: 'MISSING' }).textContent.trim());
  check('auth modal injected', !!q('#authBack'));
  check('auth modal has discord support', (q('#authBack') || {}).textContent?.includes('evopsico'));
  check('dashboard has discord banner', !!q('.supportbar') && (q('.supportbar') || {}).textContent?.includes('evopsico'));
  check('health pill online', (q('#htxt') || {}).textContent?.includes('online'), (q('#htxt') || {}).textContent);
  check('modules badge counted', /\d+/.test((q('[data-v="modules"] .n') || {}).textContent || ''), (q('[data-v="modules"] .n') || {}).textContent);

  // 3) full signup flow through the real UI
  T().openAuth('signup');
  await sleep(300);
  const uname = 'uitest' + Date.now().toString(36);
  q('#su-user').value = uname;
  q('#su-pass').value = 'UiTestPass1!';
  q('#su-pass2').value = 'UiTestPass1!';
  q('#su-dob').value = '1999-03-03';
  q('#suGo').click();
  await sleep(2500);
  check('signup via UI sets chip + name', (q('#acctChip') || {}).textContent?.includes(uname) && (q('#whoami') || {}).textContent === uname,
    'chip=' + ((q('#acctChip') || {}).textContent || '').trim());
  check('token persisted', (dom.window.localStorage.getItem('evosint-token') || '').startsWith('v1.'));

  // 4) logout returns to guest
  T().openAuth('account');
  await sleep(300);
  const lo = q('#logoutGo');
  check('account pane w/ logout rendered', !!lo);
  if (lo) { lo.click(); await sleep(1500); }
  check('logout -> guest chip', (q('#acctChip') || {}).textContent?.includes('Guest'), (q('#acctChip') || {}).textContent?.trim());

  // 5) persistence: fresh boot restores the account (re-login via UI first)
  T().openAuth('login');
  await sleep(300);
  q('#li-user').value = uname;
  q('#li-pass').value = 'UiTestPass1!';
  q('#liGo').click();
  await sleep(2500);
  const savedTok = dom.window.localStorage.getItem('evosint-token') || '';
  const savedMe = dom.window.localStorage.getItem('evosint-me') || '';
  check('re-login works', (q('#acctChip') || {}).textContent?.includes(uname));
  async function freshBoot(seed, offline) {
    const errs = [];
    const v2 = new VirtualConsole();
    v2.on('jsdomError', (e) => errs.push(String(e.message || e).slice(0, 200)));
    const shell = (await get('/')).body.replace(/<script src="\/public\/app\.js[^"]*"><\/script>/, '');
    const d2 = new JSDOM(shell, { url: BASE + '/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: v2 });
    d2.window.fetch = offline
      ? () => Promise.reject(new Error('offline-sim'))
      : (u, o) => globalThis.fetch(new URL(u, d2.window.location.href).toString(), o);
    d2.window.AbortController = AbortController;
    if (seed && seed.tok) d2.window.localStorage.setItem('evosint-token', seed.tok);
    if (seed && seed.me) d2.window.localStorage.setItem('evosint-me', seed.me);
    d2.window.eval(appJs + '\n;window.__T={openAuth,show,TOOLS,AUTH,S,apiGet,addEntity,buildReport,LM,lmDetect,lmMk,lmReset,renderLinkMap,GLOBE,globeDots,globeProject,globeInvert,globeTapPx,wGetMode,STREETS};');
    await sleep(2500);
    return { d2, errs };
  }
  // B: token only, network live -> session restores from server
  let b = await freshBoot({ tok: savedTok });
  check('restart restores login (server)', ((s) => s && s.textContent && s.textContent.includes(uname))(b.d2.window.document.querySelector('#acctChip')), 'chip=' + (((b.d2.window.document.querySelector('#acctChip') || {}).textContent) || '').trim());
  check('no errors on restored boot', b.errs.length === 0, b.errs.slice(0, 1).join(';;'));
  // C: token + snapshot, network dead -> instant snapshot paint
  b = await freshBoot({ tok: savedTok, me: savedMe }, true);
  check('offline boot still shows account (snapshot)', ((s) => s && s.textContent && s.textContent.includes(uname))(b.d2.window.document.querySelector('#acctChip')));

  // 6) mobile shell wiring
  check('drawer backdrop present', !!q('#sideback'));
  q('#burger').click(); await sleep(200);
  check('burger opens drawer', q('#side').classList.contains('open'));
  q('#sideback').click(); await sleep(200);
  check('backdrop tap closes drawer', !q('#side').classList.contains('open'));
  check('tabbar has 5 tabs', qa('#tabbar button').length === 5, qa('#tabbar button').length + ' tabs');
  qa('#tabbar button')[1].click(); await sleep(300);
  check('tab navigates + actives', q('#v-search').classList.contains('on') && qa('#tabbar button')[1].classList.contains('on'));
  qa('#tabbar button')[4].click(); await sleep(200);
  check('menu tab opens drawer', q('#side').classList.contains('open'));
  qa('#tabbar button')[0].click(); await sleep(300);
  check('home tab back + drawer shut', q('#v-dash').classList.contains('on') && !q('#side').classList.contains('open') && qa('#tabbar button')[0].classList.contains('on'));
  check('totp login step present (hidden)', !!q('#li-totp') && !!q('#li-code') && !!q('#liTotpGo'));
  check('report builder present', !!q('#rep-build') && !!q('#rep-dl') && !!q('#rep-md') && !!q('#rep-title'));
  T().addEntity('email', 'report-victim@example.com', 'uitest');
  T().addEntity('domain', 'report-target.example', 'uitest');
  await sleep(300);
  q('#rep-title').value = 'UITEST Case File';
  q('#rep-notes').value = 'Headless verification notes.';
  q('#rep-build').click(); await sleep(300);
  const repHtml = q('#rep-out').innerHTML;
  const repMd = (dom.window._lastReport && dom.window._lastReport.md) || '';
  check('report builds from ticked entities', repHtml.includes('UITEST Case File') && repMd.includes('report-victim@example.com') && repMd.includes('| email |') && repMd.includes('| domain |'));
  check('new tool cards mounted', ['ghorg','pkg','certs','greynoise'].every(id=>!!q(`[data-card="${id}"]`)));
  check('turnstile slots present', !!q('#cf-login') && !!q('#cf-signup'));
  // 7) link map: view mounts, seed detect is pure, synthetic tree lays out with edges
  T().show('linkmap'); await sleep(300);
  check('link map view mounted', q('#v-linkmap').classList.contains('on') && !!q('#lm-go') && !!q('#lm-seed') && !!q('#lm-tograph'));
  check('seed detect (email/domain/user)', T().lmDetect('a@b.com') === 'email' && T().lmDetect('example.com') === 'domain' && T().lmDetect('@octocat') === 'username' && T().lmDetect('octocat') === 'username');
  T().lmReset();
  const lmRoot = T().lmMk('username', 'octocat', 'USER · hop 0', '', 0, '');
  T().LM.root = lmRoot;
  T().lmMk('profile', 'GitHub', 'github.com/octocat', 'https://github.com/octocat', 1, lmRoot);
  T().lmMk('email', 'o@x.com', 'commit email', '', 1, lmRoot);
  T().LM.nodes[lmRoot].st = 'open';
  T().renderLinkMap(); await sleep(300);
  check('tree renders nodes + elbow edges', qa('#lmtree .lmnode').length === 3 && qa('#lmtree svg path').length === 2, qa('#lmtree .lmnode').length + ' nodes, ' + qa('#lmtree svg path').length + ' edges');
  check('root styled, expand affordance shown', !!q('#lmtree .lmnode.root') && q('#lmtree').textContent.includes('+ expand'));
  check('map zoom + stats controls', !!q('#lm-zin') && !!q('#lm-zout') && !!q('#lm-zfit') && !!q('#lm-home') && !!q('#lmstats'));
  check('column bands rendered', qa('#lmtree .lmband').length >= 2, qa('#lmtree .lmband').length + ' bands');
  T().LM.sel = T().LM.nodes[lmRoot].kids[0]; T().renderLinkMap(); await sleep(200);
  check('trace highlights root path', qa('#lmtree .lmnode.hot').length === 2 && qa('#lmtree svg path.hot').length === 1, qa('#lmtree .lmnode.hot').length + ' hot nodes');
  check('stats count nodes', (q('#lmstats') || {}).textContent.includes('3 nodes'), (q('#lmstats') || {}).textContent);
  T().lmReset(); T().renderLinkMap(); await sleep(200);
  check('empty state offers examples', !!q('#lmtree [data-ex="octocat"]'));
  T().lmReset(); T().renderLinkMap(); await sleep(200);
  // 8) kitty: view mounts, taps count locally, state paints balance
  T().show('kitty'); await sleep(2500);
  check('kitty view mounted', q('#v-kitty').classList.contains('on') && !!q('#kit-btn') && !!q('#kit-n') && !!q('#kit-bar'));
  q('#kit-btn').click(); q('#kit-btn').click(); q('#kit-btn').click(); await sleep(300);
  check('kitty taps count up top', (q('#kit-n') || {}).textContent.trim() === '3', 'counter=' + ((q('#kit-n') || {}).textContent || '').trim());
  await sleep(2500);
  check('kitty flush reconciles with server', (q('#kit-n') || {}).textContent.trim() === '3', 'counter=' + ((q('#kit-n') || {}).textContent || '').trim());
  // 9) world: view mounts, presets render, geo search resolves
  T().show('world'); await sleep(300);
  check('world view mounted', q('#v-world').classList.contains('on') && !!q('#w-q') && !!q('#w-atkgo') && !!q('#w-auto'));
  check('world presets render', qa('#w-presets [data-wp]').length >= 6, qa('#w-presets [data-wp]').length + ' presets');
  check('globe canvas mounted, dormant headless', !!q('#w-globe') && !T().GLOBE.on);
  check('globe land dots embedded', T().globeDots().length > 8000, T().globeDots().length + ' dots');
  T().GLOBE.rot.lam = 0.6; T().GLOBE.rot.phi = 0.35;
  const gp = T().globeProject(52.52, 13.41, 200);
  const gb = T().globeInvert(gp.x, gp.y, 200);
  check('globe project/invert round-trips', Math.abs(gb.lat - 52.52) < 0.5 && Math.abs(gb.lon - 13.41) < 0.5, `back=${gb.lat.toFixed(2)},${gb.lon.toFixed(2)}`);
  check('globe misses space', T().globeInvert(0, 0, 200) === null);
  q('#w-q').value = 'Berlin'; q('#w-go').click();
  let geoOk = false;
  for (let i = 0; i < 50 && !geoOk; i++) { await sleep(500); geoOk = qa('#w-geo [data-gi]').length > 0; }
  check('world geo resolves Berlin', geoOk && q('#w-geo').textContent.includes('Berlin'), (q('#w-geo') || {}).textContent.slice(0, 80));
  check('streets toggle present', !!q('#w-mode-globe') && !!q('#w-mode-streets') && !!q('#w-map'));
  check('headless defaults to dot globe (no WebGL)', T().wGetMode() === 'globe' && q('#w-globewrap').hidden === false && q('#w-streetswrap').hidden === true && typeof dom.window.maplibregl === 'undefined');

  console.log(failures === 0 ? '\nALL UI TESTS GREEN' : `\n${failures} FAILURES`);
  srv.kill();
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('HARNESS FAIL', e); process.exit(1); });
