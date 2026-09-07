'use strict';
/* Evosint console — DataVoid-style dark dashboard. XSS-safe: every dynamic string via esc(). */
const API = '/api';
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => [...(r || document).querySelectorAll(s)];

/* ---------- safe primitives ---------- */
function esc(s){ return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function safeHref(u){ try{ const x = new URL(String(u), location.origin); return (x.protocol==='https:'||x.protocol==='http:') ? x.toString() : null; }catch{ return null; } }
function link(u, label){ const h = safeHref(u); return h ? `<a href="${esc(h)}" target="_blank" rel="noopener noreferrer">${esc(label||h)}</a>` : esc(label||u||'—'); }
function toast(m){ const d=document.createElement('div'); d.className='toast'; d.textContent=m; $('#toasts').appendChild(d); setTimeout(()=>d.remove(),2600); }
function badge(t,k){ const safe = ['g','r','a','b','gr'].includes(k) ? k : 'gr'; return `<span class="bdg ${safe}">${esc(t)}</span>`; }
function safeImg(u){ const h = safeHref(u); return h || ''; }
function kv(o){ return '<dl>'+Object.entries(o).map(([k,v])=>`<div class="kv"><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join('')+'</dl>'; }
function mono(t){ return `<div class="mono">${esc(t)}</div>`; }
function tbl(cols, rows){ return `<table class="tbl"><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</table>`; }
function dl(name, text, type){ const b=new Blob([text],{type:type||'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),4000); }
function copyT(t){ (navigator.clipboard?navigator.clipboard.writeText(String(t)):Promise.reject()).then(()=>toast('Copied')).catch(()=>toast('Copy failed')); }
function fav(domain){ return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=128`; }

async function apiFetch(url, opts, ms){
  opts = opts || {}; ms = ms || 45000;
  // convention: bare paths ('/auth/me'); a stray '/api/' prefix is tolerated, never doubled
  const path = url.indexOf('/api/') === 0 ? url : API + url;
  const ctl = new AbortController(); const t = setTimeout(()=>ctl.abort(), ms);
  try{
    const r = await fetch(path, { ...opts, signal: ctl.signal, headers:{ 'Content-Type':'application/json', ...authHeaders(), ...(opts.headers||{}) } });
    const left = r.headers.get('x-searches-left');
    if(left !== null){
      AUTH.left = left === 'infinite' ? Infinity : (parseInt(left, 10) || 0);
      const tier = r.headers.get('x-tier'); if(tier) AUTH.tier = tier;
      try{ renderAccount(); }catch{}
    }
    const data = await r.json().catch(()=>({}));
    if(r.status === 402){ try{ openAuth('login', data.error || 'Scan quota exhausted'); }catch{} throw new Error(data.error || 'Scan quota exhausted'); }
    if(r.status === 401 && AUTH.token && path.indexOf('/auth/') < 0){
      AUTH.token = ''; TokenStore.del();
      try{ renderAccount(); openAuth('login', 'Session expired — log in again'); }catch{}
    }
    if(!r.ok) throw new Error(data.error || ('HTTP '+r.status));
    return data;
  }catch(e){ if(e.name==='AbortError') throw new Error('Timed out — upstream slow, result may be cached; retry'); throw e; }
  finally{ clearTimeout(t); }
}
const apiGet = (p, ms) => apiFetch(API + p, {}, ms);
const apiPost = (p, body, ms) => apiFetch(API + p, { method:'POST', body: JSON.stringify(body||{}) }, ms);

/* ---------- state ---------- */
const S = { runs: 0, lat: null, history: [], entities: [], autolink: false, caseNo: '' };
S.caseNo = 'EV-' + new Date().toISOString().slice(2,10).replace(/-/g,'') + '-' + Math.random().toString(36).slice(2,6).toUpperCase();
function lsGet(k, legacy){ try{ return JSON.parse(localStorage.getItem(k) || localStorage.getItem(legacy) || '[]'); }catch{ return []; } }
S.history = lsGet('evosint-hist', 'osint-hist'); S.entities = lsGet('evosint-ents', 'osint-ents');
function saveHist(){ try{ localStorage.setItem('evosint-hist', JSON.stringify(S.history.slice(0,120))); }catch{} }
function saveEnts(){ try{ localStorage.setItem('evosint-ents', JSON.stringify(S.entities.slice(0,200))); }catch{} }
function pushHist(tool, input, view, ok){ S.history.unshift({tool, input:String(input||'').slice(0,140), view:view||'', ok:ok===undefined?null:!!ok, t:new Date().toISOString()}); saveHist(); renderHist(); try{ if(current==='dash') renderDash(); }catch{} }
let PINS = new Set();
try{ PINS = new Set(JSON.parse(localStorage.getItem('evosint-pins')||'[]')); }catch{}
function savePins(){ try{ localStorage.setItem('evosint-pins', JSON.stringify([...PINS].slice(0,400))); }catch{} }
function addEntity(type, value, source){
  value = String(value||'').trim().slice(0,200); if(!value) return;
  if(!S.entities.some(e=>e.type===type && e.value===value)){ S.entities.unshift({type, value, source:source||'', t:new Date().toISOString()}); saveEnts(); toast('Sent to Investigate'); }
  if(current==='graph') renderGraph();
}

/* ================= AUTH (login · signup · tiers · keys) ================= */
const AUTH = { token:'', username:'Guest', tier:'guest', left:2, logged:false };
// Session store: "remember me" (default) persists across restarts in
// localStorage; unticked logins live in sessionStorage (tab lifetime only).
const TokenStore = {
  get(){ try{ return localStorage.getItem('evosint-token') || sessionStorage.getItem('evosint-token') || ''; }catch{ return ''; } },
  set(t, remember){ try{ if(remember){ localStorage.setItem('evosint-token', t); sessionStorage.removeItem('evosint-token'); } else { sessionStorage.setItem('evosint-token', t); localStorage.removeItem('evosint-token'); } }catch{} },
  del(){ try{ localStorage.removeItem('evosint-token'); sessionStorage.removeItem('evosint-token'); }catch{} },
};
AUTH.token = TokenStore.get();
function authHeaders(){ return AUTH.token ? { Authorization:'Bearer '+AUTH.token } : {}; }
// Last-known identity snapshot: paints chip + greeting instantly on boot,
// before the network round-trip confirms the session.
function paintAccount(){
  const chip = document.getElementById('acctChip');
  const name = AUTH.logged ? AUTH.username : 'Guest';
  if(chip) chip.innerHTML = `👤 ${esc(name)} · ${esc(leftText())}`;
  const who = document.getElementById('whoami');
  if(who) who.textContent = AUTH.logged ? AUTH.username : 'analyst';
}
function saveMeSnapshot(){ try{ localStorage.setItem('evosint-me', JSON.stringify({ username:AUTH.username, tier:AUTH.tier, left:AUTH.left==null?null:(AUTH.left===Infinity?'infinite':AUTH.left), logged:AUTH.logged })); }catch{} }
function loadMeSnapshot(){
  try{
    const m = JSON.parse(localStorage.getItem('evosint-me') || 'null');
    if(m && typeof m === 'object'){ AUTH.username = m.username || 'Guest'; AUTH.tier = m.tier || 'guest'; AUTH.left = m.left === 'infinite' ? Infinity : (parseInt(m.left, 10) || 0); AUTH.logged = !!m.logged && !!TokenStore.get(); }
  }catch{}
}
function tierBadge(t){ return t==='super' ? badge('SUPER · ∞','b') : t==='user' ? badge('USER','gr') : badge('GUEST','gr'); }
function leftText(){ return AUTH.tier==='super' ? '∞ left' : (AUTH.left+' left'); }
function renderAccount(){
  paintAccount();
  if(AUTH.logged && document.getElementById('authBack')?.classList.contains('open')) renderAccountPane();
}
function openAuth(tab, msg){
  document.getElementById('authBack').classList.add('open');
  authTab(tab || (AUTH.logged ? 'account' : 'login'));
  if(msg){ const e = document.getElementById('authErr'); if(e){ e.textContent = msg; e.style.display = 'block'; } }
}
function closeAuth(){ document.getElementById('authBack').classList.remove('open'); }
function authTab(t){
  ['login','signup','account'].forEach(k=>{
    document.getElementById('auth-'+k).style.display = k===t ? 'block' : 'none';
  });
  document.querySelectorAll('[data-at]').forEach(b=>b.classList.toggle('on', b.dataset.at===t));
  const e = document.getElementById('authErr'); if(e) e.style.display = 'none';
  if(t==='account') renderAccountPane();
}
function renderAccountPane(){
  const z = document.getElementById('auth-account'); if(!z) return;
  if(!AUTH.logged){
    z.innerHTML = `<p style="color:var(--muted);font-size:13px">You are browsing as a <b>Guest</b> (${esc(leftText())}). Log in or create a free account for <b>50 scans</b>.</p>
      <div class="brow" style="margin-top:10px"><button class="btn" data-act="auth-tab" data-tab="login">Log in</button><button class="ghost" data-act="auth-tab" data-tab="signup">Sign up</button></div>`;
    return;
  }
  z.innerHTML = `
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:6px"><b style="font-size:16px">${esc(AUTH.username)}</b> ${tierBadge(AUTH.tier)}</div>
    ${kv({'Searches left': AUTH.tier==='super' ? badge('∞ infinite','b') : badge(AUTH.left+' / 50','b')})}
    <div class="sect">Change password</div>
    <div class="field"><label>Current password</label><input type="password" id="pw-cur" autocomplete="current-password"></div>
    <div class="row2"><div class="field"><label>New password (8+)</label><input type="password" id="pw-next" autocomplete="new-password"></div>
    <div class="field"><label>Repeat new</label><input type="password" id="pw-next2" autocomplete="new-password"></div></div>
    <div class="brow"><button class="btn" id="pwGo">Change password</button></div>
    ${AUTH.tier==='super' ? `<div class="sect">API keys · infinite scans</div>
      <div class="brow"><input id="keyLabel" placeholder="key label (e.g. laptop)" style="flex:1;padding:10px 12px;border-radius:8px;border:1px solid var(--border2);background:#000;color:var(--text);outline:none"><button class="btn" id="keyGen" style="flex:none">Generate</button></div>
      <div id="keyNew"></div><div id="keyList" style="margin-top:8px"></div>`
    : `<p style="font-size:12px;color:var(--faint)">API keys are issued to super users.</p>`}
    <div class="sect">Two-factor (TOTP)</div>
    <div id="totpZone"></div>
    ${AUTH.tier==='super' ? `<div class="sect">Backup &amp; restore</div>
    <div class="brow"><button class="ghost" id="bkExp">Export backup</button><label class="ghost" style="cursor:pointer">Import…<input type="file" id="bkFile" accept="application/json,.json" hidden></label></div>
    <p style="font-size:11.5px;color:var(--faint)">Full accounts, keys and quotas snapshot. Contains password hashes — guard the file. Import replaces everything.</p>` : ''}
    <div class="brow" style="margin-top:10px"><button class="ghost" id="logoutGo">Log out</button></div>`;
  renderTotpZone();
  const be = document.getElementById('bkExp'); if(be) be.onclick = doBackup;
  const bf = document.getElementById('bkFile'); if(bf) bf.onchange = doRestoreFile;
  document.getElementById('pwGo').onclick = changePw;
  document.getElementById('logoutGo').onclick = doLogout;
  if(AUTH.tier==='super'){
    document.getElementById('keyGen').onclick = genKey;
    loadKeys();
  }
}
async function refreshMe(){
  try{
    const d = await apiGet('/auth/me');
    const m = d.data || {};
    if(m.invalid_credential){ AUTH.token=''; TokenStore.del(); }
    AUTH.logged = !!m.logged_in;
    AUTH.username = m.username || 'Guest';
    AUTH.tier = m.tier || 'guest';
    AUTH.left = m.searches_left === 'infinite' ? Infinity : (parseInt(m.searches_left, 10) || 0);
    AUTH.totp = !!m.totp_enabled;
    saveMeSnapshot();
  }catch{ /* offline — snapshot paint already applied */ }
  renderAccount();
}
// Captcha token reader — null when Turnstile isn't configured (server skips it too).
// Uses the widget ID returned by turnstile.render (getResponse takes an ID, not an element).
function cfToken(id){
  try{
    if(!AUTH.cfSiteKey || typeof turnstile === 'undefined') return null;
    const wid = window._cfWidgets ? window._cfWidgets[id] : undefined;
    const t = turnstile.getResponse(wid);
    return t || null;
  }catch{ return null; }
}
async function doLogin(){
  const u = document.getElementById('li-user').value.trim();
  const p = document.getElementById('li-pass').value;
  const err = document.getElementById('authErr');
  if(!u || !p){ err.textContent='Username + password required'; err.style.display='block'; return; }
  err.style.display = 'none';
  document.getElementById('li-totp').style.display = 'none';
  try{
    const d = await apiPost('/auth/login', { username:u, password:p, cf_token:cfToken('cf-login') });
    cfReset('cf-login');
    if(d.data && d.data.totp_required){
      AUTH.tmp = d.data.tmp;
      AUTH.tmpUser = d.data.username || u;
      document.getElementById('li-totp').style.display = 'block';
      document.getElementById('li-code').value = '';
      document.getElementById('li-code').focus();
      toast('Two-factor code required');
      return;
    }
    AUTH.token = d.data.token;
    TokenStore.set(AUTH.token, document.getElementById('li-remember')?.checked !== false);
    await refreshMe(); closeAuth(); toast('Welcome back, ' + AUTH.username);
  }catch(e){ err.textContent = e.message; err.style.display='block'; }
}
function cfReset(id){
  try{
    if(typeof turnstile !== 'undefined' && window._cfWidgets && window._cfWidgets[id] !== undefined) turnstile.reset(window._cfWidgets[id]);
  }catch{}
}
// Second login step: 6-digit app code, or a single-use backup code.
async function doTotpVerify(){
  const err = document.getElementById('authErr');
  const useBackup = document.getElementById('li-totp-mode').dataset.backup === '1';
  const val = document.getElementById('li-code').value.trim();
  if(!val){ err.textContent = useBackup ? 'Enter a backup code' : 'Enter the 6-digit code'; err.style.display='block'; return; }
  err.style.display = 'none';
  try{
    const body = useBackup ? { tmp:AUTH.tmp, backup_code:val } : { tmp:AUTH.tmp, code:val };
    const d = await apiPost('/auth/totp/verify', body);
    AUTH.token = d.data.token;
    AUTH.tmp = null;
    TokenStore.set(AUTH.token, document.getElementById('li-remember')?.checked !== false);
    await refreshMe(); closeAuth();
    toast('Welcome back, ' + AUTH.username + (d.data.backup_remaining !== undefined ? ` (${d.data.backup_remaining} backup codes left)` : ''));
  }catch(e){ err.textContent = e.message; err.style.display='block'; }
}
async function doSignup(){
  const u = document.getElementById('su-user').value.trim();
  const p1 = document.getElementById('su-pass').value;
  const p2 = document.getElementById('su-pass2').value;
  const dob = document.getElementById('su-dob').value;
  const err = document.getElementById('authErr');
  if(p1 !== p2){ err.textContent='Passwords do not match'; err.style.display='block'; return; }
  try{
    const d = await apiPost('/auth/signup', { username:u, password:p1, repeat:p2, dob, cf_token:cfToken('cf-signup') });
    AUTH.token = d.data.token;
    TokenStore.set(AUTH.token, true); // new accounts always persist
    await refreshMe(); closeAuth();
    toast(d.data.tier === 'super' ? 'Account created — INFINITE scans (first super), ' + AUTH.username : 'Account created — 50 scans, ' + AUTH.username);
    cfReset('cf-signup');
  }catch(e){ err.textContent = e.message; err.style.display='block'; }
}
function doLogout(){
  AUTH.token=''; TokenStore.del();
  try{ localStorage.removeItem('evosint-me'); }catch{}
  refreshMe(); toast('Logged out — guest mode');
}
async function changePw(){
  const cur = document.getElementById('pw-cur').value;
  const nx = document.getElementById('pw-next').value;
  const nx2 = document.getElementById('pw-next2').value;
  if(nx !== nx2){ toast('New passwords do not match'); return; }
  try{ await apiPost('/auth/password', { current:cur, next:nx }); toast('Password changed'); renderAccountPane(); }
  catch(e){ toast(e.message); }
}
// ---- TOTP panel (states render into #totpZone) ----
function renderTotpZone(){
  const z = document.getElementById('totpZone'); if(!z) return;
  if(AUTH.totp){
    z.innerHTML = `<p style="font-size:12.5px">${badge('2FA ON','g')} <span style="color:var(--muted)">App codes required at login. Backup codes were shown once at setup.</span></p>
      <div class="row2" style="margin-top:8px"><div class="field"><label>Password to disable</label><input type="password" id="totp-off-pw" autocomplete="current-password"></div>
      <div class="field"><label>&nbsp;</label><button class="ghost" id="totpOffGo" style="width:100%">Disable 2FA</button></div></div>`;
    document.getElementById('totpOffGo').onclick = async ()=>{
      try{ await apiPost('/auth/totp/disable', { password:document.getElementById('totp-off-pw').value }); toast('2FA disabled'); await refreshMe(); }
      catch(e){ toast(e.message); }
    };
    return;
  }
  z.innerHTML = `<p style="font-size:12.5px;color:var(--muted)">Authenticator-app codes plus 8 one-time backup codes. Takes a minute.</p>
    <div class="brow"><button class="btn" id="totpSetupGo">Enable 2FA ▸</button></div><div id="totpSetup" style="margin-top:8px"></div>`;
  document.getElementById('totpSetupGo').onclick = async ()=>{
    try{
      const d = await apiPost('/auth/totp/setup', {});
      const s = d.data || {};
      document.getElementById('totpSetup').innerHTML =
        `<div class="field"><label>1 · Add this key to your authenticator app</label><div class="mono" id="totpSec" style="cursor:pointer">${esc(s.secret||'')}</div></div>
         <div class="brow"><button class="mini" id="totpCopySec">Copy key</button><button class="mini" id="totpCopyUri">Copy setup link</button></div>
         <div class="field" style="margin-top:8px"><label>2 · Enter the 6-digit code to activate</label><input id="totp-code" inputmode="numeric" maxlength="6" placeholder="123456"></div>
         <div class="brow"><button class="btn" id="totpEnableGo">Activate ▸</button></div><div id="totpBackup"></div>`;
      document.getElementById('totpCopySec').onclick = e=>copyT(s.secret||'');
      document.getElementById('totpCopyUri').onclick = e=>copyT(s.uri||'');
      document.getElementById('totpEnableGo').onclick = async ()=>{
        try{
          const e2 = await apiPost('/auth/totp/enable', { code:document.getElementById('totp-code').value.trim() });
          const codes = (e2.data && e2.data.backup_codes) || [];
          document.getElementById('totpBackup').innerHTML = `<p style="font-size:12px;color:var(--amber);margin:8px 0 4px">Save these backup codes now — each works once, never shown again:</p><div class="mono" id="totpCodes" style="cursor:pointer">${esc(codes.join('\n'))}</div>`;
          document.getElementById('totpCodes').onclick = ev=>copyT(ev.target.innerText);
          await refreshMe(); toast('Two-factor enabled');
        }catch(err){ toast(err.message); }
      };
    }catch(e){ toast(e.message); }
  };
}
// ---- super backup / restore ----
async function doBackup(){
  try{
    const d = await apiGet('/auth/backup');
    dl(`evosint-backup-${new Date().toISOString().slice(0,10)}.json`, JSON.stringify(d.data, null, 2));
    toast('Backup downloaded — guard the file');
  }catch(e){ toast(e.message); }
}
async function doRestoreFile(ev){
  const f = ev.target && ev.target.files && ev.target.files[0];
  if(!f) return;
  let parsed = null;
  try{ parsed = JSON.parse(await f.text()); }
  catch{ toast('Not valid JSON'); ev.target.value=''; return; }
  if(!window.confirm('Replace ALL accounts, keys and quotas with this backup? This cannot be undone.')){ ev.target.value=''; return; }
  try{
    const d = await apiPost('/auth/backup/restore', { data:parsed });
    toast(`Restored — ${d.data.users} users, ${d.data.keys} keys`);
    await refreshMe();
  }catch(e){ toast(e.message); }
  ev.target.value = '';
}
async function loadKeys(){
  const z = document.getElementById('keyList'); if(!z) return;
  try{
    const d = await apiGet('/auth/keys');
    const rows = d.data || [];
    z.innerHTML = rows.length ? rows.map(k=>`<div class="keyrow"><span class="mono" style="border:none;background:none;padding:0">${esc(k.label)} · ${esc(k.prefix)}</span><span style="color:var(--faint);font-size:11px">${esc((k.created||'').slice(0,10))}</span><button class="mini" data-revoke="${esc(k.id)}">Revoke</button></div>`).join('')
      : '<p style="font-size:12px;color:var(--faint)">No keys yet.</p>';
    z.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=async()=>{ await apiFetch('/auth/keys/'+b.dataset.revoke, { method:'DELETE' }); toast('Key revoked'); loadKeys(); });
  }catch(e){ z.innerHTML = `<p style="font-size:12px;color:var(--bad)">${esc(e.message)}</p>`; }
}
async function genKey(){
  const label = (document.getElementById('keyLabel').value || 'default').trim();
  try{
    const d = await apiPost('/auth/keys', { label });
    document.getElementById('keyNew').innerHTML = `<p style="font-size:12px;color:var(--muted)">Copy now — shown once:</p><div class="mono" style="cursor:pointer" id="keyOnce">${esc(d.data.key)}</div>`;
    document.getElementById('keyOnce').onclick = e=>copyT(e.target.innerText);
    loadKeys(); toast('Infinite key minted');
  }catch(e){ toast(e.message); }
}
function injectAuth(){
  const hp = document.querySelector('.top .pill');
  const chip = document.createElement('button');
  chip.className = 'pill'; chip.id = 'acctChip'; chip.style.cursor = 'pointer';
  chip.onclick = ()=>openAuth(AUTH.logged ? 'account' : 'login');
  if(hp && hp.parentElement) hp.parentElement.insertBefore(chip, hp);
  const back = document.createElement('div');
  back.className = 'pal-back'; back.id = 'authBack';
  back.innerHTML = `<div class="pal auth-pal" role="dialog" aria-label="Account">
    <div class="auth-tabs">
      <button class="fbtn" data-at="login">Log in</button>
      <button class="fbtn" data-at="signup">Sign up</button>
      <button class="fbtn" data-at="account">Account</button>
      <span style="flex:1"></span><button class="mini" data-at="x">✕</button>
    </div>
    <div id="authErr" class="auth-err" style="display:none"></div>
    <div id="auth-login">
      <div class="field"><label>Username</label><input id="li-user" autocomplete="username" placeholder="evo"></div>
      <div class="field"><label>Password</label><input id="li-pass" type="password" autocomplete="current-password"></div>
      <div id="li-totp" style="display:none">
        <div class="field"><label>Two-factor code</label><input id="li-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="12"></div>
        <div class="brow"><button class="btn" id="liTotpGo">Verify ▸</button><button class="ghost" id="li-totp-mode" data-backup="0">Use backup code</button></div>
      </div>
      <div id="cf-login" style="margin:6px 0"></div>
      <label class="checkline"><input type="checkbox" id="li-remember" checked> Remember me on this device</label>
      <div class="brow"><button class="btn" id="liGo">Log in ▸</button></div>
    </div>
    <div id="auth-signup" style="display:none">
      <div class="field"><label>Username (3–24: letters/numbers/._-)</label><input id="su-user" autocomplete="username" placeholder="analyst_01"></div>
      <div class="row2"><div class="field"><label>Password (8+ chars)</label><input id="su-pass" type="password" autocomplete="new-password"></div>
      <div class="field"><label>Repeat password</label><input id="su-pass2" type="password" autocomplete="new-password"></div></div>
      <div class="field"><label>Date of birth</label><input id="su-dob" type="date" min="1900-01-01"></div>
      <div id="cf-signup" style="margin:6px 0"></div>
      <p style="font-size:11.5px;color:var(--faint)">Free accounts get <b>50 scans</b>. Guests get 2.</p>
      <div class="brow"><button class="btn" id="suGo">Create account ▸</button></div>
    </div>
    <div id="auth-account" style="display:none"></div>
    <div class="auth-support">🔧 Problems logging in or out of scans? Contact <b>evopsico</b> on Discord <button class="mini" data-act="copy-variants" data-v="evopsico">Copy</button></div>
  </div>`;
  document.body.appendChild(back);
  back.querySelectorAll('[data-at]').forEach(b=>b.onclick=()=>{ b.dataset.at==='x' ? closeAuth() : authTab(b.dataset.at); });
  back.addEventListener('mousedown', e=>{ if(e.target.id==='authBack') closeAuth(); });
  document.getElementById('liGo').onclick = doLogin;
  document.getElementById('suGo').onclick = doSignup;
  document.getElementById('liTotpGo').onclick = doTotpVerify;
  document.getElementById('li-totp-mode').onclick = (e)=>{
    const b = e.currentTarget;
    const backup = b.dataset.backup !== '1';
    b.dataset.backup = backup ? '1' : '0';
    b.textContent = backup ? 'Use app code' : 'Use backup code';
    document.querySelector('#li-totp .field label').textContent = backup ? 'Backup code' : 'Two-factor code';
    document.getElementById('li-code').value = '';
    document.getElementById('li-code').focus();
  };
  document.getElementById('li-code').addEventListener('keydown', e=>{ if(e.key==='Enter') doTotpVerify(); });
  document.getElementById('li-pass').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });
  document.getElementById('su-pass2').addEventListener('keydown', e=>{ if(e.key==='Enter') doSignup(); });
}

/* ---------- nav / views ---------- */
const NAV = [
  ['sec','Console'],
  ['dash','◈','Dashboard'], ['search','◎','Search'], ['modules','▦','Modules',''], ['graph','⬡','Investigate',''],
  ['sec','Intel'],
  ['breach','✉','Breaches'], ['people','👤','People'], ['net','🌐','Network'], ['threat','☢','Threat Intel'],
  ['oath','🔑','OathNet'],
  ['geo','📍','Geo'], ['crypto','₿','Crypto'], ['company','🏢','Company'],
  ['sec','Field Ops'],
  ['recon','📁','Field Recon'],
  ['sec','Lab'],
  ['lab','🧪','Forensics & Utils'], ['api','⎔','API Docs'],
];
let current = 'dash';
const VIEW_TITLES = { dash:['Dashboard','Ops overview & exposure meter'], search:['Search','Supernova-style multi-engine battery'], modules:['Modules','Site-engine grid — username presence at scale'], graph:['Investigate','Entity relationship graph'], breach:['Breaches','Breach & credential exposure'], people:['People','Usernames, gamers, devs, profiles'], net:['Network','Infrastructure & web intel'], threat:['Threat Intel','Malware, vulns, reputation feeds'], oath:['OathNet','OAuth · OIDC · SAML · secret scan'], geo:['Geo','Places, coordinates, postal areas'], crypto:['Crypto','Addresses, markets, fees'], company:['Company','Corporate resolution'], recon:['Field Recon','Crawler · brute-force · takeover · audits'], lab:['Forensics & Utils','Parsers, validators, generators'], api:['API Docs','Every endpoint, live'] };

function renderNav(){
  $('#nav').innerHTML = NAV.map(n => n[0]==='sec' ? `<div class="nav-sec">${esc(n[1])}</div>`
    : `<button data-v="${n[0]}" class="${current===n[0]?'on':''}"><span class="ic">${n[1]}</span>${esc(n[2])}${n[3]!==undefined?`<span class="n" data-count></span>`:''}</button>`).join('');
  $$('#nav button').forEach(b=>b.onclick=()=>show(b.dataset.v));
  const mc = $('[data-v="modules"] .n'); if(mc) mc.textContent = MODULE_COUNT || '…';
}
function show(v){
  current = v; $$('#nav button').forEach(b=>b.classList.toggle('on', b.dataset.v===v));
  $$('.view').forEach(x=>x.classList.toggle('on', x.id==='v-'+v));
  $('#vtitle').childNodes[0].textContent = VIEW_TITLES[v][0];
  $('#vsub').textContent = VIEW_TITLES[v][1];
  $('#side').classList.remove('open');
  const sb = document.getElementById('sideback'); if(sb) sb.classList.remove('open');
  $$('#tabbar button').forEach(b=>b.classList.toggle('on', b.dataset.v===v));
  if(v==='graph') renderGraph();
  if(v==='dash') renderDash();
}

/* ---------- tool card shell ---------- */
function cardHTML(t){
  const inputs = t.inputs.map(i=>{
    if(i.type==='select') return `<div class="field"><label>${esc(i.label)}</label><select data-in="${i.id}">${i.options.map(o=>`<option value="${esc(o)}">${esc(o)}</option>`).join('')}</select></div>`;
    if(i.type==='textarea') return `<div class="field"><label>${esc(i.label)}</label><textarea data-in="${i.id}" placeholder="${esc(i.ph||'')}"></textarea></div>`;
    if(i.type==='check') return `<label class="checkline"><input type="checkbox" data-in="${i.id}" checked> ${esc(i.label)}</label>`;
    return `<div class="field"><label>${esc(i.label)}</label><input data-in="${i.id}" type="${esc(i.type||'text')}" placeholder="${esc(i.ph||'')}" autocomplete="off" spellcheck="false"></div>`;
  }).join('');
  return `<article class="card" data-card="${esc(t.id)}">
    <div class="chead"><div class="cico">${t.icon}</div><div><h3>${esc(t.title)}</h3><p>${esc(t.desc)}</p></div><span class="tag">${esc(t.tag||'intel')}</span></div>
    ${inputs}
    <div class="brow"><button class="btn" data-run="${esc(t.id)}">Run ▸</button></div>
    <div class="res"><div class="rbar"><span data-state>READY</span><span class="sp"></span>
      <button class="mini" data-cp>Copy</button><button class="mini" data-xp>Export</button><button class="mini" data-gr>+ Graph</button><button class="mini" data-cl>Clear</button></div>
      <div class="rbody" data-body></div></div>
  </article>`;
}
function mountCards(){
  $$('[data-cards]').forEach(zone=>{
    const list = TOOLS.filter(t=>t.view===zone.dataset.cards);
    zone.innerHTML = list.map(cardHTML).join('');
  });
  $$('[data-run]').forEach(b=>b.onclick=()=>runTool(b.dataset.run, b));
  $$('[data-cp]').forEach(b=>b.onclick=e=>{const c=e.target.closest('.card'); copyT(c._raw||$('.rbody',c).innerText);});
  $$('[data-xp]').forEach(b=>b.onclick=e=>{const c=e.target.closest('.card'); if(c._csv){ dl(c._csvName, c._csv, 'text/csv'); } else { dl(`evosint-${c.dataset.card}.json`, c._raw||'{}'); } toast('Exported');});
  $$('[data-cl]').forEach(b=>b.onclick=e=>{const c=e.target.closest('.card'); $('.res',c).classList.remove('show'); c._raw='';});
  $$('[data-gr]').forEach(b=>b.onclick=e=>{const c=e.target.closest('.card'); const t=TOOLS.find(x=>x.id===c.dataset.card); (t&&t.entity?t.entity(c._data||{},c):[{type:'note',value:c.dataset.card+' result'}]).forEach(en=>addEntity(en.type,en.value,t?t.title:''));});
  $$('.card input[data-in]').forEach(el=>el.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); el.closest('.card').querySelector('[data-run]').click(); }}));
}
function setState(card, ok, label){ const s=$('[data-state]',card); s.innerHTML = ok==null?esc(label):ok?`<span style="color:var(--green)">● ${esc(label)}</span>`:`<span style="color:var(--red)">● ${esc(label)}</span>`; }
async function runTool(id, btn){
  const t = TOOLS.find(x=>x.id===id); const card = btn.closest('.card');
  const body = $('.rbody',card), box = $('.res',card);
  const vals = {}; $$('[data-in]',card).forEach(el=>{ vals[el.dataset.in] = el.type==='checkbox' ? el.checked : el.value; });
  const need = t.inputs.find(i=>i.type!=='check' && i.type!=='select');
  if(need && !String(vals[need.id]||'').trim()){ box.classList.add('show'); body.innerHTML='<div class="load">⚠️ Enter a value first.</div>'; setState(card,false,'NEED INPUT'); return; }
  btn.disabled = true; box.classList.add('show'); setState(card,null,'SCANNING…');
  body.innerHTML = '<div class="skel" aria-hidden="true"><i class="w80"></i><i></i><i class="w60"></i><i class="tall"></i></div><div class="load" style="padding-top:6px"><div class="spin"></div>Querying sources…</div>';
  const t0 = performance.now();
  try{
    const data = await t.run(vals);
    const ctx = {};
    body.innerHTML = t.render(data, vals, ctx) || '<span style="color:var(--faint)">empty</span>';
    card._raw = JSON.stringify(data,null,2); card._data = data; card._csv = ctx.csv || ''; card._csvName = ctx.csvName || 'export.csv';
    setState(card,true,((data.cached?'CACHED ✓ ':'LIVE ✓ ')+Math.round(performance.now()-t0)+'ms').toUpperCase());
    S.runs++; S.lat = Math.round(performance.now()-t0);
    pushHist(t.title, need?vals[need.id]:JSON.stringify(vals).slice(0,80), t.view, true);
  }catch(e){ body.innerHTML = `<div class="load">❌ ${esc(e.message)}</div>`; setState(card,false,'ERROR'); try{ pushHist(t.title, need?vals[need.id]:'', t.view, false); }catch{} }
  finally{ btn.disabled = false; }
}

/* ================= TOOL REGISTRY ================= */
const TOOLS = [
/* ---- breaches ---- */
{ id:'breacher', view:'breach', icon:'🧲', title:'Breacher — Multi-Source Lookup', desc:'HIBP + XposedOrNot + HudsonRock stealers + LeakCheck + EmailRep → one Exposure Index.', tag:'flagship', timeout:90000,
  inputs:[{id:'v',label:'Email',ph:'target@example.com',type:'email'}], run:({v})=>apiPost('/breacher',{email:v.trim()},90000),
  render:d=>{const x=d.data||{}; const band=x.band||'Low exposure'; const cls=/Critical/.test(band)?'r':/High/.test(band)?'a':/Moderate/.test(band)?'a':'g';
    return `<div class="expwrap">${ringSVG(x.score??0)}<div style="flex:1;min-width:230px"><p style="margin-bottom:8px">${badge(band,cls)} ${badge((x.unique_breaches??0)+' unique','b')}</p>`+
    kv({'Factors':esc((x.factors||[]).join(' · ')||'—'),
      'Stealers':(x.stealers?.computers)?badge(x.stealers.computers+' computers','r'):badge('none','g'),
      'Data classes':esc((x.data_classes||[]).slice(0,10).join(', ')||'—'),
      'Coverage':Object.entries(x.coverage||{}).map(([k,s])=>s==='ok'?badge(k,'g'):s==='clean'?badge(k,'gr'):s==='skipped'?badge(k+' ∅','gr'):badge(k+' !','a')).join(' '),
      'Combo leaks':(x.sources?.comb?.count)?badge(x.sources.comb.count.toLocaleString()+' records','r'):badge('none','g')})+`</div></div>`+
    ((x.sources?.comb?.sample||[]).length?`<div class="sect">Combo sample (passwords redacted)</div><div class="mono">${(x.sources.comb.sample||[]).map(s=>`<span class="redact">${esc(s)}</span>`).join('\n')}</div>`:'')+
    `<div class="sect">Unified breaches</div>`+tbl(['Breach','Dates','Seen in'],(x.breaches||[]).slice(0,40).map(b=>[esc(b.name),esc((b.dates||[]).join(', ')||'—'),(b.sources||[]).map(s=>badge(s,'gr')).join(' ')]))+
    ((x.stealers?.incidents||[]).length?`<div class="sect">Infostealer incidents (HudsonRock)</div>`+tbl(['Date','OS','Services'],x.stealers.incidents.map(s=>[esc(s.date||'—'),esc((s.os||'').slice(0,42)||'—'),esc(s.services??'—')])):'')+
    ((x.pastes||[]).length?`<div class="sect">Pastes</div>`+tbl(['Source','Title','Date'],x.pastes.map(p=>[esc(p.source||''),esc(p.title||''),esc(p.date||'')])):'');},
  entity:(d,c)=>[{type:'email',value:(c.querySelector('input')||{}).value||''}] },
{ id:'email', view:'breach', icon:'📧', title:'Email Breach Check', desc:'HIBP with key, else free XposedOrNot fallback.', tag:'breach',
  inputs:[{id:'v',label:'Email',ph:'user@example.com',type:'email'}], run:({v})=>apiGet(`/email/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:9px">${x.breached?badge(`BREACHED ×${x.count}`,'r'):badge('no breaches','g')} <span style="color:var(--faint);font-size:11px">${esc(x.source||'')}</span></p>`+((x.breaches||[]).map(b=>`<div class="plat ${x.breached?'n':'f'}"><h4>${esc(b.Name||b.name||b.breach||'Breach')}</h4><div style="font-size:11.5px;color:var(--muted)">${esc(b.Domain||b.domain||'')} · ${esc(b.BreachDate||b.breachDate||b.added||'')}</div><div style="font-size:12px">${esc((b.Description||b.description||'').replace(/<[^>]*>/g,'').slice(0,280))}</div></div>`).join('')||'');},
  entity:(d,c)=>[{type:'email',value:(c.querySelector('input')||{}).value||''}] },
{ id:'pwnedpw', view:'breach', icon:'🔑', title:'Password Exposure', desc:'HIBP k-anonymity — only a 5-char hash prefix leaves your machine.', tag:'creds',
  inputs:[{id:'v',label:'Password',ph:'hunter2',type:'password'}], run:({v})=>apiPost('/verify/password',{password:v}),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${x.pwned?badge(`SEEN ×${Number(x.count).toLocaleString()}`,'r'):badge('not seen','g')}</p>`+kv({'Verdict':esc(x.verdict||''),'Length':esc(x.checks?.length??''),'Upper':x.checks?.has_upper?'yes':'no','Lower':x.checks?.has_lower?'yes':'no','Digit':x.checks?.has_digit?'yes':'no','Symbol':x.checks?.has_symbol?'yes':'no'});} },
{ id:'verifyemail', view:'breach', icon:'✉️', title:'Email Verifier', desc:'Syntax, MX, disposable, role, free-provider, Gravatar signals.', tag:'identity',
  inputs:[{id:'v',label:'Email',ph:'user@gmail.com',type:'email'}], run:({v})=>apiGet(`/verify/email/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Deliverability':x.deliverability==='likely'?badge('LIKELY','g'):x.deliverability==='unlikely'?badge('UNLIKELY','r'):badge('UNCERTAIN','a'),'Score':esc(x.score||''),'MX':x.mx_found?badge('found','g'):badge('none','r'),'Disposable':x.disposable?badge('YES','r'):badge('no','g'),'Role account':x.role_account?badge('YES','a'):badge('no','g'),'Free provider':x.free_provider?'yes':'no','Gravatar':x.gravatar_profile?badge('public profile','b'):badge('none','gr')})+((x.mx_records||[]).length?mono(x.mx_records.join('\n')):'');},
  entity:d=>[{type:'email',value:d.data?.email||''},{type:'domain',value:d.data?.domain||''}] },
{ id:'hashcheck', view:'breach', icon:'☠️', title:'Hash Reputation', desc:'Real MalwareBazaar verdict. Never faked.', tag:'malware',
  inputs:[{id:'v',label:'MD5 / SHA1 / SHA256 / SHA512',ph:'44d88612fea8a8f36de82e1278abb02f'}], run:({v})=>apiGet(`/hash/check/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${x.is_malicious===true?badge('⚠ MALICIOUS','r'):x.is_malicious===false?badge('not in MalwareBazaar','g'):badge('INCONCLUSIVE','a')} ${badge(x.threat_level||'?','gr')}</p>`+kv({'Algorithm':esc(x.algorithm||''),'Sources':esc((x.sources_checked||[]).join(', ')||'—'),'Details':esc(x.details||'—')})+mono(x.hash||'');},
  entity:d=>[{type:'hash',value:d.data?.hash||''}] },
/* ---- people ---- */
{ id:'username', view:'people', icon:'👤', title:'Username Sweep', desc:'~170 platforms: APIs where free, honest page probes elsewhere.', tag:'sweep', timeout:90000,
  inputs:[{id:'v',label:'Username',ph:'octocat'}], run:({v})=>apiGet(`/username/${encodeURIComponent(v.trim())}`,90000),
  render:d=>{const rows=d.data||[];return `<p style="margin-bottom:9px">${badge(`${d.summary?.found_count??0} / ${d.summary?.total_platforms??rows.length} found`,'b')}</p>`+tbl(['Platform','Status','Link'],rows.map(r=>[esc(r.name),r.found?badge('FOUND','g'):badge('—','gr'),link(r.url,'open')])) ;},
  entity:(d,c)=>[{type:'username',value:(c.querySelector('input')||{}).value||''}] },
{ id:'social', view:'people', icon:'📣', title:'Social Deep-Check', desc:'Keyless public APIs: GitHub, Reddit, Dev.to, Keybase, GitLab, HN, Bluesky.', tag:'social',
  inputs:[{id:'v',label:'Username',ph:'octocat'}], run:({v})=>apiGet(`/social/${encodeURIComponent(v.trim())}`),
  render:d=>`<p style="margin-bottom:9px">${badge(`${d.summary?.found_count??0} profiles`,'b')}</p>`+(d.data||[]).map(r=>`<div class="plat ${r.found?'f':'n'}"><h4>${esc(r.name)} ${r.found?badge('FOUND','g'):badge('—','gr')}</h4>${r.found&&r.data?`<div class="mono">${esc(JSON.stringify(r.data,null,1).slice(0,500))}</div><div style="margin-top:4px">${link(r.url,'open profile')}</div>`:r.error?`<div style="font-size:11.5px;color:var(--muted)">${esc(r.error)}</div>`:link(r.url,'open')}</div>`).join('') },
{ id:'github', view:'people', icon:'💻', title:'GitHub Profile', desc:'Profile + top repos. GITHUB_TOKEN lifts limits.', tag:'dev',
  inputs:[{id:'v',label:'GitHub user',ph:'octocat'}], run:({v})=>apiGet(`/github/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{},p=x.profile||{};return `<div style="display:flex;gap:11px;align-items:center;margin-bottom:9px">${p.avatar_url && safeImg(p.avatar_url)?`<img src="${esc(safeImg(p.avatar_url))}" width="48" height="48" style="border-radius:50%" loading="lazy" referrerpolicy="no-referrer" alt="">`:''}<div><b>${esc(p.login||'')}</b> <span style="color:var(--muted)">${esc(p.name||'')}</span><br><span style="font-size:11.5px;color:var(--muted)">${esc(p.bio||'')}</span></div></div>`+kv({'Repos':esc(p.public_repos??'—'),'Followers':esc(p.followers??'—'),'Location':esc(p.location||'—'),'Blog':p.blog?link(p.blog.startsWith('http')?p.blog:'https://'+p.blog,'open'):'—'})+((x.top_repos||[]).map(r=>`<div class="plat f"><h4>${link(r.url,r.name)} ${badge('★ '+r.stars,'a')}</h4><div style="font-size:11.5px;color:var(--muted)">${esc(r.description||'')} · ${esc(r.language||'')}</div></div>`).join('')||'');},
  entity:(d,c)=>[{type:'username',value:(c.querySelector('input')||{}).value||''}] },
{ id:'se', view:'people', icon:'📚', title:'Stack Exchange', desc:'Find devs across the Stack network by display name.', tag:'dev',
  inputs:[{id:'v',label:'Display name',ph:'Jon Skeet'}], run:({v})=>apiGet(`/people/stackexchange/${encodeURIComponent(v.trim())}`),
  render:d=>(d.data||[]).map(x=>`<div class="plat f"><h4>${link(x.link,x.name)} ${badge('rep '+Number(x.reputation).toLocaleString(),'a')}</h4><div style="font-size:11.5px;color:var(--muted)">${esc(x.location||'')}</div></div>`).join('')||'<span style="color:var(--faint)">no match</span>' },
{ id:'roblox', view:'people', icon:'🟥', title:'Roblox Lookup', desc:'Official user API: id, creation date, ban state.', tag:'gaming',
  inputs:[{id:'v',label:'Username',ph:'builderman'}], run:({v})=>apiGet(`/people/roblox/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'Name':esc(x.name||''),'Display':esc(x.display_name||''),'ID':esc(x.id??''),'Created':esc((x.created||'').slice(0,10)),'Banned':x.banned?badge('YES','r'):badge('no','g'),'Profile':link(x.profile,'open')})+`<div style="font-size:12px;color:var(--muted)">${esc(x.description||'')}</div>`:badge('not found','a');} },
{ id:'chess', view:'people', icon:'♞', title:'Chess.com', desc:'Ratings blitz/bullet/rapid, followers, join date.', tag:'gaming',
  inputs:[{id:'v',label:'Username',ph:'hikaru'}], run:({v})=>apiGet(`/people/chess/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'Player':link(x.profile,x.username||''),'Name':esc(x.name||'—'),'Followers':esc(x.followers??'—'),'Country':esc(x.country||'—'),'Blitz':esc(x.blitz??'—'),'Bullet':esc(x.bullet??'—'),'Rapid':esc(x.rapid??'—')}):badge('not found','a');} },
{ id:'lichess', view:'people', icon:'♜', title:'Lichess', desc:'Per-variant ratings + game count.', tag:'gaming',
  inputs:[{id:'v',label:'Username',ph:'thibault'}], run:({v})=>apiGet(`/people/lichess/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'Player':link(x.profile,x.username||''),'Games':esc(x.games??'—'),'Ratings':esc(Object.entries(x.perfs||{}).map(([k,v])=>`${k} ${v}`).join(' · ')||'—')}):badge('not found','a');} },
{ id:'discord', view:'people', icon:'💬', title:'Discord Invite', desc:'Resolve discord.gg codes: server, members, expiry.', tag:'social',
  inputs:[{id:'v',label:'Invite code',ph:'discord-developers'}], run:({v})=>apiGet(`/people/discord-invite/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};if(!x.valid)return badge('invalid / expired','r');return kv({'Server':esc(x.guild?.name||'—'),'Members':esc(x.members??'—'),'Online':esc(x.online??'—'),'Channel':esc(x.channel?.name||'—'),'Expires':esc(x.expires||'never'),'Icon':x.guild?.icon?link(x.guild.icon,'open'):'—'});} },
{ id:'wiki', view:'people', icon:'📖', title:'Wikipedia User', desc:'Account existence, edit count, groups, contribs link.', tag:'reference',
  inputs:[{id:'v',label:'Username',ph:'Jimbo Wales'}], run:({v})=>apiGet(`/people/wikipedia/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'User':esc(x.name||''),'Edits':esc(x.editcount??'—'),'Registered':esc((x.registered||'').slice(0,10)),'Groups':esc((x.groups||[]).join(', ')||'—'),'Contribs':link(x.contribs,'open')}):badge('not found','a');} },
{ id:'orcid', view:'people', icon:'🎓', title:'ORCID Researcher', desc:'Resolve 0000-0002-1825-0097-style IDs.', tag:'academic',
  inputs:[{id:'v',label:'ORCID',ph:'0000-0002-1825-0097'}], run:({v})=>apiGet(`/people/orcid/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'Name':esc([x.given,x.family].filter(Boolean).join(' ')||'—'),'Profile':link(x.profile,'open')}):badge('not found','a');} },
{ id:'gravatar', view:'people', icon:'🪪', title:'Gravatar by Email', desc:'Public profile + avatar hash check.', tag:'identity',
  inputs:[{id:'v',label:'Email',ph:'user@example.com',type:'email'}], run:({v})=>apiGet(`/people/gravatar?email=${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Public profile':x.has_profile?badge('YES','g'):badge('no','gr'),'Username':esc(x.username||'—'),'Name':esc(x.name||'—'),'Profile':x.profile?link(x.profile,'open'):'—','Avatar':link(x.avatar,'open')});},
  entity:d=>[{type:'email',value:($('.card[data-card="gravatar"] input')||{}).value||''}] },
/* ---- network ---- */
{ id:'ip', view:'net', icon:'🌐', title:'IP Lookup', desc:'Geo/ASN/ISP, triple-provider fallback + OSM map.', tag:'geo',
  inputs:[{id:'v',label:'IP address',ph:'8.8.8.8'}], run:({v})=>apiGet(`/ip/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};const lat=x.lat??x.latitude,lon=x.lon??x.longitude;return kv({'IP':esc(x.query||x.ip||''),'Country':esc(x.country||x.countryCode||'—'),'City':esc([x.city,x.regionName||x.region].filter(Boolean).join(', ')||'—'),'Coords':(lat!==undefined?esc(`${lat}, ${lon}`):'—'),'ISP':esc(x.isp||x.org||'—'),'ASN':esc(x.as||x.asn||'—'),'Private':x._private?badge('PRIVATE','a'):badge('public','b'),'Source':esc(x._source||'?')})+(lat!==undefined?`<div style="margin-top:8px">${link(`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=10/${lat}/${lon}`,'🗺 open map')}</div>`:'')+'';},
  entity:d=>[{type:'ip',value:d.data?.query||d.data?.ip||''}] },
{ id:'domain', view:'net', icon:'🔍', title:'Domain WHOIS', desc:'Authoritative RDAP + legacy fallback.', tag:'dns',
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/domain/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Domain':esc(x.ldhName||''),'Registrar':esc(x.entities?.find(e=>e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(p=>p[0]==='fn')?.[3]||'—'),'Status':esc((x.status||[]).join(', ')||'—'),'Events':esc((x.events||[]).map(e=>`${e.eventAction}: ${(e.eventDate||'').slice(0,10)}`).join(' · ')||'—'),'NS':esc((x.nameservers||[]).map(n=>n.ldhName).join(', ')||'—')});},
  entity:d=>[{type:'domain',value:d.data?.ldhName||''}] },
{ id:'dns', view:'net', icon:'📡', title:'DNS Records', desc:'10 types in parallel via DoH + DNSSEC flags.', tag:'dns',
  inputs:[{id:'v',label:'Domain',ph:'google.com'}], run:({v})=>apiGet(`/dns/${encodeURIComponent(v.trim())}`),
  render:d=>Object.entries(d.data||{}).map(([t,r])=>`<h4 style="margin:11px 0 4px;font-size:11px;letter-spacing:1px">${esc(t)} ${r.dnssec?badge('DNSSEC','g'):''}</h4>`+tbl(['Record','TTL'],(r.answer||[]).map(a=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(a.data||'')}</span>`,esc(a.TTL)]))).join('') },
{ id:'ssl', view:'net', icon:'🔒', title:'TLS / SSL', desc:'Instant handshake cert. Deep = cached SSL Labs grade.', tag:'crypto',
  inputs:[{id:'v',label:'Domain',ph:'google.com'},{id:'deep',label:'Deep scan (SSL Labs)',type:'check'}], run:({v,deep})=>apiGet(`/ssl/${encodeURIComponent(v.trim())}${deep?'?fresh=1':''}`),
  render:d=>{const c=(d.data||{}).direct||{};if(c.error)return badge('TLS failed: '+c.error,'r');return kv({'Valid':esc(`${(c.valid_from||'').slice(4,15)} → ${(c.valid_to||'').slice(4,15)}`),'Expires in':esc((c.days_remaining??'?')+' days'),'TLS':esc(c.tls_version||'—'),'Cipher':esc(c.cipher||'—'),'Issuer':esc((c.issuer||{}).O||'—')})+`<p style="margin:8px 0">${c.expired?badge('EXPIRED','r'):c.days_remaining<30?badge('EXPIRING','a'):badge('VALID','g')}</p>`;} },
{ id:'subdomains', view:'net', icon:'🌿', title:'Subdomain Enum', desc:'Certificate transparency → fast fallback.', tag:'recon', timeout:60000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/network/subdomains/${encodeURIComponent(v.trim())}`,60000),
  render:(d,vals,c)=>{const x=d.data||{};c.csv=(x.subdomains||[]).join('\n');c.csvName=`subdomains-${x.domain}.txt`;return `<p style="margin-bottom:8px">${badge(`${x.count??0} found`,'b')} <span style="color:var(--faint);font-size:11px">${esc(x.source||'')}</span></p><div class="chips">${(x.subdomains||[]).slice(0,60).map(s=>`<span class="chip">${esc(s)}</span>`).join('')||'none'}</div>`;},
  entity:d=>[{type:'domain',value:d.data?.domain||''}] },
{ id:'headers', view:'net', icon:'🧱', title:'Header Audit', desc:'Security-header score, cookie flags, server leaks.', tag:'web',
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiPost('/network/headers',{url:v.trim()}),
  render:d=>{const x=d.data||{};const col=x.score>=80?'var(--green)':x.score>=50?'var(--amber)':'var(--red)';return `<div style="display:flex;gap:13px;align-items:center;margin-bottom:9px"><div class="ring" style="width:64px;height:64px;border-radius:50%;display:grid;place-items:center;font-weight:800;border:3px solid ${col};color:${col}">${esc(x.score??0)}</div><div style="font-size:12px;color:var(--muted)">HTTP ${esc(x.status)} · ${link(x.final_url||x.url,'open')}<br>${(x.server_leaks||[]).length?badge('leaks: '+x.server_leaks.join(' · '),'a'):badge('no leaks','g')}</div></div>`+(x.checks||[]).map(c=>`<div class="chk"><span>${c.ok?'✅':'❌'}</span><div><b>${esc(c.label)}</b>${c.ok?'':`<br><span style="color:var(--muted)">Fix: ${esc(c.fix)}</span>`}</div></div>`).join('');} },
{ id:'tech', view:'net', icon:'🧪', title:'Stack Detect', desc:'CMS, CDN, frameworks from headers + HTML.', tag:'web',
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiPost('/network/tech',{url:v.trim()}),
  render:d=>{const x=d.data||{};return kv({'Server':esc(x.server||'—'),'Powered-By':esc(x.powered_by||'—')})+`<div class="chips" style="margin-top:9px">${(x.technologies||[]).map(t=>`<span class="chip">${esc(t.name)} · ${esc(t.confidence)}</span>`).join('')||'no matches'}</div>`;} },
{ id:'expand', view:'net', icon:'🔗', title:'URL Expander', desc:'Unwrap short links hop-by-hop, loop-safe.', tag:'web',
  inputs:[{id:'v',label:'Short URL',ph:'https://bit.ly/…'}], run:({v})=>apiPost('/network/expand',{url:v.trim()}),
  render:d=>{const x=d.data||{};return kv({'Final':link(x.final,'open'),'Hops':esc(x.hops??0)})+`<ol style="margin:9px 0 0 18px;font-size:12px">${(x.chain||[]).map(c=>`<li class="mono" style="margin-bottom:3px">${esc(c)}</li>`).join('')}</ol>`;} },
{ id:'blacklist', view:'net', icon:'🚫', title:'IP Blacklist', desc:'Spamhaus ZEN + SpamCop DNSBL.', tag:'reputation',
  inputs:[{id:'v',label:'IPv4',ph:'1.2.3.4'}], run:({v})=>apiGet(`/network/blacklist/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${x.clean?badge('CLEAN','g'):badge(`LISTED ×${x.listed_count}`,'r')}</p>`+tbl(['Zone','Listed','Records'],(x.results||[]).map(r=>[esc(r.zone),r.listed==null?badge('ERR','gr'):r.listed?badge('YES','r'):badge('no','g'),esc((r.records||[]).join(', ')||'—')]));} },
{ id:'portscan', view:'net', icon:'🔌', title:'Port Scan', desc:'Capped TCP connect. Authorized targets only.', tag:'recon',
  inputs:[{id:'v',label:'Host',ph:'example.com'},{id:'ports',label:'Ports (optional, comma list)',ph:'80, 443, 22'}], run:({v,ports})=>{const p=String(ports||'').split(',').map(s=>parseInt(s.trim(),10)).filter(n=>n>=1&&n<=65535);return apiPost('/network/portscan',{host:v.trim(),...(p.length?{ports:p}:{})});},
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${badge(`${(x.open||[]).length} open / ${x.scanned}`,'b')}</p>`+tbl(['Port','State','ms'],(x.results||[]).map(r=>[esc(r.port),r.state==='open'?badge('OPEN','g'):r.state==='closed'?badge('closed','gr'):badge(r.state,'a'),esc(r.latency_ms)]));} },
{ id:'asn', view:'net', icon:'🛰️', title:'ASN Lookup', desc:'Announced prefixes + registry via RIPEstat.', tag:'routing',
  inputs:[{id:'v',label:'ASN',ph:'15169'}], run:({v})=>apiGet(`/bgp/asn/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'ASN':esc('AS'+(x.asn??'')),'Description':esc((x.description||[]).join(' · ')||'—'),'Prefixes':esc(x.prefix_count??'')})+`<div class="chips" style="margin-top:8px">${(x.prefixes||[]).slice(0,24).map(p=>`<span class="chip">${esc(p.prefix)}</span>`).join('')}</div>`;},
  entity:d=>[{type:'asn',value:'AS'+(d.data?.asn??'')}] },
{ id:'bgpprefix', view:'net', icon:'🧭', title:'Prefix / IP Intel', desc:'Announcing ASNs, registry, reverse DNS.', tag:'routing',
  inputs:[{id:'v',label:'Prefix or IP',ph:'8.8.8.0/24 or 1.1.1.1'}], run:({v})=>{v=v.trim();return v.includes('/')?apiGet(`/bgp/prefix/${encodeURIComponent(v)}`):apiGet(`/bgp/ip/${encodeURIComponent(v)}`);},
  render:d=>{const x=d.data||{};return kv({'Target':esc(x.prefix||x.ip||''),'ASNs':esc((x.asns||[]).join(', ')||'—'),'Reverse':esc(x.reverse_dns||'—')});} },
{ id:'ptr', view:'net', icon:'↩️', title:'Reverse DNS', desc:'PTR records via DNS-over-HTTPS.', tag:'dns',
  inputs:[{id:'v',label:'IPv4',ph:'8.8.8.8'}], run:({v})=>apiGet(`/bgp/ptr/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?mono((x.ptr||[]).join('\n')):badge('no PTR','a');} },
{ id:'wayback', view:'net', icon:'🕰️', title:'Wayback Machine', desc:'Archived snapshots with instant replay links.', tag:'archive', timeout:75000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/archive/wayback/${encodeURIComponent(v.trim())}?limit=15`,75000),
  render:d=>(d.data||[]).map(s=>`<div class="plat f"><h4>${esc((s.timestamp||'').replace(/(\d{4})(\d{2})(\d{2}).*/, '$1-$2-$3'))} ${badge(s.status||'','gr')}</h4><div style="font-size:11.5px">${esc(s.url||'')}</div><div>${link(s.replay,'▶ replay')}</div></div>`).join('')||badge('no snapshots','a') },
{ id:'urlscan', view:'net', icon:'🔎', title:'urlscan Search', desc:'Historic scans: IPs, DOM, screenshots metadata.', tag:'archive',
  inputs:[{id:'v',label:'Query',ph:'domain:example.com'}], run:({v})=>apiGet(`/archive/urlscan?q=${encodeURIComponent(v.trim())}`),
  render:d=>(d.data||[]).map(x=>`<div class="plat f"><h4>${esc(x.domain||'')} ${badge(x.country||'?','gr')}</h4><div style="font-size:11.5px">${esc(x.page_url||'')} · ${esc(x.ip||'')}</div><div>${link(x.result,'scan result')}</div></div>`).join('')||badge('no scans','a') },
{ id:'pagemeta', view:'net', icon:'🏷️', title:'Page Metadata', desc:'Title, description, OG tags, link count.', tag:'web',
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiPost('/archive/meta',{url:v.trim()}),
  render:d=>{const x=d.data||{};return kv({'Title':esc(x.title||'—'),'Description':esc((x.description||'').slice(0,220)||'—'),'Generator':esc(x.generator||'—'),'Links':esc(x.links_found??'—')})+(x.og&&Object.keys(x.og).length?mono(Object.entries(x.og).map(([k,v])=>`og:${k} = ${v}`).join('\n')):'');} },
/* ---- threat ---- */
{ id:'ioc', view:'threat', icon:'☢️', title:'IOC Lookup', desc:'ThreatFox: IPs, domains, URLs, hashes.', tag:'ioc',
  inputs:[{id:'v',label:'IOC value',ph:'evil.com or 1.2.3.4 or sha256…'}], run:({v})=>apiPost('/threat/ioc',{value:v.trim()}),
  render:d=>{const x=d.data||{};return x.found?`<p style="margin-bottom:8px">${badge(`KNOWN ×${x.count}`,'r')}</p>`+tbl(['IOC','Malware','Conf','First seen'],(x.iocs||[]).map(i=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(i.ioc)}</span>`,esc(i.malware||'—'),esc(i.confidence??'—'),esc((i.first_seen||'').slice(0,10))])):badge('not in ThreatFox','g');},
  entity:(d,c)=>[{type:'ioc',value:(c.querySelector('input')||{}).value||''}] },
{ id:'urlhaus', view:'threat', icon:'🪤', title:'URLhaus Host', desc:'Malware-distribution reputation for a host.', tag:'reputation',
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/threat/host/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.listed?`<p style="margin-bottom:8px">${badge(`MALICIOUS ×${x.url_count} urls`,'r')}</p>`+tbl(['URL','Threat','Date'],(x.urls||[]).map(u=>[esc((u.url||'').slice(0,80)),esc(u.threat||'—'),esc(u.date||'—')])):badge('not listed','g');} },
{ id:'feodo', view:'threat', icon:'🤖', title:'Feodo C2 Check', desc:'Emotet/Dridex/TrickBot tracker blocklist.', tag:'botnet',
  inputs:[{id:'v',label:'IP',ph:'1.2.3.4'}], run:({v})=>apiGet(`/threat/feodo/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.listed?kv({'Malware':badge(x.malware||'','r'),'First seen':esc(x.first_seen||''),'Last online':esc(x.last_online||'')}):badge('not listed','g');} },
{ id:'kev', view:'threat', icon:'🚨', title:'CISA KEV', desc:'Known-exploited vulns catalog search.', tag:'vuln',
  inputs:[{id:'v',label:'Keyword (blank = recent)',ph:'apache'}], run:({v})=>apiGet(`/threat/kev${v.trim()?('?q='+encodeURIComponent(v.trim())):''}`),
  render:d=>(d.data||[]).map(v=>`<div class="plat ${v.ransomware==='Known'? 'n':'f'}"><h4>${link('https://nvd.nist.gov/vuln/detail/'+v.cve,v.cve)} ${v.ransomware==='Known'?badge('RANSOMWARE-USED','r'):''}</h4><div style="font-size:12px"><b>${esc(v.vendor||'')} ${esc(v.product||'')}</b> — ${esc(v.name||'')}</div><div style="font-size:11.5px;color:var(--muted)">${esc(v.notes||'')}</div></div>`).join('')||badge('none','a') },
{ id:'ransom', view:'threat', icon:'💀', title:'Ransomware Intel', desc:'Ransomware-tagged IOCs + KEV ransomware CVEs.', tag:'ransomware',
  inputs:[{id:'v',label:'Keyword (blank = feed)',ph:'lockbit'}], run:({v})=>apiGet(`/threat/ransomware${v.trim()?('?q='+encodeURIComponent(v.trim())):''}`),
  render:d=>(d.data||[]).map(v=>v.kind==='cve'?`<div class="plat n"><h4>${link('https://nvd.nist.gov/vuln/detail/'+v.cve,v.cve)} ${badge('KEV','r')}</h4><div style="font-size:12px">${esc(v.vendor||'')} ${esc(v.product||'')} — ${esc(v.name||'')}</div></div>`:`<div class="plat n"><h4 class="mono" style="border:none;background:none">${esc(v.ioc||'')}</h4><div style="font-size:11.5px;color:var(--muted)">${esc(v.malware||'')} · conf ${esc(v.confidence??'?')}</div></div>`).join('')||badge('no matches','a') },
{ id:'inetdb', view:'threat', icon:'👁️', title:'Shodan InternetDB', desc:'Open ports, CPEs, vulns — no key needed.', tag:'exposure',
  inputs:[{id:'v',label:'IP',ph:'8.8.8.8'}], run:({v})=>apiGet(`/threat/internetdb/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?kv({'Ports':(x.ports||[]).length?badge(x.ports.join(', '),'a'):badge('none seen','g'),'Hostnames':esc((x.hostnames||[]).join(', ')||'—'),'CPEs':esc((x.cpes||[]).join(', ')||'—'),'Vulns':(x.vulns||[]).length?badge(x.vulns.join(', '),'r'):badge('none','g'),'Tags':esc((x.tags||[]).join(', ')||'—')}):badge('no record','gr');},
  entity:d=>[{type:'ip',value:d.data?.ip||''}] },
{ id:'cve', view:'threat', icon:'🛡️', title:'CVE Search', desc:'NVD 2.0 → CIRCL → OSV, severity-badged.', tag:'vuln',
  inputs:[{id:'v',label:'Software',ph:'apache'}], run:({v})=>apiGet(`/cve/${encodeURIComponent(v.trim())}`),
  render:d=>{const items=d.data||[];return `<p style="margin-bottom:8px">${badge(`${d.totalResults??items.length} results`,'b')} <span style="color:var(--faint);font-size:11px">${esc(d.source||'')}</span></p>`+items.map(c=>{const s=String(c.severity||'UNKNOWN').toUpperCase();return `<div class="plat ${/CRITICAL|HIGH/.test(s)?'n':'f'}"><h4>${link('https://nvd.nist.gov/vuln/detail/'+c.id,c.id)} ${badge(s,/CRITICAL|HIGH/.test(s)?'r':s==='MEDIUM'?'a':'b')} ${c.score!=null?badge(c.score,'gr'):''}</h4><div style="font-size:12px">${esc((c.descriptions||[])[0]||'')}</div></div>`;}).join('')||badge('none','a');} },
/* ---- geo ---- */
{ id:'geocode', view:'geo', icon:'📍', title:'Geocode', desc:'Address → coordinates + OSM map link.', tag:'places',
  inputs:[{id:'v',label:'Address / place',ph:'Eiffel Tower'}], run:({v})=>apiGet(`/geo/code?address=${encodeURIComponent(v.trim())}`),
  render:d=>(d.data||[]).map(g=>`<div class="plat f"><h4>${esc((g.name||'').slice(0,90))}</h4><div style="font-size:12px" class="mono" style="border:none">${esc(g.lat+', '+g.lon)}</div><div>${link(g.map,'🗺 open map')}</div></div>`).join('')||badge('no match','a'),
  entity:d=>{const g=(d.data||[])[0];return g?[{type:'geo',value:`${g.lat},${g.lon} (${(g.name||'').slice(0,60)})`}]:[];} },
{ id:'revgeo', view:'geo', icon:'🧭', title:'Reverse Geocode', desc:'Coordinates → address.', tag:'places',
  inputs:[{id:'lat',label:'Latitude',ph:'48.8584'},{id:'lon',label:'Longitude',ph:'2.2945'}], run:({lat,lon})=>apiGet(`/geo/reverse?lat=${encodeURIComponent(lat.trim())}&lon=${encodeURIComponent(lon.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Place':esc(x.name||'—'),'Map':link(x.map,'🗺 open')})+mono(JSON.stringify(x.address||{},null,1));} },
{ id:'postal', view:'geo', icon:'✉️', title:'Postal Lookup', desc:'Worldwide postal codes (zippopotam).', tag:'places',
  inputs:[{id:'cc',label:'Country code',ph:'us'},{id:'code',label:'Postal code',ph:'90210'}], run:({cc,code})=>apiGet(`/geo/postal/${encodeURIComponent(cc.trim())}/${encodeURIComponent(code.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Country':esc(x.country||''),'Code':esc(x['post code']||'')})+tbl(['Place','State','Coords'],(x.places||[]).map(p=>[esc(p['place name']),esc((p.state||'')+' '+(p['state abbreviation']||'')),esc(p.latitude+', '+p.longitude)]));} },
{ id:'ukpc', view:'geo', icon:'🇬🇧', title:'UK Postcode', desc:'Constituency, ward, NHS, admins.', tag:'places',
  inputs:[{id:'v',label:'Postcode',ph:'SW1A 1AA'}], run:({v})=>apiGet(`/geo/uk/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Postcode':esc(x.postcode||''),'Country':esc(x.country||''),'Region':esc(x.region||''),'Constituency':esc(x.parliamentary_constituency||''),'Admin':esc(x.admin_district||''),'NHS':esc(x.nhs_ha||''),'Coords':esc(x.latitude+', '+x.longitude)});} },
/* ---- crypto ---- */
{ id:'addr', view:'crypto', icon:'👛', title:'Wallet Lookup', desc:'BTC/ETH/LTC/DOGE balance, txns, explorer links.', tag:'chain',
  inputs:[{id:'v',label:'Address',ph:'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'}], run:({v})=>apiGet(`/crypto/address/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Chain':esc(x.chain||''),'Balance':badge(String(x.balance_btc??x.balance??'?'),'b'),'TXs':esc(x.tx_count??'—'),'Explorer':link(x.explorer,'open')})+tbl(['TXID','Value/Fee','Info'],(x.recent_txs||[]).map(t=>[`<span class="mono" style="border:none;background:none;padding:0">${esc((t.txid||'').slice(0,24))}…</span>`,esc(t.value??t.fee_sat??'—'),esc(t.block??t.confirmations??(t.confirmed?'confirmed':''))]));},
  entity:d=>[{type:'wallet',value:d.data?.address||''}] },
{ id:'prices', view:'crypto', icon:'📈', title:'Market Prices', desc:'BTC/ETH/LTC/DOGE/XMR/SOL + 24h change.', tag:'markets',
  inputs:[], run:()=>apiGet('/crypto/prices'),
  render:d=>tbl(['Coin','USD','24h'],Object.entries(d.data||{}).map(([k,v])=>[esc(k),esc('$'+Number(v.usd).toLocaleString()),(v.usd_24h_change>=0?badge('+'+Number(v.usd_24h_change).toFixed(2)+'%','g'):badge(Number(v.usd_24h_change).toFixed(2)+'%','r'))])) },
{ id:'btcfees', view:'crypto', icon:'⛏️', title:'BTC Fees', desc:'Recommended sat/vB + chain tip.', tag:'chain',
  inputs:[], run:()=>apiGet('/crypto/btc-fees'),
  render:d=>{const x=d.data||{};return kv({'Fast':esc((x.fees_sat_vb?.fastestFee??'?')+' sat/vB'),'30 min':esc((x.fees_sat_vb?.halfHourFee??'?')+' sat/vB'),'Economy':esc((x.fees_sat_vb?.economyFee??'?')+' sat/vB'),'Tip height':esc(x.tip_height??'—')});} },
/* ---- company ---- */
{ id:'company', view:'company', icon:'🏢', title:'Company Lookup', desc:'Wikidata resolution + Wikipedia summary + logo.', tag:'corp',
  inputs:[{id:'v',label:'Company',ph:'apple'}], run:({v})=>apiGet(`/company/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};if(!x.found)return badge('no entity matched','a');return `<div style="display:flex;gap:11px;align-items:center">${x.logo && safeImg(x.logo)?`<img src="${esc(safeImg(x.logo))}" width="44" height="44" style="border-radius:10px" loading="lazy" referrerpolicy="no-referrer" alt="">`:''}<div><b>${esc(x.label||'')}</b><br><span style="font-size:11.5px;color:var(--muted)">${esc(x.description||'')}</span></div></div>`+kv({'Founded':esc((x.inception||'').slice(1,11)),'Website':x.website?link(x.website,'open'):'—','Wikipedia':x.wikipedia?link(x.wikipedia,'open'):'—'})+(x.summary?`<p style="font-size:12.5px;color:var(--muted)">${esc(x.summary)}</p>`:'');},
  entity:d=>[{type:'company',value:d.data?.label||''},{type:'domain',value:d.data?.domain||''}] },
/* ---- oathnet ---- */
{ id:'oidc', view:'oath', icon:'🪪', title:'OIDC Config Analyzer', desc:'Discovery doc: algs, flows, open registration, JWKS.', tag:'oidc',
  inputs:[{id:'v',label:'Issuer base URL',ph:'https://accounts.google.com'}], run:({v})=>apiGet(`/oauth/oidc?url=${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Issuer':esc(x.issuer||'—'),'Host match':x.issuer_matches_host?badge('yes','g'):badge('NO','r'),'JWKS':x.jwks?badge(x.jwks.count+' keys','b'):badge('none','a'),'Reg endpoint':x.registration_endpoint?badge('OPEN','a'):badge('none','g'),'Algs':esc((x.signing_algs||[]).join(', ')||'—'),'Scopes':esc((x.scopes||[]).slice(0,8).join(', ')||'—')})+`<div style="margin-top:8px">${(x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='critical'?'🔴':f.level==='warn'?'🟡':f.level==='ok'?'🟢':'🔵'}</span><div>${esc(f.msg)}</div></div>`).join('')}</div>`;},
  entity:d=>[{type:'url',value:d.data?.issuer||''}] },
{ id:'jwks', view:'oath', icon:'🔐', title:'JWKS Analyzer', desc:'Key sizes, alg mix, symmetric-key exposure.', tag:'keys',
  inputs:[{id:'v',label:'JWKS URL',ph:'https://www.googleapis.com/oauth2/v3/certs'}], run:({v})=>apiGet(`/oauth/jwks?url=${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${badge(x.key_count+' keys','b')} ${badge('algs: '+((x.algs||[]).join(', ')||'—'),'gr')}</p>`+tbl(['kid','kty','alg','bits'],(x.keys||[]).map(k=>[esc(k.kid||'—'),esc(k.kty||'—'),esc(k.alg||'—'),k.bits?(k.bits<2048?badge(k.bits,'r'):badge(k.bits,'g')):'—']))+`<div style="margin-top:8px">${(x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='critical'?'🔴':f.level==='warn'?'🟡':'🟢'}</span><div>${esc(f.msg)}</div></div>`).join('')}</div>`;} },
{ id:'oauthdisc', view:'oath', icon:'🧭', title:'OAuth Endpoint Discovery', desc:'Probe 16 well-known auth paths on a domain.', tag:'recon',
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/oauth/discover/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${x.openid_discovery?badge('OIDC DISCOVERY LIVE','g'):badge('no discovery doc','a')} ${badge(x.live_count+' live paths','b')}</p>`+tbl(['Path','Status','Type'],(x.endpoints||[]).filter(e=>e.status&&e.status<500).map(e=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(e.path)}</span>`,badge(e.status,e.status===200?'g':'a'),esc(e.content_type||'—')]));} ,
  entity:d=>[{type:'domain',value:d.data?.domain||''}] },
{ id:'saml', view:'oath', icon:'📜', title:'SAML Metadata Check', desc:'EntityID, SSO endpoints, cert expiry, signing flags.', tag:'saml',
  inputs:[{id:'v',label:'Metadata URL',ph:'https://example.com/saml/metadata'}], run:({v})=>apiGet(`/oauth/saml?url=${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Role':badge(x.role||'?','b'),'EntityID':esc((x.entityID||'').slice(0,90)||'—'),'SSO endpoints':esc((x.sso_endpoints||[]).length||0),'Certs':esc((x.certs||[]).length||0)})+((x.sso_endpoints||[]).map(s=>`<div class="kv"><dt>${esc(s.binding||'sso')}</dt><dd class="mono" style="border:none;background:none;padding:0">${esc(s.location)}</dd></div>`).join('')||'')+`<div style="margin-top:8px">${(x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='critical'?'🔴':f.level==='warn'?'🟡':'🟢'}</span><div>${esc(f.msg)}</div></div>`).join('')}</div>`;} },
{ id:'secrets', view:'oath', icon:'🕵️', title:'Secret Scanner', desc:'Page + same-origin JS sweep. Matches redacted.', tag:'secrets', timeout:60000,
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiPost('/oauth/secretscan',{url:v.trim()},60000),
  render:d=>{const x=d.data||{};const bad=(x.findings||[]).length+(x.exposures||[]).length;return `<p style="margin-bottom:8px">${bad?badge(bad+' CANDIDATES','r'):badge('clean','g')} <span style="color:var(--faint);font-size:11px">${esc(x.files_scanned||0)} files</span></p><div style="font-size:12px;color:var(--muted);margin-bottom:6px">${esc(x.verdict||'')}</div>`+tbl(['Type','File','Match'],[...(x.exposures||[]),...(x.findings||[])].map(f=>[badge(f.type,'a'),`<span class="mono" style="border:none;background:none;padding:0">${esc(f.file)}</span>`,`<span class="mono" style="border:none;background:none;padding:0">${esc(f.match)}</span>`]));} },
{ id:'ghorg', view:'recon', icon:'🏢', title:'GitHub Org Recon', desc:'Org profile, top repos, public members.', tag:'intel',
  inputs:[{id:'v',label:'Org name',ph:'github'}], run:({v})=>apiGet(`/recon/ghorg/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Org':esc(x.name||x.login||''),'About':esc((x.description||'').slice(0,160)||'—'),'Repos':esc(x.public_repos??'—'),'Followers':esc(x.followers??'—'),'Location':esc(x.location||'—'),'Blog':esc(x.blog||'—'),'Since':esc(x.created||'—')})+
    `<div class="sect">Top repos</div>`+((x.top_repos||[]).map(r=>`<div><b>${esc(r.name)}</b> ${badge('★ '+(r.stars??0),'a')} <span style="color:var(--muted)">${esc(r.language||'')}</span></div>`).join('')||'<span style="color:var(--faint)">none</span>')+
    `<div class="sect">Public members</div><div class="chips">${(x.public_members||[]).map(m=>`<span class="chip">${esc(m.login)}</span>`).join('')||'<span style="color:var(--faint)">none listed</span>'}</div>`;},
  entity:(d,c)=>[{type:'org',value:(c.querySelector('input')||{}).value||''}] },
{ id:'pkg', view:'recon', icon:'📦', title:'Package Recon', desc:'npm / PyPI / crates.io metadata, maintainers, deps.', tag:'supply',
  inputs:[{id:'reg',label:'Registry',type:'select',options:['npm','pypi','crates']},{id:'v',label:'Package',ph:'express'}],
  run:({v,reg})=>apiGet(`/recon/pkg/${encodeURIComponent(reg)}/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Package':esc(x.name||''),'Registry':esc(x.registry||''),'Latest':esc(x.latest||'—'),'License':esc(x.license||'—'),'Description':esc(x.description||'—')})+
    (x.maintainers?`<div><b>Maintainers:</b> ${esc(x.maintainers.join(', '))}</div>`:'')+
    (x.author?`<div><b>Author:</b> ${esc(x.author)} ${esc(x.author_email||'')}</div>`:'')+
    (x.downloads!=null?`<div><b>Downloads:</b> ${esc(Number(x.downloads).toLocaleString())}</div>`:'')+
    (x.deps&&x.deps.length?`<div class="sect">Dependencies</div><div class="chips">${x.deps.map(s=>`<span class="chip">${esc(s)}</span>`).join('')}</div>`:'')+
    (x.homepage?`<div style="margin-top:6px">${link(x.homepage,'homepage')}</div>`:'')+(x.repository?` <div>${link(x.repository,'repository')}</div>`:'');} },
{ id:'certs', view:'recon', icon:'📜', title:'Certificate Search', desc:'crt.sh identity search — orgs, names, issuers.', tag:'certs',
  inputs:[{id:'v',label:'Org or name',ph:'google'}], run:({v})=>apiGet(`/recon/certs?q=${encodeURIComponent(v.trim())}`),
  render:d=>tbl(['Common name','Issuer','Valid'],(d.data||[]).map(c=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(c.common_name)}</span>`,esc(c.issuer||'—'),esc((c.not_before||'').slice(0,10)+' → '+(c.not_after||'').slice(0,10))])) },
{ id:'greynoise', view:'threat', icon:'📡', title:'GreyNoise Check', desc:'Internet scanner noise or genuine threat? Community verdict.', tag:'intel',
  inputs:[{id:'v',label:'IP address',ph:'8.8.8.8'}], run:({v})=>apiGet(`/threat/greynoise/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};if(!x.observed)return `<p>${badge('NOT OBSERVED','g')}</p><p style="color:var(--muted);font-size:12.5px">${esc(x.note||'')}</p>`;
    return `<p style="margin-bottom:8px">${x.noise?badge('BACKGROUND NOISE','a'):badge('SEEN — investigate','r')} ${x.riot?badge('BENIGN SERVICE','g'):''}</p>`+
    kv({'Name':esc(x.name||'—'),'Class':esc(x.classification||'—'),'Last seen':esc(x.last_seen||'—'),'Ref':x.link?link(x.link,'GreyNoise ↗'):'—'})+(x.message?`<p style="color:var(--muted);font-size:12px">${esc(x.message)}</p>`:'');},
  entity:(d,c)=>[{type:'ip',value:(c.querySelector('input')||{}).value||''}] },
/* ---- lab ---- */
{ id:'hash', view:'lab', icon:'🔐', title:'Hash Generator', desc:'6 algorithms via POST. No URL-length bugs.', tag:'crypto',
  inputs:[{id:'algo',label:'Algorithm',type:'select',options:['sha256','md5','sha1','sha512','sha384','ripemd160']},{id:'v',label:'Text',ph:'hello world',type:'textarea'}], run:({v,algo})=>apiPost('/hash',{algorithm:algo,text:v}),
  render:d=>kv({'Algorithm':esc(d.data?.algorithm||''),'Length':esc(d.data?.text_length??'')})+mono(d.data?.hash||'') },
{ id:'hashid', view:'lab', icon:'🕵️', title:'Hash Identifier', desc:'Guess algorithm from shape/format.', tag:'crypto',
  inputs:[{id:'v',label:'Hash',ph:'5d41402abc4b2a76b9719d911017c592'}], run:({v})=>apiPost('/forensics/hash-id',{hash:v.trim()}),
  render:d=>tbl(['Algorithm','Confidence','Why'],(d.data?.candidates||[]).map(c=>[esc(c.algo),badge(c.confidence,/certain|high/.test(c.confidence)?'g':'a'),esc(c.why)])) },
{ id:'encode', view:'lab', icon:'🔤', title:'Encode / Decode', desc:'base64, hex, url, binary, morse.', tag:'text',
  inputs:[{id:'mode',label:'Mode',type:'select',options:['encode','decode']},{id:'type',label:'Format',type:'select',options:['base64','hex','url','binary','morse']},{id:'v',label:'Text',ph:'Hello, OSINT!',type:'textarea'}], run:({v,mode,type})=>apiPost(`/utils/${mode}`,{text:v,type}),
  render:d=>kv({'Format':esc(d.data?.type||'')})+mono(d.data?.output||'') },
{ id:'password', view:'lab', icon:'🎲', title:'Password Generator', desc:'CSPRNG + entropy rating.', tag:'creds',
  inputs:[{id:'length',label:'Length (8–128)',ph:'20'},{id:'symbols',label:'Symbols',type:'check'},{id:'numbers',label:'Numbers',type:'check'}], run:({length,symbols,numbers})=>apiGet(`/utils/password?length=${encodeURIComponent(length||20)}&symbols=${symbols?1:0}&numbers=${numbers?1:0}`),
  render:d=>`<p style="margin-bottom:8px">${badge(d.data?.strength||'','g')} ${badge((d.data?.entropy_bits||0)+' bits','b')}</p>`+mono(d.data?.password||'') },
{ id:'jwt', view:'oath', icon:'🎫', title:'JWT Analyzer', desc:'Decode + flag alg=none, expiry, sensitive claims.', tag:'auth',
  inputs:[{id:'v',label:'JWT',ph:'eyJhbGciOi…',type:'textarea'}], run:({v})=>apiPost('/utils/jwt',{token:v.trim()}),
  render:d=>{const x=d.data||{};return `<h4 style="font-size:11px;margin-bottom:4px;color:var(--muted)">HEADER</h4>`+mono(JSON.stringify(x.header,null,2))+`<h4 style="font-size:11px;margin:9px 0 4px;color:var(--muted)">PAYLOAD</h4>`+mono(JSON.stringify(x.payload,null,2))+`<div style="margin-top:9px">${(x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='critical'?'🔴':f.level==='warn'?'🟡':'🔵'}</span><div>${esc(f.msg)}</div></div>`).join('')||badge('clean','g')}</div>`;} },
{ id:'time', view:'lab', icon:'⏱️', title:'Time Converter', desc:'Unix ⇄ ISO ⇄ UTC. Blank = now.', tag:'text',
  inputs:[{id:'v',label:'Value (optional)',ph:'1710000000'}], run:({v})=>apiGet(`/utils/timestamp${v.trim()?('?value='+encodeURIComponent(v.trim())):''}`),
  render:d=>kv({'Unix':esc(d.data?.unix??''),'Unix ms':esc(d.data?.unix_ms??''),'ISO':esc(d.data?.iso||''),'UTC':esc(d.data?.utc||'')}) },
{ id:'url', view:'lab', icon:'🧭', title:'URL Analyzer', desc:'Params, suspicious keys, IP-host flag.', tag:'web',
  inputs:[{id:'v',label:'URL',ph:'https://example.com/?next=/admin&token=abc'}], run:({v})=>apiPost('/utils/url',{url:v.trim()}),
  render:d=>{const x=d.data||{};return kv({'Host':esc(x.hostname||''),'Path':esc(x.pathname||''),'Params':esc(x.param_count??0),'Suspicious':(x.suspicious_params||[]).length?badge(x.suspicious_params.join(', '),'a'):badge('none','g')})+((x.params||[]).map(p=>`<div class="kv"><dt>${esc(p.key)}</dt><dd class="mono" style="border:none;background:none;padding:0">${esc(p.value)}</dd></div>`).join('')||'');} },
{ id:'emailheader', view:'lab', icon:'📨', title:'Email Header Forensics', desc:'Received chain, SPF/DKIM/DMARC, spoof flags.', tag:'forensics',
  inputs:[{id:'v',label:'Raw headers',ph:'Paste full message headers…',type:'textarea'}], run:({v})=>apiPost('/forensics/email-header',{raw:v}),
  render:d=>{const x=d.data||{};return kv({'From':esc(x.from||'—'),'Spoof risk':/HIGH/.test(x.spoof_risk||'')?badge(x.spoof_risk,'r'):/low/.test(x.spoof_risk||'')?badge(x.spoof_risk,'g'):badge(x.spoof_risk||'?','a'),'Hops':esc(x.hops??''),'DKIM/SPF/DMARC':esc([x.auth?.dkim,x.auth?.spf,x.auth?.dmarc].join(' / '))})+((x.red_flags||[]).map(f=>`<div class="chk"><span>🚩</span><div>${esc(f)}</div></div>`).join('')||'')+tbl(['From','By','IP'],(x.received_chain||[]).map(h=>[esc(h.from||'—'),esc(h.by||'—'),esc(h.ip||'—')]));} },
{ id:'iban', view:'lab', icon:'🏦', title:'IBAN Validator', desc:'mod-97 check + country split.', tag:'finance',
  inputs:[{id:'v',label:'IBAN',ph:'GB29 NWBK 6016 1331 9268 19'}], run:({v})=>apiPost('/forensics/iban',{iban:v.trim()}),
  render:d=>kv({'Valid':d.data?.valid?badge('VALID','g'):badge('INVALID','r'),'Country':esc(d.data?.country||''),'BBAN':esc(d.data?.bban||'')}) },
{ id:'card', view:'lab', icon:'💳', title:'Card Check', desc:'Luhn + brand guess. PANs never stored.', tag:'finance',
  inputs:[{id:'v',label:'Number (test only)',ph:'4111 1111 1111 1111'}], run:({v})=>apiPost('/forensics/card',{number:v.trim()}),
  render:d=>kv({'Luhn':d.data?.valid_luhn?badge('VALID','g'):badge('INVALID','r'),'Brand':esc(d.data?.brand||''),'Masked':esc(d.data?.masked||'')}) },
{ id:'vin', view:'lab', icon:'🚗', title:'VIN Decoder', desc:'NHTSA: make, model, year, plant.', tag:'motors',
  inputs:[{id:'v',label:'VIN (17 chars)',ph:'1HGCM82633A004352'}], run:({v})=>apiGet(`/forensics/vin/${encodeURIComponent(v.trim())}`),
  render:d=>kv(Object.fromEntries(Object.entries(d.data||{}).slice(0,14).map(([k,v])=>[k,esc(String(v).slice(0,120))]))) },
{ id:'mac', view:'lab', icon:'📶', title:'MAC Vendor', desc:'OUI → manufacturer.', tag:'netops',
  inputs:[{id:'v',label:'MAC',ph:'44:38:39:ff:ef:57'}], run:({v})=>apiGet(`/forensics/mac/${encodeURIComponent(v.trim())}`),
  render:d=>kv({'Vendor':esc(d.data?.vendor||d.data?.note||'—'),'OUI':esc(d.data?.oui||'—')}) },
{ id:'phone', view:'lab', icon:'📱', title:'Phone Parse', desc:'Offline parse + opt-in carrier enrichment.', tag:'identity',
  inputs:[{id:'v',label:'Phone',ph:'+14155552671',type:'tel'}], run:({v})=>apiGet(`/phone/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'Valid':x.valid?badge('VALID','g'):badge('INVALID','r'),'E.164':esc(x.e164||'—'),'Intl':esc(x.international||'—'),'Country':esc(x.country||'—'),'Type':esc(x.type||'—'),'Carrier':esc(x.carrier||'—')});},
  entity:(d,c)=>[{type:'phone',value:(c.querySelector('input')||{}).value||''}] },
/* ---- field recon (GitHub-star ideas, all functional) ---- */
{ id:'crawl', view:'recon', icon:'🕷', title:'Web Crawler', desc:'Photon-style: emails, phones, socials, docs, forms, comments. Same-origin only.', tag:'crawl', timeout:90000,
  inputs:[{id:'v',label:'URL',ph:'https://example.com'},{id:'depth',label:'Depth (0–2)',ph:'1'},{id:'max',label:'Max pages',ph:'30'}],
  run:({v,depth,max})=>apiPost('/recon/crawl',{url:v.trim(),depth:+(depth||1),max:+(max||30)},90000),
  render:d=>{const x=d.data||{};return kv({'Pages':esc(x.pages_crawled??''),'Emails':esc((x.emails||[]).length||0),'Phones':esc((x.phones||[]).length||0),'Docs':esc((x.documents||[]).length||0)})+
    (x.emails?.length?`<div class="sect">Emails</div><div class="mono">${esc(x.emails.slice(0,30).join('\n'))}</div>`:'')+
    (x.phones?.length?`<div class="sect">Phones</div><div class="mono">${esc(x.phones.slice(0,30).join('\n'))}</div>`:'')+
    (x.social_profiles?.length?`<div class="sect">Social profiles</div>`+x.social_profiles.slice(0,20).map(u=>`<div>${link(u)}</div>`).join(''):'')+
    (x.documents?.length?`<div class="sect">Documents</div><div class="mono">${esc(x.documents.slice(0,30).join('\n'))}</div>`:'')+
    (x.interesting_paths?.length?`<div class="sect">Interesting paths</div><div class="mono">${esc(x.interesting_paths.slice(0,30).join('\n'))}</div>`:'')+
    (x.html_comments?.length?`<div class="sect">HTML comments</div><div class="mono">${esc(x.html_comments.slice(0,10).join('\n---\n'))}</div>`:'');},
  entity:d=>[{type:'url',value:d.data?.start||''}] },
{ id:'dnsbrute', view:'recon', icon:'🔨', title:'DNS Brute-Force', desc:'219-label built-in wordlist + your extras, via DoH.', tag:'dns', timeout:120000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'},{id:'extra',label:'Extra labels (comma, optional)',ph:'intra, erp, gitlab'}],
  run:({v,extra})=>apiPost('/recon/dns-brute',{domain:v.trim(),extra:String(extra||'').split(',').map(s=>s.trim()).filter(Boolean)},120000),
  render:(d,vals,c)=>{const x=d.data||{};c.csv=(x.found||[]).map(f=>f.host).join('\n');c.csvName=`brute-${x.domain}.txt`;return `<p style="margin-bottom:8px">${badge(`${(x.found||[]).length} live / ${x.tried} tried`,'b')}</p>`+tbl(['Host','Records'],(x.found||[]).slice(0,60).map(f=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(f.host)}</span>`,esc((f.records||[]).slice(0,2).join(', '))]));},
  entity:d=>[{type:'domain',value:d.data?.domain||''}] },
{ id:'subagg', view:'recon', icon:'🌐', title:'Subdomain Aggregator', desc:'Amass-style: crt.sh + HackerTarget + subdomain.center + urlscan (+OTX w/ key).', tag:'recon', timeout:90000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiPost('/recon/subdomains',{domain:v.trim()},90000),
  render:(d,vals,c)=>{const x=d.data||{};c.csv=(x.subdomains||[]).map(s=>s.host).join('\n');c.csvName=`subs-${x.domain}.txt`;return `<p style="margin-bottom:8px">${badge(x.count+' hosts','b')} <span style="color:var(--faint);font-size:11px">${esc(Object.entries(x.per_source_count||{}).map(([k,v])=>k+':'+v).join(' · '))}</span></p><div class="chips">${(x.subdomains||[]).slice(0,60).map(s=>`<span class="chip">${esc(s.host)}</span>`).join('')}</div>`;},
  entity:d=>[{type:'domain',value:d.data?.domain||''}] },
{ id:'wmn', view:'recon', icon:'📇', title:'WMN-700 Sweep', desc:'Live WhatsMyName dataset (Sherlock-style), cats + limit.', tag:'sweep', timeout:180000,
  inputs:[{id:'v',label:'Username',ph:'octocat'},{id:'limit',label:'Max sites (≤716)',ph:'150'},{id:'cat',label:'Category (blank=all)',ph:'social'}],
  run:({v,limit,cat})=>apiGet(`/recon/wmn/${encodeURIComponent(v.trim())}?limit=${encodeURIComponent(limit||150)}${cat.trim()?('&cat='+encodeURIComponent(cat.trim().toLowerCase())):''}`,180000),
  render:d=>{const rows=d.data||[];const f=rows.filter(r=>r.found);return `<p style="margin-bottom:8px">${badge(f.length+' HITS / '+rows.length,'b')} <span style="color:var(--faint);font-size:11px">CC BY-SA · Micah Hoffman</span></p>`+tbl(['Site','Cat','Result'],rows.filter(r=>r.found).concat(rows.filter(r=>!r.found).slice(0,0)).map(r=>[esc(r.name),esc(r.cat||''),r.found?badge('HIT','g')+` ${link(r.url,'open')}`:badge('—','gr')]));},
  entity:(d,c)=>[{type:'username',value:(c.querySelector('input')||{}).value||''}] },
{ id:'chase', view:'recon', icon:'🎯', title:'Email Chase', desc:'h8mail-style: name patterns × MX + Gravatar, ranked.', tag:'identity',
  inputs:[{id:'first',label:'First name',ph:'Jane'},{id:'last',label:'Last name',ph:'Doe'},{id:'domain',label:'Domain',ph:'example.com'}],
  run:({first,last,domain})=>apiPost('/recon/chase',{first:first.trim(),last:last.trim(),domain:domain.trim()}),
  render:d=>{const x=d.data||{};return x.mx_found?tbl(['Candidate','Gravatar','Score'],(x.candidates||[]).map(c=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(c.email)}</span>`,c.gravatar?badge('public','b'):badge('—','gr'),esc(c.score)])):badge('no MX — chase unlikely','a');} },
{ id:'wpcheck', view:'recon', icon:'🅆', title:'WordPress Audit', desc:'Version leak, REST user enum, xmlrpc, debug.log.', tag:'web',
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiPost('/recon/wpcheck',{url:v.trim()}),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${x.wordpress?badge('WordPress','b'):badge('not WP','gr')}</p>`+((x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='high'?'🔴':f.level==='warn'?'🟡':f.level==='ok'?'🟢':'🔵'}</span><div><b>${esc(f.check)}</b><br><span style="color:var(--muted)">${esc(f.detail||'')}</span></div></div>`).join(''));} },
{ id:'takeover', view:'recon', icon:'🏴', title:'Takeover Detector', desc:'Dangling CNAMEs vs 17 service fingerprints.', tag:'vuln', timeout:120000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiPost('/recon/takeover',{domain:v.trim()},120000),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${(x.vulnerable||0)?badge(x.vulnerable+' VULNERABLE','r'):badge('none vulnerable','g')} <span style="color:var(--faint);font-size:11px">${x.scanned} scanned</span></p>`+tbl(['Host','CNAME','Verdict'],(x.results||[]).filter(r=>r.verdict!=='no-cname'&&r.verdict!=='no-fingerprint').map(r=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(r.host)}</span>`,esc((r.cname||'').slice(0,40)),r.verdict==='VULNERABLE'?badge('VULNERABLE','r'):r.verdict==='not-vulnerable'?badge('safe','g'):badge(r.verdict,'a')]));} },
{ id:'goldmine', view:'recon', icon:'⛏', title:'Archive Goldmine', desc:'Wayback hunt for .env/.git/backups/admin/sql.', tag:'archive', timeout:90000,
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiPost('/recon/goldmine',{domain:v.trim()},90000),
  render:d=>`<p style="margin-bottom:8px">${badge((d.count??0)+' hits','b')} <span style="color:var(--faint);font-size:11px">${d.scanned} urls scanned</span></p>`+((d.data||[]).map(h=>`<div class="plat f"><h4 class="mono" style="border:none;background:none">${esc(h.url.slice(0,90))}</h4><div style="font-size:11px">${badge(h.pattern,'a')} ${badge(h.timestamp,'gr')}</div><div>${link(h.replay,'▶ replay')}</div></div>`).join('')||badge('clean','g')) },
{ id:'emailsec', view:'recon', icon:'📜', title:'Email Security Grade', desc:'SPF + DMARC + DKIM + MTA-STS → A–F grade.', tag:'mail',
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiGet(`/recon/emailsec/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${badge('GRADE '+x.grade,/^A/.test(x.grade||'')?'g':/^F/.test(x.grade||'')?'r':'a')} ${badge(x.score+'/100','b')}</p>`+((x.findings||[]).map(f=>`<div class="chk"><span>${f.level==='pass'?'✅':f.level==='fail'?'❌':f.level==='warn'?'⚠️':'ℹ️'}</span><div><b>${esc(f.check)}</b><br><span style="color:var(--muted)">${esc(f.detail||'')}</span></div></div>`).join(''));} },
{ id:'typosquat', view:'recon', icon:'🎭', title:'Typosquat Finder', desc:'~200 permutations → live DNS check.', tag:'brand',
  inputs:[{id:'v',label:'Domain',ph:'example.com'}], run:({v})=>apiPost('/recon/typosquat',{domain:v.trim()}),
  render:d=>{const x=d.data||{};return `<p style="margin-bottom:8px">${badge((x.live_count??0)+' LIVE of '+x.generated,'a')}</p>`+tbl(['Squat domain','DNS'],(x.live||[]).map(l=>[`<span class="mono" style="border:none;background:none;padding:0">${esc(l.domain)}</span>`,badge('LIVE','r')]))||'';} },
{ id:'favhash', view:'recon', icon:'🖼', title:'Favicon Hash', desc:'mmh3 → Shodan http.favicon.hash pivot.', tag:'pivot',
  inputs:[{id:'v',label:'URL',ph:'https://example.com'}], run:({v})=>apiGet(`/recon/favicon-hash?url=${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return kv({'mmh3':esc(x.mmh3??''),'Icon':link(x.icon,'open'),'Shodan':link(x.shodan,'pivot search ↗')});} },
{ id:'torcheck', view:'recon', icon:'🧅', title:'Tor Relay Check', desc:'Is this IP a Tor relay/exit? (onionoo).', tag:'anon',
  inputs:[{id:'v',label:'IP',ph:'8.8.8.8'}], run:({v})=>apiGet(`/recon/tor/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.is_tor?badge('TOR RELAY','a')+tbl(['Nickname','Flags'],(x.relays||[]).map(r=>[esc(r.nickname),esc((r.flags||[]).join(', '))])):badge('not tor','g');} },
{ id:'pgplookup', view:'recon', icon:'🔏', title:'PGP Key Lookup', desc:'openpgp.org + Ubuntu keyserver by email.', tag:'crypto',
  inputs:[{id:'v',label:'Email',ph:'user@example.com',type:'email'}], run:({v})=>apiGet(`/recon/pgp/${encodeURIComponent(v.trim())}`),
  render:d=>{const x=d.data||{};return x.found?tbl(['Server','KeyID','Bits','UIDs'],(x.keys||[]).map(k=>[esc(k.server),esc(k.keyid||'—'),esc(k.bits||'—'),esc((k.uids||[]).slice(0,3).join(', ')||'—')])):badge('no keys','a');} },
{ id:'ghcode', view:'recon', icon:'🐙', title:'GitHub Code Search', desc:'Leaked secrets in code. Needs free GITHUB_TOKEN.', tag:'secrets',
  inputs:[{id:'v',label:'Query',ph:'"sk_live"'}], run:({v})=>apiGet(`/recon/github-code?q=${encodeURIComponent(v.trim())}`),
  render:d=>tbl(['Repo','Path'],(d.data?.items||[]).map(i=>[esc(i.repo),link(i.url, i.path)])) },
{ id:'emailpatterns', view:'lab', icon:'✉️', title:'Email Pattern Generator', desc:'Name permutations for a domain → one-click MX verify-all.', tag:'recon',
  inputs:[{id:'first',label:'First name',ph:'Jane'},{id:'last',label:'Last name',ph:'Doe'},{id:'domain',label:'Domain',ph:'example.com'}],
  run:({first,last,domain})=>{
    const f=String(first||'').trim().toLowerCase(), l=String(last||'').trim().toLowerCase();
    const d=String(domain||'').trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];
    if(!f||!l||!d) throw new Error('First, last and domain required');
    const fi=f[0], li=l[0];
    const pats=[f,l,f+l,l+f,f+'.'+l,l+'.'+f,f+'_'+l,l+'_'+f,f+'-'+l,l+'-'+f,fi+l,li+f,f+li,l+fi,fi+'.'+l,li+'.'+f,f+'.'+li,l+'.'+fi,fi+li,f+li+l[0],l+fi+f[0]];
    const list=[...new Set(pats)].filter(p=>/^[a-z0-9._-]{1,64}$/.test(p)).map(p=>p+'@'+d);
    if(!list.length) throw new Error('No valid patterns from that input');
    return { success:true, data:{ count:list.length, patterns:list } };
  },
  render:d=>{const p=d.data?.patterns||[]; window._lastPats=p; return `<p style="margin-bottom:8px">${badge(p.length+' candidates','b')} <button class="mini" data-act="verify-all">Verify all (MX) ▸</button></p><div class="mono" style="max-height:170px;overflow:auto">${esc(p.join('\n'))}</div><div data-patout style="margin-top:8px"></div>`;} },
{ id:'uservariants', view:'lab', icon:'👥', title:'Username Variant Generator', desc:'Social + corporate permutations → click to sweep.', tag:'recon',
  inputs:[{id:'v',label:'Base handle or "First Last"',ph:'johndoe'},{id:'mode',label:'Style',type:'select',options:['social','corporate']}],
  run:({v,mode})=>{ const raw=String(v||'').trim().toLowerCase();
    if(mode==='corporate'){
      const parts=raw.split(/[\s._-]+/).filter(Boolean);
      if(parts.length<2) throw new Error('Corporate mode needs "First Last"');
      const [f,l]=parts; const fi=f[0], li=l[0]; const dom='@company.com';
      const list=[...new Set([f+'.'+l,f+l,fi+l,f+li,fi+'.'+l,f+'.'+li,l+'.'+f,l+f,f+'_'+l,f+'-'+l,l[0]+f,f[0]+l])];
      return { success:true, data:{ count:list.length, variants:list, note:'append @domain — use Email Patterns to verify' } };
    }
    const b=raw.replace(/[^a-z0-9._-]/g,''); if(!b) throw new Error('Base handle required');
    const list=[...new Set([b,b+'123',b+'01',b+'007',b+'2024',b+'2025','_'+b,b+'_','.'+b,b+'.','-'+b,b+'-','the'+b,b+'the','real'+b,b+'real','its'+b,b+'official',b+'hq',b+'tv',b+'gg',b+'dev','x'+b,b+'x',b.replace(/[._-]/g,'')])].slice(0,25);
    return { success:true, data:{ count:list.length, variants:list } }; },
  render:d=>{const v=d.data?.variants||[]; return `<p style="margin-bottom:8px">${badge(v.length+' variants','b')} <button class="mini" data-act="copy-variants" data-v="${esc(v.join('\n'))}">Copy all</button></p><div class="chips">${v.map(x=>`<span class="chip" data-act="use-variant" data-v="${esc(x)}" style="cursor:pointer" title="load into Modules sweep">${esc(x)}</span>`).join('')}</div><p style="font-size:11px;color:var(--faint);margin-top:6px">Click a variant to load it into the Modules sweep box.</p>`;} },
{ id:'dorks', view:'lab', icon:'🔎', title:'Dork Builder', desc:'Domain / phone / email / username packs → ready links.', tag:'recon',
  inputs:[{id:'pack',label:'Pack',type:'select',options:['auto','domain','phone','email','username']},{id:'v',label:'Target',ph:'example.com'}],
  run:({v,pack})=>{ const t=String(v||'').trim(); if(!t) throw new Error('Target required');
    let pk = pack==='auto' ? (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(t)?'domain':/^\+?[\d\s().-]{7,}$/.test(t)?'phone':t.includes('@')?'email':'username') : pack;
    const qs = pk==='phone' ? [`"${t}"`,`"${t}" whatsapp OR telegram OR signal OR viber`,`"${t}" breach OR leak OR exposed`,`site:facebook.com "${t}"`,`site:truecaller.com "${t}"`,`site:sync.me "${t}"`,`"${t}" "@gmail.com"`,`"${t}" spam OR scam OR fraud`,`"${t}" owner OR name`,`intext:"${t}"`]
      : pk==='email' ? [`"${t}"`,`"${t}" breach OR leak`,`"${t}" pastebin OR pastes`,`"${t}" github`,`"${t}" telegram OR discord`,`intext:"${t}"`,`"${t}" instagram OR facebook`,`"${t}" phone`,`"${t}" review OR scam`,`"${t}" whois`]
      : pk==='username' ? [`"${t}"`,`intitle:"${t}"`,`inurl:"${t}"`,`"${t}" site:github.com`,`"${t}" site:linkedin.com/in`,`"${t}" breach OR leak`,`"${t}" email`,`"${t}" telegram OR discord`,`"${t}" instagram OR tiktok`,`"${t}" review OR scam`]
      : [`site:${t}`,`site:${t} inurl:admin`,`site:${t} inurl:login`,`site:${t} intitle:"index of"`,`site:${t} ext:sql OR ext:env OR ext:log OR ext:bak`,`site:${t} intext:password`,`site:${t} inurl:api`,`site:${t} filetype:pdf`,`site:${t} "confidential"`,`site:${t} inurl:dashboard`,`site:${t} inurl:wp-admin`,`site:${t} inurl:?id=`,`site:${t} ext:xml OR ext:json OR ext:csv`,`site:pastebin.com ${t}`,`site:github.com ${t}`];
    return { success:true, data:{ target:t, pack:pk, dorks:qs.map(q=>({q, url:'https://www.google.com/search?q='+encodeURIComponent(q)})) } }; },
  render:d=>`<p style="margin-bottom:8px">${badge((d.data?.dorks||[]).length+' dorks','b')} ${badge(d.data?.pack||'','gr')} <span style="color:var(--faint);font-size:11px">for ${esc(d.data?.target||'')}</span></p>`+((d.data?.dorks||[]).map(x=>`<div class="dork"><span class="mono">${esc(x.q)}</span>${link(x.url,'open ↗')}</div>`).join('')) },
{ id:'persona', view:'lab', icon:'🪪', title:'Persona Generator', desc:'Random research legend: name, handle, email, locale, bio. Local only.', tag:'redteam',
  inputs:[{id:'locale',label:'Locale',type:'select',options:['us','uk','eu']}],
  run:({locale})=>{
    const pick=a=>a[Math.floor(Math.random()*a.length)];
    const F=['James','Mary','John','Emma','Michael','Olivia','David','Sophia','Daniel','Ava','Chris','Mia','Alex','Ella','Ryan','Zoe'];
    const L=['Smith','Johnson','Brown','Taylor','Miller','Davis','Garcia','Wilson','Anderson','Thomas','Moore','Martin'];
    const C={us:['Austin TX','Denver CO','Portland OR','Chicago IL'],uk:['Manchester','Leeds','Bristol','Glasgow'],eu:['Berlin','Amsterdam','Lyon','Warsaw']};
    const f=pick(F), l=pick(L), y=1985+Math.floor(Math.random()*18);
    const h=(f[0]+l+Math.floor(Math.random()*99)).toLowerCase();
    return { success:true, data:{ name:f+' '+l, dob:y+'-'+String(1+Math.floor(Math.random()*12)).padStart(2,'0')+'-'+String(1+Math.floor(Math.random()*28)).padStart(2,'0'), city:pick(C[locale]||C.us), handle:h, email:h+'@example.com', bio:pick(['Photographer','Hiker','Foodie','Gamer','Runner','Reader'])+' · '+pick(['coffee first','est. '+y,'views are my own','DMs open']) } };
  },
  render:d=>{const x=d.data||{};return kv({'Name':esc(x.name||''),'DOB':esc(x.dob||''),'City':esc(x.city||''),'Handle':esc(x.handle||''),'Email':esc(x.email||''),'Bio':esc(x.bio||'')})+`<p style="font-size:11px;color:var(--faint)">For authorized research accounts only. Never impersonate a real person.</p>`;} },
{ id:'imgintel', view:'lab', icon:'🖼', title:'Image Intel Launchers', desc:'Reverse-search + forensics links for an image URL.', tag:'media',
  inputs:[{id:'v',label:'Image URL',ph:'https://…/photo.jpg'}],
  run:({v})=>{ const u=String(v||'').trim(); if(!/^https?:\/\/.+\..+/.test(u)) throw new Error('Image URL required'); return { success:true, data:{ url:u } }; },
  render:d=>{const u=d.data?.url||'';return [['Google Lens','https://lens.google.com/uploadbyurl?url='+encodeURIComponent(u)],['TinEye','https://tineye.com/search?url='+encodeURIComponent(u)],['Bing Visual','https://www.bing.com/images/searchbyimage/upload?imgurl='+encodeURIComponent(u)],['Yandex Images','https://yandex.com/images/search?rpt=imageview&url='+encodeURIComponent(u)],['FotoForensics','https://fotoforensics.com/analysis.php?url='+encodeURIComponent(u)]].map(n=>`<div class="dork"><span class="mono">${esc(n[0])}</span>${link(n[1],'open ↗')}</div>`).join('');} },
{ id:'stress', view:'lab', icon:'🔥', title:'Load Stress Tester', desc:'k6-lite for YOUR sites only: ≤500 req, ≤10 concurrent, GET/HEAD, one run at a time.', tag:'loadtest', timeout:90000,
  inputs:[{id:'v',label:'Target URL (must be yours)',ph:'https://mysite.com'},{id:'requests',label:'Requests (1–500)',ph:'100'},{id:'conc',label:'Concurrency (1–10)',ph:'5'},{id:'method',label:'Method',type:'select',options:['GET','HEAD']},{id:'confirm',label:'I own this target / am authorized to load-test it',type:'check'}],
  run:({v,requests,conc,method,confirm})=>{ if(!confirm) throw new Error('Tick the ownership confirmation first'); return apiPost('/lab/stress',{url:String(v||'').trim(),requests:+(requests||100),concurrency:+(conc||5),method:method||'GET',confirm:true},90000); },
  render:d=>{const x=d.data||{};const okP=x.sent?Math.round((x.ok||0)/x.sent*100):0;
    return `<div class="warn" style="margin:0 0 10px">⚠ ${esc(x.verdict||'')}</div>`+
    kv({'Sent':esc((x.sent??'')+' / '+(x.requested??'')),'OK':esc(x.ok??''),'Failed':esc(x.failed??''),'Error rate':esc(((x.error_rate||0)*100).toFixed(1)+'%'),'Throughput':esc((x.rps??'')+' rps'),'Duration':esc((x.duration_s??'')+'s')})+
    `<div style="font-size:11px;color:var(--muted)">success share</div><div class="meter"><i style="width:${okP}%"></i></div>`+
    tbl(['Status','Hits'],Object.entries(x.status_histogram||{}).map(([k,v])=>[badge(k,/^2/.test(k)?'g':/^5/.test(k)||k==='network_error'?'r':'a'),esc(v)]))+
    kv({'avg':esc((x.ms?.avg??'')+' ms'),'p50':esc((x.ms?.p50??'')+' ms'),'p95':esc((x.ms?.p95??'')+' ms'),'max':esc((x.ms?.max??'')+' ms')})+
    (x.truncated_by_deadline?`<p style="margin-top:6px">${badge('stopped at 60s deadline','a')}</p>`:'');} },
];

/* ================= MODULES (site-engine grid) ================= */
let MODULES = [], MODULE_COUNT = 0, modFilter = 'all', modQ = '', sweepRes = null, modView = 'grid', modPinsOnly = false;
async function loadCatalog(){
  try{
    const d = await apiGet('/username/catalog/list', 20000);
    MODULES = d.data || []; MODULE_COUNT = d.count || MODULES.length;
  }catch{ MODULES = []; }
  const el = $('[data-v="modules"] .n'); if(el) el.textContent = MODULE_COUNT || '…';
  renderModFilters(); renderMods();
}
function modLabels(){
  const m = {};
  MODULES.forEach(x=>{ m[x.label] = (m[x.label]||0)+1; });
  return Object.entries(m).sort((a,b)=>b[1]-a[1]);
}
function renderModFilters(){
  const z = $('#modfilters'); if(!z) return;
  z.innerHTML = `<button class="fbtn ${modFilter==='all'?'on':''}" data-l="all">All ${MODULE_COUNT}</button>` +
    modLabels().map(([l,n])=>`<button class="fbtn ${modFilter===l?'on':''}" data-l="${esc(l)}">${esc(l)} ${n}</button>`).join('');
  $$('#modfilters .fbtn').forEach(b=>b.onclick=()=>{ modFilter=b.dataset.l; renderModFilters(); renderMods(); });
}
function renderMods(){
  const z = $('#modgrid'); if(!z) return;
  z.className = 'mods' + (modView==='list' ? ' list' : '');
  let list = MODULES.filter(m=>(modFilter==='all'||m.label===modFilter)&&(!modQ||(m.name+m.domain).toLowerCase().includes(modQ)));
  if(modPinsOnly) list = list.filter(m=>PINS.has(m.name));
  const pinned = MODULES.filter(m=>PINS.has(m.name)).length;
  $('#modcount').textContent = `Showing ${list.length} / ${MODULES.length} · ★ ${pinned} pinned`;
  z.innerHTML = list.map(m=>{
    const hit = sweepRes ? sweepRes.find(r=>r.name===m.name) : null;
    const pin = PINS.has(m.name);
    return `<div class="mod ${hit?(hit.found?'hit':'miss'):''}" title="${esc(m.domain)}">
      <img src="${fav(m.domain)}" loading="lazy" alt="" onerror="this.style.display='none'">
      <div><b>${esc(m.name)}</b><small>${esc(m.domain)} · ${esc(m.label)}</small></div>
      <span class="st"><button class="pinbtn ${pin?'pinned':''}" data-pin="${esc(m.name)}" title="${pin?'unpin':'pin'}">★</button>${hit?(hit.found?badge('HIT','g'):badge('—','gr')):m.kind==='api'?badge('API','b'):badge('probe','gr')}</span>
    </div>`;}).join('') || '<p style="color:var(--faint)">No modules match this filter.</p>';
  $$('#modgrid .mod').forEach((el,i)=>el.onclick=e=>{ if(e.target.closest('[data-pin]')) return; const m=list[i]; window.open('https://'+m.domain,'_blank'); });
  $$('#modgrid [data-pin]').forEach(b=>b.onclick=e=>{ e.stopPropagation(); const n=b.dataset.pin; if(PINS.has(n)) PINS.delete(n); else PINS.add(n); savePins(); renderMods(); });
}
function syncModViewBtns(){ const g=$('#mgrid'), l=$('#mlist'); if(g) g.classList.toggle('on', modView==='grid'); if(l) l.classList.toggle('on', modView==='list'); }
function exportSweepToGraph(){
  if(!sweepRes || !sweepRes.length){ toast('Run a sweep first'); return; }
  const f = sweepRes.filter(r=>r.found);
  if(!f.length){ toast('No hits to export'); return; }
  f.forEach(r=>addEntity('profile', r.url, r.name));
  show('graph'); toast(f.length+' profiles → graph');
}
async function runSweep(){
  const u = $('#moduser').value.trim();
  if(!u){ toast('Enter a username first'); return; }
  const btn = $('#sweepBtn'); btn.disabled = true; sweepRes = null; renderMods();
  $('#sweepstate').innerHTML = '<div class="skel"><i class="w80"></i><i></i><i class="w60"></i><i></i></div><div class="load" style="padding-top:6px"><div class="spin"></div>Sweeping engines… (~10–30s first run, cached after)</div>';
  try{
    const d = await apiGet(`/username/${encodeURIComponent(u)}`, 120000);
    sweepRes = d.data || [];
    const f = sweepRes.filter(r=>r.found);
    $('#sweepstate').innerHTML = `<p style="margin:10px 0">${badge(`${f.length} HITS / ${sweepRes.length}`,'g')} ${badge(d.cached?'cached':'live','gr')}</p><div class="chips">${f.map(r=>`<span class="chip">${esc(r.name)}</span>`).join('')||'none'}</div>`;
    pushHist('Module sweep', u, 'modules', true);
    addEntity('username', u, 'module sweep');
    f.slice(0,40).forEach(r=>addEntity('profile', r.url, r.name));
  }catch(e){ $('#sweepstate').innerHTML = `<div class="load">❌ ${esc(e.message)}</div>`; try{ pushHist('Module sweep', u, 'modules', false); }catch{} }
  finally{ btn.disabled = false; renderMods(); }
}

/* ================= SEARCH BATTERY ================= */
function detectType(v){
  v = v.trim();
  if(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';
  if(/^0x[a-fA-F0-9]{40}$/.test(v) || /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(v) || /^bc1[a-z0-9]{39,59}$/.test(v)) return 'wallet';
  if(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(v)) return 'hash';
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-fA-F:]+::/.test(v)) return 'ip';
  if(/^https?:\/\//.test(v) || /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(\/\S*)?$/i.test(v)) return 'domain';
  if(/^\+?[\d\s().-]{7,20}$/.test(v)) return 'phone';
  return 'username';
}
/* ================= NEW SEARCH (tabbed, DataVoid pattern) ================= */
const TAB_PH = { email:'name@example.com', username:'octocat', phone:'+14155552671', domain:'example.com', ip:'8.8.8.8' };
const TAB_NOTE = { email:'6 sources · scored', username:'sweep + social + dev', phone:'parse + signals', domain:'7 engines', ip:'6 engines' };
const TAB_ENGINES = {
  email:['breacher'],
  username:['username','social','github'],
  phone:['phone'],
  domain:['domain','dns','subdomains','headers','tech','urlhaus','urlscan'],
  ip:['ip','inetdb','ioc','blacklist','bgpprefix','ptr'],
  hash:['hashcheck'], wallet:['addr'],
};
let curTab = 'email';
function setTab(t){ curTab = t; $$('#stabs .fbtn').forEach(b=>b.classList.toggle('on', b.dataset.tab===t)); $('#sin').placeholder = TAB_PH[t]||'target…'; $('#stab-note').textContent = TAB_NOTE[t]||'New Search'; }
function tabHost(v){ try{ return new URL(/^https?:\/\//.test(v)?v:'https://'+v).hostname; }catch{ return v; } }
function tabVal(id, v, tab){
  if(id==='urlscan') return 'domain:'+tabHost(v);
  if(id==='headers'||id==='tech') return /^https?:\/\//.test(v)?v:'https://'+v;
  if(tab==='domain' && !['headers','tech','urlscan'].includes(id)) return tabHost(v);
  return v.trim();
}
async function runSearch(forced){
  const tab = forced || curTab;
  const ids = TAB_ENGINES[tab] || TAB_ENGINES.username;
  const v = $('#sin').value.trim();
  if(!v){ toast('Enter a target in Query'); return; }
  const box = $('#sresults');
  box.innerHTML = `<div class="pstat" id="s-prog-t">Starting ${ids.length} engine${ids.length>1?'s':''}…</div><div class="pbar"><i id="s-prog-b"></i></div><div class="skel"><i class="w80"></i><i></i><i class="w60"></i></div>`;
  $('#sgo').disabled = true;
  const out = [];
  const paintProg = ()=>{
    const b = document.getElementById('s-prog-b'), t = document.getElementById('s-prog-t');
    if(!b || !t || !document.body.contains(box)) return;
    b.style.width = Math.round(out.length/ids.length*100) + '%';
    t.textContent = `${out.length} / ${ids.length} engines done…`;
  };
  await Promise.all(ids.map(async (id)=>{
    const t = TOOLS.find(x=>x.id===id);
    if(!t){ out.push({id, title:id, ok:false, error:'engine missing'}); return; }
    const inp = t.inputs.find(i=>i.type!=='check' && i.type!=='select');
    const vals = {}; if(inp) vals[inp.id] = tabVal(id, v, tab);
    t.inputs.filter(i=>i.type==='check').forEach(i=>{ vals[i.id] = true; });
    const t0 = performance.now();
    try{ const data = await t.run(vals); out.push({id, title:t.title, ok:true, ms:Math.round(performance.now()-t0), data, vals}); }
    catch(e){ out.push({id, title:t.title, ok:false, ms:Math.round(performance.now()-t0), error:e.message}); }
    paintProg();
  }));
  const okN = out.filter(o=>o.ok).length;
  box.innerHTML = `<p style="margin-bottom:12px">${badge(`${okN}/${ids.length} engines ok`, okN?'g':'r')} ${badge(tab,'b')} <button class="mini" id="s-all-graph">+ Graph all</button> <button class="mini" id="s-exp">Export JSON</button></p>` +
    out.map(o=>{
      if(!o.ok) return `<div class="plat n"><h4>${esc(o.title||o.id)} ${badge('Search failed','r')}</h4><div style="font-size:12px;color:var(--muted)">${esc(o.error)}</div></div>`;
      const t = TOOLS.find(x=>x.id===o.id);
      let html = '';
      try{ html = t.render(o.data, o.vals||{}, {}) || ''; }catch(e){ html = `<div class="load">❌ render: ${esc(e.message)}</div>`; }
      return `<div class="plat f"><h4>${esc(o.title)} ${badge(o.ms+'ms','gr')}</h4><div style="margin-top:6px">${html}</div></div>`;
    }).join('');
  $('#sgo').disabled = false;
  $('#s-exp').onclick = ()=>dl(`search-${tab}-${Date.now()}.json`, JSON.stringify({target:v, tab, results:out},null,2));
  $('#s-all-graph').onclick = ()=>{ addEntity(tab, v, 'new search'); out.forEach(o=>{ if(o.ok && o.data && o.data.data){ const s=JSON.stringify(o.data.data).slice(0,4000); [...s.matchAll(/https?:\/\/[^\s"']{8,120}/g)].slice(0,6).forEach(m=>addEntity('url', m[0], o.title)); } }); show('graph'); };
  pushHist('New Search ['+tab+']', v, 'search', okN===ids.length);
  S.runs++;
}
// Compat entry: topbar quicksearch + palette route through auto-detect.
function runBattery(preset){
  const v = String(preset!==undefined ? preset : $('#q').value).trim();
  if(!v){ toast('Enter a target'); return; }
  const t = detectType(v);
  show('search');
  if(['email','username','phone','domain','ip'].includes(t)) setTab(t);
  else $('#stab-note').textContent = 'type: '+t;
  $('#sin').value = v;
  runSearch(TAB_ENGINES[t] ? t : 'username');
}

/* ================= EXPOSURE INDEX (Breacher-driven, DataVoid bands) ================= */
function expBand(s){ return s>=75 ? ['Critical risk','r'] : s>=50 ? ['High exposure','a'] : s>=25 ? ['Moderate exposure','a'] : ['Low exposure','g']; }
function ringSVG(score){
  const c = 2*Math.PI*64, off = c - c*score/100;
  const col = score>=75?'var(--red)':score>=50?'var(--amber)':'var(--green)';
  return `<div class="ring"><svg width="150" height="150"><circle cx="75" cy="75" r="64" fill="none" stroke="#222" stroke-width="12"/><circle cx="75" cy="75" r="64" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"/></svg><div class="num"><div><b style="color:${col}">${score}</b><small>EXPOSURE INDEX</small></div></div></div>`;
}
async function runExposure(){
  const v = $('#exp-email').value.trim();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)){ toast('Enter an email'); return; }
  $('#exp-out').innerHTML = '<div class="skel"><i class="w60"></i><i></i></div><div class="load" style="padding-top:6px"><div class="spin"></div>Querying breach sources…</div>';
  try{
    const d = await apiPost('/breacher', { email:v }, 90000);
    const x = d.data || {};
    const [label, cls] = expBand(x.score ?? 0);
    $('#exp-out').innerHTML = `<div class="expwrap">${ringSVG(x.score ?? 0)}<div style="flex:1;min-width:230px">
      <p style="margin-bottom:8px">${badge(label,cls)} ${badge((x.unique_breaches??0)+' unique breaches','b')}</p>`+
      kv({'Factors':esc((x.factors||[]).join(' · ')||'—'),
        'Stealers':(x.stealers?.computers)?badge(x.stealers.computers+' computers','r'):badge('none','g'),
        'Coverage':Object.entries(x.coverage||{}).map(([k,s])=>s==='ok'?badge(k,'g'):s==='clean'?badge(k,'gr'):s==='skipped'?badge(k+' ∅','gr'):badge(k+' !','a')).join(' ')})+
      `<div style="margin-top:9px;display:flex;gap:8px"><button class="mini" id="exp-full">Open full Breacher ▸</button></div></div></div>`;
    $('#exp-full').onclick = ()=>{ show('breach'); requestAnimationFrame(()=>{ const c=document.querySelector('[data-card="breacher"]'); if(c){ c.scrollIntoView({behavior:'smooth',block:'center'}); const i=c.querySelector('input[data-in]'); if(i&&!i.value) i.value=v; } }); };
    pushHist('Exposure index', v, 'dash', true);
  }catch(e){ $('#exp-out').innerHTML = `<div class="load">❌ ${esc(e.message)}</div>`; try{ pushHist('Exposure index', v, 'dash', false); }catch{} }
}

/* ================= INVESTIGATE GRAPH ================= */
function renderGraph(){
  const list = $('#entlist'), wrap = $('#gwrap');
  if(!list) return;
  list.innerHTML = S.entities.length ? tbl(['✓','Type','Value','Source',''], S.entities.map((e,i)=>[`<input type="checkbox" data-rep="${i}" checked>`,badge(e.type,'b'),`<span class="mono" style="border:none;background:none;padding:0">${esc(e.value.slice(0,70))}</span>`,esc(e.source||''),`<button class="mini" data-del="${i}">✕</button>`])) : '<p style="color:var(--faint)">Empty. Run any tool and press <b>+ Graph</b>, or add manually below.</p>';
  $$('#entlist [data-del]').forEach(b=>b.onclick=()=>{ S.entities.splice(+b.dataset.del,1); saveEnts(); renderGraph(); });
  if(!wrap) return;
  const n = S.entities.slice(0,40);
  if(!n.length){ wrap.innerHTML = '<p style="padding:30px;text-align:center;color:var(--faint)">No entities yet.</p>'; return; }
  const W = Math.max(600, n.length*46), H = 460, cx = W/2, cy = H/2, R = Math.min(200, 90+n.length*4);
  const links = S.autolink ? findLinks(n) : [];
  let svg = `<svg id="gin" width="${W}" height="${H}">`;
  links.forEach(([a,b])=>{
    const pa = pos(a,n.length,cx,cy,R), pb = pos(b,n.length,cx,cy,R);
    svg += `<line x1="${pa[0]}" y1="${pa[1]}" x2="${pb[0]}" y2="${pb[1]}" stroke="#666" stroke-width="1" stroke-dasharray="4 3"/>`;
  });
  n.forEach((e,i)=>{
    const [x,y] = pos(i,n.length,cx,cy,R);
    const col = '#e8e8e8';
    svg += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(0)}" y2="${y.toFixed(0)}" stroke="#333" stroke-width="1.5"/><g class="gnode" data-i="${i}"><circle cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="17" fill="#000" stroke="${col}" stroke-width="2"/><text x="${x.toFixed(0)}" y="${(y+5).toFixed(0)}" text-anchor="middle" font-size="12" font-weight="bold" fill="#fff" font-family="monospace">${esc(iconFor(e.type))}</text><text x="${x.toFixed(0)}" y="${(y+32).toFixed(0)}" text-anchor="middle" font-size="9.5" fill="#999" font-family="monospace">${esc(e.value.slice(0,22))}</text></g>`;
  });
  svg += `<g><circle cx="${cx}" cy="${cy}" r="24" fill="#000" stroke="#fff" stroke-width="2"/><text x="${cx}" y="${cy+7}" text-anchor="middle" font-size="18" fill="#fff">★</text><text x="${cx}" y="${cy+40}" text-anchor="middle" font-size="10" fill="#888" font-family="monospace">CASE · ${n.length}</text></g></svg>`;
  wrap.innerHTML = svg;
  $$('#gin .gnode').forEach(g=>g.onclick=()=>{ const e=n[+g.dataset.i]; copyT(e.value); });
}
function pos(i,total,cx,cy,R){ const a=(2*Math.PI*i/total)-Math.PI/2; return [cx+R*Math.cos(a)*1.7, cy+R*Math.sin(a)*0.92]; }
function lcs(a,b){
  a=String(a).toLowerCase(); b=String(b).toLowerCase();
  const m=[]; let best=0;
  for(let i=0;i<a.length;i++){ m[i]=[]; for(let j=0;j<b.length;j++){ m[i][j]=a[i]===b[j]?((i&&j?m[i-1][j-1]:0)+1):0; if(m[i][j]>best)best=m[i][j]; } }
  return best;
}
function findLinks(n){
  const out=[];
  for(let i=0;i<n.length;i++) for(let j=i+1;j<n.length;j++){
    const A=String(n[i].value).replace(/https?:\/\/(www\.)?/,'').replace(/[^a-z0-9]/gi,''), B=String(n[j].value).replace(/https?:\/\/(www\.)?/,'').replace(/[^a-z0-9]/gi,'');
    if(A.length>=6&&B.length>=6&&lcs(A,B)>=8) out.push([i,j]);
  }
  return out.slice(0,60);
}
function iconFor(t){ return {email:'E',domain:'D',ip:'I',username:'U',hash:'H',wallet:'W',company:'C',phone:'P',asn:'A',geo:'G',ioc:'X',profile:'L',url:'L',note:'N'}[t]||'•'; }

/* ================= DASH / HISTORY / API DOCS ================= */
// Animated counters (skip animation for reduced-motion users).
function countUp(el, to){
  if(!el) return;
  to = Number(to) || 0;
  if(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches){ el.textContent = to; return; }
  const from = parseInt(el.textContent, 10) || 0;
  if(from === to){ el.textContent = to; return; }
  const t0 = performance.now(), dur = 600;
  (function tick(t){
    const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(from + (to - from) * e);
    if(k < 1) requestAnimationFrame(tick);
  })(t0);
}
function renderDash(){
  const now = Date.now(), day = now-864e5, week = now-7*864e5;
  const ts = S.history.map(h=>new Date(h.t).getTime()).filter(Number.isFinite);
  const el = id=>document.getElementById(id);
  countUp(el('st-today'), ts.filter(t=>t>day).length);
  countUp(el('st-week'), ts.filter(t=>t>week).length);
  const tracked = S.history.filter(h=>h.ok===true||h.ok===false);
  if(el('st-rate')) el('st-rate').textContent = tracked.length ? Math.round(tracked.filter(h=>h.ok).length/tracked.length*100)+'%' : '—';
  const h = S.history.slice(0,8);
  const dh = el('dash-hist'); if(!dh) return;
  dh.innerHTML = h.length ? h.map(x=>`<div class="hi"><b>${esc(x.tool)}</b> ${x.ok===true?'<span class="ok">●</span>':x.ok===false?'<span class="bad">●</span>':''} — ${esc(x.input)}<br><time>${esc(new Date(x.t).toLocaleString())}</time></div>`).join('') : '<p style="color:var(--faint)">No scans yet.</p>';
}
function renderHist(){
  const l = $('#hlist'); if(!l) return;
  l.innerHTML = S.history.length ? '' : '<p style="color:var(--faint);font-size:12.5px">No lookups yet.</p>';
  S.history.forEach(x=>{
    const d = document.createElement('div'); d.className='hi';
    d.innerHTML = `<b>${esc(x.tool)}</b> ${x.ok===true?'<span class="ok">●</span>':x.ok===false?'<span class="bad">●</span>':''}<br><span>${esc(x.input)}</span><br><time>${esc(new Date(x.t).toLocaleString())}</time>`;
    d.onclick = ()=>{ $('#drawer').classList.remove('open'); if(x.view) show(x.view); };
    l.appendChild(d);
  });
}
const API_DOCS = [
 ['GET','/health','Server status + uptime'],['GET','/api/ip/:ip','IP geo/ASN (3-provider fallback)'],
 ['GET','/api/domain/:domain','WHOIS via RDAP'],['GET','/api/dns/:domain[?type=]','10 DNS types, parallel DoH'],
 ['GET','/api/email/:email','Breach check (HIBP/XposedOrNot)'],['POST','/api/breacher','6-source lookup + Exposure Index'],['GET','/api/phone/:phone','libphonenumber parse + enrichment'],
 ['GET','/api/username/:username[?label=]','~170-platform sweep'],['GET','/api/username/catalog/list','Module catalog'],
 ['GET','/api/github/:username','Profile + top repos'],['GET','/api/social/:username','7 keyless social APIs'],
 ['GET','/api/ssl/:domain[?fresh=1]','Direct TLS + cached Labs grade'],['GET','/api/cve/:software','NVD → CIRCL → OSV'],
 ['GET','/api/hash/:algo/:text','Hash (short texts)'],['POST','/api/hash','Hash {algorithm,text}'],['GET','/api/hash/check/:hash','MalwareBazaar verdict'],
 ['POST','/api/utils/encode|decode','base64/hex/url/binary/morse'],['GET','/api/utils/password?…','CSPRNG passwords'], ['POST','/api/utils/jwt','JWT decode + flags'],
 ['GET','/api/oauth/discover/:domain','16-path OAuth probe'],['GET','/api/oauth/oidc?url=','Discovery-doc audit'],['GET','/api/oauth/jwks?url=','JWKS key hygiene'],
 ['GET','/api/oauth/saml?url=','SAML metadata audit'],['POST','/api/oauth/secretscan','Page+JS secret sweep'],
 ['GET','/api/utils/timestamp[?value=]','Time conversions'],['POST','/api/utils/url','URL structure analysis'],
 ['GET','/api/network/subdomains/:domain','crt.sh → HackerTarget'],['POST','/api/network/headers','Security-header audit'],['POST','/api/network/tech','Stack fingerprint'],
 ['POST','/api/network/expand','Short-URL unwrap'],['GET','/api/network/blacklist/:ip','Spamhaus + SpamCop'],['POST','/api/network/portscan','Capped TCP scan'],
 ['POST','/api/threat/ioc','ThreatFox IOC'],['GET','/api/threat/host/:domain','URLhaus host'],['GET','/api/threat/feodo/:ip','Feodo C2 check'],
 ['GET','/api/threat/kev[?q=]','CISA KEV catalog'],['GET','/api/threat/ransomware[?q=]','Ransomware IOCs + KEV'],['GET','/api/threat/internetdb/:ip','Shodan InternetDB'],
 ['GET','/api/archive/wayback/:domain','Wayback snapshots'],['GET','/api/archive/available?url=','Closest snapshot'],['GET','/api/archive/urlscan?q=','urlscan search'],['POST','/api/archive/meta','Page metadata/OG'],
 ['GET','/api/geo/code?address=','Nominatim geocode'],['GET','/api/geo/reverse?lat=&lon=','Reverse geocode'],['GET','/api/geo/postal/:cc/:code','World postal'],['GET','/api/geo/uk/:postcode','UK postcode'],
 ['GET','/api/crypto/address/:addr','BTC/ETH/LTC/DOGE'],['GET','/api/crypto/prices','CoinGecko'],['GET','/api/crypto/btc-fees','mempool fees'],
 ['GET','/api/people/stackexchange/:u','SE profiles'],['GET','/api/people/roblox/:u','Roblox user'],['GET','/api/people/chess/:u','chess.com'],['GET','/api/people/lichess/:u','lichess'],
 ['GET','/api/people/discord-invite/:code','Invite resolve'],['GET','/api/people/wikipedia/:u','Wiki account'],['GET','/api/people/orcid/:id','Researcher'],['GET','/api/people/gravatar?email=','Gravatar'],
 ['GET','/api/bgp/asn/:asn','RIPEstat ASN'],['GET','/api/bgp/prefix/:cidr','Prefix intel'],['GET','/api/bgp/ip/:ip','Announcing ASN'],['GET','/api/bgp/ptr/:ip','Reverse DNS'],
 ['GET','/api/verify/email/:email','Deliverability signals'],['POST','/api/verify/password','HIBP k-anonymity'],
 ['POST','/api/forensics/email-header','Header parse'],['POST','/api/forensics/iban','IBAN mod-97'],['POST','/api/forensics/card','Luhn + brand'],
 ['POST','/api/forensics/hash-id','Hash identify'],['GET','/api/forensics/vin/:vin','NHTSA decode'],['GET','/api/forensics/mac/:mac','OUI vendor'],
 ['GET','/api/lab/limits','Stress caps'],['POST','/api/lab/stress','Capped load test (confirm)'],
 ['GET','/api/company/:name','Wikidata + Wikipedia'],
 ['POST','/api/recon/crawl','Same-origin crawler'],['POST','/api/recon/dns-brute','Built-in DNS brute-force'],['POST','/api/recon/subdomains','4-source sub aggregator'],['GET','/api/recon/wmn/:u','WhatsMyName 700 sweep'],
 ['POST','/api/recon/chase','Name→email chase'],['POST','/api/recon/wpcheck','WordPress audit'],['POST','/api/recon/takeover','Subdomain takeover'],['POST','/api/recon/goldmine','Wayback sensitive files'],
 ['GET','/api/recon/emailsec/:domain','SPF/DMARC/DKIM grade'],['POST','/api/recon/typosquat','Squat gen + DNS'],['GET','/api/recon/favicon-hash?url=','mmh3 Shodan pivot'],['GET','/api/recon/tor/:ip','Tor relay check'],['GET','/api/recon/pgp/:email','PGP keyservers'],  ['GET','/api/recon/github-code?q=','GH code (token)'],
  ['GET','/api/recon/ghorg/:org','GitHub org intel'],['GET','/api/recon/pkg/:reg/:name','npm/PyPI/crates meta'],['GET','/api/recon/certs?q=','crt.sh identity'],
  ['GET','/api/threat/greynoise/:ip','GreyNoise verdict'],
  ['GET','/api/auth/config','Public auth knobs'],['POST','/api/auth/totp/setup','TOTP secret'],['POST','/api/auth/totp/enable','TOTP activate'],['POST','/api/auth/totp/disable','TOTP off'],['POST','/api/auth/totp/verify','TOTP login step'],
  ['GET','/api/auth/backup','Full export (super)'],['POST','/api/auth/backup/restore','Full restore (super)'],
];
function renderApiDocs(){
  $('#apidocs').innerHTML = tbl(['Method','Endpoint','What'], API_DOCS.map(([m,p,d])=>[badge(m, m==='GET'?'b':'a'),`<span class="mono" style="border:none;background:none;padding:0">${esc(p)}</span>`,esc(d)]))
    + `<div class="sect">Optional keys (.env)</div>` + mono('HIBP_API_KEY=       # full breach data\nABSTRACT_API_KEY=   # phone carrier enrichment\nGITHUB_TOKEN=       # lift GitHub rate limits\nVIRUSTOTAL_API_KEY= # noted in hash verdicts\nEMAILREP_KEY=       # EmailRep reputation (breacher)');
}

/* ================= VIEW SHELLS ================= */
function buildViews(){
  const v = (id, inner) => `<div class="view" id="v-${id}">${inner}</div>`;
  $('#views').innerHTML =
  v('dash', `<div class="casehead"><span class="no">CASE FILE <b data-caseno></b></span><span class="stamp">Fictional · Training</span></div>
  <div class="welcome"><h1>Welcome back, <em id="whoami">analyst</em>.</h1><p>Breacher, 177 site engines, infrastructure intel, threat feeds and forensics — every engine keyless by default.</p></div>
    <div class="stats">
      <div class="stat"><div class="l">Today</div><div class="v" id="st-today">0</div><div class="s">scans · last 24h</div></div>
      <div class="stat"><div class="l">This week</div><div class="v" id="st-week">0</div><div class="s">scans · last 7d</div></div>
      <div class="stat"><div class="l">Success rate</div><div class="v" id="st-rate">—</div><div class="s">ok / tracked runs</div></div>
      <div class="stat"><div class="l">Workspace</div><div class="v" style="font-size:17px">Local</div><div class="s">no cloud · no retention</div></div>
      <div class="stat"><div class="l">Plan</div><div class="v" style="font-size:17px">Evosint ∞</div><div class="s">unlimited · no credits</div></div>
      <div class="stat"><div class="l">Status</div><div class="v" style="font-size:17px;color:var(--green)">● Live</div><div class="s">api online</div></div>
    </div>
    <div class="sect">Companies &amp; infra · Citizens / ID</div>
    <div class="grid2">
      <div class="card"><div class="chead"><div class="cico">🧲</div><div><h3>Exposure Index</h3><p>6 breach sources → 0–100 score + band.</p></div></div>
        <div class="field"><label>Email to measure</label><input id="exp-email" type="email" placeholder="target@example.com"></div>
        <div class="brow"><button class="btn" id="expgo">Measure ▸</button></div><div id="exp-out"></div></div>
      <div class="card"><div class="chead"><div class="cico">◎</div><div><h3>New Search</h3><p>Tabbed multi-engine runs: Email, Username, Phone, Domain, IP.</p></div></div>
        <div class="chips">
          <span class="chip">email → Breacher + score</span><span class="chip">username → sweep + social</span>
          <span class="chip">domain → 7 engines</span><span class="chip">ip → 6 engines</span>
        </div><p style="font-size:12px;color:var(--muted)">Top bar, Ctrl+K menu, or the Search view — type is auto-detected.</p>
        <div class="brow"><button class="btn" data-act="goto-search">Open Search ▸</button></div></div>
    </div>
    <div class="sect">Recent scans</div><div id="dash-hist" class="grid"></div>
    <div class="supportbar"><div class="cico">💬</div><div style="flex:1;min-width:200px"><b>Need a hand?</b><br><span style="color:var(--muted);font-size:12px">Login issues, quota questions, bugs — contact <b style="color:var(--text)">evopsico</b> on Discord.</span></div><button class="ghost" data-act="copy-variants" data-v="evopsico">Copy Discord</button></div>`) +
  v('search', `<div class="superbox"><div class="searchtabs" id="stabs">
      ${['email','username','phone','domain','ip'].map((t,i)=>`<button class="fbtn ${i===0?'on':''}" data-tab="${t}">${t==='ip'?'IP Address':t[0].toUpperCase()+t.slice(1)}</button>`).join('')}
      <span style="flex:1"></span><span class="pill" id="stab-note">6 sources · scored</span></div>
      <div style="height:12px"></div>
      <div class="field"><label>Query</label><input id="sin" placeholder="name@example.com" autocomplete="off" spellcheck="false"></div>
      <div style="height:12px"></div>
      <div class="brow"><button class="btn" id="sgo">Run search ▸</button></div></div>
    <div id="sresults"></div>
    <div class="sect">Search failed?</div><p style="font-size:12.5px;color:var(--muted);max-width:780px">Check the target format for the active tab (RFC email, E.164 phone like +14155552671, bare domain). Every failed run is logged to History with its error. For single-engine control open Breaches, People or Network.</p>`) +
  v('modules', `<div class="card" style="margin-bottom:14px"><div class="chead"><div class="cico">▦</div><div><h3>Site Engines</h3><p>One username → sweep every engine. White border = hit. Click a card to open the profile.</p></div></div>
      <div class="brow"><input id="moduser" placeholder="username to sweep…" style="flex:1;padding:10px 14px;border-radius:10px;border:1px solid var(--border2);background:#000;color:var(--text);font-family:var(--mono);outline:none"><button class="btn" id="sweepBtn" style="flex:none">Sweep ▸</button></div>
      <div id="sweepstate"></div></div>
    <div class="modbar"><input id="modq" placeholder="filter engines…"><button class="fbtn on" id="mgrid">Grid view</button><button class="fbtn" id="mlist">List view</button><button class="fbtn" id="mpins">★ Pinned</button><button class="fbtn" id="mexp">Export to graph</button><span class="pill" id="modcount"></span></div>
    <div class="modbar" id="modfilters" style="margin-top:-4px"></div>
    <div class="mods" id="modgrid"></div>`) +
  v('graph', `<div class="casehead"><span class="no">CASE FILE <b data-caseno></b></span><span class="stamp">Link chart · Fictional</span></div>
  <div class="brow" style="margin-bottom:12px;max-width:860px"><input id="ent-type" placeholder="type (email, domain, ip…)" style="width:150px;padding:10px 12px;border-radius:10px;border:1px solid var(--border2);background:#000;color:var(--text);outline:none"><input id="ent-val" placeholder="value…" style="flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--border2);background:#000;color:var(--text);font-family:var(--mono);outline:none"><button class="btn" id="ent-add" style="flex:none">+ Add</button><button class="ghost" id="ent-clear">Clear</button><button class="ghost" id="ent-link">Auto-link: off</button><button class="ghost" id="ent-exp">Export</button></div>
    <div id="gwrap"><p style="padding:30px;text-align:center;color:var(--faint)">No entities yet.</p></div>
    <div class="sect">Entities (click node to copy · tick for report)</div><div id="entlist"></div>
    <div class="sect">Case report</div>
    <div class="card"><div class="field"><label>Report title</label><input id="rep-title" placeholder="Subject profile — case EV-…"></div>
    <div class="field"><label>Analyst notes</label><textarea id="rep-notes" placeholder="What was found, confidence, next steps…"></textarea></div>
    <div class="brow"><button class="btn" id="rep-build">Build report ▸</button><button class="ghost" id="rep-dl" disabled>Download HTML</button><button class="ghost" id="rep-md" disabled>Copy Markdown</button></div>
    <div id="rep-out" style="margin-top:10px"></div></div>`) +
  v('breach', `<div class="grid" data-cards="breach"></div>`) +
  v('people', `<div class="grid" data-cards="people"></div>`) +
  v('net', `<div class="grid" data-cards="net"></div>`) +
  v('threat', `<div class="grid" data-cards="threat"></div>`) +
  v('oath', `<div class="grid" data-cards="oath"></div>`) +
  v('geo', `<div class="grid" data-cards="geo"></div>`) +
  v('crypto', `<div class="grid" data-cards="crypto"></div>`) +
  v('company', `<div class="grid" data-cards="company"></div>`) +
  v('recon', `<div class="grid" data-cards="recon"></div>`) +
  v('lab', `<div class="grid" data-cards="lab"></div>`) +
  v('api', `<div class="card"><div class="chead"><div class="cico">⎔</div><div><h3>REST API</h3><p>Every console feature is a plain HTTP endpoint. Base: <span class="mono" style="display:inline">/api</span></p></div></div><div id="apidocs"></div></div>`);
}

/* ================= MAIN MENU + QUICKSEARCH PALETTE ================= */
const PAL = { open:false, rows:[], sel:0 };
function palRecent(){ try{ return JSON.parse(localStorage.getItem('evosint-pal-recent')||'[]'); }catch{ return []; } }
function palPushRecent(it){ try{ const r = palRecent().filter(x=>!(x.kind===it.kind&&x.id===it.id)); r.unshift({kind:it.kind,id:it.id,label:it.label}); localStorage.setItem('evosint-pal-recent', JSON.stringify(r.slice(0,6))); }catch{} }
function palIndex(){
  const items = [];
  NAV.filter(n=>n[0]!=='sec').forEach(n=>items.push({kind:'view', id:n[0], icon:n[1], label:n[2]+' view', hint:VIEW_TITLES[n[0]]?VIEW_TITLES[n[0]][1]:''}));
  TOOLS.forEach(t=>items.push({kind:'tool', id:t.id, icon:t.icon, label:t.title, hint:t.desc+' · '+t.view}));
  ['Social Media','Gaming','Development','Music','Entertainment','Photography','Community'].forEach(l=>items.push({kind:'engines', id:l, icon:'▦', label:l+' engines', hint:'open Modules filtered'}));
  items.push({kind:'action', id:'sweep', icon:'⚡', label:'Sweep username…', hint:'uses top-bar query'});
  items.push({kind:'action', id:'battery', icon:'◎', label:'Run New Search…', hint:'uses top-bar query'});
  items.push({kind:'action', id:'exposure', icon:'🧲', label:'Exposure meter…', hint:'uses top-bar query as email'});
  items.push({kind:'action', id:'expjson', icon:'⤓', label:'Export history (JSON)', hint:'downloads'});
  items.push({kind:'action', id:'graph', icon:'⬡', label:'Open Investigate graph', hint:String(S.entities.length)+' entities'});
  return items;
}
function fuzzy(q, text){
  q = q.toLowerCase(); text = text.toLowerCase();
  if(!q) return 1;
  if(text.includes(q)) return 100 - text.indexOf(q);
  let qi = 0, score = 0, last = -2;
  for(let i=0;i<text.length && qi<q.length;i++){
    if(text[i]===q[qi]){ score += (last===i-1)?3:1; last = i; qi++; }
  }
  return qi===q.length ? score : -1;
}
function palFilter(q){
  const idx = palIndex();
  if(!q){
    const rec = palRecent().map(r=>({...r, recent:true})).filter(r=>idx.some(x=>x.kind===r.kind&&x.id===r.id));
    return { rec, groups:[['Views', idx.filter(x=>x.kind==='view')], ['Tools', idx.filter(x=>x.kind==='tool')], ['Engines', idx.filter(x=>x.kind==='engines')], ['Actions', idx.filter(x=>x.kind==='action')]] };
  }
  const scored = idx.map(x=>({x, s:Math.max(fuzzy(q,x.label), fuzzy(q,(x.hint||'').slice(0,60))-20)})).filter(o=>o.s>0).sort((a,b)=>b.s-a.s).slice(0,40).map(o=>o.x);
  return { rec:[], groups:[['Results', scored]] };
}
function renderPal(){
  const q = $('#palInput').value.trim();
  const { rec, groups } = palFilter(q);
  PAL.rows = [];
  let html = '';
  if(rec.length){ html += '<div class="pal-sec">Recent</div>' + rec.map(r=>palRow(r)).join(''); }
  for(const [g, items] of groups){
    if(!items.length) continue;
    html += `<div class="pal-sec">${esc(g)}</div>` + items.map(r=>palRow(r)).join('');
  }
  $('#palList').innerHTML = html || '<div class="pal-empty">No match — try a tool name, view, or engine.</div>';
  PAL.sel = 0; paintPalSel();
  $$('#palList .pal-it').forEach(el=>{
    el.onclick = ()=>palGo(PAL.rows[+el.dataset.i]);
    el.onmousemove = ()=>{ PAL.sel = +el.dataset.i; paintPalSel(); };
  });
}
function palRow(r){
  const i = PAL.rows.length; PAL.rows.push(r);
  const sub = r.kind==='tool' ? r.hint : r.kind==='view' ? r.hint : r.kind==='engines' ? 'modules grid' : r.hint;
  return `<button class="pal-it" data-i="${i}"><span class="pic">${r.icon}</span><span>${esc(r.label)}<small>${esc(r.kind)} · ${esc(sub||'')}</small></span></button>`;
}
function paintPalSel(){ $$('#palList .pal-it').forEach((el,i)=>el.classList.toggle('sel', i===PAL.sel)); const s=$('#palList .pal-it.sel'); if(s) s.scrollIntoView({block:'nearest'}); }
function openPal(){ $('#palBack').classList.add('open'); PAL.open = true; $('#palInput').value=''; renderPal(); setTimeout(()=>$('#palInput').focus(),30); }
function closePal(){ $('#palBack').classList.remove('open'); PAL.open = false; }
function palGo(r){
  if(!r) return;
  palPushRecent(r); closePal();
  if(r.kind==='view'){ show(r.id); }
  else if(r.kind==='engines'){ show('modules'); modFilter = r.id; renderModFilters(); renderMods(); }
  else if(r.kind==='tool'){
    const t = TOOLS.find(x=>x.id===r.id); if(!t) return;
    show(t.view);
    requestAnimationFrame(()=>{
      const card = document.querySelector(`[data-card="${CSS.escape(t.id)}"]`);
      if(!card) return;
      card.scrollIntoView({behavior:'smooth', block:'center'});
      const inp = card.querySelector('input[data-in]:not([type=checkbox]), textarea[data-in]');
      if(inp){ const hint = lastPalQuery; if(hint && !inp.value && inp.type!=='checkbox') inp.value = hint; inp.focus(); }
    });
  }
  else if(r.kind==='action'){
    if(r.id==='sweep'){ const v=$('#q').value.trim(); show('modules'); if(v){ $('#moduser').value=v; runSweep(); } }
    if(r.id==='battery'){ const v=$('#q').value.trim(); show('search'); if(v) runBattery(v); }
    if(r.id==='exposure'){ const v=$('#q').value.trim(); show('dash'); if(v){ $('#exp-email').value=v; runExposure(); } }
    if(r.id==='expjson'){ $('#expJson').click(); }
    if(r.id==='graph'){ show('graph'); }
  }
}
let lastPalQuery = '';
function bindPal(){
  const inp = $('#palInput');
  inp.addEventListener('input', ()=>{ lastPalQuery = inp.value.trim(); renderPal(); });
  inp.addEventListener('keydown', e=>{
    if(e.key==='ArrowDown'){ e.preventDefault(); PAL.sel = Math.min(PAL.rows.length-1, PAL.sel+1); paintPalSel(); }
    else if(e.key==='ArrowUp'){ e.preventDefault(); PAL.sel = Math.max(0, PAL.sel-1); paintPalSel(); }
    else if(e.key==='Enter'){ palGo(PAL.rows[PAL.sel]); }
    else if(e.key==='Escape'){ closePal(); }
  });
  $('#palBack').addEventListener('mousedown', e=>{ if(e.target.id==='palBack') closePal(); });
  $('#menuBtn').onclick = ()=>PAL.open?closePal():openPal();
  document.addEventListener('keydown', e=>{
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName||'');
    if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); PAL.open?closePal():openPal(); }
    else if(e.key==='/' && !typing && !PAL.open){ e.preventDefault(); openPal(); }
    else if(e.key==='Escape' && PAL.open){ closePal(); }
  });
}

/* ================= BOOT HELPERS (turnstile, PWA) ================= */
// Turnstile bot wall: activates only when the server publishes a site key.
// Without keys the widgets never render and the server skips verification.
async function initTurnstile(){
  try{
    const d = await apiGet('/auth/config', 10000);
    const key = d && d.data && d.data.turnstileSiteKey;
    if(!key) return;
    AUTH.cfSiteKey = key;
    await new Promise((res, rej)=>{
      if(typeof turnstile !== 'undefined') return res();
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true; s.defer = true;
      s.onload = res; s.onerror = ()=>rej(new Error('captcha-load'));
      document.head.appendChild(s);
    });
    window._cfWidgets = window._cfWidgets || {};
    for (const id of ['cf-login', 'cf-signup']) {
      const el = document.getElementById(id);
      if(el && !el.dataset.done){
        window._cfWidgets[id] = turnstile.render('#' + id, { sitekey:key, theme:'dark', size:'compact' });
        el.dataset.done = '1';
      }
    }
  }catch{ /* offline, blocked CDN, or unconfigured — server skips captcha too */ }
}
// PWA shell: cache the console chrome, never API data (see sw.js).
function registerSW(){
  try{
    if('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
      navigator.serviceWorker.register('/sw.js').catch(()=>{});
    }
  }catch{}
}

/* ================= BOOT ================= */
buildViews();
$$('[data-caseno]').forEach(el=>el.textContent=S.caseNo);
injectAuth();
loadMeSnapshot(); paintAccount(); // instant: last-known identity before network confirms
renderNav();
mountCards();
renderApiDocs();
renderHist();
bindPal();
loadCatalog();
refreshMe();
initTurnstile();
registerSW();
show('dash');

$('#burger').onclick = ()=>{ $('#side').classList.toggle('open'); const sb = document.getElementById('sideback'); if(sb) sb.classList.toggle('open'); };
$('#sideback').onclick = ()=>{ $('#side').classList.remove('open'); document.getElementById('sideback').classList.remove('open'); };
$$('#tabbar button').forEach(b=>b.onclick=()=>{
  if(b.dataset.v==='__menu'){ $('#side').classList.add('open'); document.getElementById('sideback')?.classList.add('open'); }
  else show(b.dataset.v);
});
$('#sgo').onclick = ()=>runSearch();
$('#sin').addEventListener('keydown',e=>{ if(e.key==='Enter') runSearch(); });
$$('#stabs .fbtn').forEach(b=>b.onclick=()=>setTab(b.dataset.tab));
$('#mgrid').onclick = ()=>{ modView='grid'; syncModViewBtns(); renderMods(); };
$('#mlist').onclick = ()=>{ modView='list'; syncModViewBtns(); renderMods(); };
$('#mpins').onclick = ()=>{ modPinsOnly=!modPinsOnly; $('#mpins').classList.toggle('on',modPinsOnly); renderMods(); };
$('#mexp').onclick = exportSweepToGraph;
$('#expgo').onclick = runExposure;
$('#exp-email').addEventListener('keydown',e=>{ if(e.key==='Enter') runExposure(); });
$('#sweepBtn').onclick = runSweep;
$('#modq').addEventListener('input',e=>{ modQ = e.target.value.toLowerCase().trim(); renderMods(); });
$('#moduser').addEventListener('keydown',e=>{ if(e.key==='Enter') runSweep(); });
$('#ent-add').onclick = ()=>{ const t=$('#ent-type').value.trim()||'note', v=$('#ent-val').value.trim(); if(v){ addEntity(t,v,'manual'); $('#ent-val').value=''; } };
$('#ent-clear').onclick = ()=>{ S.entities=[]; saveEnts(); renderGraph(); };
$('#ent-link').onclick = ()=>{ S.autolink=!S.autolink; $('#ent-link').textContent='Auto-link: '+(S.autolink?'on':'off'); $('#ent-link').classList.toggle('on',S.autolink); renderGraph(); };
$('#ent-exp').onclick = ()=>dl(`case-${S.caseNo}.json`, JSON.stringify({case:S.caseNo, exported:new Date().toISOString(), entities:S.entities},null,2));
$('#rep-build').onclick = buildReport;
$('#rep-dl').onclick = ()=>{
  if(!window._lastReport) return toast('Build the report first');
  const slug = (window._lastReport.title || 'case').toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,60) || 'case';
  dl(`${slug}.html`, window._lastReport.html, 'text/html');
};
$('#rep-md').onclick = ()=>{ if(!window._lastReport) return toast('Build the report first'); copyT(window._lastReport.md); };
// ---- case report builder (ticked entities → standalone HTML + Markdown) ----
function selectedEntities(){
  const boxes = $$('#entlist [data-rep]');
  if(!boxes.length) return S.entities.slice(0,40);
  const idx = new Set(boxes.filter(b=>b.checked).map(b=>+b.dataset.rep));
  return S.entities.filter((_,i)=>idx.has(i)).slice(0,40);
}
function buildReport(){
  const list = selectedEntities();
  const title = ($('#rep-title').value.trim() || 'Case ' + S.caseNo);
  const notes = $('#rep-notes').value.trim();
  if(!list.length){ toast('Add entities first (or tick some below)'); return; }
  const cell = s=>String(s ?? '').replace(/\|/g,'\\|');
  const rows = list.map(e=>`<tr><td>${esc(e.type)}</td><td>${esc(e.value)}</td><td>${esc(e.source||'')}</td></tr>`).join('');
  const md = `# ${title}\n\n_Case ${S.caseNo} · ${new Date().toISOString().slice(0,10)} · Evosint_\n\n${notes?notes+'\n\n':''}## Entities (${list.length})\n\n| Type | Value | Source |\n|---|---|---|\n` + list.map(e=>`| ${cell(e.type)} | ${cell(e.value)} | ${cell(e.source||'')} |`).join('\n') + '\n';
  window._lastReport = { title, md,
    html: `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:820px;margin:32px auto;padding:0 16px;color:#111}table{border-collapse:collapse;width:100%}td,th{border:1px solid #999;padding:6px 9px;text-align:left;font-size:13px}.meta{color:#555;font-size:12px}pre{white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:8px}</style></head><body><h1>${esc(title)}</h1><p class="meta">Case ${esc(S.caseNo)} · ${esc(new Date().toLocaleString())} · generated by Evosint (fictional training tool)</p>${notes?`<pre>${esc(notes)}</pre>`:''}<h2>Entities (${list.length})</h2><table><tr><th>Type</th><th>Value</th><th>Source</th></tr>${rows}</table></body></html>` };
  $('#rep-out').innerHTML = `<div class="plat f"><h4>${esc(title)} ${badge(list.length+' entities','b')}</h4><div style="font-size:12px;color:var(--muted)">Preview ready — download the standalone HTML file or copy Markdown.</div></div>`;
  $('#rep-dl').disabled = false; $('#rep-md').disabled = false;
  toast('Report built');
}
document.addEventListener('click', e=>{
  const b = e.target.closest('[data-act]'); if(!b) return;
  if(b.dataset.act==='verify-all') verifyAllPatterns(b);
  else if(b.dataset.act==='auth-tab') authTab(b.dataset.tab || 'login');
  else if(b.dataset.act==='goto-search'){ const t = document.querySelector('[data-v=search]'); if(t) t.click(); }
  else if(b.dataset.act==='use-variant'){ show('modules'); $('#moduser').value = b.dataset.v || ''; $('#moduser').focus(); toast('Loaded — press Sweep'); }
  else if(b.dataset.act==='copy-variants'){ copyT(b.dataset.v || ''); }
});
async function verifyAllPatterns(btn){
  const list = window._lastPats || [];
  const box = btn.closest('.rbody').querySelector('[data-patout]');
  if(!list.length){ toast('Generate patterns first'); return; }
  btn.disabled = true;
  const rows = []; let done = 0;
  const worker = async q=>{
    while(q.length){
      const em = q.shift();
      try{ const d = await apiGet(`/verify/email/${encodeURIComponent(em)}`, 25000); rows.push({em, ok:true, d:d.data}); }
      catch(err){ rows.push({em, ok:false, err:err.message}); }
      done++;
      if(document.body.contains(box)) box.innerHTML = `<div class="load"><div class="spin"></div>Verifying ${done}/${list.length}…</div>`;
    }
  };
  const qq = [...list];
  await Promise.all(Array.from({length: Math.min(5, qq.length)}, ()=>worker(qq)));
  rows.sort((a,b)=>list.indexOf(a.em)-list.indexOf(b.em));
  const cand = rows.filter(r=>r.ok && r.d && r.d.mx_found && !r.d.disposable);
  box.innerHTML = `<p style="margin:8px 0">${badge(cand.length+' deliverable candidates','g')}</p>` + tbl(['Email','Deliverability','MX','Role?'], rows.map(r=>r.ok?[
    `<span class="mono" style="border:none;background:none;padding:0">${esc(r.em)}</span>`,
    r.d.deliverability==='likely'?badge('likely','g'):r.d.deliverability==='unlikely'?badge('unlikely','r'):badge('uncertain','a'),
    r.d.mx_found?badge('yes','g'):badge('no','r'),
    r.d.role_account?badge('role','a'):badge('—','gr')
  ]:[`<span class="mono" style="border:none;background:none;padding:0">${esc(r.em)}</span>`,badge('ERR','r'),'—','—']));
  btn.disabled = false;
  pushHist('Pattern verify-all', list.length+' candidates', 'lab', cand.length>0);
}
$('#histBtn').onclick = ()=>$('#drawer').classList.add('open');
$('#xDrawer').onclick = ()=>$('#drawer').classList.remove('open');
$('#clrHist').onclick = ()=>{ S.history=[]; saveHist(); renderHist(); };
$('#expJson').onclick = ()=>dl(`history-${Date.now()}.json`, JSON.stringify(S.history,null,2));
$('#expCsv').onclick = ()=>dl(`history-${Date.now()}.csv`, 'tool,input,view,time\n'+S.history.map(h=>`"${h.tool}","${h.input.replace(/"/g,'""')}","${h.view}","${h.t}"`).join('\n'), 'text/csv');
$('#printBtn').onclick = ()=>window.print();
$('#qgo').onclick = ()=>{ const v=$('#q').value.trim(); if(v){ show('search'); runBattery(v); } };
$('#q').addEventListener('keydown',e=>{ if(e.key==='Enter') $('#qgo').click(); });

fetch('/api/health').then(r=>r.json()).then(h=>{ $('#hdot').className='dot ok'; $('#htxt').textContent='online · v'+(h.version||'?'); })
  .catch(()=>{ $('#hdot').className='dot bad'; $('#htxt').textContent='offline'; });
