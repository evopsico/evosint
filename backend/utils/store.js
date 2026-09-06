const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

// Pluggable persistence.
//   STORE=file      (default) local JSON files under backend/data — dev/self-host.
//   STORE=vercel-kv Vercel KV (Redis) — required on Vercel, where the filesystem
//                         is ephemeral and local writes silently vanish.
// The API is promise-based so both backends share one shape; all callers await.

// users: { [id]: {id, username, pass:{salt,hash}, tier, left, dob, created} }
// keys:  [ {id, userId, label, hash, prefix, created, last_used} ]
// guests:{ [ip]: {left, seen} }
const BACKEND = String(process.env.STORE || 'file').toLowerCase();
const DIR = path.join(__dirname, '..', 'data');

function ensureDataDir() {
  if (BACKEND !== 'file') return;
  if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
}
function dataFile(name) {
  ensureDataDir();
  return path.join(DIR, name);
}

// ---------- file backend ----------
async function fLoad(name, fallback) {
  try {
    const p = dataFile(name);
    if (!fs.existsSync(p)) return fallback;
    return JSON.parse(await fsp.readFile(p, 'utf8'));
  } catch {
    return fallback;
  }
}
async function fSave(name, obj) {
  ensureDataDir();
  const p = dataFile(name);
  const tmp = p + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 2));
  await fsp.rename(tmp, p);
}

// ---------- vercel-kv backend ----------
let kvClient = null;
function kv() {
  if (kvClient) return kvClient;
  let mod;
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    mod = require('@vercel/kv');
  } catch {
    throw new Error('STORE=vercel-kv needs the @vercel/kv package (npm i @vercel/kv)');
  }
  if (!process.env.KV_REST_API_URL) {
    throw new Error('STORE=vercel-kv is set but no KV database is connected (KV_REST_API_URL missing). In the Vercel dashboard: Storage → Create Database → KV, then redeploy. Locally, unset STORE to use files.');
  }
  kvClient = mod.kv;
  return kvClient;
}
const K = { users: 'evosint:users', keys: 'evosint:keys', guests: 'evosint:guests', secret: 'evosint:secret' };
async function kLoad(key, fallback) {
  try {
    const v = await kv().get(key);
    return v === null || v === undefined ? fallback : v;
  } catch (e) {
    if (/KV_REST_API_URL|needs/.test(e.message)) throw e;
    return fallback;
  }
}
async function kSave(key, obj) {
  await kv().set(key, obj);
}

function backendName() {
  if (BACKEND !== 'file' && BACKEND !== 'vercel-kv') {
    throw new Error(`Unknown STORE="${process.env.STORE}" (use "file" or "vercel-kv")`);
  }
  return BACKEND;
}

async function loadUsers() { return backendName() === 'vercel-kv' ? kLoad(K.users, {}) : fLoad('users.json', {}); }
async function saveUsers(u) { return backendName() === 'vercel-kv' ? kSave(K.users, u) : fSave('users.json', u); }
async function loadKeys() { return backendName() === 'vercel-kv' ? kLoad(K.keys, []) : fLoad('keys.json', []); }
async function saveKeys(k) { return backendName() === 'vercel-kv' ? kSave(K.keys, k) : fSave('keys.json', k); }
async function loadGuests() { return backendName() === 'vercel-kv' ? kLoad(K.guests, {}) : fLoad('guests.json', {}); }
async function saveGuests(g) { return backendName() === 'vercel-kv' ? kSave(K.guests, g) : fSave('guests.json', g); }

let secretWarned = false;
async function getSecret() {
  if (backendName() === 'vercel-kv') {
    let s = await kLoad(K.secret, null);
    if (typeof s !== 'string') {
      s = require('crypto').randomBytes(32).toString('hex');
      try {
        if (typeof kv().setnx === 'function' && !(await kv().setnx(K.secret, s))) s = await kLoad(K.secret, s);
        else await kSave(K.secret, s);
      } catch { await kSave(K.secret, s); }
    }
    return s;
  }
  let s = await fLoad('.secret', null);
  if (!s || typeof s.v !== 'string') {
    s = { v: require('crypto').randomBytes(32).toString('hex') };
    await fSave('.secret', s);
    if (!secretWarned) {
      secretWarned = true;
      console.warn('(!) SESSION_SECRET not set — generated + persisted to backend/data/.secret. Set an explicit value in production.');
    }
  }
  return s.v;
}

module.exports = { DIR, ensureDataDir, dataFile, loadUsers, saveUsers, loadKeys, saveKeys, loadGuests, saveGuests, getSecret, backendName };
