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

// ---------- vercel-kv backend (Vercel KV legacy *or* Upstash Redis) ----------
// Vercel deprecated @vercel/kv: old projects expose KV_REST_API_URL, new ones
// get Upstash Redis (UPSTASH_REDIS_REST_URL) from the Marketplace. Both speak
// the same get/set/setnx, so we accept either pair of env vars.
let kvClient = null;
function kv() {
  if (kvClient) return kvClient;
  if (process.env.KV_REST_API_URL) {
    let mod;
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      mod = require('@vercel/kv');
    } catch {
      throw new Error('KV_REST_API_URL is set but @vercel/kv is not installed (npm i @vercel/kv)');
    }
    kvClient = mod.kv;
    return kvClient;
  }
  if (process.env.UPSTASH_REDIS_REST_URL) {
    let mod;
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      mod = require('@upstash/redis');
    } catch {
      throw new Error('UPSTASH_REDIS_REST_URL is set but @upstash/redis is not installed (npm i @upstash/redis)');
    }
    kvClient = new mod.Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN });
    return kvClient;
  }
  throw new Error('STORE=vercel-kv is set but no Redis/KV database is connected (neither KV_REST_API_URL nor UPSTASH_REDIS_REST_URL found). In Vercel: Storage/Marketplace → add Upstash Redis → connect it to this project → redeploy. Locally, unset STORE to use files.');
}
const K = { users: 'evosint:users', keys: 'evosint:keys', guests: 'evosint:guests', secret: 'evosint:secret' };
async function kLoad(key, fallback) {
  // Fail CLOSED: a Redis outage must 500 loudly, never silently reset
  // quotas or log everyone out by degrading to empty stores.
  const v = await kv().get(key);
  return v === null || v === undefined ? fallback : v;
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
