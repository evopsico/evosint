const fs = require('fs');
const path = require('path');

// Tiny JSON file store (local tool — no DB server needed).
const DIR = path.join(__dirname, '..', 'data');

function ensureDataDir() {
  if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
}

function dataFile(name) {
  ensureDataDir();
  return path.join(DIR, name);
}

function loadJSON(name, fallback) {
  try {
    const p = dataFile(name);
    if (!fs.existsSync(p)) return fallback;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return fallback;
  }
}

function saveJSON(name, obj) {
  ensureDataDir();
  const p = dataFile(name);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, p);
}

// users.json: { [id]: {id, username, pass:{salt,hash}, tier, left, dob, created} }
// keys.json:  [ {id, userId, label, hash, prefix, created, last_used} ]
// guests.json:{ [ip]: {left, seen} }
function loadUsers() { return loadJSON('users.json', {}); }
function saveUsers(u) { saveJSON('users.json', u); }
function loadKeys() { return loadJSON('keys.json', []); }
function saveKeys(k) { saveJSON('keys.json', k); }
function loadGuests() { return loadJSON('guests.json', {}); }
function saveGuests(g) { saveJSON('guests.json', g); }

function getSecret() {
  let s = loadJSON('.secret', null);
  if (!s || typeof s.v !== 'string') {
    s = { v: require('crypto').randomBytes(32).toString('hex') };
    saveJSON('.secret', s);
    console.warn('(!) SESSION_SECRET not set — generated + persisted to backend/data/.secret. Set an explicit value in production.');
  }
  return s.v;
}

module.exports = { DIR, ensureDataDir, dataFile, loadJSON, saveJSON, loadUsers, saveUsers, loadKeys, saveKeys, loadGuests, saveGuests, getSecret };
