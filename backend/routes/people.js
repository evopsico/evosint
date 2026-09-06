const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidUsername, ok, fail } = require('../utils/validate');

// People / gaming / dev identity hub — all keyless.

// GET /api/people/stackexchange/:username — Stack Exchange network profile search
// (display names may contain spaces, so validation is looser here than username hunt)
router.get('/stackexchange/:username', async (req, res) => {
  const u = String(req.params.username || '').trim();
  if (!u || u.length > 60 || /[<>"'\\]/.test(u)) return fail(res, 400, 'Display name required (max 60 chars)');
  try {
    const { data, cached } = await getOrSet(`se:${u.toLowerCase()}`, 3600, async () => {
      const r = await http.get(`https://api.stackexchange.com/2.3/users?inname=${encodeURIComponent(u)}&site=stackoverflow&pagesize=5&order=desc&sort=reputation`, { timeout: 12000 });
      if (r.status !== 200) throw Object.assign(new Error('StackExchange error'), { status: 502 });
      return (r.data?.items || []).map((x) => ({ name: x.display_name, reputation: x.reputation, badges: x.badge_counts, location: x.location, link: x.link, creation: x.creation_date }));
    });
    return ok(res, data, { cached, source: 'stackexchange', count: data.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Lookup failed'); }
});

// GET /api/people/roblox/:username — Roblox user lookup (official, keyless)
router.get('/roblox/:username', async (req, res) => {
  const u = String(req.params.username || '').trim();
  if (!isValidUsername(u)) return fail(res, 400, 'Invalid username');
  try {
    const { data, cached } = await getOrSet(`rbx:${u.toLowerCase()}`, 3600, async () => {
      const r = await http.post('https://users.roblox.com/v1/usernames/users', { usernames: [u], excludeBannedUsers: true }, { timeout: 12000 });
      const hit = r.data?.data?.[0];
      if (!hit) return { found: false, note: 'No Roblox user with that name' };
      const info = await http.get(`https://users.roblox.com/v1/users/${hit.id}`, { timeout: 10000 });
      return { found: true, id: hit.id, name: hit.name, display_name: hit.displayName, profile: `https://www.roblox.com/users/${hit.id}/profile`, created: info.data?.created || null, description: (info.data?.description || '').slice(0, 500), banned: info.data?.isBanned || false };
    });
    return ok(res, data, { cached, source: 'roblox' });
  } catch (e) { return fail(res, 502, 'Roblox lookup failed'); }
});

// GET /api/people/chess/:username — chess.com public profile (keyless)
router.get('/chess/:username', async (req, res) => {
  const u = String(req.params.username || '').trim().toLowerCase();
  if (!isValidUsername(u)) return fail(res, 400, 'Invalid username');
  try {
    const { data, cached } = await getOrSet(`chess:${u}`, 3600, async () => {
      const r = await http.get(`https://api.chess.com/pub/player/${encodeURIComponent(u)}`, { timeout: 10000 });
      if (r.status === 404) return { found: false, note: 'No chess.com player with that name' };
      if (r.status !== 200) throw Object.assign(new Error('chess.com error'), { status: 502 });
      const stats = await http.get(`https://api.chess.com/pub/player/${encodeURIComponent(u)}/stats`, { timeout: 10000 });
      const s = stats.data || {};
      return { found: true, username: r.data?.username, name: r.data?.name || null, followers: r.data?.followers ?? null, country: r.data?.country?.split('/').pop() || null, joined: r.data?.joined ? new Date(r.data.joined * 1000).toISOString().slice(0, 10) : null, blitz: s.chess_blitz?.last?.rating ?? null, bullet: s.chess_bullet?.last?.rating ?? null, rapid: s.chess_rapid?.last?.rating ?? null, profile: r.data?.url };
    });
    return ok(res, data, { cached, source: 'chess.com' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Lookup failed'); }
});

// GET /api/people/lichess/:username — lichess public profile (keyless)
router.get('/lichess/:username', async (req, res) => {
  const u = String(req.params.username || '').trim();
  if (!isValidUsername(u)) return fail(res, 400, 'Invalid username');
  try {
    const { data, cached } = await getOrSet(`lichess:${u.toLowerCase()}`, 3600, async () => {
      const r = await http.get(`https://lichess.org/api/user/${encodeURIComponent(u)}`, { timeout: 10000 });
      if (r.status === 404) return { found: false, note: 'No lichess user with that name' };
      if (r.status !== 200) throw Object.assign(new Error('lichess error'), { status: 502 });
      const d = r.data || {};
      return { found: true, username: d.username, perfs: Object.fromEntries(Object.entries(d.perfs || {}).slice(0, 8).map(([k, v]) => [k, v.rating])), games: d.count?.all ?? null, created: d.createdAt ? new Date(d.createdAt).toISOString().slice(0, 10) : null, profile: d.url || `https://lichess.org/@/${u}` };
    });
    return ok(res, data, { cached, source: 'lichess' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Lookup failed'); }
});

// GET /api/people/discord-invite/:code — Discord invite metadata (official, keyless)
router.get('/discord-invite/:code', async (req, res) => {
  const code = String(req.params.code || '').trim();
  if (!/^[\w-]{2,32}$/.test(code)) return fail(res, 400, 'Invite code required (the part after discord.gg/)');
  try {
    const { data, cached } = await getOrSet(`dinv:${code}`, 3600, async () => {
      const r = await http.get(`https://discord.com/api/v9/invites/${encodeURIComponent(code)}?with_counts=true&with_expiration=true`, { timeout: 10000 });
      if (r.status === 404) return { valid: false, note: 'Invite invalid or expired' };
      if (r.status !== 200) throw Object.assign(new Error('Discord API error'), { status: 502 });
      const d = r.data || {};
      return { valid: true, code, guild: d.guild ? { id: d.guild.id, name: d.guild.name, icon: d.guild.icon ? `https://cdn.discordapp.com/icons/${d.guild.id}/${d.guild.icon}.png` : null, verification: d.guild.verification_level, vanity: d.guild.vanity_url_code || null } : null, channel: d.channel ? { name: d.channel.name, type: d.channel.type } : null, members: d.approximate_member_count ?? null, online: d.approximate_presence_count ?? null, expires: d.expires_at || null };
    });
    return ok(res, data, { cached, source: 'discord' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Invite lookup failed'); }
});

// GET /api/people/wikipedia/:username — account existence + edit count (MediaWiki, keyless)
router.get('/wikipedia/:username', async (req, res) => {
  const u = String(req.params.username || '').trim();
  if (!u || u.length > 100) return fail(res, 400, 'Username required');
  try {
    const { data, cached } = await getOrSet(`wiki:${u.toLowerCase()}`, 86400, async () => {
      const r = await http.get(`https://en.wikipedia.org/w/api.php?action=query&list=users&ususers=${encodeURIComponent(u)}&usprop=editcount|registration|groups&format=json&origin=*`, { timeout: 10000 });
      const info = r.data?.query?.users?.[0];
      if (!info || info.missing || info.invalid) return { found: false, note: 'No Wikipedia account with that name' };
      return { found: true, name: info.name, userid: info.userid, editcount: info.editcount ?? null, registered: info.registration || null, groups: info.groups || [], contribs: `https://en.wikipedia.org/wiki/Special:Contributions/${encodeURIComponent(u)}` };
    });
    return ok(res, data, { cached, source: 'mediawiki' });
  } catch (e) { return fail(res, 502, 'Wikipedia lookup failed'); }
});

// GET /api/people/orcid/:id — researcher profile (0000-0002-1825-0097 style, keyless)
router.get('/orcid/:id', async (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!/^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/.test(id)) return fail(res, 400, 'ORCID format: 0000-0002-1825-0097');
  try {
    const { data, cached } = await getOrSet(`orcid:${id}`, 86400 * 7, async () => {
      const r = await http.get(`https://pub.orcid.org/v3.0/${id}/personal-details`, { headers: { Accept: 'application/json' }, timeout: 10000 });
      if (r.status === 404) return { found: false, note: 'ORCID not found' };
      if (r.status !== 200) throw Object.assign(new Error('ORCID error'), { status: 502 });
      const n = r.data?.name || {};
      return { found: true, orcid: id, given: n['given-names']?.value || null, family: n['family-name']?.value || null, profile: `https://orcid.org/${id}` };
    });
    return ok(res, data, { cached, source: 'orcid' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'ORCID lookup failed'); }
});

// GET /api/people/gravatar?email= — avatar + profile existence by email hash (keyless)
router.get('/gravatar', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Query ?email= required');
  const crypto = require('crypto');
  const hash = crypto.createHash('md5').update(email).digest('hex');
  try {
    const r = await http.get(`https://en.gravatar.com/${hash}.json`, { timeout: 10000 });
    if (r.status === 404) return ok(res, { has_profile: false, hash, avatar: `https://www.gravatar.com/avatar/${hash}?d=404`, note: 'No public Gravatar profile' }, { source: 'gravatar' });
    const p = r.data?.entry?.[0] || {};
    return ok(res, { has_profile: true, hash, username: p.preferredUsername || null, name: p.displayName || null, profile: p.profileUrl || null, avatar: `https://www.gravatar.com/avatar/${hash}?s=200` }, { source: 'gravatar' });
  } catch (e) { return fail(res, 502, 'Gravatar lookup failed'); }
});

module.exports = router;
