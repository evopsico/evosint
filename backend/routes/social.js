const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidUsername, ok, fail } = require('../utils/validate');

/**
 * GET /api/social/:username — deep presence using only free, keyless public APIs.
 * v1 flaws fixed: queried Twitter/YouTube/Twitch/Medium APIs with EMPTY keys (always failed),
 * used dead Instagram ?__a=1 endpoint, and crashed on missing Keybase follower fields.
 */
router.get('/:username', async (req, res) => {
  const username = String(req.params.username || '').trim();
  if (!isValidUsername(username)) return fail(res, 400, 'Invalid username (1–39 chars: letters, numbers, . _ -)');

  try {
    const { data, cached } = await getOrSet(`social:${username.toLowerCase()}`, 1800, async () => {
      const GH = { 'User-Agent': 'Evosint/2.0', Accept: 'application/json' };
      if (process.env.GITHUB_TOKEN) GH.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

      const jobs = [
        (async () => {
          const url = `https://api.github.com/users/${encodeURIComponent(username)}`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            if (r.status === 200 && r.data?.login) {
              return { name: 'GitHub', found: true, status_code: 200, url: r.data.html_url || url, data: {
                login: r.data.login, name: r.data.name, bio: r.data.bio, public_repos: r.data.public_repos,
                followers: r.data.followers, following: r.data.following, company: r.data.company,
                location: r.data.location, email: r.data.email, blog: r.data.blog, created_at: r.data.created_at,
              } };
            }
            return { name: 'GitHub', found: false, status_code: r.status, url };
          } catch (e) { return { name: 'GitHub', found: false, status_code: e.response?.status ?? null, url, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`;
          try {
            const r = await http.get(url, { headers: { 'User-Agent': 'Evosint/2.0' }, timeout: 8000 });
            if (r.status === 200 && r.data?.data?.name) {
              const u = r.data.data;
              return { name: 'Reddit', found: true, status_code: 200, url: `https://www.reddit.com/user/${encodeURIComponent(username)}/`, data: {
                name: u.name, comment_karma: u.comment_karma ?? 0, link_karma: u.link_karma ?? 0,
                is_employee: !!u.is_employee, verified: !!u.verified, created_utc: u.created_utc ?? null,
              } };
            }
            return { name: 'Reddit', found: false, status_code: r.status, url };
          } catch (e) { return { name: 'Reddit', found: false, status_code: e.response?.status ?? null, url, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://dev.to/api/articles?username=${encodeURIComponent(username)}&per_page=5`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            if (r.status === 200 && Array.isArray(r.data)) {
              return { name: 'Dev.to', found: r.data.length > 0, status_code: 200, url: `https://dev.to/${encodeURIComponent(username)}`, data: {
                username, article_count: r.data.length,
                articles: r.data.slice(0, 5).map((a) => ({ title: a.title, published_at: a.published_at, url: a.url })),
              } };
            }
            return { name: 'Dev.to', found: false, status_code: r.status, url };
          } catch (e) { return { name: 'Dev.to', found: false, status_code: e.response?.status ?? null, url, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(username)}&fields=basics,pictures`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            const them = r.data?.them?.[0];
            if (r.status === 200 && them) {
              return { name: 'Keybase', found: true, status_code: 200, url: `https://keybase.io/${encodeURIComponent(username)}`, data: {
                username: them.username ?? username,
                full_name: them.basics?.name ?? them.name ?? '',
                bio: them.basics?.bio ?? them.bio ?? '',
                profile_pic_url: them.pictures?.primary?.url ?? them.pictures?.primary ?? null,
              } };
            }
            return { name: 'Keybase', found: false, status_code: r.status, url };
          } catch (e) { return { name: 'Keybase', found: false, status_code: e.response?.status ?? null, url, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            if (r.status === 200 && Array.isArray(r.data) && r.data.length > 0) {
              const u = r.data[0];
              return { name: 'GitLab', found: true, status_code: 200, url: u.web_url || `https://gitlab.com/${encodeURIComponent(username)}`, data: {
                username: u.username, name: u.name, state: u.state, avatar_url: u.avatar_url, web_url: u.web_url,
              } };
            }
            return { name: 'GitLab', found: false, status_code: r.status, url: `https://gitlab.com/${encodeURIComponent(username)}` };
          } catch (e) { return { name: 'GitLab', found: false, status_code: e.response?.status ?? null, url: `https://gitlab.com/${encodeURIComponent(username)}`, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(username)}.json`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            if (r.status === 200 && r.data?.id) {
              return { name: 'HackerNews', found: true, status_code: 200, url: `https://news.ycombinator.com/user?id=${encodeURIComponent(username)}`, data: {
                id: r.data.id, karma: r.data.karma ?? 0, about: (r.data.about || '').slice(0, 500), created: r.data.created ?? null,
              } };
            }
            return { name: 'HackerNews', found: false, status_code: r.status, url: `https://news.ycombinator.com/user?id=${encodeURIComponent(username)}` };
          } catch (e) { return { name: 'HackerNews', found: false, status_code: e.response?.status ?? null, url: `https://news.ycombinator.com/user?id=${encodeURIComponent(username)}`, error: String(e.message).slice(0, 200) }; }
        })(),
        (async () => {
          const url = `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(username)}`;
          try {
            const r = await http.get(url, { headers: GH, timeout: 8000 });
            if (r.status === 200 && r.data?.handle) {
              return { name: 'Bluesky', found: true, status_code: 200, url: `https://bsky.app/profile/${r.data.handle}`, data: {
                handle: r.data.handle, name: r.data.displayName || null, followers: r.data.followersCount ?? null,
                following: r.data.followsCount ?? null, posts: r.data.postsCount ?? null, bio: (r.data.description || '').slice(0, 300),
              } };
            }
            return { name: 'Bluesky', found: false, status_code: r.status, url: `https://bsky.app/profile/${encodeURIComponent(username)}` };
          } catch (e) { return { name: 'Bluesky', found: false, status_code: e.response?.status ?? null, url: `https://bsky.app/profile/${encodeURIComponent(username)}`, error: String(e.message).slice(0, 200) }; }
        })(),
      ];

      const results = await Promise.all(jobs);
      const found = results.filter((r) => r.found).length;
      return { results, summary: { total_platforms: results.length, found_count: found, not_found_count: results.length - found } };
    });
    return ok(res, data.results, { summary: data.summary, cached });
  } catch (e) {
    return fail(res, 500, e.message || 'Social lookup failed');
  }
});

module.exports = router;
