const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidGitHubUsername, ok, fail, axiosError } = require('../utils/validate');

/** GET /api/github/:username — profile + top repos, token-aware. */
router.get('/:username', async (req, res) => {
  const username = String(req.params.username || '').trim();
  if (!isValidGitHubUsername(username)) return fail(res, 400, 'Invalid GitHub username');

  try {
    const { data, cached } = await getOrSet(`github:${username.toLowerCase()}`, 900, async () => {
      const headers = { 'User-Agent': 'Evosint/2.0', Accept: 'application/vnd.github+json' };
      if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
      const [profile, repos] = await Promise.all([
        http.get(`https://api.github.com/users/${encodeURIComponent(username)}`, { headers, timeout: 9000 }),
        http.get(`https://api.github.com/users/${encodeURIComponent(username)}/repos?per_page=5&sort=updated`, { headers, timeout: 9000 }),
      ]);
      if (profile.status === 404) throw Object.assign(new Error('GitHub user not found'), { status: 404 });
      if (profile.status === 403 && String(profile.headers?.['x-ratelimit-remaining']) === '0') {
        throw Object.assign(new Error('GitHub rate limit reached — set GITHUB_TOKEN or wait'), { status: 502 });
      }
      if (profile.status !== 200) throw Object.assign(new Error(`GitHub API returned ${profile.status}`), { status: 502 });
      return {
        profile: profile.data,
        top_repos: Array.isArray(repos.data) ? repos.data.map((r) => ({
          name: r.name, description: r.description, language: r.language,
          stars: r.stargazers_count, forks: r.forks_count, updated_at: r.updated_at, url: r.html_url,
        })) : [],
        rate_limit_remaining: profile.headers?.['x-ratelimit-remaining'] ?? null,
      };
    });
    return ok(res, data, { cached });
  } catch (error) {
    if (error.status) return fail(res, error.status, error.message);
    return axiosError(res, error, 'GitHub lookup failed');
  }
});

module.exports = router;
