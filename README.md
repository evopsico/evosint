# Evosint v2.12 — "Ghost" Monochrome Console (fictional agency theme)

A pure black-and-white case-file interface — no gradients, no purple, no gold — **an obvious parody/training build, not affiliated with the CIA, FBI, or
any government agency**. Under the theme: **~100 API endpoints + 177-engine sweep
+ live WhatsMyName-700 dataset**, tabbed New Search, Breacher with Exposure Index,
Ctrl+K Main Menu, link-chart investigations, threat feeds, OathNet, geo, crypto,
forensics and a full Field Recon suite — keyless by default, unlimited (local mode, no credits).

## Quick start

```bash
cd "ai section"
npm install
npm start
# open http://localhost:3001
```

Double-click `launch-evosint.bat` for start-if-needed + browser launch.
Health: `http://localhost:3001/health` (mirrored at `/api/health`).
Smoke tests: `node smoke-test.js` (signs up a throwaway user, runs the suite).
UI tests: `node test-ui.js` (boots the real server headlessly, renders every view,
runs a full signup→logout flow — must print ALL UI TESTS GREEN).
Sharing: see `SHARE.txt` — same-WiFi IP, free Cloudflare Tunnel link, or VPS.
Set `TRUST_PROXY=1` behind any proxy/tunnel and `DISABLE_STRESS=1` on public instances.

## Deploy to Vercel (public link, free tier)

The repo ships Vercel-ready: static console + the Express API as one serverless
catch-all function (`api/[...all].js`, 60s `maxDuration`, no rewrites needed).

1. Push this folder to GitHub (see below), then on vercel.com: **Add New →
   Project → Import** the repo. Framework preset: **Other**. No build command,
   output directory: repo root (default static). Deploy.
2.  **Storage (required, 2 clicks):** serverless functions have no disk, so
   accounts/quotas need Redis — dashboard: add **Upstash Redis** from the
   Vercel Marketplace (the old Vercel KV is deprecated; either works) and
   connect it to the project, redeploy. Then set env var `STORE=vercel-kv`.
   Without this, auth endpoints fail fast with setup instructions instead of
   silently losing data. Local dev keeps using `backend/data/` files (`STORE=file`).
3. Copy the env keys you use (`HIBP_API_KEY`, `GITHUB_TOKEN`, …) plus a long
   random `SESSION_SECRET` into the project's Environment Variables. Never
   commit `.env` (already git-ignored, like `backend/data/` and `.vercel/`).
4. First cold start seeds the owner login (override with `EVO_ADMIN_USER` /
   `EVO_ADMIN_PASS` env before deploying, then change the password in-app).
5. Honest limits on serverless: quick lookups fly, but multi-minute sweeps
   (username/WMN sweeps, DNS brute-force, takeovers) can hit the function
   timeout — run those against your local instance, or raise `maxDuration`
   (needs a Pro plan past the free allowance).
Caching: the server sends `Cache-Control: no-store` on everything and stamps asset
URLs with the package version, so edits appear on plain reload — no hard refresh needed.

## Accounts & scan quota

| Tier | Scans | How |
|------|-------|-----|
| Guest | 2 lifetime | just open the console (tracked per IP) |
| User | 50 lifetime | sign up free: username + password + repeat + date of birth (13+) |
| Super | infinite | seeded owner login + API keys |

- Owner login is seeded on first boot: username `evo`. Change its password immediately in the Account panel (top-right chip → Account → Change password). Override the seed via `EVO_ADMIN_USER` / `EVO_ADMIN_PASS` env before first boot.
- Passwords are scrypt-hashed; sessions are HMAC-signed 30-day tokens; API keys are `evk_…` (SHA-256 stored, full key shown once, infinite scans, super-only minting, revocable). Super accounts can enable **TOTP two-factor** (authenticator app + 8 one-time backup codes) from the Account panel; if the database ever ends up with no super user, the next signup automatically claims super (logged server-side).
- **Bot wall (optional):** set `TURNSTILE_SITE_KEY` + `TURNSTILE_SECRET` (free at cloudflare.com) to require a captcha on signup/login; when unset, everything works without it.
- **Backup & restore (super):** Account panel → Export downloads the full accounts/keys/quotas snapshot (password hashes included — guard the file); Import replaces everything after confirmation.
- Every scan response carries `X-Searches-Left` / `X-Tier`; exhausted quotas return HTTP 402 and the UI opens the login modal. Auth data lives in `backend/data/` (git-ignored).
- Dashboard greets you by your chosen username once logged in.
- Sessions persist: "Remember me" (default) survives browser restarts; unticked
  logins last for the tab session only. The dashboard paints your last-known
  identity instantly, then confirms with the server (works offline).
- Fully responsive: bottom thumb-navigation bar (Home/Search/Modules/Graph/Menu)
  plus swipe-away drawer with backdrop on tablets and phones, roomy single-column
  cards, grids collapse, touch targets hit 44px+, inputs stay at 16px so iOS
  never auto-zooms, notch safe-areas respected. Installable as a PWA
  (phone: browser menu → Add to Home Screen) with an offline app shell —
  scan results always go live, never cached.

## Console views

| View | What |
|------|------|
| Dashboard | Welcome stats (Today / This week / Success rate / Workspace / Plan / Status), **Exposure Index** ring, shortcuts, recent scans |
| Search | DataVoid-style tabs (Email/Username/Phone/Domain/IP) + Query + Run search; Email tab runs the full Breacher |
| Modules | **177 site engines** with favicons, label filters, Grid/List views, ★ pins, sweep, Export to graph |
| Investigate | Case-numbered link chart (click-to-copy, auto-link toggle), manual + one-click entities, JSON export, **case report builder (standalone HTML + Markdown)** |
| Breaches | **Breacher** (HIBP + XposedOrNot + HudsonRock stealers + LeakCheck + ProxyNova combos + EmailRep → Exposure Index + unified timeline), email check, password exposure, verifier, hash reputation |
| People | Username sweep, social deep-check (incl. Bluesky), GitHub, StackExchange, Roblox, Chess.com, Lichess, Discord invites, Wikipedia, ORCID, Gravatar |
| Network | IP, WHOIS/RDAP, DNS×10, TLS, subdomains, headers, stack detect, URL expander, blacklist, portscan, ASN/prefix/IP (RIPEstat), PTR, Wayback, urlscan, page meta |
| Threat Intel | ThreatFox IOC, URLhaus, Feodo C2, CISA KEV, ransomware feed, Shodan InternetDB, CVE search, **GreyNoise verdict** |
| OathNet | OIDC discovery audit, JWKS hygiene, 16-path OAuth discovery, SAML metadata audit, secret scanner, JWT analyzer |
| Geo | Nominatim geocode/reverse, world postal codes, UK postcodes |
| Crypto | BTC/ETH/LTC/DOGE address intel, CoinGecko prices, mempool fees |
| Company | Wikidata + Wikipedia resolution, logo |
| Field Recon | Web crawler, DNS brute-force, 4-source subdomain aggregator, WMN-700 sweep, email chase, WordPress audit, takeover detector, archive goldmine, email-security grade, typosquat finder, favicon hash, Tor check, PGP lookup, GitHub code search, **GitHub org recon, npm/PyPI/crates package recon, crt.sh certificate search** |
| Lab | Hash gen/identify, encode/decode, passwords, time, URL, email-header forensics, IBAN, card Luhn, VIN, MAC, **email pattern generator + verify-all, username variants (social+corporate), dork builder (domain/phone/email/username packs), persona generator, image-intel launchers, **load stress tester (your sites only: ≤500 req, ≤10 concurrent, GET/HEAD, ownership checkbox)** |
| API Docs | Live in-app endpoint reference |

## Security model (production-grade pass, v2.8)

- **Secrets**: every key/token/password comes from env or the git-ignored `backend/data/` store — never hardcoded, never returned (API keys shown once at mint). Request logs redact `key`/`api_key`/`token`/`password` params (`[REDACTED]`). Passwords are scrypt hashes (8–200 chars); sessions are HMAC-signed 30-day tokens. Note on Vercel builds: the function bundle unavoidably contains a stale copy of `backend/data/` (Vercel's file tracer follows the file backend; `excludeFiles` has no effect on traced assets). It is unreachable over HTTP (no route serves it, static output excludes it — verified in CI-style bundle checks) and fully inert once `SESSION_SECRET` is set (env wins over the bundled `.secret`) with `STORE=vercel-kv` (file backend refuses to run on Vercel with a clear setup error).
- **Injection**: no SQL exists anywhere (JSON file store, no query language, no `eval`, no `child_process`, no dynamic `require`) — SQL injection is structurally impossible. Query parser is `simple` (no array/object coercion, no prototype games). Free-text fields are control-char stripped + length-capped.
- **XSS**: full Content-Security-Policy (`script-src 'self'`, no inline handlers — all delegated), every dynamic string escaped via `esc()`, links validated to http(s) + `noopener noreferrer`, images restricted to http(s), badge classes whitelisted.
- **Headers**: HSTS (1yr, auto-ignored on plain HTTP), `frame-ancestors 'self'` + `X-Frame-Options: SAMEORIGIN`, `nosniff`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, no `X-Powered-By`. (COEP stays off or cross-origin favicons/avatars break — documented in code.)
- **Rate limits**: global 300/15min, scans 90/15min, auth 40/15min, **login 10/15min**. Login errors are identical for bad user vs bad password, and unknown users still cost one full scrypt (no timing oracle).
- **Errors**: clients only ever see curated messages (`clientError` gate) + generic 500s; stacks stay server-side. Upstream failures surface as 502/504 without provider internals.

## Configuration (all optional — free fallbacks everywhere)

```
PORT=3001
CORS_ORIGIN=
HIBP_API_KEY=        # full breach data (else XposedOrNot)
ABSTRACT_API_KEY=    # phone carrier enrichment (else offline parse)
GITHUB_TOKEN=        # lift GitHub limits
VIRUSTOTAL_API_KEY=  # noted in hash verdicts
EMAILREP_KEY=        # EmailRep reputation (breach hub skips it when empty)

# Bot wall (optional — everything works without these)
TURNSTILE_SITE_KEY=  # public site key: enables captcha widgets on login/signup
TURNSTILE_SECRET=    # secret key: server verifies captchas (unset = no captcha)
```

## Architecture

```
├── index.html            # shell: sidebar, topbar, history drawer
├── public/
│   ├── styles.css        # dark ops-console theme (no CDN)
│   └── app.js            # view router, ~55 tool cards, batteries, graph, meter
├── backend/
│   ├── server.js         # helmet/cors/compression/morgan/rate-limit/registry
│   ├── routes/           # 24 files: ip domain dns email phone username github social
│   │                     #   ssl cve hash utils network threat archive geo blockchain
│   │                     #   people bgp verify forensics company oauth breacher recon
│   └── utils/            # validate.js cache.js http.js crypto.js platforms.js (177)
└── smoke-test.js
```

Notes: 300 req/15 min global, 90/15 min on sweep routes; expensive lookups cached;
256 kb body cap; SSRF guards on server-fetched URLs; page probes are best-effort
(labeled as such — confirm manually); errors never leak stacks.

## Authorized use only

Education + authorized testing / defensive security / CTFs. Get permission first.
Sweeps and scans hit third-party services — respect their terms and rate limits.
