// Vercel catch-all function: EVERY /api/* request lands here, no rewrites needed.
// The Express app below already declares full /api/... routes, and Vercel passes
// the original request path through, so everything matches as it does locally.
// Needs STORE=vercel-kv + a connected KV database (see README "Deploy to Vercel").
const app = require('../backend/server.js');

module.exports = app;
