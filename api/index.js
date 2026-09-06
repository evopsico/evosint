// Vercel serverless entrypoint: the whole Express app runs as one function.
// Static files (/, /public/*) are served by Vercel's CDN; /api/* rewrites here.
// Needs STORE=vercel-kv + a connected KV database (see README "Deploy to Vercel").
const app = require('../backend/server.js');

module.exports = app;
