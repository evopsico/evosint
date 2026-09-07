// Single API entrypoint. Vercel rewrites EVERY /api/* here (see vercel.json);
// the original request path is preserved, so the Express app below routes
// exactly like it does locally — no segment-matching quirks involved.
const app = require('../backend/server.js');

module.exports = app;
