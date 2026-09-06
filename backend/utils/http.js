const axios = require('axios');

// Shared HTTP client: sane UA (many sites 403 default axios UA), timeouts, no proxy leaks.
const UA = process.env.EVOSINT_USER_AGENT || process.env.OSINT_USER_AGENT || 'Evosint/2.1 (+authorized-use-only)';

const http = axios.create({
  timeout: 9000,
  headers: { 'User-Agent': UA, Accept: 'application/json, text/html;q=0.9, */*;q=0.8' },
  maxRedirects: 5,
  validateStatus: () => true, // callers decide what status means
});

module.exports = { http, UA };
