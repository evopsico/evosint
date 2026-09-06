const NodeCache = require('node-cache');

// Short-lived in-memory cache for expensive upstream lookups.
const cache = new NodeCache({ stdTTL: 600, checkperiod: 120, useClones: false });

function getOrSet(key, ttlSeconds, fetcher) {
  const hit = cache.get(key);
  if (hit !== undefined) return Promise.resolve({ data: hit, cached: true });
  return fetcher().then((data) => {
    cache.set(key, data, ttlSeconds);
    return { data, cached: false };
  });
}

function delPattern(prefix) {
  cache.keys().forEach((k) => { if (k.startsWith(prefix)) cache.del(k); });
}

module.exports = { cache, getOrSet, delPattern };
