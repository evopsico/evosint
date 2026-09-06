const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidIP, isPrivateIP, ok, fail, axiosError } = require('../utils/validate');

/**
 * GET /api/ip/:ip — geolocation with fallback chain (ipwho.is → ip-api.com → ipinfo.io).
 * v1 flaw fixed: old code accepted 999.999.999.999 and only tried ipinfo.io (rate-limited).
 */
router.get('/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'Invalid IP address (IPv4 or IPv6 required)');

  try {
    const { data, cached } = await getOrSet(`ip:${ip}`, 3600, async () => {
      // 1) ipwho.is — free, no key, generous limits
      let r = await http.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 8000 });
      if (r.status === 200 && r.data && r.data.success !== false) {
        return { ...r.data, _source: 'ipwho.is', _private: isPrivateIP(ip) };
      }
      // 2) ip-api.com — free tier (45 req/min), http only without key
      r = await http.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query`, { timeout: 8000 });
      if (r.status === 200 && r.data && r.data.status === 'success') {
        return { ...r.data, _source: 'ip-api.com', _private: isPrivateIP(ip) };
      }
      // 3) ipinfo.io — works without token at low volume
      r = await http.get(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, { timeout: 8000 });
      if (r.status === 200 && r.data && !r.data.error) {
        return { ...r.data, _source: 'ipinfo.io', _private: isPrivateIP(ip) };
      }
      const err = new Error('All IP geolocation providers failed');
      err.status = 502;
      throw err;
    });
    return ok(res, data, { cached });
  } catch (error) {
    if (error.status) return fail(res, error.status, error.message);
    return axiosError(res, error);
  }
});

module.exports = router;
