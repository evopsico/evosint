const express = require('express');
const router = express.Router();
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const { http } = require('../utils/http');
const { ok, fail, axiosError } = require('../utils/validate');

/**
 * GET /api/phone/:phone — local parse via libphonenumber-js (always works),
 * plus AbstractAPI enrichment when ABSTRACT_API_KEY is configured.
 * v1 flaw fixed: hardcoded api_key=free so every request failed.
 */
router.get('/:phone', async (req, res) => {
  const raw = String(req.params.phone || '').trim();
  if (!raw) return fail(res, 400, 'Phone number is required');

  const parsed = parsePhoneNumberFromString(raw, 'US');
  const local = parsed ? {
    valid: parsed.isValid(),
    possible: parsed.isPossible(),
    e164: parsed.isValid() ? parsed.format('E.164') : null,
    international: parsed.isValid() ? parsed.formatInternational() : null,
    national: parsed.isValid() ? parsed.formatNational() : null,
    country: parsed.country || null,
    countryCallingCode: parsed.countryCallingCode || null,
    type: parsed.isValid() ? (parsed.getType() || 'unknown') : null,
  } : { valid: false, possible: false };

  if (!parsed || !parsed.isPossible()) {
    return fail(res, 400, 'Invalid phone number (use international format, e.g. +14155552671)');
  }

  let enrichment = null;
  const key = process.env.ABSTRACT_API_KEY;
  if (key) {
    try {
      const r = await http.get(
        `https://phonevalidation.abstractapi.com/v1/?api_key=${encodeURIComponent(key)}&phone=${encodeURIComponent(raw)}`,
        { timeout: 9000 }
      );
      enrichment = r.data;
    } catch (e) {
      enrichment = { _error: 'AbstractAPI enrichment failed, local parse still valid' };
    }
  }

  return ok(res, {
    input: raw,
    ...local,
    carrier: enrichment && enrichment.carrier ? enrichment.carrier : null,
    location: enrichment && enrichment.location ? enrichment.location : null,
    _enrichment: enrichment,
    _note: key ? 'enriched via AbstractAPI' : 'local parse only — set ABSTRACT_API_KEY for carrier/line-type enrichment',
  });
});

module.exports = router;
