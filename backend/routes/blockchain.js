const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail } = require('../utils/validate');

// Blockchain hub — all keyless.

const BTC = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
const ETH = /^0x[a-fA-F0-9]{40}$/;
const LTC = /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$|^ltc1[a-z0-9]{39,59}$/;
const DOGE = /^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$/;

function detect(addr) {
  if (BTC.test(addr)) return 'btc';
  if (ETH.test(addr)) return 'eth';
  if (LTC.test(addr)) return 'ltc';
  if (DOGE.test(addr)) return 'doge';
  return null;
}

// GET /api/crypto/address/:addr — balance, tx count, history links (auto-detect chain)
router.get('/address/:addr', async (req, res) => {
  const addr = String(req.params.addr || '').trim();
  const chain = detect(addr);
  if (!chain) return fail(res, 400, 'Unrecognized address (BTC/ETH/LTC/DOGE supported)');
  try {
    const { data, cached } = await getOrSet(`chain:${chain}:${addr}`, 600, async () => {
      if (chain === 'btc') {
        const [a, txs] = await Promise.all([
          http.get(`https://blockstream.info/api/address/${addr}`, { timeout: 12000 }),
          http.get(`https://blockstream.info/api/address/${addr}/txs`, { timeout: 12000 }),
        ]);
        if (a.status !== 200) throw Object.assign(new Error('Address not found / API error'), { status: 502 });
        const s = a.data?.chain_stats || {};
        return {
          chain: 'bitcoin', address: addr,
          balance_btc: (s.funded_txo_sum - s.spent_txo_sum) / 1e8,
          funded_btc: s.funded_txo_sum / 1e8, spent_btc: s.spent_txo_sum / 1e8, tx_count: s.tx_count,
          recent_txs: (Array.isArray(txs.data) ? txs.data : []).slice(0, 10).map((t) => ({ txid: t.txid, fee_sat: t.fee, confirmed: t.status?.confirmed, block: t.status?.block_height || null })),
          explorer: `https://blockstream.info/address/${addr}`, source: 'blockstream.info',
        };
      }
      // ETH/LTC/DOGE via BlockCypher (keyless tier)
      const r = await http.get(`https://api.blockcypher.com/v1/${chain === 'eth' ? 'eth' : chain}/main/addrs/${addr}?limit=10`, { timeout: 12000 });
      if (r.status !== 200) throw Object.assign(new Error('Address not found / API error'), { status: 502 });
      const d = r.data || {};
      return {
        chain, address: addr,
        balance: d.balance / Math.pow(10, chain === 'eth' ? 18 : 8),
        total_received: d.total_received / Math.pow(10, chain === 'eth' ? 18 : 8),
        tx_count: d.n_tx, unconfirmed: d.unconfirmed_n_tx ?? 0,
        recent_txs: (d.txrefs || []).slice(0, 10).map((t) => ({ txid: t.tx_hash, value: t.value / Math.pow(10, chain === 'eth' ? 18 : 8), confirmations: t.confirmations })),
        explorer: `https://live.blockcypher.com/${chain}/address/${addr}/`, source: 'blockcypher',
      };
    });
    return ok(res, data, { cached });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Address lookup failed'); }
});

// GET /api/crypto/prices — CoinGecko simple prices (keyless)
router.get('/prices', async (req, res) => {
  try {
    const { data, cached } = await getOrSet('cg:prices', 300, async () => {
      const r = await http.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,litecoin,dogecoin,monero,solana&vs_currencies=usd&include_24hr_change=true', { timeout: 12000 });
      if (r.status !== 200) throw Object.assign(new Error('Price feed unreachable'), { status: 502 });
      return r.data;
    });
    return ok(res, data, { cached, source: 'coingecko' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Price lookup failed'); }
});

// GET /api/crypto/btc-fees — mempool.space fee + height snapshot
router.get('/btc-fees', async (req, res) => {
  try {
    const { data, cached } = await getOrSet('mempool:fees', 300, async () => {
      const [fees, height] = await Promise.all([
        http.get('https://mempool.space/api/v1/fees/recommended', { timeout: 10000 }),
        http.get('https://mempool.space/api/blocks/tip/height', { timeout: 10000 }),
      ]);
      return { fees_sat_vb: fees.data, tip_height: height.data, source: 'mempool.space' };
    });
    return ok(res, data, { cached });
  } catch (e) { return fail(res, 502, 'Fee lookup failed'); }
});

module.exports = router;
