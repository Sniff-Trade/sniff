// Sniff API (Cloudflare Worker + D1): token risk checks for AI agents on Solana, built for pump.fun launches.
//   GET  /v1/check/:mint           risk report (score 0-100, verdict, reasons, signals)
//   GET  /v1/trending?limit=20     tokens trending on Jupiter in the last hour, for agents looking for tokens to check
//   GET  /v1/usage                 calls left today for your key or IP
//   POST /v1/keys                  { address, message, signature, tx } -> API key, paid by burning $SNIFF
//   POST /mcp                      Model Context Protocol (streamable HTTP): tools check_token, trending_tokens
//   POST /v1/rpc                   a few read-only Solana RPC methods for the site (keeps the RPC key private)
// Free: FREE_PER_DAY checks per IP per day. Keys: unlimited (fair use), valid for days bought.

import { ed25519 } from '@noble/curves/ed25519';
import { inspect, VERSION, VERDICTS } from './score.js';
import { client, isPubkey, b58decode } from './chain.js';

const DAY_MS = 86400000;
const B58 = '[1-9A-HJ-NP-Za-km-z]';
const KEY_MSG = new RegExp(`^Sniff API key\\nWallet: (${B58}{32,44})\\nTx: (${B58}{64,90})\\nTime: (\\S+)$`);
const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, authorization, x-api-key, mcp-session-id, mcp-protocol-version',
  'access-control-expose-headers': 'x-sniff-remaining, mcp-session-id',
};
const json = (body, status = 200, extra = {}) => new Response(JSON.stringify(body, null, 1), { status, headers: { ...cors, 'content-type': 'application/json', ...extra } });
const today = () => new Date().toISOString().slice(0, 10);
const sha256 = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('');

// ---------- who is calling: a key, or an IP on the free tier ----------
async function caller(request, env, url) {
  const raw = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '') || request.headers.get('x-api-key') || url.searchParams.get('key') || '';
  if (raw.startsWith('sniff_')) {
    const row = await env.DB.prepare('SELECT wallet, expires FROM keys WHERE hash = ?').bind(await sha256(raw)).first();
    if (!row) return { error: 'unknown API key' };
    if (row.expires < Date.now()) return { error: 'API key expired, burn $SNIFF to extend it' };
    return { who: 'key:' + row.wallet, limit: Number(env.KEY_PER_DAY || 20000), key: true, expires: row.expires };
  }
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  return { who: 'ip:' + ip, limit: Number(env.FREE_PER_DAY || 30), key: false };
}

async function used(env, who) {
  const row = await env.DB.prepare('SELECT n FROM usage WHERE day = ? AND who = ?').bind(today(), who).first();
  return row ? row.n : 0;
}
async function spend(env, who) {
  await env.DB.prepare('INSERT INTO usage (day, who, n) VALUES (?1, ?2, 1) ON CONFLICT(day, who) DO UPDATE SET n = n + 1').bind(today(), who).run();
}

// ---------- the check itself, cached for 60 seconds ----------
async function checked(mint, env, ctx) {
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const cacheKey = new Request(`https://cache.sniff/${mint}`);
  if (cache) { const hit = await cache.match(cacheKey); if (hit) return { ...(await hit.json()), cached: true }; }
  const report = await inspect(mint, env);
  if (cache) ctx?.waitUntil?.(cache.put(cacheKey, new Response(JSON.stringify(report), { headers: { 'cache-control': 'max-age=60' } })));
  return report;
}

async function metered(request, env, url, run) {
  const c = await caller(request, env, url);
  if (c.error) return { status: 401, body: { error: c.error } };
  const n = await used(env, c.who);
  if (n >= c.limit) return { status: 429, body: { error: c.key ? 'daily fair-use limit reached' : `free limit of ${c.limit} checks a day reached. Get a key: ${env.SITE_URL || 'the Sniff site'}/#/keys`, limit: c.limit } };
  try {
    const body = await run();
    await spend(env, c.who);
    return { status: 200, body, remaining: c.limit - n - 1 };
  } catch (e) {
    return { status: e.status || 502, body: { error: e.message || 'check failed' } };
  }
}

// tokens trending on Jupiter over the last hour, with market data
async function trending(limit) {
  const list = await fetch(`https://lite-api.jup.ag/tokens/v2/toptrending/1h?limit=100`).then((r) => r.json()).catch(() => []);
  // launchpad tokens only (pump.fun and friends): no majors, stables or tokenized stocks
  return (Array.isArray(list) ? list : []).filter((t) => t.launchpad)
    .slice(0, Math.min(30, Math.max(1, limit))).map((t) => ({
      token: t.id, name: t.name, symbol: t.symbol, launchpad: t.launchpad || null,
      ageHours: t.firstPool?.createdAt ? Math.round((Date.now() - Date.parse(t.firstPool.createdAt)) / 360000) / 10 : null,
      marketCapUsd: Math.round(t.mcap || 0), liquidityUsd: Math.round(t.liquidity || 0), holders: t.holderCount ?? null,
      volume1hUsd: Math.round((t.stats1h?.buyVolume || 0) + (t.stats1h?.sellVolume || 0)), trades1h: (t.stats1h?.numBuys || 0) + (t.stats1h?.numSells || 0),
    }));
}

// ---------- API keys, paid by burning $SNIFF ----------
// sums $SNIFF burned by `wallet` in a transaction (Burn / BurnChecked, top-level or inner instructions)
function burnedIn(tx, mint, wallet) {
  const all = [...(tx.transaction.message.instructions || []), ...(tx.meta.innerInstructions || []).flatMap((x) => x.instructions)];
  let raw = 0n;
  for (const ix of all) {
    const p = ix.parsed;
    if (!p || (p.type !== 'burn' && p.type !== 'burnChecked')) continue;
    if (p.info.mint !== mint || (p.info.authority || p.info.multisigAuthority) !== wallet) continue;
    raw += BigInt(p.info.amount ?? p.info.tokenAmount?.amount ?? 0);
  }
  return raw;
}

async function createKey(request, env) {
  if (!env.TOKEN_ADDRESS) return json({ error: 'keys open at the $SNIFF launch' }, 400);
  const { address, message, signature, tx } = await request.json().catch(() => ({}));
  if (!isPubkey(address ?? '') || typeof message !== 'string' || typeof signature !== 'string' || typeof tx !== 'string') return json({ error: 'bad request' }, 400);
  const m = message.match(KEY_MSG);
  if (!m || m[1] !== address || m[2] !== tx) return json({ error: 'bad message' }, 400);
  if (!(Math.abs(Date.now() - Date.parse(m[3])) < 15 * 60000)) return json({ error: 'signature expired, sign again' }, 400);
  let ok = false;
  try { ok = ed25519.verify(b58decode(signature), new TextEncoder().encode(message), b58decode(address)); } catch {}
  if (!ok) return json({ error: 'signature does not match the wallet' }, 401);
  if (await env.DB.prepare('SELECT 1 FROM burns WHERE tx = ?').bind(tx).first()) return json({ error: 'this burn was already used for a key' }, 409);

  const t = await client(env.SOL_RPC_URL || 'https://api.mainnet-beta.solana.com').call('getTransaction', [tx, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 1, commitment: 'confirmed' }]).catch(() => null);
  if (!t) return json({ error: 'transaction not found yet, try again in a few seconds' }, 404);
  if (t.meta?.err) return json({ error: 'transaction failed' }, 400);
  const burned = burnedIn(t, env.TOKEN_ADDRESS, address);
  const unit = 10n ** BigInt(env.TOKEN_DECIMALS || 6);
  const price = BigInt(env.KEY_PRICE || '100000') * unit;
  if (burned < price) return json({ error: `burn at least ${env.KEY_PRICE || 100000} $SNIFF from this wallet` }, 400);

  // every KEY_PRICE burned buys KEY_DAYS days; burning again extends the same wallet's key
  const days = Number((burned * BigInt(env.KEY_DAYS || 30)) / price);
  const prev = await env.DB.prepare('SELECT expires FROM keys WHERE wallet = ? ORDER BY expires DESC LIMIT 1').bind(address).first();
  const expires = Math.max(Date.now(), prev?.expires || 0) + days * DAY_MS;
  const key = 'sniff_' + [...crypto.getRandomValues(new Uint8Array(24))].map((b) => b.toString(16).padStart(2, '0')).join('');
  await env.DB.batch([
    env.DB.prepare('INSERT INTO burns (tx, wallet, amount, created) VALUES (?, ?, ?, ?)').bind(tx, address, Number(burned / unit), Date.now()),
    env.DB.prepare('UPDATE keys SET expires = ? WHERE wallet = ?').bind(expires, address),
    env.DB.prepare('INSERT INTO keys (hash, wallet, created, expires) VALUES (?, ?, ?, ?)').bind(await sha256(key), address, Date.now(), expires),
  ]);
  return json({ key, wallet: address, days, expires: new Date(expires).toISOString(), note: 'Store this key now: it is shown once. Older keys of this wallet were extended too.' });
}

// ---------- RPC proxy for the site: only what the burn flow needs ----------
const RPC_ALLOWED = new Set(['getLatestBlockhash', 'getTokenAccountsByOwner', 'getAccountInfo', 'getSignatureStatuses']);
async function rpcProxy(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || Array.isArray(body) || !RPC_ALLOWED.has(body.method)) return json({ jsonrpc: '2.0', id: body?.id ?? null, error: { code: -32601, message: 'method not allowed' } }, 400);
  try {
    const result = await client(env.SOL_RPC_URL || 'https://api.mainnet-beta.solana.com').call(body.method, body.params || []);
    return json({ jsonrpc: '2.0', id: body.id ?? 1, result });
  } catch (e) { return json({ jsonrpc: '2.0', id: body.id ?? 1, error: { code: -32000, message: e.message } }, 502); }
}

// ---------- MCP: JSON-RPC over streamable HTTP ----------
const TOOLS = [
  {
    name: 'check_token',
    title: 'Sniff a token before buying',
    description: 'Risk check for a Solana token (built for pump.fun launches). Returns a 0-100 score, a verdict (CLEAN / SUSPECT / ROTTEN), the reasons behind every deduction and raw signals: mint and freeze authority, Token-2022 traps (permanent delegate, transfer hooks, fees), launch-block bundles, creator selling, holder concentration, copycats, liquidity and activity. Call this before any buy and refuse to buy on ROTTEN.',
    inputSchema: { type: 'object', properties: { token: { type: 'string', description: 'Token mint address (base58)' } }, required: ['token'] },
  },
  {
    name: 'trending_tokens',
    title: 'Trending Solana tokens',
    description: 'Solana tokens trending on Jupiter in the last hour, with market cap, liquidity, holders, volume and age. Use check_token on any of them before buying.',
    inputSchema: { type: 'object', properties: { limit: { type: 'number', description: '1-30, default 10' } } },
  },
];

async function mcp(request, env, url, ctx) {
  const msg = await request.json().catch(() => null);
  if (!msg || msg.jsonrpc !== '2.0') return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }, 400);
  const reply = (result) => json({ jsonrpc: '2.0', id: msg.id, result });
  const fail = (code, message) => json({ jsonrpc: '2.0', id: msg.id, error: { code, message } });
  if (msg.id === undefined) return new Response(null, { status: 202, headers: cors }); // notification

  switch (msg.method) {
    case 'initialize':
      return reply({
        protocolVersion: msg.params?.protocolVersion || '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'sniff', title: 'Sniff: token checks for AI agents on Solana', version: VERSION },
        instructions: 'Before buying any Solana token, call check_token. Do not buy when the verdict is ROTTEN; size down on SUSPECT.',
      });
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: TOOLS });
    case 'tools/call': {
      const { name, arguments: args = {} } = msg.params || {};
      if (name === 'check_token') {
        if (!isPubkey(args.token ?? '')) return reply({ isError: true, content: [{ type: 'text', text: 'token must be a Solana mint address (base58)' }] });
        const r = await metered(request, env, url, () => checked(args.token, env, ctx));
        if (r.status !== 200) return reply({ isError: true, content: [{ type: 'text', text: r.body.error }] });
        const lines = [r.body.summary, '', ...r.body.reasons.map((x) => `${x.impact} · ${x.text}`), ...r.body.positives.map((p) => `+ ${p}`), ...r.body.notes.map((n) => `note: ${n}`)];
        return reply({ content: [{ type: 'text', text: lines.join('\n') }, { type: 'text', text: JSON.stringify(r.body) }], structuredContent: r.body });
      }
      if (name === 'trending_tokens') {
        const list = await trending(Number(args.limit) || 10);
        return reply({ content: [{ type: 'text', text: list.map((x) => `${x.symbol} ${x.token} · ${x.launchpad} · mcap $${x.marketCapUsd.toLocaleString('en-US')} · ${x.ageHours ?? '?'}h old · ${x.trades1h} trades 1h`).join('\n') }, { type: 'text', text: JSON.stringify(list) }], structuredContent: { tokens: list } });
      }
      return fail(-32602, `unknown tool: ${name}`);
    }
    default:
      return fail(-32601, `method not found: ${msg.method}`);
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    try {
      if (path === '/' || path === '/v1') return json({ name: 'Sniff', chain: 'solana', version: VERSION, docs: (env.SITE_URL || '') + '/#/docs/introduction', endpoints: ['/v1/check/:mint', '/v1/trending', '/v1/usage', '/v1/keys', '/v1/rpc', '/mcp'], verdicts: VERDICTS });
      if (path === '/health') return json({ ok: true });
      const m = path.match(/^\/v1\/check\/([^/]+)$/);
      if (m && request.method === 'GET') {
        if (!isPubkey(m[1])) return json({ error: 'use /v1/check/<Solana mint address>' }, 400);
        const r = await metered(request, env, url, () => checked(m[1], env, ctx));
        return json(r.body, r.status, r.remaining != null ? { 'x-sniff-remaining': String(r.remaining) } : {});
      }
      if (path === '/v1/trending' && request.method === 'GET') return json({ tokens: await trending(Number(url.searchParams.get('limit')) || 20) });
      if (path === '/v1/usage') {
        const c = await caller(request, env, url);
        if (c.error) return json({ error: c.error }, 401);
        const n = await used(env, c.who);
        return json({ plan: c.key ? 'key' : 'free', usedToday: n, limit: c.limit, remaining: Math.max(0, c.limit - n), expires: c.expires ? new Date(c.expires).toISOString() : null });
      }
      if (path === '/v1/keys' && request.method === 'POST') return await createKey(request, env);
      if (path === '/v1/rpc' && request.method === 'POST') return await rpcProxy(request, env);
      if (path === '/mcp') {
        if (request.method === 'POST') return await mcp(request, env, url, ctx);
        return json({ error: 'MCP endpoint: send JSON-RPC with POST' }, 405, { allow: 'POST' });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: 'server error' }, 500);
    }
  },
};
