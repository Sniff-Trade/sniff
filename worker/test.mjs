// Exercises the worker in Node: node:sqlite stands in for D1, burn transactions are faked, token checks hit the live chain.
// Run: node test.mjs            (SOL_RPC_URL=<your rpc> node test.mjs to avoid public RPC rate limits)
import { ed25519 } from '@noble/curves/ed25519';
import worker from './src/index.js';
import { sqliteD1 } from './d1-sqlite.mjs';
import { b58encode } from './src/chain.js';

const SNIFF = 'SniffTestMint1111111111111111111111111111111'.slice(0, 44);
const RPC = process.env.SOL_RPC_URL || 'https://api.mainnet-beta.solana.com';
const env = { DB: sqliteD1(), SOL_RPC_URL: RPC, TOKEN_ADDRESS: SNIFF, TOKEN_DECIMALS: '6', KEY_PRICE: '100000', KEY_DAYS: '30', FREE_PER_DAY: '3', KEY_PER_DAY: '100', SITE_URL: 'https://sniff.test' };
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // stable live mint: has a freeze authority

// a live pump.fun token from DexScreener for the pump checks
const prof = await (await fetch('https://api.dexscreener.com/token-profiles/latest/v1')).json();
const PUMPED = prof.find((p) => p.chainId === 'solana' && p.tokenAddress.endsWith('pump')).tokenAddress;

// fake burn transactions; everything else goes to the real network
const txs = {};
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url) === RPC && init?.body) {
    const body = JSON.parse(init.body);
    if (body.method === 'getTransaction' && body.params[0] in txs) return new Response(JSON.stringify({ result: txs[body.params[0]] }));
  }
  return realFetch(url, init);
};
const burnTx = (authority, tokens, mint = SNIFF) => ({ meta: { err: null, innerInstructions: [] }, transaction: { message: { instructions: [{ parsed: { type: 'burnChecked', info: { mint, authority, tokenAmount: { amount: String(BigInt(tokens) * 10n ** 6n) } } } }] } } });
const wallet = () => { const sk = ed25519.utils.randomPrivateKey(); return { sk, address: b58encode(ed25519.getPublicKey(sk)) }; };
const sign = (w, message) => b58encode(ed25519.sign(new TextEncoder().encode(message), w.sk));
const sig = (c) => c.repeat(88);

const call = async (path, init = {}, ip = '1.1.1.1') => {
  const res = await worker.fetch(new Request('https://api.sniff.test' + path, { ...init, headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip, ...(init.headers || {}) } }), env, { waitUntil() {} });
  const text = await res.text();
  return [res.status, text ? JSON.parse(text) : null, res.headers];
};
const rpc = (method, params, id = 1, headers = {}) => call('/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id, method, params }), headers });
let failed = 0;
const check = (name, ok, detail) => { if (!ok) failed++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : ': ' + JSON.stringify(detail).slice(0, 400)}`); };

// ---- REST ----
const [s0, info] = await call('/');
check('root describes the API', s0 === 200 && info.chain === 'solana' && info.endpoints.includes('/mcp'), info);
check('bad address', (await call('/v1/check/0x123'))[0] === 400);
const [s1, rep, h1] = await call(`/v1/check/${PUMPED}`);
check(`live check of a pump.fun token (${PUMPED.slice(0, 6)}…)`, s1 === 200 && rep.signals.pumpLaunch === true && rep.score >= 0 && rep.score <= 100 && ['CLEAN', 'SUSPECT', 'ROTTEN'].includes(rep.verdict) && Array.isArray(rep.reasons) && Array.isArray(rep.notes), [s1, rep]);
check('remaining header', h1.get('x-sniff-remaining') === '2', h1.get('x-sniff-remaining'));
check('pump signals', ['curve', 'graduated'].includes(rep.signals.stage) && rep.signals.creator && rep.signals.mintAuthority === null, rep.signals);
const [s2, usdc] = await call(`/v1/check/${USDC}`);
check('freeze authority is flagged', s2 === 200 && usdc.signals.pumpLaunch === false && usdc.reasons.some((r) => r.signal === 'freezeAuthority'), [s2, usdc]);
const [s3, notMint] = await call('/v1/check/11111111111111111111111111111111');
check('not a mint', s3 === 404 || s3 === 502, [s3, notMint]);
await call(`/v1/check/${USDC}`);
const [s4, limited] = await call(`/v1/check/${PUMPED}`);
check('free tier limit', s4 === 429 && /free limit/.test(limited.error), [s4, limited]);
const [, usage] = await call('/v1/usage');
check('usage', usage.plan === 'free' && usage.remaining === 0 && usage.limit === 3, usage);
const [s5, list] = await call('/v1/trending?limit=5');
check('trending', s5 === 200 && list.tokens.length > 0 && list.tokens.every((t) => t.launchpad) && list.tokens[0].token, list);

const [r1, bh] = await call('/v1/rpc', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLatestBlockhash', params: [] }) });
check('rpc proxy: allowed method', r1 === 200 && bh.result?.value?.blockhash, bh);
check('rpc proxy: other methods refused', (await call('/v1/rpc', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'sendTransaction', params: [] }) }))[0] === 400);

// ---- keys paid by burning $SNIFF ----
const alice = wallet(), bob = wallet();
txs[sig('a')] = burnTx(alice.address, 200000);
txs[sig('b')] = burnTx(alice.address, 50000);
txs[sig('c')] = burnTx(bob.address, 100000);
txs[sig('d')] = burnTx(bob.address, 500000, 'OtherMint11111111111111111111111111111111111');
const keyReq = (w, tx, time = new Date(), signer = w) => {
  const message = `Sniff API key\nWallet: ${w.address}\nTx: ${tx}\nTime: ${time.toISOString()}`;
  return call('/v1/keys', { method: 'POST', body: JSON.stringify({ address: w.address, message, signature: sign(signer, message), tx }) });
};
const [k1, key1] = await keyReq(alice, sig('a'));
check('key for a 200K burn = 60 days', k1 === 200 && key1.key.startsWith('sniff_') && key1.days === 60, key1);
check('same burn twice', (await keyReq(alice, sig('a')))[0] === 409);
check('burn too small', (await keyReq(alice, sig('b')))[0] === 400);
check("someone else's burn", (await keyReq(alice, sig('c')))[0] === 400);
check('burn of another token', (await keyReq(bob, sig('d')))[0] === 400);
check('old signature', (await keyReq(bob, sig('c'), new Date(Date.now() - 3600000)))[0] === 400);
check('signed by another wallet', (await keyReq(bob, sig('c'), new Date(), alice))[0] === 401);
const [k2, key2] = await keyReq(bob, sig('c'));
check('bob gets 30 days', k2 === 200 && key2.days === 30, key2);
const [s6, keyed] = await call(`/v1/check/${USDC}`, { headers: { authorization: `Bearer ${key1.key}` } });
check('key bypasses the free limit', s6 === 200 && keyed.token === USDC, [s6, keyed]);
const [, kusage] = await call('/v1/usage', { headers: { 'x-api-key': key1.key } });
check('key usage', kusage.plan === 'key' && kusage.limit === 100 && kusage.expires, kusage);
check('wrong key', (await call(`/v1/check/${USDC}`, { headers: { authorization: 'Bearer sniff_nope' } }))[0] === 401);

// ---- MCP ----
const [m1, init] = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
check('mcp initialize', m1 === 200 && init.result.serverInfo.name === 'sniff' && init.result.capabilities.tools, init);
check('mcp notification -> 202', (await call('/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) }))[0] === 202);
const [, tl] = await rpc('tools/list', {}, 2);
check('mcp tools/list', tl.result.tools.map((t) => t.name).join() === 'check_token,trending_tokens', tl);
const [, tc] = await rpc('tools/call', { name: 'check_token', arguments: { token: USDC } }, 3, { authorization: `Bearer ${key1.key}` });
check('mcp check_token', !tc.result.isError && tc.result.structuredContent.token === USDC && /: (CLEAN|SUSPECT|ROTTEN)/.test(tc.result.content[0].text), tc);
const [, tcLimited] = await rpc('tools/call', { name: 'check_token', arguments: { token: USDC } }, 4);
check('mcp respects the free limit', tcLimited.result.isError && /free limit/.test(tcLimited.result.content[0].text), tcLimited);
const [, bad] = await rpc('tools/call', { name: 'check_token', arguments: { token: 'nope' } }, 5);
check('mcp bad input', bad.result.isError, bad);
const [, tt] = await rpc('tools/call', { name: 'trending_tokens', arguments: { limit: 3 } }, 6);
check('mcp trending_tokens', tt.result.structuredContent.tokens.length > 0, tt);
const [, unk] = await rpc('nope/method', {}, 7);
check('mcp unknown method', unk.error?.code === -32601, unk);

globalThis.fetch = realFetch;
console.log(failed ? `\n${failed} FAILED` : '\nall passed');
process.exit(failed ? 1 : 0);
