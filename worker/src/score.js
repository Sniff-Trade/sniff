// Sniff's token check: gathers on-chain and market signals for a Solana token and turns them into a 0-100 score.
// Every deduction is listed in `reasons`, so an agent (or a person) can see exactly why.
// Sources: Solana RPC (mint, pump.fun curve, holders, launch block) and Jupiter's token API (market, dev history, look-alikes).
import { client, bondingCurve, decodeCurve, decodeTokenAccount, ata, PUMP, PUMP_AMM, SYSTEM, TOKEN, TOKEN_2022, CURVE_TOKENS } from './chain.js';

export const VERSION = '1.0.0';
const MAX_SIG_PAGES = 8; // walk back at most 8,000 curve transactions to find the launch block
const MAX_LAUNCH_TXS = 12; // launch-block transactions we read in full
const JUP = 'https://lite-api.jup.ag/tokens/v2';

export const VERDICTS = [
  { min: 70, id: 'CLEAN', text: 'No major red flags found.' },
  { min: 45, id: 'SUSPECT', text: 'Some risk signals. Size down or wait.' },
  { min: 0, id: 'ROTTEN', text: 'Serious red flags. Do not buy.' },
];
export const verdictFor = (score) => VERDICTS.find((v) => score >= v.min);

const round = (n, d = 2) => Math.round(n * 10 ** d) / 10 ** d;
const share = (part, whole) => (whole > 0n ? Number((part * 1000000n) / whole) / 10000 : 0);

async function getJson(url, ms = 4000) {
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(ms) });
    return res.ok ? await res.json() : null;
  } catch { return null; }
}
// token metadata JSON: the uri as given, then the same IPFS content through other gateways
async function metadataJson(uri) {
  const cid = (uri || '').match(/(?:ipfs:\/\/|\/ipfs\/)([A-Za-z0-9]+)/)?.[1];
  const urls = cid ? [`https://${cid}.ipfs.4everland.io/`, `https://gateway.pinata.cloud/ipfs/${cid}`, `https://ipfs.io/ipfs/${cid}`] : [uri];
  const tries = urls.map((u) => getJson(u, 3000).then((j) => j || Promise.reject()));
  return Promise.any(tries).catch(() => null);
}

// the launch block: walk the curve's history back to its first transaction, then read that block's trades
async function launchBlock(rpc, curve, mint) {
  const sigs = [];
  let before;
  for (let i = 0; i < MAX_SIG_PAGES; i++) {
    const page = await rpc.call('getSignaturesForAddress', [curve, { limit: 1000, before }]);
    sigs.push(...page);
    if (page.length < 1000) break;
    before = page.at(-1).signature;
    if (i === MAX_SIG_PAGES - 1) return null; // too busy to reach the start
  }
  if (!sigs.length) return null;
  const slot = sigs.at(-1).slot;
  const inSlot = sigs.filter((s) => s.slot === slot && !s.err).reverse().slice(0, MAX_LAUNCH_TXS);
  const txs = await Promise.all(inSlot.map((s) => rpc.call('getTransaction', [s.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 1 }]).catch(() => null)));
  const buys = [];
  for (const tx of txs) {
    if (!tx || tx.meta?.err) continue;
    const signer = tx.transaction.message.accountKeys[0].pubkey;
    const created = (tx.meta.logMessages || []).some((l) => /Instruction: Create/.test(l));
    // tokens that landed in wallets other than the curve in this transaction
    const pre = new Map((tx.meta.preTokenBalances || []).filter((b) => b.mint === mint).map((b) => [b.owner, BigInt(b.uiTokenAmount.amount)]));
    for (const b of tx.meta.postTokenBalances || []) {
      if (b.mint !== mint || b.owner === curve) continue;
      const got = BigInt(b.uiTokenAmount.amount) - (pre.get(b.owner) || 0n);
      if (got > 0n) buys.push({ wallet: b.owner, signer, tokens: got, created });
    }
  }
  return { slot, time: sigs.at(-1).blockTime, buys, totalTxs: sigs.length };
}

export async function inspect(mint, env) {
  const rpc = client(env.SOL_RPC_URL || 'https://api.mainnet-beta.solana.com');
  const started = Date.now();
  const curve = bondingCurve(mint);

  const [accs, largest, jupRaw] = await Promise.all([
    rpc.call('getMultipleAccounts', [[mint, curve], { encoding: 'jsonParsed' }]),
    rpc.call('getTokenLargestAccounts', [mint]).catch(() => null),
    getJson(`${JUP}/search?query=${mint}`),
  ]);
  const [mintAcc, curveAcc] = accs.value;
  if (!mintAcc || mintAcc.data?.parsed?.type !== 'mint') { const e = new Error('not a token mint on Solana'); e.status = 404; throw e; }
  const info = mintAcc.data.parsed.info;
  const program = mintAcc.owner;
  const supply = BigInt(info.supply);
  const decimals = info.decimals;
  if (!supply) { const e = new Error('token has zero supply'); e.status = 422; throw e; }
  const ext = Object.fromEntries((info.extensions || []).map((x) => [x.extension, x.state || {}]));
  const meta = ext.tokenMetadata || null;

  const isPump = !!(curveAcc && curveAcc.owner === PUMP);
  const bc = isPump ? decodeCurve(curveAcc.data[0]) : null;
  const creator = bc?.creator || null;

  // market data and the dev's launch history from Jupiter
  const jup = (jupRaw || []).find((t) => t.id === mint) || null;
  const symbol = meta?.symbol || jup?.symbol || null;
  const name = meta?.name || jup?.name || null;

  // holders: the 20 largest token accounts -> their owners -> which owners are programs (curve, pools, lockers)
  const tops = largest?.value || [];
  const tokenAccs = tops.length ? await rpc.call('getMultipleAccounts', [tops.map((t) => t.address), { encoding: 'base64' }]) : { value: [] };
  const holders = tops.map((t, i) => ({ account: t.address, amount: BigInt(t.amount), owner: tokenAccs.value[i] ? decodeTokenAccount(tokenAccs.value[i].data[0])?.owner : null }));
  const owners = [...new Set(holders.map((h) => h.owner).filter(Boolean))];
  const ownerAccs = owners.length ? await rpc.call('getMultipleAccounts', [owners, { encoding: 'base64', dataSlice: { offset: 0, length: 0 } }]) : { value: [] };
  const ownerProgram = new Map(owners.map((o, i) => [o, ownerAccs.value[i]?.owner || SYSTEM]));
  // a person's wallet is owned by the system program (or doesn't exist yet); anything else is a program account
  const parked = (h) => h.owner === curve || (ownerProgram.get(h.owner) && ownerProgram.get(h.owner) !== SYSTEM);
  const people = holders.filter((h) => h.owner && !parked(h));
  const inPools = holders.filter((h) => h.owner && parked(h)).reduce((t, h) => t + h.amount, 0n);

  // the launch block (pump.fun only): creator buy and wallets bundled into the same block
  const launch = isPump ? await launchBlock(rpc, curve, mint).catch(() => null) : null;
  // the wallet that signed the create transaction is the launcher; the curve's creator (fee wallet) can be another address
  const launcher = launch?.buys.find((b) => b.created)?.signer || null;
  const dev = new Set([creator, launcher].filter(Boolean));
  const isDev = (b) => dev.has(b.wallet) || dev.has(b.signer);
  const creatorBuy = launch ? launch.buys.filter(isDev).reduce((t, b) => t + b.tokens, 0n) : null;
  const bundled = launch ? launch.buys.filter((b) => !isDev(b)) : [];
  const bundleWallets = [...new Set(bundled.map((b) => b.wallet))];

  // current balances of the creator and the bundled wallets, read from their token accounts
  const watch = [...dev, ...bundleWallets];
  const atas = watch.map((w) => ata(w, mint, program));
  const ataAccs = atas.length ? await rpc.call('getMultipleAccounts', [atas, { encoding: 'base64' }]) : { value: [] };
  const now = new Map(watch.map((w, i) => [w, ataAccs.value[i] ? decodeTokenAccount(ataAccs.value[i].data[0])?.amount || 0n : 0n]));
  const balOf = (w) => now.get(w) || 0n;
  const devBal = [...dev].reduce((t, w) => t + balOf(w), 0n);

  // socials from the token metadata file, or Jupiter
  const [uriJson, search] = await Promise.all([
    meta?.uri ? metadataJson(meta.uri) : null,
    symbol ? getJson(`${JUP}/search?query=${encodeURIComponent(symbol)}`) : null,
  ]);
  const socials = [];
  if (uriJson?.twitter || jup?.twitter) socials.push('twitter');
  if (uriJson?.telegram || jup?.telegram) socials.push('telegram');
  if (uriJson?.website || jup?.website) socials.push('website');

  // look-alikes: another token with the same ticker and a much bigger market cap
  const mcap = jup?.mcap || 0;
  const twins = (search || []).filter((t) => t.id !== mint && t.symbol?.toLowerCase() === symbol.toLowerCase());
  const original = twins.sort((a, b) => (b.mcap || 0) - (a.mcap || 0)).find((t) => (t.mcap || 0) > Math.max(50000, mcap * 3));

  const top10 = people.slice(0, 10).reduce((t, h) => t + h.amount, 0n);
  const created = launch?.time || (jup?.firstPool?.createdAt ? Date.parse(jup.firstPool.createdAt) / 1000 : null);
  const day = jup?.stats24h || null;
  const fee = ext.transferFeeConfig?.newerTransferFee?.transferFeeBasisPoints ?? ext.transferFeeConfig?.olderTransferFee?.transferFeeBasisPoints ?? 0;
  const ts = Date.now() / 1000;

  const signals = {
    pumpLaunch: isPump,
    stage: isPump ? (bc.complete ? 'graduated' : 'curve') : jup?.liquidity ? 'trading' : 'unlisted',
    curveProgressPct: isPump && !bc.complete ? round(Math.max(0, Number(CURVE_TOKENS - bc.realToken) / Number(CURVE_TOKENS)) * 100, 1) : null,
    tokenProgram: program === TOKEN_2022 ? 'token-2022' : program === TOKEN ? 'spl-token' : program,
    mintAuthority: info.mintAuthority || null,
    freezeAuthority: info.freezeAuthority || null,
    permanentDelegate: ext.permanentDelegate?.delegate || null,
    transferFeePct: fee / 100,
    transferHook: ext.transferHook?.programId || null,
    nonTransferable: 'nonTransferable' in ext,
    defaultFrozen: ext.defaultAccountState?.accountState === 'frozen',
    ageHours: created ? round((ts - created) / 3600, 1) : null,
    marketCapUsd: mcap ? Math.round(mcap) : null,
    liquidityUsd: jup?.liquidity != null ? Math.round(jup.liquidity) : null,
    volume24hUsd: day ? Math.round((day.buyVolume || 0) + (day.sellVolume || 0)) : null,
    trades24h: day ? (day.numBuys || 0) + (day.numSells || 0) : jup ? 0 : null,
    holders: jup?.holderCount ?? null,
    organicScore: jup?.organicScore != null ? Math.round(jup.organicScore) : null,
    devLaunches: jup?.audit?.devMints ?? null,
    devGraduated: jup?.audit?.devMigrations ?? null,
    top10Pct: tops.length ? share(top10, supply) : jup?.audit?.topHoldersPercentage != null ? round(jup.audit.topHoldersPercentage, 2) : null,
    largestHolderPct: people.length ? share(people[0].amount, supply) : null,
    largestHolder: people.length ? people[0].owner : null,
    inPoolsPct: tops.length ? share(inPools, supply) : null,
    creator,
    launcher,
    creatorPct: dev.size ? share(devBal, supply) : null,
    creatorBoughtPct: creatorBuy != null ? share(creatorBuy, supply) : null,
    creatorSoldPct: creatorBuy ? Math.max(0, Math.min(100, round(100 - share(devBal, creatorBuy), 1))) : creatorBuy === 0n ? 0 : null,
    bundledWallets: launch ? bundleWallets.length : null,
    bundledBoughtPct: launch ? share(bundled.reduce((t, b) => t + b.tokens, 0n), supply) : null,
    bundledHoldPct: launch ? share(bundleWallets.reduce((t, w) => t + balOf(w), 0n), supply) : null,
    launchTraced: isPump ? !!launch : null,
    copycatOf: original ? { token: original.id, symbol: original.symbol, marketCapUsd: Math.round(original.mcap) } : null,
    socials,
  };

  const reasons = [];
  const hit = (points, severity, signal, text) => reasons.push({ signal, impact: -points, severity, text });
  const s = signals;
  const pct = (n) => `${round(n, 1)}%`;
  if (s.nonTransferable) hit(60, 'high', 'nonTransferable', 'The token cannot be transferred or sold.');
  if (s.mintAuthority) hit(35, 'high', 'mintAuthority', 'Mint authority is still active: more tokens can be printed at any time.');
  if (s.freezeAuthority) hit(30, 'high', 'freezeAuthority', 'Freeze authority is still active: your tokens can be frozen so you cannot sell.');
  if (s.permanentDelegate) hit(35, 'high', 'permanentDelegate', 'A permanent delegate can move or burn tokens from any wallet.');
  if (s.defaultFrozen) hit(30, 'high', 'defaultFrozen', 'New token accounts start frozen.');
  if (s.transferHook) hit(20, 'medium', 'transferHook', 'A transfer hook runs custom code on every transfer and can block sells.');
  if (s.transferFeePct >= 5) hit(15, 'medium', 'transferFeePct', `Every transfer pays a ${s.transferFeePct}% fee.`);
  else if (s.transferFeePct > 0) hit(5, 'low', 'transferFeePct', `Every transfer pays a ${s.transferFeePct}% fee.`);
  if (s.copycatOf) hit(35, 'high', 'copycatOf', `Likely a copycat: another $${s.copycatOf.symbol} (${s.copycatOf.token.slice(0, 8)}…) has a $${s.copycatOf.marketCapUsd.toLocaleString('en-US')} market cap.`);
  if (s.bundledHoldPct != null) {
    const t = `${s.bundledWallets} wallet(s) bought in the same block as the launch and still hold ${pct(s.bundledHoldPct)} of supply.`;
    if (s.bundledHoldPct >= 15) hit(30, 'high', 'bundledHoldPct', t);
    else if (s.bundledHoldPct >= 7) hit(10, 'medium', 'bundledHoldPct', t);
    else if (s.bundledHoldPct >= 3) hit(4, 'low', 'bundledHoldPct', t);
  }
  if (s.creatorSoldPct != null && s.creatorBoughtPct >= 1) {
    if (s.creatorSoldPct >= 50) hit(22, 'high', 'creatorSoldPct', `The creator has sold or moved ${round(s.creatorSoldPct, 0)}% of their launch buy.`);
    else if (s.creatorSoldPct >= 10) hit(8, 'medium', 'creatorSoldPct', `The creator has sold or moved ${round(s.creatorSoldPct, 0)}% of their launch buy.`);
  }
  if (s.creatorPct >= 20) hit(22, 'high', 'creatorPct', `The creator wallet holds ${pct(s.creatorPct)} of supply.`);
  else if (s.creatorPct >= 10) hit(12, 'medium', 'creatorPct', `The creator wallet holds ${pct(s.creatorPct)} of supply.`);
  else if (s.creatorPct >= 5) hit(5, 'low', 'creatorPct', `The creator wallet holds ${pct(s.creatorPct)} of supply.`);
  if (s.devLaunches >= 50) hit(20, 'high', 'devLaunches', `The dev wallet has launched ${s.devLaunches} tokens${s.devGraduated != null ? `, ${s.devGraduated} graduated` : ''}: a serial launcher.`);
  else if (s.devLaunches >= 10) hit(10, 'medium', 'devLaunches', `The dev wallet has launched ${s.devLaunches} tokens${s.devGraduated != null ? `, ${s.devGraduated} graduated` : ''}.`);
  if (s.organicScore != null && s.organicScore < 20 && s.trades24h > 50) hit(8, 'medium', 'organicScore', `Most trading looks automated (organic score ${s.organicScore}/100).`);
  if (s.holders != null && s.holders < 20 && s.stage !== 'unlisted') hit(6, 'low', 'holders', `Only ${s.holders} holders.`);
  if (s.top10Pct != null) {
    const t = `The top 10 holders own ${pct(s.top10Pct)} of supply (curve and pools excluded).`;
    if (s.top10Pct >= 50) hit(20, 'high', 'top10Pct', t);
    else if (s.top10Pct >= 35) hit(12, 'medium', 'top10Pct', t);
    else if (s.top10Pct >= 25) hit(5, 'low', 'top10Pct', t);
  }
  if (s.stage !== 'curve' && s.liquidityUsd != null && s.liquidityUsd < 5000) hit(10, 'medium', 'liquidityUsd', `Only $${s.liquidityUsd.toLocaleString('en-US')} of liquidity: hard to sell any size.`);
  if (s.stage === 'unlisted') hit(10, 'medium', 'stage', 'No liquidity found for this token.');
  if (s.trades24h === 0) hit(8, 'medium', 'trades24h', 'No trades in the last 24 hours.');
  if (!s.socials.length) hit(7, 'low', 'socials', 'No website or social links.');
  if (s.ageHours != null && s.ageHours < 0.25) hit(5, 'low', 'ageHours', 'Launched minutes ago: holder data is still thin.');
  if (s.volume24hUsd != null && s.volume24hUsd < 1000 && s.trades24h !== 0) hit(4, 'low', 'volume24hUsd', `24h volume is only $${s.volume24hUsd}.`);

  const notes = [];
  if (isPump && !launch) notes.push('Launch block not traced: over 8,000 curve transactions, so bundle and creator-sell checks were skipped.');
  if (!tops.length) notes.push(s.top10Pct != null ? 'Top 10 share comes from Jupiter: the on-chain holder list was unavailable.' : 'Holder list unavailable right now, so concentration checks were skipped.');

  const good = [];
  if (!s.mintAuthority && !s.freezeAuthority) good.push('Mint and freeze authority are revoked: supply is fixed and nobody can freeze your tokens.');
  if (s.stage === 'graduated') good.push('Graduated from the pump.fun curve.');
  if (s.stage === 'curve') good.push(`On the pump.fun curve, ${s.curveProgressPct}% to graduation.`);
  if (s.creatorSoldPct != null && s.creatorSoldPct < 10 && s.creatorBoughtPct >= 1) good.push('The creator has not sold.');
  if (s.bundledWallets === 0) good.push('No other wallets bought in the launch block.');
  if (s.holders >= 300) good.push(`${s.holders.toLocaleString('en-US')} holders.`);
  if (s.devGraduated >= 1 && s.devLaunches != null && s.devLaunches <= 5) good.push(`The dev has graduated ${s.devGraduated} of ${s.devLaunches} launches.`);

  const score = Math.max(0, Math.min(100, 100 + reasons.reduce((t, r) => t + r.impact, 0)));
  const verdict = verdictFor(score);
  return {
    token: mint,
    name, symbol, decimals,
    score, verdict: verdict.id,
    summary: `${symbol || 'Token'}: ${verdict.id} (${score}/100). ${reasons.filter((r) => r.severity !== 'low').map((r) => r.text).slice(0, 3).join(' ') || verdict.text}`,
    reasons: reasons.sort((a, b) => a.impact - b.impact),
    positives: good,
    notes,
    signals,
    pump: isPump ? { curve, launchSlot: launch?.slot || null } : null,
    links: { pump: isPump ? `https://pump.fun/coin/${mint}` : null, dexscreener: `https://dexscreener.com/solana/${mint}`, solscan: `https://solscan.io/token/${mint}` },
    checkedAt: new Date().toISOString(),
    tookMs: Date.now() - started,
    rpcCalls: rpc.calls,
    version: VERSION,
    disclaimer: 'Automated risk signals from public data. Not financial advice.',
  };
}
