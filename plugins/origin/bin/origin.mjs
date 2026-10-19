#!/usr/bin/env node
// ORIGIN for Claude Code: pairing and local controls. Zero dependencies.
//
//   origin.mjs connect [--label "…"]  pair this computer with your ORIGIN account
//   origin.mjs status                  what is configured here (never prints the token)
//   origin.mjs pause | resume          stop or restart recording from this computer
//   origin.mjs disconnect              forget this computer's connection (revoke it on the site too)
//   origin.mjs mcp-headers             for Claude Code's MCP headersHelper: the Authorization header
//
// Pairing never shows a token. This computer makes a one-time X25519 key pair and asks the site
// for a short code; you approve the code while signed in; the site seals the connection token to
// this computer's public key; a background step collects and opens it, and saves it to
// ~/.origin/config.json (mode 0600). The private key never leaves this computer.

import { createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, appendFileSync, chmodSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = join(homedir(), '.origin');
const configPath = join(dir, 'config.json');
const pairingPath = join(dir, 'pairing.json');
const pauseFlag = join(dir, 'ambient-off');
const ensureDir = () => { mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700); };
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
const writeSecret = (p, v) => { ensureDir(); writeFileSync(p, JSON.stringify(v, null, 2), { mode: 0o600 }); chmodSync(p, 0o600); };
const log = (m) => { try { ensureDir(); appendFileSync(join(dir, 'hook.log'), `${new Date().toISOString()} ${m}\n`, { mode: 0o600 }); } catch {} };
const site = () => (process.env.ORIGIN_URL || readJson(configPath)?.url || 'https://theoriginrecord.com').replace(/\/$/, '');

// Opening a token sealed by the site (src/lib/pairing/seal.ts holds the sealing half).
function openSealed(privateKeyPem, sealedB64url) {
  const priv = createPrivateKey(privateKeyPem);
  const ownRaw = Buffer.from(createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  const buf = Buffer.from(sealedB64url, 'base64url');
  const ephRaw = buf.subarray(0, 32);
  const eph = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: ephRaw.toString('base64url') }, format: 'jwk' });
  const key = Buffer.from(hkdfSync('sha256', diffieHellman({ privateKey: priv, publicKey: eph }), Buffer.concat([ephRaw, ownRaw]), Buffer.from('ORIGIN-PAIR-v1'), 32));
  const d = createDecipheriv('aes-256-gcm', key, buf.subarray(32, 44));
  d.setAuthTag(buf.subarray(44, 60));
  return Buffer.concat([d.update(buf.subarray(60)), d.final()]).toString('utf8');
}

async function connect(args) {
  const label = args.includes('--label') ? args[args.indexOf('--label') + 1] : `Claude Code on ${hostname().replace(/\.local$/, '')}`;
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pub = publicKey.export({ format: 'jwk' }).x;
  const res = await fetch(`${site()}/api/pair`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ host: 'claude-code', public_key: pub, client_label: label }), signal: AbortSignal.timeout(10_000),
  }).catch((e) => ({ ok: false, status: 0, text: async () => e.message }));
  if (!res.ok) return console.log(`Could not reach ORIGIN at ${site()} (${res.status || 'network'}): ${(await res.text()).slice(0, 200)}`);
  const p = await res.json();
  writeSecret(pairingPath, { id: p.id, user_code: p.user_code, expires_at: p.expires_at, private_key: privateKey.export({ format: 'pem', type: 'pkcs8' }), url: site() });
  if (process.platform === 'darwin' && !process.env.ORIGIN_NO_BROWSER) spawn('open', [p.verification_url], { detached: true, stdio: 'ignore' }).unref();
  // Wait here for the approval, so the account this computer joins is the last thing shown.
  const waitMs = Number(process.env.ORIGIN_CONNECT_WAIT_MS ?? 90_000);
  const r = await collect({ until: Date.now() + waitMs });
  if (r === 'connected') return console.log(joinedLine());
  if (r && r !== 'pending') return console.log(`Your code ${p.user_code} ended without connecting (${r}). Run /origin:connect again for a fresh code.`);
  // Not approved yet: keep waiting in the background; the next prompt shows the account once.
  spawn(process.execPath, [fileURLToPath(import.meta.url), 'collect'], { detached: true, stdio: 'ignore' }).unref();
  console.log([
    `Your code: ${p.user_code}`,
    `Approve it at ${p.verification_url} (it should have opened in your browser). Check the code matches what is shown here.`,
    `Once you approve, the next message you send shows which account this computer joined. The code expires in 15 minutes.`,
  ].join('\n'));
}

function joinedLine() {
  const c = readJson(configPath) ?? {};
  return `Connected to ${c.account ?? 'an ORIGIN account'}, recording into ${c.project_name ?? 'its project'}. If that is not your account, run /origin:disconnect now.`;
}

/** Wait for the approval and save the connection. Returns 'connected', 'pending' (gave up waiting), or how it ended. */
async function collect({ until, announce = false } = {}) {
  const p = readJson(pairingPath);
  if (!p) return null;
  const deadline = Math.min(Date.parse(p.expires_at), until ?? Date.now() + 16 * 60_000);
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2500));
    const r = await fetch(`${p.url}/api/pair/${p.id}`, { method: 'POST', signal: AbortSignal.timeout(10_000) }).then((x) => x.json()).catch(() => null);
    if (!r || r.status === 'pending') continue;
    rmSync(pairingPath, { force: true });
    if (r.status !== 'approved') { log(`pairing ${p.user_code} ended: ${r.status}`); return r.status; }
    try {
      const opened = JSON.parse(openSealed(p.private_key, r.sealed));
      // announce: the hook shows the joined account once, on the next prompt (background collection).
      writeSecret(configPath, { url: p.url, token: opened.token, project_id: opened.project_id, connection_id: opened.connection_id, account: opened.account ?? null, project_name: opened.project_name ?? null, paired_at: new Date().toISOString(), announce });
      log(`paired with ${p.url} (connection ${opened.connection_id})`);
      return 'connected';
    } catch (e) { log(`pairing: could not open the sealed token: ${e.message}`); return 'failed'; }
  }
  if (Date.now() >= Date.parse(p.expires_at)) { rmSync(pairingPath, { force: true }); return 'expired'; }
  return 'pending';
}

async function status() {
  const c = readJson(configPath);
  const pending = readJson(pairingPath);
  const lines = [];
  if (c?.token) {
    lines.push(`Connected to the ORIGIN account ${c.account ?? '(account not recorded; run /origin:connect again to see it)'}, recording into ${c.project_name ?? 'its project'}, at ${c.url}, since ${c.paired_at ?? 'an earlier pairing'}.`);
    lines.push('If that is not your account, run /origin:disconnect at once and revoke it on the site.');
    const r = await fetch(`${c.url}/api/mcp`, { method: 'POST', headers: { authorization: `Bearer ${c.token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }), signal: AbortSignal.timeout(8000) }).catch(() => null);
    lines.push(!r ? 'ORIGIN could not be reached just now.' : r.status === 401 || r.status === 403 ? 'The site no longer accepts this connection (it was revoked). Run /origin:connect to pair again.' : 'The site accepts this connection.');
  } else if (pending) lines.push(`Waiting for approval of code ${pending.user_code} at ${pending.url}/connect.`);
  else lines.push('Not connected. Run /origin:connect.');
  lines.push(existsSync(pauseFlag) || process.env.ORIGIN_AMBIENT === 'off' ? 'Recording from this computer is paused (/origin:resume to restart).' : 'Recording from this computer is on.');
  const logFile = join(dir, 'hook.log');
  if (existsSync(logFile)) {
    const last = readFileSync(logFile, 'utf8').trim().split('\n').slice(-3);
    if (last.length) lines.push('Last notes from the hook:', ...last.map((l) => `  ${l.replace(/orgn_[a-z0-9]{12}_[A-Za-z0-9_-]{43}/g, '[token]')}`));
  }
  console.log(lines.join('\n'));
}

function mcpHeaders() {
  const t = process.env.ORIGIN_TOKEN || readJson(configPath)?.token;
  process.stdout.write(JSON.stringify(t ? { Authorization: `Bearer ${t}` } : {}));
}

const [cmd, ...rest] = process.argv.slice(2);
const run = {
  connect: () => connect(rest),
  collect: () => collect({ announce: true }),
  status,
  pause: () => { ensureDir(); writeFileSync(pauseFlag, ''); console.log('Paused: nothing is sent from this computer until /origin:resume.'); },
  resume: () => { rmSync(pauseFlag, { force: true }); console.log('Resumed: recording from this computer is on.'); },
  disconnect: () => { rmSync(configPath, { force: true }); console.log(`This computer no longer holds an ORIGIN connection. To revoke it on the site as well, open ${site()}/projects.`); },
  'mcp-headers': mcpHeaders,
}[cmd];
if (!run) { console.log('usage: origin.mjs connect | status | pause | resume | disconnect | mcp-headers'); process.exit(0); }
Promise.resolve(run()).catch((e) => console.log(`ORIGIN: ${e.message}`));
