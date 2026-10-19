#!/usr/bin/env node
// ORIGIN ambient capture for Claude Code. Zero dependencies.
//
// Registered for three documented Claude Code hook events:
//   SessionStart       records how the session began (startup, resume, clear, compact)
//   UserPromptSubmit   (1) first message: sends the prompt's TEXT only if it is the first message
//                      of a session that began fresh and whose transcript holds no model turn
//                      before it (Ruling 3);
//                      (2) every turn: commits to the prompt (salted) and sends ONLY the commitment
//   Stop               every turn: commits to the model's reply and sends only the commitment
//
// Every-turn capture is the person's own switch (off by default, turned on in ORIGIN). The text
// and salt of each turn stay in ~/.origin/turns/<session>.jsonl (mode 0600) on this machine, so
// the person alone can later reveal a turn and anyone can check it against its commitment.
//
// What a capture establishes: a turn by this role at this position of a Claude Code session, at
// ORIGIN's server time. Never who composed the text.
//
// It never blocks or changes your prompt: it prints nothing, always exits 0, and each request
// gives up after 6 seconds (the hook itself is capped at 10). Failures go to ~/.origin/hook.log.
//
// Opting out: stop it in ORIGIN (Projects & connections), or run /origin:pause (it creates
// ~/.origin/ambient-off), or set ORIGIN_AMBIENT=off, or disable the plugin.
//
// Configuration, written by /origin:connect: ~/.origin/config.json (mode 0600) holding the site URL
// and the connection token. Overrides: ORIGIN_URL, ORIGIN_TOKEN. Older installs: the token in
// ~/.origin/claude-code-token.

import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const dir = join(homedir(), '.origin');
const stateDir = join(dir, 'claude-code-sessions');
const turnsDir = join(dir, 'turns');
const log = (msg) => {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    appendFileSync(join(dir, 'hook.log'), `${new Date().toISOString()} ${msg}\n`, { mode: 0o600 });
  } catch {}
};

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

function transcript(path) {
  if (!path || !existsSync(path)) return [];
  const out = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch {}
  }
  return out;
}

const isAssistant = (e) => e.type === 'assistant' || e.message?.role === 'assistant';
const textOf = (content) =>
  typeof content === 'string' ? content : Array.isArray(content) ? content.filter((b) => b?.type === 'text').map((b) => b.text).join('\n') : '';
// A human prompt, as opposed to a tool result the host files under the user role.
const isHumanPrompt = (e) =>
  (e.type === 'user' || e.message?.role === 'user') &&
  (typeof e.message?.content === 'string' || (Array.isArray(e.message?.content) && e.message.content.some((b) => b?.type === 'text')));

/** The model's reply since the last human prompt: its text blocks, in order. */
function lastModelReply(entries) {
  let start = 0;
  entries.forEach((e, i) => { if (isHumanPrompt(e)) start = i + 1; });
  return entries.slice(start).filter(isAssistant).map((e) => textOf(e.message?.content)).filter(Boolean).join('\n');
}

// JCS for {kind, role, text}: keys already in sorted order, string values only.
const canonicalTurn = (role, text) => JSON.stringify({ kind: 'turn', role, text });
function commit(canonical) {
  const salt = randomBytes(32);
  const commitment = createHash('sha256').update('ORIGIN-COMMIT-v1\n').update(salt).update(canonical, 'utf8').digest('hex');
  return { salt_b64: salt.toString('base64'), commitment };
}

function config() {
  try { return JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')); } catch { return {}; }
}
function token() {
  if (process.env.ORIGIN_TOKEN) return process.env.ORIGIN_TOKEN;
  if (config().token) return config().token;
  // A token from before pairing existed belongs to a local ORIGIN; only the old hand-installed
  // hook (which points at that local instance) may use it, never the plugin.
  if (!process.env.ORIGIN_LEGACY_LOCAL) return '';
  const f = join(dir, 'claude-code-token');
  return existsSync(f) ? readFileSync(f, 'utf8').trim() : '';
}
const baseUrl = () => (process.env.ORIGIN_URL || config().url || 'https://theoriginrecord.com').replace(/\/$/, '');

async function post(body) {
  const res = await fetch(baseUrl() + '/api/ingest/claude-code', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token()}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(6000),
  });
  const text = await res.text();
  return { ok: res.ok, status: res.status, json: (() => { try { return JSON.parse(text); } catch { return null; } })(), text };
}

async function sendTurn(sid, state, role, text) {
  if (!text) return;
  const sequence = (state.seq ?? 0) + 1;
  const canonical = canonicalTurn(role, text);
  const { salt_b64, commitment } = commit(canonical);
  const r = await post({ host: 'claude-code', kind: 'turn', host_session_id: sid, role, sequence, commitment, ...(state.idea_id ? { idea_id: state.idea_id } : {}) });
  if (r.status === 403) { state.turns_off = true; return; } // the person has not switched every-turn capture on
  if (!r.ok) return log(`turn refused (${r.status}): ${r.text.slice(0, 200)}`);
  state.seq = sequence;
  mkdirSync(turnsDir, { recursive: true, mode: 0o700 });
  appendFileSync(join(turnsDir, `${sid}.jsonl`), JSON.stringify({ sequence, role, salt_b64, canonical, commitment, event_id: r.json?.event_id, at: new Date().toISOString() }) + '\n', { mode: 0o600 });
}

async function main() {
  if (process.env.ORIGIN_AMBIENT === 'off' || existsSync(join(dir, 'ambient-off'))) return;
  const input = await readStdin();
  const sid = String(input.session_id ?? '').replace(/[^A-Za-z0-9_-]/g, '');
  if (!sid) return;
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const stateFile = join(stateDir, `${sid}.json`);
  const state = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : {};
  const save = () => writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });

  if (input.hook_event_name === 'SessionStart') {
    Object.assign(state, { source: input.source ?? 'unknown', sent: false, seq: 0 });
    return save();
  }
  if (!token()) return log('no ORIGIN token configured; nothing sent');

  // Once, after a pairing finished in the background: show the person (not Claude) which account
  // this computer joined. systemMessage is displayed to the user; nothing enters Claude's context.
  const cfg = config();
  if (cfg.announce && cfg.token) {
    try { writeFileSync(join(dir, 'config.json'), JSON.stringify({ ...cfg, announce: false }, null, 2), { mode: 0o600 }); } catch {}
    process.stdout.write(JSON.stringify({ systemMessage: `ORIGIN: this computer is now connected to ${cfg.account ?? 'an ORIGIN account'}, recording into ${cfg.project_name ?? 'its project'}. If that is not your account, run /origin:disconnect now.` }));
  }

  if (input.hook_event_name === 'UserPromptSubmit') {
    const prompt = String(input.prompt ?? '');
    // (1) First message, with its text (Ruling 3).
    if (!state.sent && !state.declined) {
      if (state.source !== 'startup' && state.source !== 'clear') state.declined = 'session did not start fresh';
      else if (transcript(input.transcript_path).some(isAssistant)) state.declined = 'model turns precede this message';
      else {
        const r = await post({ host: 'claude-code', host_session_id: sid, session_source: state.source, prior_model_turns: 0, prompt });
        if (r.ok) Object.assign(state, { sent: true, idea_id: r.json?.idea_id });
        else if (r.status !== 403) log(`first message refused (${r.status}): ${r.text.slice(0, 200)}`);
      }
    }
    // (2) Every turn, as a commitment only.
    if (!state.turns_off) await sendTurn(sid, state, 'human', prompt);
    return save();
  }

  if (input.hook_event_name === 'Stop') {
    if (!state.turns_off) await sendTurn(sid, state, 'model', lastModelReply(transcript(input.transcript_path)));
    return save();
  }
}

main().catch((e) => log(`error: ${e?.message ?? e}`)).finally(() => process.exit(0));
