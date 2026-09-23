#!/usr/bin/env node
// One headless agent call, and the only place this skill talks to a model.
//
// An agent's word is not evidence, so nothing here trusts the text it gets back. The result is
// extracted, parsed and validated against the schema the caller named before it is allowed out
// as `ok`. A result that fails any of those is DISCARDED whole and re-asked once. Repairing it
// would make this file a co-author of the answer, and the answer is the thing under test.

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { validate } from './validate.ts';

const CLI = 'claude';
const DEFAULT_TIMEOUT_MS = 300000;

// --------------------------------------------------------------------- invoke

// Agents run inside the target, so without these flags the target's CLAUDE.md, its settings
// hooks and the operator's plugin hooks all apply to the call. Measured on claude 2.1.280 in
// .work/probe/isolation.txt. --bare would also isolate, but it never reads the keychain login.
const ISOLATION = ['--setting-sources', 'user', '--settings', '{"disableAllHooks":true}'];

// --allowed-tools only pre-approves; the tool set and the permission mode decide the rest, and the
// operator's mode was `auto`. So the set is named with --tools, anything unlisted is refused by
// dontAsk, MCP servers are dropped, and --restricted holds file tools to the cwd. Measured on
// claude 2.1.280 in .work/probe/sandbox.txt.
const CONFINEMENT = ['--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk'];

function argvFor({ prompt, model, tools }: { prompt: string; model?: string | null; tools: string[] }) {
  const argv = ['-p', prompt, '--output-format', 'json', ...ISOLATION, ...CONFINEMENT,
    '--tools', tools.join(',')];
  if (model) argv.push('--model', model);
  // Variadic on the CLI side, so it goes last or it swallows whatever follows it.
  argv.push('--allowed-tools', ...tools);
  return argv;
}

// The injectable seam. `exec(argv, {cwd, timeoutMs}) -> {code, stdout, stderr, timedOut}`.
// Tests pass their own; nothing else in the skill spawns a model.
type ExecResult = { code: number; stdout: string; stderr: string; timedOut: boolean };

function realExec(argv: string[], { cwd, timeoutMs, command = CLI }: { cwd?: string; timeoutMs?: number; command?: string } = {}): Promise<ExecResult> {
  return new Promise((resolve) => {
    // detached gives the child its own process group. The CLI spawns tool subprocesses of its
    // own, and killing the parent alone leaves those holding the run open past its budget.
    const child = spawn(command, argv, { cwd, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ } };
    const guard = setTimeout(() => { timedOut = true; kill(); }, timeoutMs || DEFAULT_TIMEOUT_MS);
    child.on('error', (e) => {
      clearTimeout(guard);
      resolve({ code: -1, stdout, stderr: `${stderr}${e.message}`, timedOut });
    });
    child.on('close', (code) => { clearTimeout(guard); resolve({ code, stdout, stderr, timedOut }); });
  });
}

// ------------------------------------------------------------------- envelope

// Measured against claude 2.1.278, not assumed: `-p ... --output-format json` prints an ARRAY
// of events whose last `type: "result"` element carries the answer as a string in `result`.
// Other builds print that element by itself, so both shapes are read.
function resultText(stdout) {
  let envelope;
  try { envelope = JSON.parse(stdout); } catch { return { error: 'envelope is not JSON' }; }
  const events = Array.isArray(envelope) ? envelope : [envelope];
  let result = null;
  for (const e of events) if (e && e.type === 'result') result = e;
  if (!result) return { error: 'envelope carries no result event' };
  if (result.is_error || (result.subtype && result.subtype !== 'success')) {
    return { error: `agent reported failure (${result.subtype || 'unknown'})` };
  }
  if (typeof result.result !== 'string') return { error: 'result event carries no text' };
  return { text: result.result };
}

// The outermost balanced object, returned parsed, or null. A loose regex stops at the first
// `}` and a greedy one eats a brace out of the prose that follows, and both failures hand the
// caller something that still looks like valid JSON.
//
// Candidates are tried outermost first and a candidate that is not JSON is stepped past, not
// patched: agents write `{like this}` in prose, and the brace counter cannot tell that span
// from the answer. Stepping past is a narrower read of the text, never a repair of it.
function extractJson(text) {
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '{') continue;
    let depth = 0;
    let inStr = false;
    let esc = false;
    for (let j = i; j < text.length; j++) {
      const c = text[j];
      if (esc) { esc = false; continue; }
      if (c === '\\') { if (inStr) esc = true; continue; }
      if (c === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (c === '{') depth++;
      else if (c === '}' && --depth === 0) {
        try { return JSON.parse(text.slice(i, j + 1)); } catch { break; }
      }
    }
  }
  return null;
}

// ------------------------------------------------------------------ validate

const SCHEMA_CACHE = new Map();

function schemaAt(schemaPath, pointer) {
  const abs = path.resolve(schemaPath);
  if (!SCHEMA_CACHE.has(abs)) SCHEMA_CACHE.set(abs, JSON.parse(fs.readFileSync(abs, 'utf8')));
  const doc = SCHEMA_CACHE.get(abs);
  return { root: { $ref: pointer, ...(doc.$defs ? { $defs: doc.$defs } : {}) }, dir: path.dirname(abs) };
}

// ----------------------------------------------------------------- one attempt

async function attempt(opts, exec) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const run = await exec(argvFor(opts), { cwd: opts.cwd, timeoutMs });

  // A timeout is a failure, and it is the one failure that is not re-asked: the budget it was
  // given is already spent, and spending it twice is the hang this rule exists to prevent.
  if (run.timedOut) {
    return { ok: false, reason: `timed out after ${timeoutMs}ms`, raw: run.stdout || '', spent: true };
  }
  if (run.code !== 0) {
    return { ok: false, reason: `cli exited ${run.code}`, raw: run.stderr || run.stdout || '' };
  }

  const envelope = resultText(run.stdout || '');
  if (envelope.error) return { ok: false, reason: envelope.error, raw: run.stdout || '' };

  const data = extractJson(envelope.text);
  if (data === null) return { ok: false, reason: 'no JSON object in result', raw: envelope.text };

  const { root, dir } = schemaAt(opts.schemaPath, opts.schemaPointer);
  const errs = validate(root, data, dir);
  // A schema failure is malformed output. It takes the discard path, not a repair path.
  if (errs.length) {
    return { ok: false, reason: `schema: ${errs.join('; ')}`, raw: envelope.text };
  }
  return { ok: true, data };
}

async function runAgent(opts) {
  if (!opts || typeof opts.prompt !== 'string' || opts.prompt.length === 0) {
    throw new Error('runAgent needs a prompt');
  }
  if (!opts.schemaPath || !opts.schemaPointer) {
    throw new Error('runAgent needs schemaPath and schemaPointer: an unvalidated result is not a result');
  }
  if (!Array.isArray(opts.tools) || opts.tools.length === 0) {
    throw new Error('runAgent needs tools: without --tools the CLI default set includes a shell');
  }
  const exec = opts.exec || realExec;

  const first = await attempt(opts, exec);
  if (first.ok) return { ok: true, data: first.data };
  if (first.spent) return { ok: false, reason: first.reason, raw: first.raw };

  // Exactly one re-ask, with a fresh call and the same prompt. Never two.
  const second = await attempt(opts, exec);
  if (second.ok) return { ok: true, data: second.data };
  return { ok: false, reason: `discarded twice: ${first.reason} | ${second.reason}`, raw: second.raw };
}

export { runAgent, realExec, argvFor, resultText, extractJson, DEFAULT_TIMEOUT_MS };

if (import.meta.main) {
  const [schemaPath, pointer, ...rest] = process.argv.slice(2);
  const prompt = rest.join(' ');
  if (!schemaPath || !pointer || !prompt) {
    console.error('usage: agent.ts <schema.json> <#/$defs/name> <prompt>');
    process.exit(2);
  }
  runAgent({ prompt, schemaPath, schemaPointer: pointer, tools: ['Read', 'Grep', 'Glob'] }).then((r) => {
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  });
}
