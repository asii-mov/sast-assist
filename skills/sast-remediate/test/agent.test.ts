#!/usr/bin/env node
// Run: node test/agent.test.ts
// Every model call here is a fake `exec`. The suite never runs the real CLI and never touches
// the network. The one real subprocess is a node child used to prove the group kill, because
// a timeout that leaves a grandchild running is the failure the kill exists to prevent.

import fs from 'fs';
import os from 'os';
import path from 'path';
import assert from 'assert';
import { runAgent, realExec, argvFor, extractJson } from '../bin/agent.ts';

const ROOT = path.resolve(import.meta.dirname, '..');

const SCHEMA = path.join(ROOT, 'schema/agent-results.schema.json');
const TRIAGE = '#/$defs/triage';
const TOOLS = ['Read'];

const tests = [];
const t = (name, fn) => tests.push([name, fn]);
const section = (s) => tests.push([s, null]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A queued fake. It throws when the runner asks for a call the test did not queue, so an extra
// retry is a failure rather than a silent reuse of the last answer.
const fakeExec = (...runs) => {
  const queue = [...runs];
  const calls = [];
  const exec = async (argv, opts) => {
    calls.push({ argv, ...opts });
    if (!queue.length) throw new Error(`exec called ${calls.length} times, test queued ${runs.length}`);
    return { code: 0, stdout: '', stderr: '', timedOut: false, ...queue.shift() };
  };
  exec.calls = calls;
  exec.left = () => queue.length;
  return exec;
};

// The shape observed from claude 2.1.278: an array of events, answer in the last result event.
const envelope = (text, over = {}) => ({
  stdout: JSON.stringify([
    { type: 'system', subtype: 'init', session_id: 'x' },
    { type: 'assistant', message: {} },
    { type: 'result', subtype: 'success', is_error: false, result: text, num_turns: 1, ...over },
  ]),
});

const GOOD = {
  verdict: 'not_exploitable',
  established_by: 'agent',
  refutation: { reason: 'unreachable_code', control: null, explanation: 'branch is dead' },
};

section('envelope: the shape the real CLI prints');

t('clean JSON in the result text validates and returns ok on one call', async () => {
  const exec = fakeExec(envelope(JSON.stringify(GOOD)));
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
  assert.deepStrictEqual(r.data, GOOD);
  assert.strictEqual(exec.calls.length, 1);
});

t('prose around the object is stripped, braces in the prose and nesting survive it', async () => {
  const text = `Here is my call {see below}. I judged it safe.\n\n\`\`\`json\n${
    JSON.stringify(GOOD)}\n\`\`\`\n\nHappy to re-check {if asked}.`;
  const exec = fakeExec(envelope(text));
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
  assert.deepStrictEqual(r.data, GOOD);
});

t('a bare result object, not an array, is read the same way', async () => {
  const exec = fakeExec({ stdout: JSON.stringify({ type: 'result', subtype: 'success', result: JSON.stringify(GOOD) }) });
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
});

t('is_error in the envelope is a failure even when the text parses', async () => {
  const bad = envelope(JSON.stringify(GOOD), { is_error: true, subtype: 'error_during_execution' });
  const exec = fakeExec(bad, bad);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /reported failure/);
});

t('stdout that is not JSON at all is a failure, not a crash', async () => {
  const junk = { stdout: 'claude: command failed\n' };
  const exec = fakeExec(junk, junk);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /not JSON/);
});

section('discard and re-ask exactly once');

t('malformed then good returns ok on the second call', async () => {
  const exec = fakeExec(envelope('I could not decide, sorry.'), envelope(JSON.stringify(GOOD)));
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
  assert.deepStrictEqual(r.data, GOOD);
  assert.strictEqual(exec.calls.length, 2, 'the re-ask must be a fresh call');
});

t('malformed twice gives up, and the third call is never made', async () => {
  const junk = envelope('no object here');
  const spare = envelope(JSON.stringify(GOOD));
  const exec = fakeExec(junk, junk, spare);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(exec.calls.length, 2, 'never two retries');
  assert.strictEqual(exec.left(), 1, 'a third call would have consumed the spare good answer');
  assert.match(r.reason, /discarded twice/);
  assert.strictEqual(typeof r.raw, 'string');
  assert.match(r.raw, /no object here/, 'raw carries what was discarded');
});

t('truncated JSON is discarded, never repaired into an object', async () => {
  const cut = envelope('{"verdict":"not_exploitable","established_by":"agent"');
  const exec = fakeExec(cut, cut);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(exec.calls.length, 2);
});

t('a non-zero exit is re-asked once like any other discard', async () => {
  const exec = fakeExec({ code: 1, stderr: 'boom' }, envelope(JSON.stringify(GOOD)));
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(exec.calls.length, 2);
});

section('schema validation stands between the agent and ok');

t('well formed JSON of the wrong shape is rejected, not returned', async () => {
  const wrong = envelope(JSON.stringify({ verdict: 'exploitable', severity: 'critical' }));
  const exec = fakeExec(wrong, wrong);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /schema:/);
  assert.strictEqual(r.data, undefined, 'a schema failure must not leak data');
});

t('a severity on a not_exploitable verdict is rejected', async () => {
  // The rule the schema exists to hold: only exploitable carries a severity.
  const sneaky = envelope(JSON.stringify({ ...GOOD, severity: 'high' }));
  const exec = fakeExec(sneaky, sneaky);
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /schema:/);
});

t('schema-invalid then valid returns the valid one', async () => {
  const exec = fakeExec(envelope('{"verdict":"nope"}'), envelope(JSON.stringify(GOOD)));
  const r = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, exec });
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(exec.calls.length, 2);
});

t('the fix pointer validates a fix envelope and rejects a triage one', async () => {
  const fix = { outcome: 'cannot_fix', reason: 'the contract cannot be met here' };
  const okExec = fakeExec(envelope(JSON.stringify(fix)));
  const good = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: '#/$defs/fix', tools: TOOLS, exec: okExec });
  assert.strictEqual(good.ok, true, good.reason);

  const mixed = envelope(JSON.stringify(GOOD));
  const badExec = fakeExec(mixed, mixed);
  const bad = await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: '#/$defs/fix', tools: TOOLS, exec: badExec });
  assert.strictEqual(bad.ok, false, 'a triage result must not pass as a fix');
});

t('a caller that names no schema is refused outright', async () => {
  const exec = fakeExec(envelope(JSON.stringify(GOOD)));
  await assert.rejects(
    () => runAgent({ prompt: 'p', tools: TOOLS, exec }),
    /schemaPath/,
    'an unvalidated result is not a result',
  );
  assert.strictEqual(exec.calls.length, 0, 'it must refuse before spending a call');
});

section('timeout is a failure, not a hang');

t('a timed out call fails and is not re-asked', async () => {
  const exec = fakeExec({ timedOut: true, stdout: '' }, envelope(JSON.stringify(GOOD)));
  const r = await runAgent({
    prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, timeoutMs: 1500, exec,
  });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /timed out after 1500ms/);
  assert.strictEqual(exec.calls.length, 1, 'the budget is spent once, never twice');
  assert.strictEqual(exec.left(), 1);
});

t('the default budget is 300000ms and cwd reaches the runner', async () => {
  const exec = fakeExec(envelope(JSON.stringify(GOOD)));
  await runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: TOOLS, cwd: '/tmp', exec });
  assert.strictEqual(exec.calls[0].timeoutMs, 300000);
  assert.strictEqual(exec.calls[0].cwd, '/tmp');
});

t('realExec kills the whole process group, not just the child it spawned', async () => {
  // Without detached plus kill(-pid) the grandchild outlives the timeout and holds the run
  // open. This is the only real subprocess in the suite, and it is node, not the CLI.
  const script = 'const {spawn}=require("child_process");'
    + 'const kid=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});'
    + 'require("fs").writeFileSync(process.argv[1],String(kid.pid));'
    + 'setInterval(()=>{},1000);';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-agent-'));
  const pidFile = path.join(dir, 'kid.pid');
  let kid = 0;
  try {
    const run = await realExec(['-e', script, pidFile], { command: process.execPath, timeoutMs: 1200 });
    assert.strictEqual(run.timedOut, true, 'the guard must fire');
    kid = Number(fs.readFileSync(pidFile, 'utf8'));
    assert.ok(kid > 0, 'the grandchild never started');
    await sleep(400);
    assert.throws(() => process.kill(kid, 0), /ESRCH/, `grandchild ${kid} survived the group kill`);
    kid = 0;
  } finally {
    if (kid) { try { process.kill(kid, 'SIGKILL'); } catch { /* gone */ } }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

section('argv and extraction');

t('every call is confined: the role\'s tools only, no MCP, dontAsk, file tools held to the cwd, allowed tools last', () => {
  const argv = argvFor({ prompt: 'hello', model: 'opus', tools: ['Read', 'Grep'] });
  assert.deepStrictEqual(argv, [
    '-p', 'hello', '--output-format', 'json',
    '--setting-sources', 'user', '--settings', '{"disableAllHooks":true}',
    '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
    '--tools', 'Read,Grep',
    '--model', 'opus', '--allowed-tools', 'Read', 'Grep',
  ]);
  const last = argv.indexOf('--allowed-tools');
  assert.ok(argv.slice(last + 1).every((a) => !a.startsWith('--')), 'a variadic flag must end the argv');
  assert.deepStrictEqual(argvFor({ prompt: 'hello', tools: ['Read'] }).slice(-4),
    ['--tools', 'Read', '--allowed-tools', 'Read']);
});

t('a call with no tool list is refused before the CLI runs, because the default set has a shell', async () => {
  const exec = fakeExec();
  await assert.rejects(runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, exec }),
    /runAgent needs tools/);
  await assert.rejects(runAgent({ prompt: 'p', schemaPath: SCHEMA, schemaPointer: TRIAGE, tools: [], exec }),
    /runAgent needs tools/);
  assert.strictEqual(exec.calls.length, 0);
});

t('extraction takes the outermost object, not the first closing brace', () => {
  const nested = { a: { b: 1 }, c: '}{' };
  assert.deepStrictEqual(extractJson(`prefix ${JSON.stringify(nested)} suffix`), nested);
});

t('a prose brace span is stepped past, and a nested object is not mistaken for it', () => {
  const text = `I note {see above} then answer {"a":{"b":1},"c":"}{"} and stop`;
  assert.deepStrictEqual(extractJson(text), { a: { b: 1 }, c: '}{' });
});

t('an escaped quote inside a string does not end the string', () => {
  const obj = { why: 'he said "no\\" really"' };
  assert.deepStrictEqual(extractJson(`talk ${JSON.stringify(obj)} talk`), obj);
});

t('text with no object at all extracts nothing', () => {
  assert.strictEqual(extractJson('no braces here'), null);
  assert.strictEqual(extractJson('{ unclosed'), null);
  assert.strictEqual(extractJson('{"a":1'), null, 'a truncated object is not half-read');
});

(async () => {
  let pass = 0;
  let fail = 0;
  for (const [name, fn] of tests) {
    if (fn === null) { console.log(`\n${name}`); continue; }
    try { await fn(); pass++; console.log(`  ok   ${name}`); }
    catch (e) { fail++; console.log(`  FAIL ${name}\n         ${e.message}`); }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
