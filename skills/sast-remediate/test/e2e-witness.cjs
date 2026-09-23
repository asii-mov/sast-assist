#!/usr/bin/env node
'use strict';
// End-to-end proof of the differential witness and the functional control.
// Run: node test/e2e-witness.cjs   (boots the fixture app on loopback, three trees)
//
// The case that matters is head-cheat. Its differential passes: the attack genuinely stops
// working. It would satisfy the guard, the witness, the rescan and a diff-reading auditor.
// Only the control catches it, because the control asks the other question: does the
// legitimate path still work.

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.resolve(ROOT, '../../fixtures/vuln-app');
const { discoverAppHarness, boot } = require(path.join(ROOT, 'bin/app-harness.cjs'));
const { runWitness, witnessObligations } = require(path.join(ROOT, 'bin/witness-run.cjs'));

const HONEST = `const fs = require('fs');
const path = require('path');
const url = require('url');

const ROOT = path.resolve(__dirname, '..', '..', 'public');

function read(req, res) {
  const name = url.parse(req.url, true).query.name;
  const target = path.resolve(ROOT, String(name || ''));
  if (target !== ROOT && !target.startsWith(ROOT + path.sep)) {
    res.statusCode = 400;
    return res.end('bad name');
  }
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) { res.statusCode = 404; return res.end('not found'); }
    res.setHeader('content-type', 'text/plain');
    res.end(data);
  });
}

module.exports = { read };
`;

const CHEAT = `const url = require('url');

function read(req, res) {
  const name = url.parse(req.url, true).query.name;
  res.statusCode = 404;
  res.end('not found');
}

module.exports = { read };
`;

const witness = {
  tier: 'dynamic',
  harness_id: 'npm_start',
  attack: { method: 'GET', path: '/files', headers: {}, query: { name: '../secret.txt' },
            body: { kind: 'none' }, as_principal: 'dummy_anonymous' },
  observable: { kind: 'body_contains', canary: 'CANARY_DUMMY_SECRET_d41d8cd9' },
  control: {
    kind: 'http',
    exchange: { method: 'GET', path: '/files', headers: {}, query: { name: 'hello.txt' },
                body: { kind: 'none' }, as_principal: 'dummy_anonymous' },
    expect: { kind: 'body_contains', canary: 'public file' },
  },
  expected_pre_fix: 'observable_fires',
  expected_post_fix: 'observable_absent',
};

const freePort = () => new Promise((res) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
});

// Pids whose working directory is inside `dir`. Every booted app runs from one of the trees
// under the work dir, so an empty list means every app was shut down. Linux only (/proc).
const runningUnder = (dir) => {
  const out = [];
  for (const pid of fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d))) {
    try {
      const cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      if (cwd === dir || cwd.startsWith(dir + path.sep)) out.push(Number(pid));
    } catch { /* exited, zombie, or not ours to read */ }
  }
  return out;
};
// A SIGKILL lands asynchronously, so give the kernel a moment before calling it a leak.
const settle = async (dir) => {
  for (let i = 0; i < 20 && runningUnder(dir).length; i++) await new Promise((r) => setTimeout(r, 100));
  return runningUnder(dir);
};
const canSeeProcs = process.platform === 'linux' && fs.existsSync('/proc/self/cwd');

(async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-e2e-'));
  const tree = (name, patch) => {
    const d = path.join(work, name);
    fs.cpSync(FIXTURE, d, { recursive: true });
    if (patch) fs.writeFileSync(path.join(d, 'src/routes/files.js'), patch);
    return d;
  };
  const base = tree('base', null);
  const trees = { honest: tree('head-honest', HONEST), cheat: tree('head-cheat', CHEAT) };
  const harness = discoverAppHarness(base)[0];

  let pass = 0, fail = 0;
  const pending = [];
  const t = (n, fn) => {
    const done = (e) => {
      if (e) { fail++; console.log(`  FAIL ${n}\n         ${e.message}`); }
      else { pass++; console.log(`  ok   ${n}`); }
    };
    try {
      const r = fn();
      if (r && typeof r.then === 'function') pending.push(r.then(() => done(), done));
      else done();
    } catch (e) { done(e); }
  };

  try {
    assert.ok(harness, 'a harness must be discoverable for the fixture app');
    const results = {};
    for (const [name, dir] of Object.entries(trees)) {
      const [pb, ph] = [await freePort(), await freePort()];
      const b = await boot(harness, base, { port: pb });
      const h = await boot(harness, dir, { port: ph });
      try {
        assert.ok(b.ok && h.ok, `boot failed: ${b.why || h.why || ''}`);
        results[name] = await runWitness(witness, { base: b, head: h }, { allowDynamic: true });
      } finally { b.kill(); h.kill(); }
    }

    const leftAfterBoots = canSeeProcs ? await settle(work) : [];
    const obligations = await witnessObligations(witness,
      { baseDir: base, headDir: trees.honest, harnesses: [harness] }, { allowDynamic: true });
    const leftAfterObligations = canSeeProcs ? await settle(work) : [];

    console.log('\ne2e: dynamic witness');
    t('the attack actually works on base (a vacuous witness proves nothing)', () => {
      assert.strictEqual(results.honest.pre.signal, true);
      assert.ok(results.honest.pre.detail.includes('200'));
    });
    t('an honest fix stops the attack and keeps the control green', () => {
      assert.strictEqual(results.honest.post.signal, false);
      assert.strictEqual(results.honest.control.passed_post, true);
      assert.strictEqual(results.honest.differential_ok, true);
      assert.strictEqual(results.honest.failure, null);
    });
    t('a fix that disables the endpoint still passes the DIFFERENTIAL', () => {
      // This is why obligations 3 and 4 are a pair and neither is sufficient alone.
      assert.strictEqual(results.cheat.differential_ok, true,
        'the attack does stop working, which is exactly the trap');
    });
    t('and is rejected by the functional control', () => {
      assert.strictEqual(results.cheat.control.passed_post, false);
      assert.strictEqual(results.cheat.control_ok, false);
      assert.strictEqual(results.cheat.failure, 'witness_control_failed');
    });
    t('the dynamic tier refuses to run unless explicitly opted in', async () => {
      // Guards the deferral: a repo that happens to have a bootable app is never driven
      // by default. See design/FUTURE-IMPROVEMENTS.md.
      let threw = false;
      try { await runWitness(witness, {}, {}); } catch (e) {
        threw = /opt-in/.test(e.message);
      }
      assert.ok(threw, 'runWitness must reject a dynamic witness without allowDynamic');
    });
    t('the parent records a transcript with headers redacted', () => {
      const tr = results.honest.transcript;
      assert.ok(tr.length >= 4, 'control-base, attack-base, attack-head, control-head');
      assert.deepStrictEqual(tr.map((x) => `${x.label}:${x.tree}`),
        ['control:base', 'attack:base', 'attack:head', 'control:head']);
      const hdrs = Object.values(tr[0].headers);
      assert.ok(hdrs.length > 0 && !hdrs.includes(undefined));
    });
    t('witnessObligations boots both trees and reports the honest fix as passing', () => {
      assert.strictEqual(obligations.differential_witness.status, 'pass');
      assert.strictEqual(obligations.functional_control.status, 'pass');
    });
    t('no app is left running after the witness shuts down', () => {
      if (!canSeeProcs) { console.log('         (skipped: no /proc on this platform)'); return; }
      assert.deepStrictEqual(leftAfterBoots, [], `apps still running after boot().kill(): ${leftAfterBoots}`);
      assert.deepStrictEqual(leftAfterObligations, [],
        `apps still running after witnessObligations returned: ${leftAfterObligations}`);
    });
    await Promise.all(pending);
  } finally {
    if (canSeeProcs) for (const pid of runningUnder(work)) { try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ } }
    fs.rmSync(work, { recursive: true, force: true });
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
