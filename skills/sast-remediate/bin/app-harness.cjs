#!/usr/bin/env node
'use strict';
// Discover, boot, probe and tear down the target application. Discovery reads the repository
// and never invents a command. If nothing is found the dynamic witness tier is unavailable,
// which is a recorded obstacle, not a best-effort fallback.

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const exists = (root, rel) => fs.existsSync(path.join(root, rel));
const readJson = (root, rel) => {
  try { return JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8')); } catch { return null; }
};

// Readiness: prefer a real health route, else expect anything below 500 from the root.
function readyProbe(root) {
  const hints = ['/healthz', '/health', '/_health', '/ping', '/readyz'];
  let text = '';
  const walk = (d, depth) => {
    if (depth > 3) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (/\.(js|ts|py|rb|go|java)$/.test(e.name) && text.length < 400000) {
        try { text += fs.readFileSync(p, 'utf8'); } catch { /* unreadable file, skip */ }
      }
    }
  };
  try { walk(root, 0); } catch { /* unreadable tree */ }
  for (const h of hints) if (text.includes(h)) return { probe_path: h, expect_status: 200, timeout_s: 30 };
  return { probe_path: '/', expect_status: 0, timeout_s: 30 }; // 0 means "anything under 500"
}

function discoverAppHarness(root) {
  const out = [];
  const ready = readyProbe(root);
  const mk = (id, kind, up, extra = {}) => ({
    id, kind, up, ready, base_url: null, down: [], reset: null,
    fixtures: { seed: null, dummy_principals: ['dummy_user'] },
    boot_s_observed: null, ...extra,
  });

  // An explicit block always wins over inference.
  const toml = exists(root, '.sast-remediate.toml')
    ? fs.readFileSync(path.join(root, '.sast-remediate.toml'), 'utf8') : '';
  const custom = /\[harness\][\s\S]*?up\s*=\s*\[([^\]]+)\]/.exec(toml);
  if (custom) {
    const argv = custom[1].split(',').map((s) => s.trim().replace(/^["']|["']$/g, ''));
    return [mk('custom', 'custom', argv)];
  }

  for (const f of ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml']) {
    if (exists(root, f)) out.push(mk('compose', 'docker_compose', ['docker', 'compose', '-f', f, 'up']));
  }
  if (exists(root, 'Procfile')) {
    const web = /^web:\s*(.+)$/m.exec(fs.readFileSync(path.join(root, 'Procfile'), 'utf8'));
    if (web) out.push(mk('procfile', 'procfile', web[1].trim().split(/\s+/)));
  }
  const pkg = readJson(root, 'package.json');
  if (pkg && pkg.scripts) {
    for (const s of ['start', 'dev', 'serve']) {
      if (pkg.scripts[s]) { out.push(mk(`npm_${s}`, 'npm_script', ['npm', 'run', s])); break; }
    }
    if (!out.some((h) => h.kind === 'npm_script') && pkg.main) {
      out.push(mk('node_main', 'npm_script', ['node', pkg.main]));
    }
  }
  if (exists(root, 'manage.py')) out.push(mk('django', 'django', ['python', 'manage.py', 'runserver']));
  if (exists(root, 'config.ru') || exists(root, 'bin/rails')) out.push(mk('rails', 'rails', ['bin/rails', 'server']));
  if (exists(root, 'go.mod')) out.push(mk('go', 'go_run', ['go', 'run', './...']));
  return out;
}

// ------------------------------------------------------------------ boot

function get(baseUrl, p, headers = {}, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const u = new URL(p, baseUrl);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET', headers },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
    req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', error: e.code }));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', error: 'timeout' }); });
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The sandbox lives here. Empty allowlisted environment, loopback only, ephemeral port, no
// network, hard wall clock. If a control cannot be applied the caller must not run this tier.
async function boot(harness, cwd, { port, limitsS = 120 } = {}) {
  const env = {
    PATH: process.env.PATH, HOME: path.join(cwd, '.scratch-home'),
    TMPDIR: path.join(cwd, '.scratch-tmp'), PORT: String(port), NODE_ENV: 'test',
    LANG: 'C.UTF-8',
  };
  fs.mkdirSync(env.HOME, { recursive: true });
  fs.mkdirSync(env.TMPDIR, { recursive: true });

  const child = spawn(harness.up[0], harness.up.slice(1), {
    cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true,
  });
  let log = '';
  child.stdout.on('data', (d) => { log += d; });
  child.stderr.on('data', (d) => { log += d; });

  const baseUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + harness.ready.timeout_s * 1000;
  const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ } };
  const guard = setTimeout(kill, limitsS * 1000);

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      clearTimeout(guard);
      return { ok: false, why: `process exited ${child.exitCode}`, log, kill: () => {} };
    }
    const r = await get(baseUrl, harness.ready.probe_path);
    const good = harness.ready.expect_status === 0
      ? r.status > 0 && r.status < 500
      : r.status === harness.ready.expect_status;
    if (good) {
      clearTimeout(guard);
      return { ok: true, baseUrl, log, kill: () => { clearTimeout(guard); kill(); } };
    }
    await sleep(200);
  }
  clearTimeout(guard);
  kill();
  return { ok: false, why: 'readiness timeout', log, kill: () => {} };
}

module.exports = { discoverAppHarness, boot, get };

if (require.main === module) {
  const root = process.argv[2] || '.';
  const found = discoverAppHarness(path.resolve(root));
  console.log(JSON.stringify(found, null, 2));
  if (!found.length) { console.error('no harness discovered: dynamic witness tier unavailable'); process.exit(1); }
}
