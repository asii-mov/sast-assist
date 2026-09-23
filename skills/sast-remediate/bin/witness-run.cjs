#!/usr/bin/env node
'use strict';
// The differential witness runner. Deterministic. No agent grades a witness.
//
// The parent performs every request itself and records the transcript, so evidence never
// originates inside the target-controlled process and never has to be promoted out of it.
// That is why this skill carries no file-promotion procedure.

const http = require('http');
const { boot } = require('./app-harness.cjs');

const REDACT_ALLOW = new Set(['content-type', 'content-length', 'location', 'x-request-id']);

function request(baseUrl, ex, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const u = new URL(ex.path, baseUrl);
    for (const [k, v] of Object.entries(ex.query || {})) u.searchParams.set(k, v);
    const bodyText = ex.body && ex.body.kind === 'json' ? JSON.stringify(ex.body.value)
      : ex.body && ex.body.kind === 'raw' ? ex.body.value
      : ex.body && ex.body.kind === 'form' ? new URLSearchParams(ex.body.value).toString()
      : null;
    const headers = { ...(ex.headers || {}) };
    if (bodyText !== null) {
      headers['content-length'] = Buffer.byteLength(bodyText);
      if (!headers['content-type']) {
        headers['content-type'] = ex.body.kind === 'json' ? 'application/json'
          : ex.body.kind === 'form' ? 'application/x-www-form-urlencoded'
          : ex.body.content_type || 'text/plain';
      }
    }
    const started = Date.now();
    // Path is taken raw so a traversal payload is sent as written, not normalized away.
    const rawPath = u.pathname + (u.search || '');
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: rawPath, method: ex.method || 'GET', headers },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => resolve({
          status: res.statusCode, headers: res.headers, body, ms: Date.now() - started,
        }));
      });
    req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', ms: Date.now() - started, error: e.code }));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', ms: timeoutMs, error: 'timeout' }); });
    if (bodyText !== null) req.write(bodyText);
    req.end();
  });
}

function jsonPath(obj, p) {
  return p.replace(/^\$\.?/, '').split('.').filter(Boolean)
    .reduce((o, k) => (o == null ? o : o[/^\d+$/.test(k) ? Number(k) : k]), obj);
}

// Returns true when the observable FIRED, meaning the attack worked.
function observed(obs, res) {
  switch (obs.kind) {
    case 'status_code': return res.status === obs.equals;
    case 'body_contains': return res.body.includes(obs.canary);
    case 'header_present': return new RegExp(obs.matches).test(String(res.headers[obs.name.toLowerCase()] || ''));
    case 'reflected_unescaped': return res.body.includes(obs.marker);
    case 'latency_exceeds': return res.ms - obs.baseline_ms > obs.ms;
    case 'body_json_path': {
      try { return JSON.stringify(jsonPath(JSON.parse(res.body), obs.path)) === JSON.stringify(obs.equals); }
      catch { return false; }
    }
    case 'row_appears': throw new Error('row_appears requires a fixture database adapter');
    default: throw new Error(`unknown observable: ${obs.kind}`);
  }
}

const redact = (h) => Object.fromEntries(
  Object.entries(h).map(([k, v]) => [k, REDACT_ALLOW.has(k.toLowerCase()) ? v : '<redacted>']));

const describe = (res) => res.error
  ? `transport ${res.error}`
  : `status ${res.status}, ${res.body.length}B, ${res.ms}ms`;

async function runDynamic(w, trees, transcript) {
  const step = async (label, tree, ex) => {
    const res = await request(trees[tree].baseUrl, ex);
    transcript.push({ label, tree, method: ex.method, path: ex.path, query: ex.query,
      status: res.status, ms: res.ms, headers: redact(res.headers), body_len: res.body.length });
    return res;
  };

  // 1. The control must be a valid baseline BEFORE anything else is believed.
  const ctl = w.control;
  if (ctl.kind !== 'http') throw new Error('dynamic witness requires an http control');
  const cPre = await step('control', 'base', ctl.exchange);
  if (!observed(ctl.expect, cPre)) {
    return {
      tier: 'dynamic',
      pre: { ran: false, signal: false, detail: 'not attempted' },
      post: { ran: false, signal: false, detail: 'not attempted' },
      control: { ran: true, passed_pre: false, passed_post: false,
        detail: `control failed on base (${describe(cPre)}); it is not a valid baseline` },
      differential_ok: false, control_ok: false,
    };
  }

  // 2. The attack must WORK on base, or nothing has been proven.
  const aPre = await step('attack', 'base', w.attack);
  const preSignal = observed(w.observable, aPre);

  // 3. The attack must fail on head.
  const aPost = await step('attack', 'head', w.attack);
  const postSignal = observed(w.observable, aPost);

  // 4. The control must STILL pass on head. This catches fixing by breaking the endpoint.
  const cPost = await step('control', 'head', ctl.exchange);
  const ctlPost = observed(ctl.expect, cPost);

  return {
    tier: 'dynamic',
    pre: { ran: true, signal: preSignal, detail: describe(aPre) },
    post: { ran: true, signal: postSignal, detail: describe(aPost) },
    control: { ran: true, passed_pre: true, passed_post: ctlPost, detail: describe(cPost) },
    differential_ok: preSignal && !postSignal,
    control_ok: ctlPost,
  };
}

// Maps a result to the obligation it failed, so the caller never has to re-derive it.
function classify(r) {
  if (!r.control.ran) return r.differential_ok ? null : 'witness_red';
  if (!r.control.passed_pre) return 'witness_control_failed';
  if (!r.pre.signal) return 'witness_vacuous';
  if (r.post.signal) return 'witness_red';
  if (!r.control.passed_post) return 'witness_control_failed';
  return null;
}

// The dynamic tier is opt-in. The caller passes { allowDynamic: true } only when the operator
// asked for it, so a repository that happens to have a bootable app is never driven by default.
async function runWitness(w, trees, opts = {}) {
  if (w.tier === 'dynamic' && !opts.allowDynamic) {
    throw new Error('dynamic witness tier is opt-in; pass --witness=dynamic (see design/FUTURE-IMPROVEMENTS.md)');
  }
  return runWitnessInner(w, trees);
}

async function runWitnessInner(w, trees) {
  const transcript = [];
  let result;
  switch (w.tier) {
    case 'dynamic': result = await runDynamic(w, trees, transcript); break;
    case 'argued':
      result = {
        tier: 'argued',
        pre: { ran: false, signal: false, detail: w.obstacle },
        post: { ran: false, signal: false, detail: w.obstacle },
        control: { ran: false, why: w.obstacle },
        differential_ok: false, control_ok: false,
      };
      break;
    default:
      throw new Error(`tier "${w.tier}" is not implemented in this runner yet`);
  }
  return { ...result, transcript, failure: classify(result) };
}

module.exports = { runWitness, runDynamic, observed, request, boot };
