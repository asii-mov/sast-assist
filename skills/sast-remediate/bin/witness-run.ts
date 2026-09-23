#!/usr/bin/env node
// The differential witness runner. Deterministic. No agent grades a witness.
//
// The parent performs every request itself and records the transcript, so evidence never
// originates inside the target-controlled process and never has to be promoted out of it.
// That is why this skill carries no file-promotion procedure.

import net from 'net';
import http from 'http';
import { boot } from './app-harness.ts';
import type { HttpResult } from './app-harness.ts';
import type { ObligationResult } from './stage.ts';
import type { AppHarness, Booted } from './app-harness.ts';
import type { HttpExchange, Observable, Witness } from '../schema/types.ts';

type Response = HttpResult & { ms: number };
type Trees = { base: { baseUrl: string }; head: { baseUrl: string } };
type Probe = { ran: boolean; signal: boolean; detail: string };
type ControlResult = { ran: true; passed_pre: boolean; passed_post: boolean; detail: string } | { ran: false; why: string };
type WitnessFailure = 'witness_red' | 'witness_control_failed' | 'witness_vacuous';
type WitnessResult = {
  tier: 'dynamic' | 'argued'; pre: Probe; post: Probe; control: ControlResult; differential_ok: boolean; control_ok: boolean;
};
type TranscriptEntry = {
  label: string; tree: keyof Trees; method: string; path: string; query: unknown;
  status: number; ms: number; headers: Record<string, unknown>; body_len: number;
};

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

// The schema leaves the body shape open, so each kind's value is checked here before it is sent.
function bodyText(body: Record<string, unknown> | undefined): string | null {
  switch (body?.kind) {
    case 'json': return JSON.stringify(body.value);
    case 'raw': return String(body.value);
    case 'form': return isRecord(body.value)
      ? new URLSearchParams(Object.entries(body.value).map(([k, v]) => [k, String(v)])).toString()
      : '';
    default: return null;
  }
}

const REDACT_ALLOW = new Set(['content-type', 'content-length', 'location', 'x-request-id']);

function request(baseUrl: string, ex: HttpExchange, timeoutMs = 8000): Promise<Response> {
  return new Promise((resolve) => {
    const u = new URL(ex.path, baseUrl);
    for (const [k, v] of Object.entries(ex.query || {})) u.searchParams.set(k, String(v));
    const text = bodyText(ex.body);
    const headers: Record<string, string | number> = Object.fromEntries(
      Object.entries(ex.headers || {}).map(([k, v]) => [k, String(v)]));
    if (text !== null) {
      headers['content-length'] = Buffer.byteLength(text);
      if (!headers['content-type']) {
        headers['content-type'] = ex.body.kind === 'json' ? 'application/json'
          : ex.body.kind === 'form' ? 'application/x-www-form-urlencoded'
          : String(ex.body.content_type || 'text/plain');
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
          status: res.statusCode ?? 0, headers: res.headers, body, ms: Date.now() - started,
        }));
      });
    req.on('error', (e: NodeJS.ErrnoException) => resolve({ status: 0, headers: {}, body: '', ms: Date.now() - started, error: e.code }));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', ms: timeoutMs, error: 'timeout' }); });
    if (text !== null) req.write(text);
    req.end();
  });
}

function jsonPath(obj: unknown, p: string): unknown {
  return p.replace(/^\$\.?/, '').split('.').filter(Boolean)
    .reduce<unknown>((o, k) => (o == null ? o : (o as Record<string, unknown>)[k]), obj);
}

// Returns true when the observable FIRED, meaning the attack worked.
function observed(obs: Observable, res: Response): boolean {
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
    default: {
      const unknown: never = obs;
      throw new Error(`unknown observable: ${(unknown as { kind: unknown }).kind}`);
    }
  }
}

const redact = (h: Record<string, unknown>) => Object.fromEntries(
  Object.entries(h).map(([k, v]) => [k, REDACT_ALLOW.has(k.toLowerCase()) ? v : '<redacted>']));

const describe = (res: Response) => res.error
  ? `transport ${res.error}`
  : `status ${res.status}, ${res.body.length}B, ${res.ms}ms`;

async function runDynamic(w: Extract<Witness, { tier: 'dynamic' }>, trees: Trees, transcript: TranscriptEntry[]): Promise<WitnessResult> {
  const step = async (label: string, tree: keyof Trees, ex: HttpExchange) => {
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
function classify(r: WitnessResult): WitnessFailure | null {
  if (!r.control.ran) return r.differential_ok ? null : 'witness_red';
  if (!r.control.passed_pre) return 'witness_control_failed';
  if (!r.pre.signal) return 'witness_vacuous';
  if (r.post.signal) return 'witness_red';
  if (!r.control.passed_post) return 'witness_control_failed';
  return null;
}

// The dynamic tier is opt-in. The caller passes { allowDynamic: true } only when the operator
// asked for it, so a repository that happens to have a bootable app is never driven by default.
async function runWitness(w: Witness, trees: Trees, opts: { allowDynamic?: boolean } = {}) {
  if (w.tier === 'dynamic' && !opts.allowDynamic) {
    throw new Error('dynamic witness tier is opt-in; pass --witness=dynamic (see design/FUTURE-IMPROVEMENTS.md)');
  }
  return runWitnessInner(w, trees);
}

async function runWitnessInner(w: Witness, trees: Trees) {
  const transcript: TranscriptEntry[] = [];
  let result: WitnessResult;
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

const freePort = (): Promise<number> => new Promise((resolve) => {
  const s = net.createServer();
  // A TCP listener's address() is always an AddressInfo; only a pipe or socket path is a string.
  s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => resolve(p)); });
});

const unavailable = (reason: string): ObligationResult => ({ status: 'unavailable', reason });

// Answers obligations 3 and 4 (differential_witness, functional_control) for one tier, one
// attempt. The caller writes the result into patch.verification without reinterpreting it: this
// is the one place that knows what each tier can and cannot prove. Rows follow
// docs/plans/R5-verify-full.md section 3 in order.
type WitnessObligations = { differential_witness: ObligationResult; functional_control?: ObligationResult };

async function witnessObligations(
  w: Witness,
  { baseDir, headDir, harnesses }: { baseDir: string | null; headDir: string; harnesses: AppHarness[] },
  { allowDynamic = false } = {},
): Promise<WitnessObligations> {
  if (w.tier === 'argued') {
    return {
      differential_witness: unavailable(`argued_tier:${w.obstacle}`),
      functional_control: unavailable('argued_tier_has_no_control'),
    };
  }
  if (w.tier !== 'dynamic') {
    return { differential_witness: unavailable(`tier_not_implemented:${w.tier}`) };
  }
  if (!allowDynamic) {
    return { differential_witness: unavailable('dynamic_tier_not_enabled') };
  }
  if (!baseDir) {
    return { differential_witness: unavailable('no_base_tree') };
  }
  const harness = (harnesses || []).find((h) => h.id === w.harness_id);
  if (!harness) {
    return { differential_witness: unavailable(`no_app_harness:${w.harness_id}`) };
  }

  // boot() returns a no-op kill on failure, so calling it unconditionally in the finally is safe.
  const b = await boot(harness, baseDir, { port: await freePort() });
  let h: Booted | null = null;
  try {
    if (!b.ok) return { differential_witness: unavailable(`base_did_not_boot:${b.why}`) };

    h = await boot(harness, headDir, { port: await freePort() });
    if (!h.ok) {
      const fail: ObligationResult = { status: 'fail', reason: `patched_tree_did_not_boot:${h.why}` };
      return { differential_witness: fail, functional_control: fail };
    }

    const r = await runWitness(w, { base: b, head: h }, { allowDynamic: true });
    return {
      differential_witness: r.differential_ok
        ? { status: 'pass', detail: r.post.detail, transcript: r.transcript }
        : { status: 'fail', reason: r.failure || 'witness_not_differential', transcript: r.transcript },
      functional_control: r.control_ok && r.control.ran
        ? { status: 'pass', detail: r.control.detail }
        : { status: 'fail', reason: r.control.ran && !r.control.passed_pre ? 'control_failed_on_base' : 'control_failed_on_patched_tree' },
    };
  } finally {
    b.kill();
    if (h) h.kill();
  }
}

export { runWitness, runDynamic, observed, request, boot, witnessObligations, freePort };
