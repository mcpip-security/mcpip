#!/usr/bin/env node
/// <reference types="node" />
/* ---------------------------------------------------------------------------
   @mcpip/sdk — the `mcpip` command-line interface (thin bin over the clients).

   A zero-dependency mirror of the flagship Python CLI (docs/start/CLI.md). It WRAPS
   McpipClient / McpipSandboxClient — no reimplemented wire logic — and inherits
   the gateway's discipline: fail-closed and OPAQUE (a deny prints only a
   correlation id), secrets never touch argv/stdout/logs, stable exit codes.

   Built only on Node stdlib (node:fs with mode 0o600 + O_EXCL, node:readline
   with muted input for the OTP prompt) so the package stays dependency-free.

   Tranche 1 (this file): connect/config/context, catalog, authorize + step-up
   complete, decision, mcp tools list/call, all reads, and the sandbox bootstrap
   (dev-token / authenticator). The admin control plane is a fast-follow — until
   then use the Python bin (`mcpip admin …`).
--------------------------------------------------------------------------- */

import { closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';

import { McpipClient, McpipSandboxClient } from './index.js';
import {
  McpipDenied,
  McpipInvalidRequest,
  McpipSandboxOnly,
  McpipUnavailable,
} from './errors.js';
import type { TokenSource } from './client.js';
import type { AuthorizeRequest, AuthorizeStaged, SourceFormat } from './types.js';

// ---------------------------------------------------------------------------
// Exit codes — identical contract to the Python CLI (docs/start/CLI.md).
// ---------------------------------------------------------------------------

const EXIT = {
  OK: 0,
  ERROR: 1,
  USAGE: 2,
  DENIED: 3,
  UNAVAILABLE: 4,
  INVALID_REQUEST: 5,
  NOT_FOUND: 6,
  SANDBOX_ONLY: 7,
  CONFIG: 8,
  STEP_UP_PENDING: 9,
} as const;

const DEFAULT_BASE_URL = 'http://localhost:8080';
const TOKEN_SOURCE_SCHEMES = ['env:', 'file:', 'cmd:'];

class ConfigError extends Error {}
class StepUpPending extends Error {
  constructor(readonly challengeId: string) {
    super(`step-up required; resume with: mcpip complete --challenge ${challengeId}`);
  }
}

function mapExit(err: unknown): number {
  if (err instanceof McpipDenied) return EXIT.DENIED;
  if (err instanceof McpipUnavailable) return EXIT.UNAVAILABLE;
  if (err instanceof McpipSandboxOnly) return EXIT.SANDBOX_ONLY;
  if (err instanceof McpipInvalidRequest) return EXIT.INVALID_REQUEST;
  if (err instanceof StepUpPending) return EXIT.STEP_UP_PENDING;
  if (err instanceof ConfigError) return EXIT.CONFIG;
  return EXIT.ERROR;
}

// ---------------------------------------------------------------------------
// Argument parsing (manual — subcommands + repeatable --arg, no third-party dep).
// ---------------------------------------------------------------------------

const VALUE_FLAGS = new Set([
  'gateway', 'context', 'config', 'token-file', 'token-cmd', 'format', 'tool-call',
  'vendor', 'action', 'authz-context', 'arg', 'tenant', 'agent', 'role', 'cap',
  'compartment', 'out', 'challenge', 'token-source', 'credential-out',
]);
const REPEATABLE = new Set(['arg', 'cap']);

interface Parsed {
  positionals: string[];
  flags: Record<string, string | boolean>;
  multi: Record<string, string[]>;
}

function parse(argv: string[]): Parsed {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const multi: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok.startsWith('--')) {
      let name = tok.slice(2);
      let value: string | boolean = true;
      const eq = name.indexOf('=');
      if (eq >= 0) {
        value = name.slice(eq + 1);
        name = name.slice(0, eq);
      } else if (VALUE_FLAGS.has(name)) {
        value = argv[++i] ?? '';
      }
      if (REPEATABLE.has(name)) {
        (multi[name] ??= []).push(String(value));
      } else {
        flags[name] = value;
      }
    } else {
      positionals.push(tok);
    }
  }
  return { positionals, flags, multi };
}

function flagStr(p: Parsed, name: string): string | undefined {
  const v = p.flags[name];
  return typeof v === 'string' ? v : undefined;
}
function flagBool(p: Parsed, name: string): boolean {
  return p.flags[name] === true || p.flags[name] === 'true';
}

// ---------------------------------------------------------------------------
// --arg coercion — string by default, explicit prefixes only (NO inference).
// ---------------------------------------------------------------------------

function coerce(raw: string): unknown {
  if (raw.startsWith('str:')) return raw.slice(4);
  if (raw.startsWith('int:')) {
    const n = Number(raw.slice(4));
    if (!Number.isInteger(n)) throw new ConfigError(`--arg int: not an integer: ${raw}`);
    return n;
  }
  if (raw.startsWith('float:')) {
    const n = Number(raw.slice(6));
    if (Number.isNaN(n)) throw new ConfigError(`--arg float: not a number: ${raw}`);
    return n;
  }
  if (raw.startsWith('bool:')) {
    const b = raw.slice(5).toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(b)) return true;
    if (['false', '0', 'no', 'off'].includes(b)) return false;
    throw new ConfigError(`--arg bool: not a boolean: ${raw}`);
  }
  if (raw.startsWith('json:')) {
    try {
      return JSON.parse(raw.slice(5));
    } catch {
      throw new ConfigError(`--arg json: invalid JSON: ${raw}`);
    }
  }
  return raw; // default: string, no inference (a ZIP stays a string).
}

function collectArgs(pairs: string[] | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const pair of pairs ?? []) {
    const eq = pair.indexOf('=');
    if (eq < 0) throw new ConfigError(`--arg must be key=value: ${pair}`);
    out[pair.slice(0, eq)] = coerce(pair.slice(eq + 1));
  }
  return out;
}

function loadDocument(spec: string): unknown {
  let text: string;
  if (spec === '-') {
    text = readFileSync(0, 'utf8');
  } else if (spec.startsWith('@')) {
    text = readFileSync(spec.slice(1), 'utf8');
  } else {
    text = spec;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ConfigError(`input is not valid JSON: ${spec}`);
  }
}

// ---------------------------------------------------------------------------
// Config (kubeconfig-shaped TOML, 0600, fail-closed perms, atomic writes).
// ---------------------------------------------------------------------------

interface Context {
  name: string;
  baseUrl: string;
  sandbox: boolean;
  tokenSource?: string;
}
interface Config {
  currentContext?: string;
  contexts: Record<string, Context>;
}

function configHome(): string {
  const override = process.env['MCPIP_CONFIG_HOME'];
  return override ? override : join(homedir(), '.mcpip');
}
function configPath(): string {
  return process.env['MCPIP_CONFIG'] ?? join(configHome(), 'config.toml');
}

function refuseIfAccessible(path: string): void {
  const mode = statSync(path).mode;
  if (mode & 0o077) {
    throw new ConfigError(
      `refusing to use ${path}: it is group/world-accessible (mode ${(mode & 0o777).toString(8)}); run \`chmod 600 ${path}\``,
    );
  }
}

function readSecretFile(path: string): string {
  refuseIfAccessible(path);
  return readFileSync(path, 'utf8').trim();
}

function writeSecretFile(path: string, content: string, exclusive: boolean): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (exclusive) {
    atomicCreate(path, content);
    return;
  }
  const tmp = `${path}.tmp.${process.pid}`;
  atomicCreate(tmp, content);
  renameSync(tmp, path);
}

function atomicCreate(path: string, content: string): void {
  // wx = O_CREAT | O_EXCL; mode 0600.
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new ConfigError(`refusing to overwrite existing file ${path}`);
    }
    throw err;
  }
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
}

function loadConfig(): Config {
  const path = configPath();
  let text: string;
  try {
    refuseIfAccessible(path);
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { contexts: {} };
    throw err;
  }
  return parseConfig(text);
}

function parseConfig(text: string): Config {
  // Constrained schema only: `current-context` + [context.NAME] tables.
  const config: Config = { contexts: {} };
  let current: Context | null = null;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const table = /^\[context\.(.+)\]$/.exec(line);
    if (table) {
      const name = unquote(table[1]!);
      current = { name, baseUrl: DEFAULT_BASE_URL, sandbox: false };
      config.contexts[name] = current;
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const key = kv[1]!;
    const value = kv[2]!.trim();
    if (key === 'current-context' && !current) {
      config.currentContext = unquote(value);
    } else if (current) {
      if (key === 'base_url') current.baseUrl = unquote(value);
      else if (key === 'sandbox') current.sandbox = value === 'true';
      else if (key === 'token-source') current.tokenSource = unquote(value);
    }
  }
  return config;
}

function unquote(v: string): string {
  if (v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return v;
}
function quote(v: string): string {
  return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function saveConfig(config: Config): void {
  const lines: string[] = [
    '# MCPIP CLI config — managed by `mcpip login` / `mcpip context` / `mcpip config`.',
    '# Mode 0600; a token-source is a REFERENCE, never a token.',
  ];
  if (config.currentContext) lines.push(`current-context = ${quote(config.currentContext)}`);
  for (const name of Object.keys(config.contexts).sort()) {
    const c = config.contexts[name]!;
    lines.push('', `[context.${name}]`, `base_url = ${quote(c.baseUrl)}`, `sandbox = ${c.sandbox}`);
    if (c.tokenSource) lines.push(`token-source = ${quote(c.tokenSource)}`);
  }
  writeSecretFile(configPath(), lines.join('\n') + '\n', false);
}

function validateTokenSource(ref: string): string {
  if (!TOKEN_SOURCE_SCHEMES.some((s) => ref.startsWith(s))) {
    throw new ConfigError(
      "token-source must be env:VARNAME | file:PATH | cmd:'...'; a literal token is refused (it would leak into config)",
    );
  }
  return ref;
}

// ---------------------------------------------------------------------------
// Resolution + token/OTP (bearer never via argv).
// ---------------------------------------------------------------------------

interface Resolved {
  baseUrl: string;
  sandbox: boolean;
  contextName?: string;
  tokenSource?: string;
}

function resolve(config: Config, p: Parsed, strict: boolean): Resolved {
  const ctxName = flagStr(p, 'context') ?? process.env['MCPIP_CONTEXT'] ?? config.currentContext;
  let ctx: Context | undefined;
  if (ctxName && config.contexts[ctxName]) ctx = config.contexts[ctxName];
  else if (strict && ctxName && (flagStr(p, 'context') || process.env['MCPIP_CONTEXT'])) {
    throw new ConfigError(`no such context: ${ctxName}`);
  }
  const baseUrl =
    flagStr(p, 'gateway') ?? process.env['MCPIP_GATEWAY'] ?? ctx?.baseUrl ?? DEFAULT_BASE_URL;
  let sandbox = ctx?.sandbox ?? false;
  if (p.flags['sandbox'] !== undefined) sandbox = true;
  else if (p.flags['no-sandbox'] !== undefined) sandbox = false;
  else if (process.env['MCPIP_SANDBOX']) sandbox = /^(1|true|yes|on)$/i.test(process.env['MCPIP_SANDBOX']);
  return { baseUrl, sandbox, contextName: ctxName ?? undefined, tokenSource: ctx?.tokenSource };
}

async function resolveToken(p: Parsed, contextRef?: string): Promise<TokenSource | undefined> {
  const file = flagStr(p, 'token-file');
  if (file) return readSecretFile(file);
  if (flagBool(p, 'token-stdin')) return (await readStdinLine()).trim();
  const cmd = flagStr(p, 'token-cmd');
  if (cmd) return commandProvider(cmd);
  if (process.env['MCPIP_TOKEN']) return process.env['MCPIP_TOKEN'];
  if (contextRef) return fromSourceRef(contextRef);
  return undefined;
}

function fromSourceRef(ref: string): TokenSource {
  if (ref.startsWith('env:')) {
    const v = process.env[ref.slice(4)];
    if (!v) throw new ConfigError(`token-source ${ref} is not set`);
    return v;
  }
  if (ref.startsWith('file:')) return readSecretFile(ref.slice(5));
  if (ref.startsWith('cmd:')) return commandProvider(ref.slice(4));
  throw new ConfigError(`unrecognized token-source: ${ref}`);
}

function commandProvider(command: string): () => Promise<string> {
  return async () => {
    const { execSync } = await import('node:child_process');
    try {
      const out = execSync(command, { encoding: 'utf8' }).trim();
      if (!out) throw new ConfigError('token-cmd produced no token');
      return out;
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new ConfigError('token-cmd failed');
    }
  };
}

function readStdinLine(): Promise<string> {
  return new Promise((res) => {
    const rl = createInterface({ input: process.stdin });
    rl.once('line', (line) => {
      rl.close();
      res(line);
    });
    rl.once('close', () => res(''));
  });
}

async function readOtp(p: Parsed): Promise<string> {
  if (flagBool(p, 'otp-stdin')) return (await readStdinLine()).trim();
  if (flagBool(p, 'otp-prompt') || process.stdin.isTTY) {
    return promptNoEcho('one-time code: ');
  }
  throw new ConfigError('no OTP available non-interactively; pass --otp-stdin or run in a TTY');
}

function hasInteractiveOtp(p: Parsed): boolean {
  return flagBool(p, 'otp-stdin') || flagBool(p, 'otp-prompt') || Boolean(process.stdin.isTTY);
}

function promptNoEcho(prompt: string): Promise<string> {
  return new Promise((res) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const asAny = rl as unknown as { _writeToOutput: (s: string) => void };
    const original = asAny._writeToOutput.bind(rl);
    let first = true;
    asAny._writeToOutput = (_s: string) => {
      if (first) {
        original(prompt);
        first = false;
      } // swallow echoed keystrokes
    };
    rl.question(prompt, (answer) => {
      rl.close();
      process.stdout.write('\n');
      res(answer);
    });
  });
}

// ---------------------------------------------------------------------------
// Rendering — human blocks + --json + the ONE opaque error renderer.
// ---------------------------------------------------------------------------

interface Mode {
  json: boolean;
  quiet: boolean;
}
function modeOf(p: Parsed): Mode {
  return { json: flagBool(p, 'json'), quiet: flagBool(p, 'quiet') };
}

function emitObject(mode: Mode, model: unknown, human: () => void, quietId?: string): void {
  if (mode.quiet) {
    if (quietId) process.stdout.write(quietId + '\n');
    return;
  }
  if (mode.json) console.log(JSON.stringify(model, null, 2));
  else human();
}

function block(pairs: [string, unknown][]): void {
  const width = Math.max(...pairs.map(([k]) => k.length));
  for (const [k, v] of pairs) console.log(`${k.padEnd(width)} : ${cell(v)}`);
}
function cell(v: unknown): string {
  if (v === null || v === undefined) return '-';
  if (Array.isArray(v)) return v.length ? v.map(cell).join(', ') : '-';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function renderError(mode: Mode, err: unknown): void {
  if (err instanceof McpipDenied) {
    // A deny discloses ONLY the opaque correlation id. err.httpStatus varies by
    // cause/edge (401/403/200/500) — surfacing it hands a scripted caller a reason
    // discriminator the gateway deliberately collapses. Exit code 3 is the single
    // uniform deny signal; "error":"denied" is the invariant field.
    if (mode.json)
      console.log(JSON.stringify({ error: 'denied', correlation_id: err.correlationId }));
    else console.error(`denied: request denied by policy (correlation_id=${err.correlationId})`);
    return;
  }
  if (err instanceof McpipUnavailable) {
    if (mode.json) console.log(JSON.stringify({ error: 'unavailable', retry_after: err.retryAfterSeconds }));
    else console.error('error: gateway unreachable');
    return;
  }
  if (err instanceof McpipSandboxOnly) {
    if (mode.json) console.log(JSON.stringify({ error: 'sandbox_only' }));
    else console.error('error: endpoint not available on this gateway');
    return;
  }
  if (err instanceof McpipInvalidRequest) {
    if (mode.json) console.log(JSON.stringify({ error: 'invalid_request', correlation_id: err.correlationId }));
    else console.error('error: request rejected before authorization');
    return;
  }
  if (err instanceof StepUpPending) {
    if (mode.json) console.log(JSON.stringify({ error: 'step_up_pending', challenge_id: err.challengeId }));
    else console.error(`step-up required: resume with \`mcpip complete --challenge ${err.challengeId}\``);
    return;
  }
  if (err instanceof ConfigError) {
    if (mode.json) console.log(JSON.stringify({ error: 'config', detail: err.message }));
    else console.error(`error: ${err.message}`);
    return;
  }
  if (mode.json) console.log(JSON.stringify({ error: 'unexpected' }));
  else console.error(`error: ${(err as Error)?.name ?? 'unexpected'}`);
}

// ---------------------------------------------------------------------------
// Staged step-up persistence (0600, keyed by challenge_id).
// ---------------------------------------------------------------------------

function stagedPath(challengeId: string): string {
  const safe = challengeId.replace(/[^A-Za-z0-9_-]/g, '_');
  if (!safe) throw new ConfigError('empty challenge id');
  return join(configHome(), 'staged', `${safe}.json`);
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

const VERSION = '0.1.0';

async function run(argv: string[]): Promise<number> {
  const p = parse(argv);
  const path = p.positionals;

  if (p.flags['version'] === true && path.length === 0) {
    console.log(`mcpip ${VERSION} (@mcpip/sdk ${VERSION})`);
    return EXIT.OK;
  }
  if (path.length === 0 || p.flags['help'] === true) {
    printHelp();
    return path.length === 0 ? EXIT.USAGE : EXIT.OK;
  }
  if (flagStr(p, 'config')) process.env['MCPIP_CONFIG'] = flagStr(p, 'config');

  const mode = modeOf(p);
  const [group, ...rest] = path;
  const configManaging = ['login', 'config', 'context'].includes(group!) ||
    (group === 'sandbox' && rest[0] === 'dev-token');

  let config: Config;
  let resolved: Resolved;
  try {
    config = loadConfig();
    resolved = resolve(config, p, !configManaging);
  } catch (err) {
    renderError(mode, err);
    return mapExit(err);
  }

  try {
    return await dispatch(group!, rest, p, mode, config, resolved);
  } catch (err) {
    renderError(mode, err);
    return mapExit(err);
  }
}

function client(resolved: Resolved, token: TokenSource | undefined): McpipClient {
  return new McpipClient({ baseUrl: resolved.baseUrl, token });
}
function sandbox(resolved: Resolved, token: TokenSource | undefined): McpipSandboxClient {
  return new McpipSandboxClient({ baseUrl: resolved.baseUrl, token });
}

async function dispatch(
  group: string,
  rest: string[],
  p: Parsed,
  mode: Mode,
  config: Config,
  resolved: Resolved,
): Promise<number> {
  switch (group) {
    case 'login':
      return cmdLogin(p, mode, config, resolved);
    case 'whoami':
      return cmdWhoami(p, mode, resolved);
    case 'config':
      return cmdConfig(rest, p, mode);
    case 'context':
      return cmdContext(rest, p, mode, config);
    case 'catalog':
      return cmdCatalog(p, mode, resolved);
    case 'authorize':
      return cmdAuthorize(rest, p, mode, resolved);
    case 'complete':
      return cmdComplete(p, mode, resolved);
    case 'decision':
      return cmdDecision(rest, p, mode, resolved);
    case 'mcp':
      return cmdMcp(rest, p, mode, resolved);
    case 'health':
    case 'ready':
    case 'version':
    case 'license':
    case 'discovery':
    case 'audit':
      return cmdReads(group, rest, p, mode, resolved);
    case 'sandbox':
      return cmdSandbox(rest, p, mode, config, resolved);
    case 'admin':
      console.error('error: the admin control plane is not yet in the TS bin — use the Python `mcpip admin …`');
      return EXIT.USAGE;
    default:
      printHelp();
      return EXIT.USAGE;
  }
}

async function cmdLogin(p: Parsed, mode: Mode, config: Config, resolved: Resolved): Promise<number> {
  const name = flagStr(p, 'context') ?? 'default';
  const baseUrl = flagStr(p, 'gateway') ?? resolved.baseUrl;
  const tokenSource = flagStr(p, 'token-source');
  if (tokenSource) validateTokenSource(tokenSource);
  const c = client({ ...resolved, baseUrl }, undefined);
  const health = await c.health();
  const existing = config.contexts[name];
  config.contexts[name] = {
    name,
    baseUrl,
    sandbox: p.flags['sandbox'] !== undefined ? true : resolved.sandbox,
    tokenSource: tokenSource ?? existing?.tokenSource,
  };
  config.currentContext = name;
  saveConfig(config);
  emitObject(
    mode,
    { context: name, gateway: baseUrl, reachable: true, gateway_version: health.version },
    () => block([['context', name], ['gateway', baseUrl], ['reachable', true], ['gateway_version', health.version]]),
    name,
  );
  return EXIT.OK;
}

async function cmdWhoami(p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  const provider = await resolveToken(p, resolved.tokenSource);
  if (!provider) throw new ConfigError('no bearer resolved for the active context');
  const token = typeof provider === 'string' ? provider : await provider();
  const claims = decodeClaims(token);
  const c = client(resolved, token);
  const version = await c.version();
  emitObject(
    mode,
    { tenant_id: claims['tenant_id'], agent_id: claims['agent_id'] ?? claims['sub'], role: claims['role'], exp: claims['exp'], capabilities: claims['capabilities'] ?? [], gateway_accepts: true },
    () =>
      block([
        ['context', resolved.contextName],
        ['tenant_id', claims['tenant_id']],
        ['agent_id', claims['agent_id'] ?? claims['sub']],
        ['role', claims['role']],
        ['exp', claims['exp']],
        ['capabilities', claims['capabilities'] ?? []],
        ['gateway_accepts', true],
        ['gateway_running', version.running],
      ]),
    String(claims['agent_id'] ?? ''),
  );
  return EXIT.OK;
}

function decodeClaims(token: string): Record<string, unknown> {
  try {
    const payload = token.split('.')[1]!;
    const json = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const claims = JSON.parse(json);
    return typeof claims === 'object' && claims ? claims : {};
  } catch {
    return {};
  }
}

function cmdConfig(rest: string[], _p: Parsed, mode: Mode): number {
  const [action, key, value] = rest;
  const config = loadConfig();
  if (action === 'list') {
    const rows: [string, unknown][] = [];
    if (config.currentContext) rows.push(['current-context', config.currentContext]);
    for (const name of Object.keys(config.contexts).sort()) {
      const c = config.contexts[name]!;
      rows.push([`context.${name}.base_url`, c.baseUrl]);
      rows.push([`context.${name}.sandbox`, c.sandbox]);
      rows.push([`context.${name}.token-source`, c.tokenSource ?? '-']);
    }
    if (mode.json) console.log(JSON.stringify(Object.fromEntries(rows), null, 2));
    else if (rows.length) block(rows);
    else console.log('No config.');
    return EXIT.OK;
  }
  if (action === 'get') {
    console.log(String(configGet(config, key!) ?? '-'));
    return EXIT.OK;
  }
  if (action === 'set') {
    configSet(config, key!, value!);
    saveConfig(config);
    if (!mode.quiet) console.error(`set ${key}`);
    return EXIT.OK;
  }
  if (action === 'unset') {
    configUnset(config, key!);
    saveConfig(config);
    if (!mode.quiet) console.error(`unset ${key}`);
    return EXIT.OK;
  }
  console.error('error: config <list|get|set|unset>');
  return EXIT.USAGE;
}

function configGet(config: Config, key: string): unknown {
  if (key === 'current-context') return config.currentContext;
  const [, name, attr] = key.split('.');
  const c = name ? config.contexts[name] : undefined;
  if (!c) return undefined;
  if (attr === 'base_url') return c.baseUrl;
  if (attr === 'sandbox') return c.sandbox;
  if (attr === 'token-source') return c.tokenSource;
  return undefined;
}
function configSet(config: Config, key: string, value: string): void {
  if (key === 'current-context') {
    if (!config.contexts[value]) throw new ConfigError(`no such context: ${value}`);
    config.currentContext = value;
    return;
  }
  const [, name, attr] = key.split('.');
  if (!name) throw new ConfigError(`unknown config key: ${key}`);
  const c = (config.contexts[name] ??= { name, baseUrl: DEFAULT_BASE_URL, sandbox: false });
  if (attr === 'base_url') c.baseUrl = value;
  else if (attr === 'sandbox') c.sandbox = /^(1|true|yes|on)$/i.test(value);
  else if (attr === 'token-source') c.tokenSource = validateTokenSource(value);
  else throw new ConfigError(`unknown config key: ${key}`);
}
function configUnset(config: Config, key: string): void {
  if (key === 'current-context') {
    delete config.currentContext;
    return;
  }
  const [, name, attr] = key.split('.');
  const c = name ? config.contexts[name] : undefined;
  if (!c) return;
  if (attr === 'token-source') delete c.tokenSource;
  else if (attr === 'sandbox') c.sandbox = false;
  else if (attr === 'base_url') c.baseUrl = DEFAULT_BASE_URL;
}

function cmdContext(rest: string[], p: Parsed, mode: Mode, config: Config): number {
  const [action, name] = rest;
  if (action === 'list') {
    const names = Object.keys(config.contexts).sort();
    if (!names.length) console.log(mode.json ? '[]' : 'No contexts.');
    else if (mode.json)
      console.log(JSON.stringify(names.map((n) => ({ ...config.contexts[n], current: n === config.currentContext }))));
    else for (const n of names) console.log(`${n === config.currentContext ? '*' : ' '} ${n}\t${config.contexts[n]!.baseUrl}`);
    return EXIT.OK;
  }
  if (action === 'current') {
    console.log(config.currentContext ?? '-');
    return EXIT.OK;
  }
  if (action === 'use') {
    if (!config.contexts[name!]) throw new ConfigError(`no such context: ${name}`);
    config.currentContext = name!;
    saveConfig(config);
    return EXIT.OK;
  }
  if (action === 'set') {
    const ts = flagStr(p, 'token-source');
    if (ts) validateTokenSource(ts);
    const existing = config.contexts[name!];
    config.contexts[name!] = {
      name: name!,
      baseUrl: flagStr(p, 'gateway') ?? existing?.baseUrl ?? DEFAULT_BASE_URL,
      sandbox: p.flags['sandbox'] !== undefined ? true : existing?.sandbox ?? false,
      tokenSource: ts ?? existing?.tokenSource,
    };
    saveConfig(config);
    return EXIT.OK;
  }
  if (action === 'delete') {
    delete config.contexts[name!];
    if (config.currentContext === name) delete config.currentContext;
    saveConfig(config);
    return EXIT.OK;
  }
  console.error('error: context <list|current|use|set|delete>');
  return EXIT.USAGE;
}

async function cmdCatalog(p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  const items = await c.catalog();
  if (!items.length) {
    if (!mode.quiet) console.log(mode.json ? '[]' : 'No catalog entries.');
    return EXIT.OK;
  }
  if (mode.quiet) items.forEach((i) => console.log(i.alias));
  else if (mode.json) console.log(JSON.stringify(items, null, 2));
  else for (const i of items) console.log(`${i.alias}\t[${i.risk_tier}]\t${i.transport_class}`);
  return EXIT.OK;
}

async function cmdAuthorize(rest: string[], p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  const alias = rest[0];
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  const toolCall = flagStr(p, 'tool-call');
  const fmt = (flagStr(p, 'format') ?? 'raw_mcp') as SourceFormat;
  let request: AuthorizeRequest;
  if (toolCall) {
    const dict = loadDocument(toolCall) as Record<string, unknown>;
    const vendor = flagStr(p, 'vendor');
    request = vendor ? { tool_call: dict, vendor } : { tool_call: dict, source_format: fmt };
  } else {
    if (!alias) throw new ConfigError('an ALIAS (or --tool-call) is required');
    request = { tool_call: { tool: alias, arguments: collectArgs(p.multi['arg']) }, source_format: fmt };
  }
  const credentialOut = flagStr(p, 'credential-out');
  const result = await c.authorize(request);
  if (result.status === 'allowed') {
    renderReceipt(mode, result, credentialOut);
    return EXIT.OK;
  }
  // Staged — persist the exact request, then step up inline or defer.
  writeSecretFile(stagedPath(result.challengeId), JSON.stringify({ challengeId: result.challengeId, request: result.request, correlationId: result.correlationId }), false);
  if (hasInteractiveOtp(p)) {
    const otp = await readOtp(p);
    const receipt = await c.complete(result, otp);
    renderReceipt(mode, receipt, credentialOut);
    return EXIT.OK;
  }
  throw new StepUpPending(result.challengeId);
}

async function cmdComplete(p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  const challengeId = flagStr(p, 'challenge');
  if (!challengeId) throw new ConfigError('--challenge is required');
  let record: { challengeId: string; request: Record<string, unknown>; correlationId?: string };
  try {
    record = JSON.parse(readSecretFile(stagedPath(challengeId)));
  } catch {
    throw new McpipUnavailable(`no staged challenge ${challengeId} on this machine`);
  }
  const otp = await readOtp(p);
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  const receipt = await c.complete(stagedFrom(challengeId, record.request, record.correlationId), otp);
  renderReceipt(mode, receipt, flagStr(p, 'credential-out'));
  return EXIT.OK;
}

function stagedFrom(challengeId: string, request: Record<string, unknown>, correlationId?: string): AuthorizeStaged {
  return {
    status: 'staged',
    challengeId,
    request: request as unknown as AuthorizeRequest,
    correlationId: correlationId ?? '',
    actionRequired: '',
    riskTier: 'pin_required',
    challenge: {} as never,
  };
}

function renderReceipt(mode: Mode, receipt: { correlationId: string; transactionRef: string; executedTargetClass: string; wormSequence: number; vendedCredential: unknown; receipt: { decision: string; status: string } }, credentialOut?: string): void {
  // A vended cloud credential is a real secret: it NEVER reaches stdout — not on
  // a TTY, not down a pipe, not to a redirect (isTTY is false for a CI pipe,
  // `| tee` and `> file` alike, so it is no proxy for a private sink). To CAPTURE
  // the material, pass `--credential-out FILE`: it lands via O_EXCL 0600 (the
  // dev-token / OTP pattern) and only the path is printed.
  let writtenPath: string | undefined;
  if (receipt.vendedCredential && credentialOut) {
    writeSecretFile(credentialOut, JSON.stringify(receipt.vendedCredential), true);
    writtenPath = credentialOut;
  }
  if (mode.quiet) {
    console.log(receipt.transactionRef);
    return;
  }
  if (mode.json) {
    const payload: Record<string, unknown> = { decision: receipt.receipt.decision, status: receipt.receipt.status, transaction_ref: receipt.transactionRef, executed_target_class: receipt.executedTargetClass, worm_sequence: receipt.wormSequence, correlation_id: receipt.correlationId };
    if (receipt.vendedCredential) payload['vended_credential'] = writtenPath ? { redacted: true, written_to: writtenPath } : { redacted: true, reason: 'withheld from stdout; capture it with `mcpip authorize --credential-out FILE` (O_EXCL 0600)' };
    console.log(JSON.stringify(payload, null, 2));
    return;
  }
  block([
    ['decision', receipt.receipt.decision],
    ['status', receipt.receipt.status],
    ['transaction_ref', receipt.transactionRef],
    ['executed_target_class', receipt.executedTargetClass],
    ['worm_sequence', receipt.wormSequence],
    ['correlation_id', receipt.correlationId],
    ...(receipt.vendedCredential ? ([['vended_credential', 'present (redacted)']] as [string, unknown][]) : []),
    ...(writtenPath ? ([['credential_written_to', writtenPath]] as [string, unknown][]) : []),
  ]);
}

async function cmdDecision(rest: string[], p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  const alias = rest[0];
  if (!alias) throw new ConfigError('an ALIAS is required');
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  const ctxSpec = flagStr(p, 'authz-context');
  const verdict = await c.authzDecision(alias, collectArgs(p.multi['arg']), {
    actionName: flagStr(p, 'action'),
    ...(ctxSpec ? { context: loadDocument(ctxSpec) as Record<string, unknown> } : {}),
  });
  emitObject(
    mode,
    verdict,
    () => block([['decision', verdict.decision], ['obligations', (verdict.obligations ?? []).map((o) => o.id)]]),
    verdict.decision ? 'permit' : 'deny',
  );
  return EXIT.OK;
}

async function cmdMcp(rest: string[], p: Parsed, _mode: Mode, resolved: Resolved): Promise<number> {
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  if (rest[0] === 'initialize') {
    console.log(JSON.stringify(await c.mcpCall('initialize'), null, 2));
    return EXIT.OK;
  }
  if (rest[0] === 'tools' && rest[1] === 'list') {
    console.log(JSON.stringify(await c.mcpCall('tools/list'), null, 2));
    return EXIT.OK;
  }
  if (rest[0] === 'tools' && rest[1] === 'call') {
    const alias = rest[2];
    if (!alias) throw new ConfigError('an ALIAS is required');
    const result = (await c.mcpCall('tools/call', { name: alias, arguments: collectArgs(p.multi['arg']) })) as { isError?: boolean; content?: { text?: string }[] };
    if (result?.isError) {
      const text = result.content?.[0]?.text;
      const challenge = text ? (JSON.parse(text) as { challenge_id?: string }) : {};
      throw new StepUpPending(challenge.challenge_id ?? '');
    }
    console.log(JSON.stringify(result, null, 2));
    return EXIT.OK;
  }
  console.error('error: mcp <initialize|tools list|tools call>');
  return EXIT.USAGE;
}

async function cmdReads(group: string, rest: string[], p: Parsed, mode: Mode, resolved: Resolved): Promise<number> {
  if (group === 'version' && flagBool(p, 'client')) {
    console.log(`mcpip ${VERSION} (@mcpip/sdk ${VERSION})`);
    return EXIT.OK;
  }
  const c = client(resolved, await resolveToken(p, resolved.tokenSource));
  let model: unknown;
  let human: () => void;
  if (group === 'health') {
    const h = await c.health();
    model = h;
    human = () => block([['status', h.status], ['version', h.version], ['loop', h.loop]]);
  } else if (group === 'ready') {
    const r = await c.ready();
    model = r;
    human = () => block([['ready', r.ready], ['redis', r.redis]]);
  } else if (group === 'version') {
    const v = await c.version();
    model = v;
    human = () => block([['running', v.running], ['latest', v.latest], ['update_available', v.update_available], ['channel', v.channel]]);
  } else if (group === 'license') {
    const l = await c.license();
    model = l;
    human = () => block([['licensed', l.licensed], ['tier', l.tier ?? null]]);
  } else if (group === 'discovery') {
    const d = await c.protectedResourceMetadata();
    model = d;
    human = () => block([['resource', d.resource], ['authorization_servers', d.authorization_servers], ['bearer_methods_supported', d.bearer_methods_supported]]);
  } else if (group === 'audit' && rest[0] === 'attestation') {
    const a = await c.auditAttestation();
    model = a;
    human = () => block([['signing_key_id', a.signing_key_id], ['intact', a.intact], ['epoch', a.epoch ?? null]]);
  } else {
    console.error('error: unknown read command');
    return EXIT.USAGE;
  }
  emitObject(mode, model, human);
  return EXIT.OK;
}

async function cmdSandbox(rest: string[], p: Parsed, mode: Mode, config: Config, resolved: Resolved): Promise<number> {
  const token = await resolveToken(p, resolved.tokenSource);
  const c = sandbox(resolved, token);
  if (rest[0] === 'dev-token') {
    const jwt = await c.devToken({
      tenant_id: flagStr(p, 'tenant') ?? 'tenant-acme',
      agent_id: flagStr(p, 'agent') ?? 'agent-orchestrator-1',
      role: flagStr(p, 'role') ?? 'ops',
      ...(flagStr(p, 'compartment') ? { compartment: flagStr(p, 'compartment') } : {}),
      ...(p.multi['cap'] ? { capabilities: p.multi['cap'] } : {}),
    });
    const out = flagStr(p, 'out');
    let target: string;
    if (out) {
      writeSecretFile(out, jwt, true);
      target = out;
    } else {
      const name = resolved.contextName ?? 'default';
      target = join(configHome(), 'tokens', `${name.replace(/[^A-Za-z0-9_-]/g, '_')}.jwt`);
      writeSecretFile(target, jwt, false);
      const existing = config.contexts[name];
      config.contexts[name] = { name, baseUrl: existing?.baseUrl ?? resolved.baseUrl, sandbox: existing?.sandbox ?? resolved.sandbox, tokenSource: `file:${target}` };
      config.currentContext = config.currentContext ?? name;
      saveConfig(config);
    }
    emitObject(mode, { token_written: true, path: target }, () => block([['token_written', true], ['path', target]]), target);
    return EXIT.OK;
  }
  if (rest[0] === 'authenticator') {
    const challenge = rest[1];
    if (!challenge) throw new ConfigError('a CHALLENGE_ID is required');
    const otp = await c.authenticatorCode(challenge);
    const out = flagStr(p, 'out');
    if (out) {
      writeSecretFile(out, otp, true);
      emitObject(mode, { otp_written: true, path: out }, () => block([['otp_written', true], ['path', out]]), out);
      return EXIT.OK;
    }
    let record: { request: Record<string, unknown>; correlationId?: string };
    try {
      record = JSON.parse(readSecretFile(stagedPath(challenge)));
    } catch {
      throw new ConfigError('no locally-staged challenge; pass --out FILE to capture the OTP into a 0600 file');
    }
    // complete() lives on the agent client — build one with the same identity.
    const agent = client(resolved, token);
    const receipt = await agent.complete(stagedFrom(challenge, record.request, record.correlationId), otp);
    renderReceipt(mode, receipt, flagStr(p, 'credential-out'));
    return EXIT.OK;
  }
  if (rest[0] === 'audit' && rest[1] === 'verify') {
    const r = await c.auditVerify();
    emitObject(mode, r, () => block([['intact', r.intact], ['first_bad_epoch', r.first_bad_epoch ?? null]]));
    return EXIT.OK;
  }
  if (rest[0] === 'audit' && rest[1] === 'proof') {
    const proof = await c.auditProof(rest[2]!);
    emitObject(mode, proof, () => block([['event_id', proof.event_id], ['epoch', proof.epoch], ['merkle_root', proof.merkle_root]]));
    return EXIT.OK;
  }
  console.error('error: sandbox <dev-token|authenticator|audit verify|audit proof>');
  return EXIT.USAGE;
}

function printHelp(): void {
  console.log(`mcpip — authorize every AI action before execution.

Zero to authorized:
  mcpip login --gateway URL --sandbox --context NAME
  mcpip sandbox dev-token --agent AGENT      (sandbox identity, never printed)
  mcpip authorize ALIAS --arg k=v

Commands: login whoami config context catalog authorize complete decision
          mcp health ready version license discovery audit sandbox
Global:   --gateway URL --context NAME --sandbox/--no-sandbox --json --quiet
          --token-file PATH | --token-stdin | --token-cmd 'CMD'   (never --token)
Exit:     0 ok · 3 deny · 4 unreachable · 5 invalid · 7 sandbox-only · 8 config · 9 step-up
Docs:     docs/start/CLI.md   (admin control plane: use the Python bin for now)`);
}

run(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`error: ${(err as Error)?.message ?? err}`);
    process.exit(EXIT.ERROR);
  });
