/* ---------------------------------------------------------------------------
   Developer API Console — a runnable REST terminal wired to the CONNECTED
   gateway. Every request is REAL: it goes to the same base URL the console
   itself talks to, prints the verbatim status + response, and never mocks a
   result. Plug-and-play presets cover the common reads; an "attach admin
   bearer" toggle mints a CAP_DIRECTORY_ADMIN token (sandbox/dev-minter only —
   a production gateway 404s the minter and the console says so) for the
   admin-gated routes.

   Honesty: the gateway's opaque-denial contract is preserved verbatim — a 403
   prints exactly `{error, correlation_id}`, never a decoded reason. The worker
   never caches /v1/*, so this always hits the live gateway. Nothing here can
   authorize an action the gateway wouldn't; it is a thin, honest HTTP client.
--------------------------------------------------------------------------- */

import { useCallback, useRef, useState } from 'react';
import { Loader2, PlugZap, SendHorizontal, SquareTerminal, Trash2 } from 'lucide-react';
import { Input, Panel, PanelHeader, Select } from '../ui';
import type { GatewayLive } from '../../lib/useGatewayLive';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';
const METHODS: ReadonlyArray<Method> = ['GET', 'POST', 'PUT', 'DELETE'];

/** Max response body characters rendered (a hostile/huge body can't flood the DOM). */
const MAX_BODY_CHARS = 20000;

interface Preset {
  label: string;
  method: Method;
  path: string;
  body?: string;
  /** Whether this route needs the admin bearer attached by default. */
  auth: boolean;
}

/** Curated, safe starting points — every one is a real gateway route. */
const PRESETS: ReadonlyArray<Preset> = [
  // JWT-gated, unlike /readyz and /healthz below — firing it without a bearer
  // answers 403, which reads as a broken gateway rather than a missing header.
  { label: 'version', method: 'GET', path: '/v1/version', auth: true },
  { label: 'readyz', method: 'GET', path: '/readyz', auth: false },
  { label: 'healthz', method: 'GET', path: '/healthz', auth: false },
  { label: 'audit attestation', method: 'GET', path: '/v1/audit/attestation', auth: true },
  { label: 'admin stats', method: 'GET', path: '/v1/admin/stats', auth: true },
  {
    label: 'recent decisions',
    method: 'GET',
    path: '/v1/admin/decisions/recent?limit=5',
    auth: true,
  },
  {
    label: 'decisions (filtered)',
    method: 'GET',
    path: '/v1/admin/decisions?decision=deny&limit=5',
    auth: true,
  },
];

interface LogEntry {
  id: number;
  method: Method;
  path: string;
  status: number | null; // null = transport failure (no response)
  statusText: string;
  ms: number;
  body: string;
  truncated: boolean;
}

function prettify(text: string): { body: string; truncated: boolean } {
  let out = text;
  try {
    out = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* not JSON — show verbatim. */
  }
  if (out.length > MAX_BODY_CHARS) {
    return { body: `${out.slice(0, MAX_BODY_CHARS)}\n… (truncated)`, truncated: true };
  }
  return { body: out, truncated: false };
}

export function ApiConsole({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const [method, setMethod] = useState<Method>('GET');
  const [path, setPath] = useState('/v1/version');
  const [body, setBody] = useState('');
  const [attachAuth, setAttachAuth] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const nextId = useRef(1);
  const live = gateway.mode === 'live';
  const hasBody = method === 'POST' || method === 'PUT';
  // apiBase '' means same-origin; show something human either way.
  const shownBase = gateway.apiBase === '' ? gateway.apiHost || 'same-origin' : gateway.apiBase;

  const applyPreset = (p: Preset): void => {
    setMethod(p.method);
    setPath(p.path);
    setBody(p.body ?? '');
    setAttachAuth(p.auth);
    setNote(null);
  };

  const send = useCallback(async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    setNote(null);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (attachAuth) {
      const token = await gateway.ensureAdminToken();
      if (!token) {
        setNote(
          'Admin bearer unavailable — the dev-token minter is sandbox-only (a production gateway 404s it). Sending without Authorization.',
        );
      } else {
        headers.Authorization = `Bearer ${token}`;
      }
    }
    const init: RequestInit = { method, headers };
    if (hasBody && body.trim()) {
      headers['Content-Type'] = 'application/json';
      init.body = body;
    }
    const url = `${gateway.apiBase}${path}`;
    const started = performance.now();
    let entry: LogEntry;
    try {
      const res = await fetch(url, init);
      const text = await res.text();
      const { body: pretty, truncated } = prettify(text);
      entry = {
        id: nextId.current++,
        method,
        path,
        status: res.status,
        statusText: res.statusText,
        ms: Math.round(performance.now() - started),
        body: pretty,
        truncated,
      };
    } catch (err) {
      entry = {
        id: nextId.current++,
        method,
        path,
        status: null,
        statusText: err instanceof Error ? err.message : 'network error',
        ms: Math.round(performance.now() - started),
        body: '',
        truncated: false,
      };
    }
    setLog((prev) => [entry, ...prev].slice(0, 50));
    setBusy(false);
    // Depend on the specific stable members used, not the whole `gateway` object
    // (a fresh object each render) — keeps this handler's identity stable.
  }, [busy, attachAuth, method, hasBody, body, path, gateway.apiBase, gateway.ensureAdminToken]);

  return (
    <Panel className="h-full">
      <PanelHeader
        title="API Console"
        icon={SquareTerminal}
        right={
          <span className="flex items-center gap-1.5">
            <span className={`h-1.5 w-1.5 rounded-full ${live ? 'bg-verified' : 'bg-denied'}`} />
            <span className="font-mono text-[11px]">{shownBase}</span>
          </span>
        }
      />

      {/* Presets */}
      <div className="flex flex-wrap gap-1.5 border-b border-hairline px-4 py-2.5">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            type="button"
            onClick={() => applyPreset(p)}
            className="rounded-md border border-hairline bg-canvas px-2 py-1 font-mono text-[11px] text-slate-400 transition hover:border-ink/30 hover:text-ink"
            title={`${p.method} ${p.path}${p.auth ? ' · admin' : ''}`}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Request bar */}
      <div className="flex flex-col gap-2 border-b border-hairline px-4 py-3">
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="w-full sm:w-28">
            <Select
              value={method}
              onChange={(e) => setMethod(e.target.value as Method)}
              mono
            >
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </Select>
          </div>
          <Input
            mono
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/v1/version"
            onKeyDown={(e) => {
              if (e.key === 'Enter') void send();
            }}
          />
          <button
            type="button"
            onClick={() => void send()}
            disabled={busy}
            className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-ink/20 bg-ink px-3.5 py-1.5 text-[12px] font-semibold text-surface transition hover:opacity-90 disabled:opacity-50"
          >
            {busy ? <Loader2 size={13} className="animate-spin" /> : <SendHorizontal size={13} />}
            Send
          </button>
        </div>
        {hasBody ? (
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder='{ "source_format": "openai_tool_call", "tool_call": { … }, "jwt": "…" }'
            spellCheck={false}
            rows={4}
            className="w-full rounded-lg border border-hairline bg-canvas px-2.5 py-2 font-mono text-[12px] text-ink outline-none focus:border-ink/30 focus:shadow-focus-ring"
          />
        ) : null}
        <label className="flex items-center gap-2 text-[12px] text-slate-400">
          <input
            type="checkbox"
            checked={attachAuth}
            onChange={(e) => setAttachAuth(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-hairline"
          />
          Attach admin bearer (CAP_DIRECTORY_ADMIN — sandbox/dev-minter only)
        </label>
        {note ? <p className="text-[11px] text-staged">{note}</p> : null}
      </div>

      {/* Scrollback */}
      <div className="min-h-0 flex-1 overflow-auto bg-elevated/40 px-4 py-3 font-mono text-[12px]">
        {log.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
            {live ? (
              <>
                <SquareTerminal size={22} className="text-slate-600" />
                <p className="text-[12px] text-slate-500">
                  Fire a real request against the connected gateway. Pick a preset or type a path.
                </p>
              </>
            ) : (
              <>
                <PlugZap size={22} className="text-slate-600" />
                <p className="text-[12px] text-slate-500">
                  No gateway connected — requests will fail honestly until one answers.
                </p>
              </>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {log.map((e) => {
              const ok = e.status !== null && e.status >= 200 && e.status < 300;
              const tone = e.status === null ? 'text-staged' : ok ? 'text-verified' : 'text-denied';
              return (
                <div key={e.id}>
                  <div className="flex items-center gap-2 text-slate-400">
                    <span className="text-ink">$</span>
                    <span className="font-semibold">{e.method}</span>
                    <span className="truncate">{e.path}</span>
                  </div>
                  <div className={`mt-0.5 ${tone}`}>
                    {e.status === null ? `✕ ${e.statusText}` : `${e.status} ${e.statusText}`}
                    <span className="ml-2 text-slate-500">· {e.ms} ms</span>
                  </div>
                  {e.body ? (
                    <pre className="mt-1 whitespace-pre-wrap break-words text-[11.5px] text-slate-300">
                      {e.body}
                    </pre>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      {log.length > 0 ? (
        <div className="flex shrink-0 items-center justify-end border-t border-hairline px-4 py-2">
          <button
            type="button"
            onClick={() => setLog([])}
            className="inline-flex items-center gap-1.5 text-[12px] font-medium text-slate-500 transition hover:text-ink"
          >
            <Trash2 size={13} />
            Clear
          </button>
        </div>
      ) : null}
    </Panel>
  );
}
