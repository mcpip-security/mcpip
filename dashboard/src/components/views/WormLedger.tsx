/* ---------------------------------------------------------------------------
   WORM Audit Ledger — the console's core promise, rendered honestly.

   'events'    — the session-observed decision feed (lib/ledger.ts ring buffer
                 over /v1/admin/decisions/recent) with the REAL worm_sequence,
                 filter presets for the tripwire denies, and a master-detail
                 inspector whose fields are the VERBATIM whitelist projection.
                 The killer feature: per-event inclusion proofs — fetched from
                 /v1/audit/proof/{event_id} and re-verified IN THIS BROWSER by
                 recomputing the Merkle path with WebCrypto.
   'integrity' — the signed epoch chain: live /v1/audit/verify state with
                 first_bad_epoch detail, an on-demand check (which force-seals
                 the open tail epoch — a real side effect), and the honest
                 external-verifier explanation on production gateways.

   Nothing here is fabricated: offline renders the standard EmptyState with a
   connect CTA; every number, hash, and verdict traces to a gateway response
   or to crypto computed here over gateway bytes.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  BadgeCheck,
  Check,
  ClipboardCheck,
  Copy,
  Download,
  FileJson,
  FileSearch,
  Fingerprint,
  Inbox,
  Loader2,
  Lock,
  MousePointerClick,
  Radio,
  RefreshCw,
  ScrollText,
  Search,
  SearchX,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Camera,
  CameraOff,
} from 'lucide-react';
import { Badge, Detail, EmptyState, Panel, PanelHeader, Select } from '../ui';
import type {
  AuditAttestation,
  ComplianceEvidence,
  ForensicFeatureStatus,
} from '../../lib/api';
import { formatClock } from '../../lib/format';
import {
  ALL_STATUSES,
  STATUS_META,
  runForensicRead,
  runInclusionProof,
  useChainVerify,
  useWormLedger,
} from '../../lib/ledger';
import type { ForensicRun, LedgerRow, ProofRun, UseWormLedger } from '../../lib/ledger';
import type { GatewayLive } from '../../lib/useGatewayLive';

/** Decision-state tint recipes (charter: /25 border · /5–/8 fill · full text). */
const TONE_CHIP = {
  verified: 'border-verified/25 bg-verified/8 text-verified',
  denied: 'border-denied/25 bg-denied/8 text-denied',
  staged: 'border-staged/25 bg-staged/8 text-staged',
} as const;
const TONE_BANNER = {
  verified: 'border-verified/25 bg-verified/5 text-verified',
  denied: 'border-denied/25 bg-denied/5 text-denied',
  staged: 'border-staged/25 bg-staged/5 text-staged',
} as const;

/** Keep the DOM sane under a large session buffer; the export carries it all. */
const MAX_RENDERED = 500;

function navigateTo(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

function fmtTimestamp(ts: number): string {
  const d = new Date(ts);
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes(),
  )}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function clock(ts: number): string {
  const d = new Date(ts);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function ConnectAction(): JSX.Element {
  return (
    <button type="button" className="btn-primary" onClick={() => navigateTo('gateway', 'connection')}>
      Connect gateway
    </button>
  );
}

/* One short muted helper line — the only in-panel explanation treatment. */
function Hint({ children }: { children: React.ReactNode }): JSX.Element {
  return <p className="text-[10.5px] leading-relaxed text-slate-500">{children}</p>;
}

/* --- Toolbar: search · observed-value filters · the one honest export ------ */

function Toolbar({ ledger }: { ledger: UseWormLedger }): JSX.Element {
  const radioTone =
    ledger.feedState === 'ok'
      ? 'text-verified'
      : ledger.feedState === 'unavailable'
        ? 'text-staged'
        : 'text-slate-500';
  return (
    <div className="panel shrink-0">
      <div className="flex flex-wrap items-center gap-2.5 px-4 py-2.5">
        <div className="relative min-w-[220px] flex-1">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={ledger.filters.query}
            onChange={(e) => ledger.setQuery(e.target.value)}
            placeholder="Filter · correlation id · event id · alias · agent · reason"
            className="w-full rounded-lg border border-hairline bg-canvas py-1.5 pl-8 pr-3 font-mono text-[12px] text-ink placeholder:font-sans placeholder:text-slate-500 focus:border-ink/30 focus:outline-none focus:shadow-focus-ring"
          />
        </div>

        <Select
          mono
          value={ledger.filters.alias}
          onChange={(e) => ledger.setAlias(e.target.value)}
          className="!w-auto min-w-[140px]"
        >
          <option value="">All aliases</option>
          {ledger.aliases.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </Select>

        <Select
          mono
          value={ledger.filters.agent}
          onChange={(e) => ledger.setAgent(e.target.value)}
          className="!w-auto min-w-[140px]"
        >
          <option value="">All agents</option>
          {ledger.agents.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </Select>

        <Select
          mono
          value={ledger.filters.reason}
          onChange={(e) => ledger.setReason(e.target.value)}
          className="!w-auto min-w-[160px]"
        >
          <option value="">All deny reasons</option>
          {ledger.reasons.map(({ reason, count }) => (
            <option key={reason} value={reason}>
              {reason} ({count})
            </option>
          ))}
        </Select>

        <button
          type="button"
          onClick={ledger.exportJsonl}
          disabled={ledger.observedCount === 0}
          className="btn-ghost ml-auto"
          title="Download the session-observed projection rows (JSONL). A console projection — the signed WORM chain is the authority."
        >
          <Download size={13} /> Export session JSONL
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-1.5 border-t border-hairline px-4 py-2">
        <span className="mr-1 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
          Decision
        </span>
        {ALL_STATUSES.map((s) => {
          const on = ledger.filters.statuses.has(s);
          const meta = STATUS_META[s];
          return (
            <button
              key={s}
              type="button"
              onClick={() => ledger.toggleStatus(s)}
              className={`rounded-md border px-1.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide transition-colors focus:outline-none focus-visible:shadow-focus-ring ${
                on ? TONE_CHIP[meta.tone] : 'border-hairline bg-canvas text-slate-500 hover:text-ink'
              }`}
            >
              {meta.label}
            </button>
          );
        })}
        {ledger.hasActiveFilters ? (
          <button
            type="button"
            onClick={ledger.clearFilters}
            className="ml-1 text-[11px] font-medium text-slate-500 transition-colors hover:text-ink focus:outline-none focus-visible:shadow-focus-ring"
          >
            Reset filters
          </button>
        ) : null}
        <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-500">
          <Radio size={12} className={radioTone} />
          {ledger.feedState === 'unavailable' ? (
            <span className="text-staged">feed read failing — session buffer shown</span>
          ) : ledger.observedSince !== null ? (
            <>
              <span className="tabular">{ledger.observedCount}</span> observed since{' '}
              <span className="font-mono text-[10.5px] text-slate-400">{clock(ledger.observedSince)}</span>
            </>
          ) : (
            'contacting feed'
          )}
        </span>
      </div>
    </div>
  );
}

/* --- Inspector: the verbatim projection + the per-event inclusion proof ---- */

function InspectorEmpty(): JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <MousePointerClick size={22} className="text-slate-600" />
      <p className="text-[12.5px] font-medium text-slate-400">Select an event</p>
      <p className="max-w-[230px] text-[11.5px] leading-relaxed text-slate-500">
        Pick a row to inspect its record and verify its integrity proof.
      </p>
    </div>
  );
}

function ProofOutcome({ proof }: { proof: ProofRun }): JSX.Element | null {
  if (proof.phase === 'fetching') {
    return null; // the button's spinner narrates the in-flight fetch
  }

  if (proof.phase === 'unsealed') {
    return (
      <div className="mt-2.5 space-y-1.5">
        <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${TONE_BANNER.staged}`}>
          <ShieldAlert size={13} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Not sealed yet. </span>
            {proof.detail}.
          </span>
        </div>
        <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
          The tail epoch is still open — run a check on the Integrity tab, or retry in a moment.
        </p>
      </div>
    );
  }

  if (proof.phase === 'unavailable') {
    return (
      <div className="mt-2.5 space-y-1.5">
        <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
          <ShieldAlert size={13} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Proof endpoint unavailable. </span>
            {proof.detail}.
          </span>
        </div>
        <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
          Production gateways never mount this endpoint — export the ledger with{' '}
          <span className="font-mono text-[10.5px]">mcpip export-audit</span> and verify externally.
        </p>
      </div>
    );
  }

  // proved — render the REAL proof material plus this browser's own verdict.
  const { proof: incl, local } = proof;
  const banner =
    local.verdict === 'match'
      ? {
          classes: TONE_BANNER.verified,
          icon: <ShieldCheck size={13} className="mt-0.5 shrink-0" />,
          title: 'Inclusion proved in this browser.',
          text: `SHA-256 over the sealed record and the ${incl.proof.length}-hop sibling path reproduces the signed epoch-${incl.epoch} root exactly.`,
        }
      : local.verdict === 'mismatch'
        ? {
            classes: TONE_BANNER.denied,
            icon: <ShieldAlert size={13} className="mt-0.5 shrink-0" />,
            title: 'Inclusion NOT verified.',
            text: `${local.detail}. Treat this event as unverified — run a chain verification and audit the gateway.`,
          }
        : {
            classes: 'border-hairline bg-canvas text-slate-400',
            icon: <ShieldAlert size={13} className="mt-0.5 shrink-0" />,
            title: 'Proof fetched, not recomputed.',
            text: `${local.detail}.`,
          };

  return (
    <div className="mt-2.5 space-y-4">
      <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${banner.classes}`}>
        {banner.icon}
        <span>
          <span className="font-semibold">{banner.title} </span>
          {banner.text}
        </span>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
        <Detail label="Epoch" mono>
          #{incl.epoch}
        </Detail>
        <Detail label="Leaf index" mono>
          {incl.index}
        </Detail>
        <Detail label="Signed Merkle root" mono span>
          {incl.merkle_root}
        </Detail>
        {local.computedRoot !== null ? (
          <Detail
            label="Root recomputed here"
            mono
            span
            tone={local.verdict === 'match' ? 'verified' : 'denied'}
          >
            {local.computedRoot}
          </Detail>
        ) : null}
        <Detail label="Epoch hash" mono span>
          {incl.epoch_hash}
        </Detail>
        <Detail label="Ed25519 signature" mono span>
          {incl.signature}
        </Detail>
      </dl>

      <div>
        <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
          Merkle path · {incl.proof.length} {incl.proof.length === 1 ? 'hop' : 'hops'}
        </p>
        {incl.proof.length === 0 ? (
          <p className="text-[10.5px] leading-relaxed text-slate-500">
            Single-leaf epoch — the record&apos;s leaf hash is the epoch root itself.
          </p>
        ) : (
          <ol className="overflow-hidden rounded-lg border border-hairline">
            {incl.proof.map(([side, sibling], i) => (
              <li
                key={i}
                className="flex items-baseline gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-1.5 last:border-0"
              >
                <span className="tabular w-4 shrink-0 font-mono text-[10px] text-slate-500">{i}</span>
                <span className="shrink-0 font-mono text-[10px] font-semibold text-ink">{side}</span>
                <span className="break-all font-mono text-[10px] leading-relaxed text-slate-400">
                  {sibling}
                </span>
              </li>
            ))}
          </ol>
        )}
      </div>

      <div>
        <div className="mb-1.5 flex items-center gap-1.5">
          <FileJson size={12} className="text-slate-500" />
          <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
            Sealed WORM record
          </span>
        </div>
        <pre className="max-h-44 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-hairline bg-canvas p-3 font-mono text-[10.5px] leading-relaxed text-ink">
          {incl.record}
        </pre>
        <div className="mt-1.5">
          <Hint>
            The exact bytes the gateway sealed, returned verbatim by{' '}
            <span className="font-mono">/v1/audit/proof</span>.
          </Hint>
        </div>
      </div>
    </div>
  );
}

/* --- Forensic reconstruction: the CAP_FORENSIC_READ investigator payload ---- */

function fmtCapturedAt(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return '—';
  }
  return fmtTimestamp(Math.round(seconds * 1000));
}

function ForensicOutcome({ forensic }: { forensic: ForensicRun }): JSX.Element | null {
  if (forensic.phase === 'fetching') {
    return null; // the button spinner narrates the in-flight read
  }

  if (forensic.phase === 'absent') {
    return (
      <div className="mt-2.5 space-y-1.5">
        <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
          <FileSearch size={13} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">No reconstructed payload for this correlation id. </span>
            This is not an error.
          </span>
        </div>
        <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
          Capture may be off, never taken, or expired — the gateway keeps these indistinguishable
          by design.
        </p>
      </div>
    );
  }

  if (forensic.phase === 'denied') {
    return (
      <div className="mt-2.5 space-y-1.5">
        <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${TONE_BANNER.denied}`}>
          <ShieldAlert size={13} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Forensic read denied. </span>
            The credential lacked <span className="font-mono text-[10.5px]">CAP_FORENSIC_READ</span>.
          </span>
        </div>
        <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
          Raw-payload reconstruction is a separately-granted investigator authority — directory
          admin alone does not confer it (least privilege). The read is also blocked for a revoked
          or quarantined credential.
        </p>
      </div>
    );
  }

  if (forensic.phase === 'unavailable') {
    return (
      <div className="mt-2.5 space-y-1.5">
        <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
          <ShieldAlert size={13} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Forensic read unavailable. </span>
            {forensic.detail}.
          </span>
        </div>
      </div>
    );
  }

  // found — render the REAL reconstructed query. Every field is gateway-served;
  // secrets and the hidden target are never in this record (redacted at capture).
  const r = forensic.record;
  const argsJson = JSON.stringify(r.arguments, null, 2);

  return (
    <div className="mt-2.5 space-y-4">
      <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${TONE_BANNER.verified}`}>
        <FileSearch size={13} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">Query reconstructed. </span>
          The real alias and normalized arguments this agent sent — decrypted from the encrypted
          forensic capture. This read was WORM-audited before disclosure.
        </span>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
        <Detail label="Alias" mono span tone="ink">
          {r.alias}
        </Detail>
        <Detail label="Agent" mono>
          {r.agent_id || '—'}
        </Detail>
        <Detail label="Role (authorizes nothing)" mono>
          {r.role || '—'}
        </Detail>
        <Detail label="Issuer" mono>
          {r.issuer || '—'}
        </Detail>
        <Detail label="Tenant" mono>
          {r.tenant_id}
        </Detail>
        <Detail label="Source format" mono>
          {r.source_format || '—'}
        </Detail>
        <Detail label="Decision" tone={r.decision === 'allow' ? 'verified' : 'denied'}>
          {r.decision || '—'}
        </Detail>
        <Detail label="Deny reason" mono tone={r.deny_reason !== null ? 'ink' : 'muted'}>
          {r.deny_reason ?? '—'}
        </Detail>
        {r.act_sub !== null ? (
          <Detail label="Delegation actor (act.sub)" mono span>
            {r.act_sub}
          </Detail>
        ) : null}
        <Detail label="Captured at" mono span>
          {fmtCapturedAt(r.captured_at)}
        </Detail>
      </dl>

      <div>
        <div className="mb-1.5 flex items-center gap-1.5">
          <FileJson size={12} className="text-slate-500" />
          <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
            Normalized arguments
          </span>
        </div>
        <pre className="max-h-56 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-hairline bg-canvas p-3 font-mono text-[10.5px] leading-relaxed text-ink">
          {argsJson === '{}' ? '{ }  — this request carried no arguments' : argsJson}
        </pre>
        <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">
          The already-canonicalized arguments the gateway hashed for the payload lock, run through
          the WORM redaction discipline. Secrets — pin, jwt, tokens, vended credentials — are never
          captured, and the hidden real <span className="font-mono">target</span> is never included.
        </p>
      </div>
    </div>
  );
}

/* --- Proactive forensic-capture posture: the honest deployment-wide signal ---
   Shown BEFORE the reconstruct button so the operator learns WHY a reconstruct
   would come back empty (feature off / absent) instead of only discovering it
   reactively as an 'absent' 404. This is the coarse, deployment-wide posture read
   from admin_stats.features.forensic_capture — NOT a per-correlation-id oracle (the
   per-id 404 stays deliberately opaque). ------------------------------------- */
function ForensicCaptureBanner({
  posture,
}: {
  posture: ForensicFeatureStatus | null | 'loading';
}): JSX.Element | null {
  if (posture === 'loading' || posture === null) {
    // Unknown posture (no admin token / pre-block gateway) — say nothing rather
    // than guess. The reactive 'absent' outcome remains the per-id fallback.
    return null;
  }
  if (posture.status === 'enabled') {
    return (
      <div className="mb-2.5 flex items-start gap-2 rounded-lg border border-verified/25 bg-verified/8 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
        <Camera size={13} className="mt-0.5 shrink-0 text-verified" />
        <span>
          <span className="font-semibold text-ink">Forensic capture is live on this gateway. </span>
          {posture.detail}
        </span>
      </div>
    );
  }
  // disabled (production-default / explicit-opt-out) or absent (flag-on-no-key):
  // a prominent, honest banner explaining WHY reconstruction is unavailable + how
  // to enable it — the server-supplied detail carries the exact reason.
  const absent = posture.status === 'absent';
  return (
    <div
      className={`mb-2.5 flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed ${
        absent ? TONE_BANNER.denied : 'border-staged/25 bg-staged/8 text-slate-500'
      }`}
    >
      {absent ? (
        <AlertTriangle size={13} className="mt-0.5 shrink-0" />
      ) : (
        <CameraOff size={13} className="mt-0.5 shrink-0 text-staged" />
      )}
      <span>
        <span className="font-semibold text-ink">
          {absent
            ? 'Forensic capture is configured but ABSENT (no key).'
            : 'Forensic capture is disabled on this gateway.'}{' '}
        </span>
        {posture.detail}
      </span>
    </div>
  );
}

function Inspector({
  row,
  proof,
  forensic,
  capturePosture,
  onRunProof,
  onRunForensic,
}: {
  row: LedgerRow;
  proof: ProofRun | null;
  forensic: ForensicRun | null;
  capturePosture: ForensicFeatureStatus | null | 'loading';
  onRunProof: () => void;
  onRunForensic: () => void;
}): JSX.Element {
  const p = row.projection;
  const meta = STATUS_META[row.status];
  const fetching = proof?.phase === 'fetching';
  const forensicFetching = forensic?.phase === 'fetching';

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-2.5 border-b border-hairline px-4 py-3">
        <Fingerprint size={15} className="text-slate-500" />
        <span className="text-[13px] font-semibold text-ink">Decision event</span>
        <Badge tone={meta.tone}>{meta.label}</Badge>
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="Correlation id" mono span>
            {p.correlation_id}
          </Detail>
          <Detail label="Event id" mono span tone={p.event_id !== null ? 'ink' : 'muted'}>
            {p.event_id ?? 'not projected by this gateway'}
          </Detail>
          <Detail label="WORM sequence" mono>
            #{p.worm_sequence}
          </Detail>
          {/* timestamp_ns exceeds JS number precision (2^53) — render at the ms
              precision a browser can actually hold, never a silently-drifted ns. */}
          <Detail label="Timestamp" mono>
            {fmtTimestamp(row.ts)}
          </Detail>
          <Detail label="Tenant" mono>
            {p.tenant_id}
          </Detail>
          <Detail label="Agent" mono>
            {p.agent_id ?? '—'}
          </Detail>
          <Detail label="Alias" mono>
            {p.alias ?? '—'}
          </Detail>
          <Detail label="Decision" tone={p.decision === 'allow' ? 'verified' : 'denied'}>
            {p.decision}
          </Detail>
          <Detail label="Deny reason" mono tone={p.deny_reason !== null ? 'ink' : 'muted'}>
            {p.deny_reason ?? '—'}
          </Detail>
          <Detail label="Transport class" mono>
            {p.transport ?? '—'}
          </Detail>
          <Detail label="Risk tier" mono>
            {p.risk_tier ?? '—'}
          </Detail>
          <Detail label="Classification" mono>
            {p.classification ?? '—'}
          </Detail>
          <Detail label="Source format" mono>
            {p.source_format ?? '—'}
          </Detail>
          {p.transaction_ref !== null ? (
            <Detail label="Transaction ref" mono span>
              {p.transaction_ref}
            </Detail>
          ) : null}
        </dl>

        <Hint>
          The gateway&apos;s own record of this decision — payloads and real targets are never
          included.
        </Hint>

        {/* Integrity (Merkle inclusion) proof — the per-event affordance, surfaced
            only when the row carries an event_id the proof endpoint can anchor on. */}
        {p.event_id === null ? (
          <div className="border-t border-hairline pt-4">
            <div className="mb-2 flex items-center gap-1.5">
              <ShieldCheck size={12} className="text-slate-500" />
              <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
                Integrity proof
              </span>
            </div>
            <p className="text-[10.5px] leading-relaxed text-slate-500">
              This gateway&apos;s feed rows carry no{' '}
              <span className="font-mono">event_id</span> — upgrade the gateway to request
              per-event proofs.
            </p>
          </div>
        ) : (
          <div className="border-t border-hairline pt-4">
            <div className="mb-2 flex items-center gap-1.5">
              <ShieldCheck size={12} className="text-slate-500" />
              <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
                Integrity proof
              </span>
            </div>
            <button
              type="button"
              onClick={onRunProof}
              disabled={fetching}
              className="btn-primary w-full"
            >
              {fetching ? <Loader2 size={13} className="animate-spin" /> : <ShieldCheck size={13} />}
              Verify integrity proof
            </button>
            {proof !== null ? <ProofOutcome proof={proof} /> : null}
          </div>
        )}

        {/* Forensic reconstruction — the CAP_FORENSIC_READ investigator payload. */}
        <div className="border-t border-hairline pt-4">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <FileSearch size={12} className="text-slate-500" />
              <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
                Forensic reconstruction
              </span>
            </div>
            <span className="inline-flex items-center gap-1 rounded-md border border-staged/25 bg-staged/8 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-staged">
              <Lock size={10} className="shrink-0" />
              access is audited
            </span>
          </div>
          <Hint>
            Rebuilds the real query behind this correlation id — needs{' '}
            <span className="font-mono">CAP_FORENSIC_READ</span>, and the read itself is
            WORM-logged.
          </Hint>
          <div className="mt-2.5">
            <ForensicCaptureBanner posture={capturePosture} />
            <button
              type="button"
              onClick={onRunForensic}
              disabled={forensicFetching}
              className="btn-primary w-full"
            >
              {forensicFetching ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <FileSearch size={13} />
              )}
              Reconstruct payload
            </button>
            {forensic !== null ? <ForensicOutcome forensic={forensic} /> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

/* --- Events sub-tab: toolbar + master table + inspector --------------------- */

function Events({ gateway, ledger }: { gateway: GatewayLive; ledger: UseWormLedger }): JSX.Element {
  const [selected, setSelected] = useState<LedgerRow | null>(null);
  const [proof, setProof] = useState<ProofRun | null>(null);
  const [forensic, setForensic] = useState<ForensicRun | null>(null);
  // Deployment-wide forensic-capture posture (admin_stats.features.forensic_capture),
  // read once per live connection to drive the PROACTIVE inspector banner. 'loading'
  // until first read; null when unknown (no admin token / pre-block gateway).
  const [capturePosture, setCapturePosture] = useState<
    ForensicFeatureStatus | null | 'loading'
  >('loading');
  const selectedKeyRef = useRef<string | null>(null);
  const { fetchDeploymentStats } = gateway;

  // A connection drop (or gateway switch) resets the buffer — drop the stale
  // selection with it so the inspector never shows another ledger's row.
  useEffect(() => {
    if (gateway.mode !== 'live') {
      selectedKeyRef.current = null;
      setSelected(null);
      setProof(null);
      setForensic(null);
      setCapturePosture('loading');
    }
  }, [gateway.mode]);

  // Read the coarse capture posture once the gateway is live. Fails soft to null
  // (unknown) — never a fabricated "enabled".
  useEffect(() => {
    if (gateway.mode !== 'live') return;
    let cancelled = false;
    const ac = new AbortController();
    setCapturePosture('loading');
    void fetchDeploymentStats(ac.signal).then((s) => {
      if (cancelled) return;
      setCapturePosture(s === null ? null : (s.features?.forensic_capture ?? null));
    });
    return () => {
      cancelled = true;
      ac.abort();
    };
  }, [gateway.mode, fetchDeploymentStats]);

  if (gateway.mode !== 'live') {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={ScrollText}
          title="No gateway connected"
          detail="Connect a gateway to stream its live decision feed."
          action={<ConnectAction />}
        />
      </Panel>
    );
  }

  const select = (row: LedgerRow): void => {
    selectedKeyRef.current = row.key;
    setSelected(row);
    setProof(null);
    setForensic(null);
  };

  const runProof = (row: LedgerRow): void => {
    const eventId = row.projection.event_id;
    if (eventId === null) return;
    const key = row.key;
    setProof({ phase: 'fetching' });
    void runInclusionProof(gateway, eventId).then((outcome) => {
      // Ignore a result landing after the operator moved to another row.
      if (selectedKeyRef.current === key) {
        setProof(outcome);
      }
    });
  };

  const runForensic = (row: LedgerRow): void => {
    const key = row.key;
    setForensic({ phase: 'fetching' });
    void runForensicRead(gateway, row.projection.correlation_id).then((outcome) => {
      // Ignore a result landing after the operator moved to another row.
      if (selectedKeyRef.current === key) {
        setForensic(outcome);
      }
    });
  };

  const visible = ledger.rows.slice(0, MAX_RENDERED);

  let body: JSX.Element;
  if (ledger.observedCount === 0) {
    body =
      ledger.feedState === 'unavailable' ? (
        <EmptyState
          icon={ShieldAlert}
          title="Decision feed unavailable"
          detail="The admin feed read failed — the console needs a CAP_DIRECTORY_ADMIN credential on this gateway."
        />
      ) : ledger.feedState === 'waiting' ? (
        <EmptyState
          icon={Radio}
          title="Contacting the decision feed"
          detail="The first read of /v1/admin/decisions/recent is in flight."
        />
      ) : (
        <EmptyState
          icon={Inbox}
          title="No decisions observed this session"
          detail="The feed is live and idle — real agent traffic appears within ~3 s."
          action={
            <button type="button" className="btn-ghost" onClick={() => navigateTo('command', 'probe')}>
              Fire an Authorize Probe
            </button>
          }
        />
      );
  } else if (ledger.rows.length === 0) {
    body = (
      <EmptyState
        icon={SearchX}
        title="No events match the current filters"
        detail={`${ledger.observedCount} session-observed events are hidden by the active filters.`}
        action={
          <button type="button" className="btn-ghost" onClick={ledger.clearFilters}>
            Clear filters
          </button>
        }
      />
    );
  } else {
    body = (
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-hairline text-[10.5px] font-semibold uppercase tracking-[0.06em] text-slate-500">
              <th className="px-4 py-2.5 font-semibold">Time</th>
              <th className="px-4 py-2.5 font-semibold">WORM seq</th>
              <th className="px-4 py-2.5 font-semibold">Decision</th>
              <th className="px-4 py-2.5 font-semibold">Alias</th>
              <th className="px-4 py-2.5 font-semibold">Agent</th>
              <th className="px-4 py-2.5 font-semibold">Deny reason</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => {
              const on = selected?.key === row.key;
              const meta = STATUS_META[row.status];
              return (
                <tr
                  key={row.key}
                  onClick={() => select(row)}
                  className={`cursor-pointer border-b border-hairline/60 transition-colors last:border-0 ${
                    on ? 'bg-canvas' : 'hover:bg-canvas'
                  }`}
                >
                  <td className="tabular whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-400">
                    {formatClock(row.ts)}
                  </td>
                  <td className="tabular whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-400">
                    #{row.projection.worm_sequence}
                  </td>
                  <td className="px-4 py-2">
                    <Badge tone={meta.tone}>{meta.label}</Badge>
                  </td>
                  <td className="px-4 py-2 font-mono text-[11px] text-ink">
                    <span className="block max-w-[200px] truncate">{row.projection.alias ?? '—'}</span>
                  </td>
                  <td className="px-4 py-2 font-mono text-[11px] text-slate-400">
                    <span className="block max-w-[180px] truncate">
                      {row.projection.agent_id ?? '—'}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-[11px] text-slate-400">
                    {row.projection.deny_reason ?? '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {ledger.rows.length > MAX_RENDERED ? (
          <p className="border-t border-hairline/60 px-4 py-2 text-[10.5px] text-slate-500">
            Showing the newest {MAX_RENDERED} of{' '}
            <span className="tabular">{ledger.rows.length}</span> matching events — refine the
            filters, or export the full session projection.
          </p>
        ) : null}
      </div>
    );
  }

  const inspector = selected !== null ? (
    <Inspector
      row={selected}
      proof={proof}
      forensic={forensic}
      capturePosture={capturePosture}
      onRunProof={() => runProof(selected)}
      onRunForensic={() => runForensic(selected)}
    />
  ) : (
    <InspectorEmpty />
  );

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar ledger={ledger} />

      {/* ONE job per screen: the live decision feed as a master-detail. Chain
          integrity lives on its own Integrity child tab (Ledger → Integrity). */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_400px]">
        <Panel>
          <PanelHeader
            icon={ScrollText}
            title="Decisions"
            right={
              <span className="tabular">
                {ledger.rows.length} of {ledger.observedCount} observed this session
              </span>
            }
          />
          <div className="flex min-h-0 flex-1 flex-col">{body}</div>
        </Panel>

        <Panel className="hidden xl:flex">{inspector}</Panel>
      </div>

      {/* Below xl the inspector stacks under the table when a row is selected. */}
      {selected !== null ? <Panel className="max-h-[55vh] shrink-0 xl:hidden">{inspector}</Panel> : null}
    </div>
  );
}

/** The Integrity child tab — chain verify + attestation & evidence, alone on its
 *  own screen (the operator asked for tab splits over stacked scrolls). Its own
 *  offline guard: the Events guard no longer stands in front of it. */
function Integrity({ gateway }: { gateway: GatewayLive }): JSX.Element {
  if (gateway.mode !== 'live') {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={ScrollText}
          title="No gateway connected"
          detail="Connect a gateway to verify its chain and export its signed attestation."
          action={<ConnectAction />}
        />
      </Panel>
    );
  }
  return (
    <div className="h-full overflow-y-auto pr-0.5">
      <ChainIntegritySection gateway={gateway} />
    </div>
  );
}

/* --- Chain Integrity sub-tab ------------------------------------------------ */

function MetricTile({
  label,
  value,
  tone = 'ink',
  sub,
}: {
  label: string;
  value: string;
  tone?: 'ink' | 'verified' | 'denied';
  sub?: string;
}): JSX.Element {
  const toneClass =
    tone === 'verified' ? 'text-verified' : tone === 'denied' ? 'text-denied' : 'text-ink';
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span className={`metric-value truncate ${toneClass}`}>{value}</span>
      {sub !== undefined ? <span className="truncate text-[10.5px] text-slate-500">{sub}</span> : null}
    </div>
  );
}

/* --- Attestation & evidence: the ONE portable audit-export panel ------------
   The former standalone 'Portable attestation' and 'Compliance evidence' panels
   merged into a single panel. The signed attestation is the DEFAULT FOCUS (it is
   the only production-available read); the CAP_DIRECTORY_ADMIN compliance bundle
   — control mapping + verbatim disclaimer + its own evidence export — is folded
   into a COLLAPSED disclosure beneath it. Two independent live reads, honest
   states throughout: neither ever fabricates a header. ------------------------ */

type AttestationState =
  | { phase: 'loading' }
  | { phase: 'unavailable' }
  | { phase: 'ok'; att: AuditAttestation; atMs: number };

type ComplianceState =
  | { phase: 'loading' }
  | { phase: 'unavailable' }
  | { phase: 'ok'; bundle: ComplianceEvidence };

function AttestationEvidence({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { fetchAuditAttestation, fetchComplianceEvidence } = gateway;

  // Attestation — GET /v1/audit/attestation (production-available, plain-JWT). It
  // mints no key and signs nothing new: every signed field was Ed25519-signed at
  // epoch close / anchor append.
  const [state, setState] = useState<AttestationState>({ phase: 'loading' });
  const [copied, setCopied] = useState(false);

  // Compliance evidence — GET /v1/admin/compliance/evidence (CAP_DIRECTORY_ADMIN).
  // Evidence, NEVER a certification; the bundle's own disclaimer prints verbatim.
  const [compState, setCompState] = useState<ComplianceState>({ phase: 'loading' });
  const [compCopied, setCompCopied] = useState(false);

  const load = useCallback(
    async (signal?: AbortSignal): Promise<void> => {
      setState({ phase: 'loading' });
      const att = await fetchAuditAttestation(signal);
      if (signal?.aborted) return;
      setState(att === null ? { phase: 'unavailable' } : { phase: 'ok', att, atMs: Date.now() });
    },
    [fetchAuditAttestation],
  );

  const loadComp = useCallback(
    async (signal?: AbortSignal): Promise<void> => {
      setCompState({ phase: 'loading' });
      const bundle = await fetchComplianceEvidence(signal);
      if (signal?.aborted) return;
      setCompState(bundle === null ? { phase: 'unavailable' } : { phase: 'ok', bundle });
    },
    [fetchComplianceEvidence],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    const controller = new AbortController();
    void loadComp(controller.signal);
    return () => controller.abort();
  }, [loadComp]);

  const copyJson = async (att: AuditAttestation): Promise<void> => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(att, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable (permissions / insecure context) — nothing to fake */
    }
  };

  const exportComp = async (bundle: ComplianceEvidence): Promise<void> => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCompCopied(true);
      window.setTimeout(() => setCompCopied(false), 1500);
    } catch {
      /* clipboard unavailable — nothing to fake */
    }
  };

  const att = state.phase === 'ok' ? state.att : null;
  const sealed = att !== null && att.epoch !== null;
  const bundle = compState.phase === 'ok' ? compState.bundle : null;

  return (
    <Panel className="shrink-0">
      <PanelHeader
        icon={BadgeCheck}
        title="Audit exports"
        right={
          <div className="flex items-center gap-2">
            <span className="text-[10.5px] text-slate-500">signed attestation · evidence bundle</span>
            <button
              type="button"
              onClick={() => void load()}
              disabled={state.phase === 'loading'}
              className="btn-ghost !px-1.5 !py-1"
              title="Re-read /v1/audit/attestation"
            >
              {state.phase === 'loading' ? (
                <Loader2 size={12} className="animate-spin" />
              ) : (
                <RefreshCw size={12} />
              )}
            </button>
          </div>
        }
      />
      <div className="space-y-3 px-5 py-4">
        {att !== null ? (
          <>
            <div
              className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11.5px] leading-relaxed ${
                att.intact ? TONE_BANNER.verified : TONE_BANNER.denied
              }`}
            >
              {att.intact ? (
                <ShieldCheck size={14} className="mt-0.5 shrink-0" />
              ) : (
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              )}
              <span>
                <span className="font-semibold">
                  {att.intact ? 'Chain attested intact.' : 'Chain attested TAMPERED.'}
                </span>{' '}
                {att.intact
                  ? 'A fresh verify_chain over the whole signed chain passed at read time.'
                  : `First bad epoch ${att.first_bad_epoch !== null ? `#${att.first_bad_epoch}` : 'unknown'} — preserve the store and export for forensics.`}
              </span>
            </div>

            <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
              <Detail label="Signing key id" mono span tone="ink">
                {att.signing_key_id}
              </Detail>
              {sealed ? (
                <>
                  <Detail label="Sealed epoch" mono>
                    #{att.epoch}
                  </Detail>
                  <Detail label="End sequence" mono>
                    {att.end_seq !== null ? `#${att.end_seq}` : '—'}
                  </Detail>
                  <Detail label="Signed Merkle root" mono span>
                    {att.merkle_root}
                  </Detail>
                  <Detail label="Epoch hash" mono span>
                    {att.epoch_hash}
                  </Detail>
                  <Detail label="Ed25519 signature" mono span>
                    {att.signature}
                  </Detail>
                </>
              ) : null}
              {att.anchor_epoch !== null ? (
                <Detail label="Anchor low-watermark" mono>
                  #{att.anchor_epoch}
                </Detail>
              ) : null}
              {att.anchor_epoch_hash !== null ? (
                <Detail label="Anchor epoch hash" mono span>
                  {att.anchor_epoch_hash}
                </Detail>
              ) : null}
            </dl>

            {!sealed ? (
              <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
                <ShieldAlert size={13} className="mt-0.5 shrink-0" />
                <span>
                  No epoch sealed yet — the attestation carries only the signing key id and the
                  fresh chain verdict. The epoch header commits on the next seal.
                </span>
              </div>
            ) : null}

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void copyJson(att)}
                className="btn-ghost"
                title="Copy the signed attestation JSON for an external verifier"
              >
                {copied ? <Check size={13} /> : <Copy size={13} />}
                {copied ? 'Copied' : 'Copy attestation JSON'}
              </button>
            </div>

            <Hint>
              Verify the signature against the published audit public key with the external
              verifier.
            </Hint>
          </>
        ) : (
          <div className="space-y-1.5">
            <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
              {state.phase === 'loading' ? (
                <Loader2 size={14} className="mt-0.5 shrink-0 animate-spin" />
              ) : (
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              )}
              <span>
                {state.phase === 'loading' ? (
                  'Reading the signed attestation…'
                ) : (
                  <>
                    <span className="font-semibold">Attestation unavailable. </span>
                    The connected gateway did not serve a signed attestation (a pre-endpoint build),
                    or the console holds no verified identity for the read.
                  </>
                )}
              </span>
            </div>
          </div>
        )}
        {/* Compliance evidence — the CAP_DIRECTORY_ADMIN bundle beneath the
            attestation. Evidence, NEVER a certification: the bundle's own disclaimer
            prints verbatim. Its own live read + export. */}
        <div className="border-t border-hairline pt-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <ClipboardCheck size={13} className="text-slate-500" />
              <span className="text-[12.5px] font-semibold text-ink">Compliance evidence</span>
            </div>
            <span className="text-[10.5px] text-slate-500">evidence · not a certification</span>
          </div>
          <div className="mt-3 space-y-3">
            {bundle !== null ? (
              <>
                <div
                  className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11.5px] leading-relaxed ${
                    bundle.attestation.intact ? TONE_BANNER.verified : TONE_BANNER.denied
                  }`}
                >
                  {bundle.attestation.intact ? (
                    <ShieldCheck size={14} className="mt-0.5 shrink-0" />
                  ) : (
                    <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                  )}
                  <span>
                    <span className="font-semibold">
                      {bundle.attestation.intact
                        ? 'Evidence assembled from a live, intact chain.'
                        : 'Evidence assembled — chain reads TAMPERED.'}
                    </span>{' '}
                    {bundle.sealed
                      ? `Bound to sealed epoch #${bundle.attestation.epoch} under signing key ${bundle.attestation.signing_key_id}.`
                      : 'No epoch sealed yet — the bundle carries the honest empty state, not a fabricated header.'}
                  </span>
                </div>

                <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
                  <Detail label="Gateway version" mono>
                    {bundle.gateway_version || '—'}
                  </Detail>
                  <Detail label="Generated at" mono>
                    {bundle.generated_at || '—'}
                  </Detail>
                  <Detail
                    label="Release verified"
                    tone={bundle.release_provenance.verified ? 'verified' : 'ink'}
                  >
                    {bundle.release_provenance.verified === null
                      ? 'stated, not proven'
                      : bundle.release_provenance.verified
                        ? 'true'
                        : 'false'}
                  </Detail>
                  <Detail label="Chain intact" tone={bundle.attestation.intact ? 'verified' : 'denied'}>
                    {bundle.attestation.intact ? 'true' : 'false'}
                  </Detail>
                  <Detail label="Signing key id" mono span tone="ink">
                    {bundle.attestation.signing_key_id}
                  </Detail>
                </dl>

                <div>
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
                    Control mapping · {bundle.control_mapping.length}{' '}
                    {bundle.control_mapping.length === 1 ? 'framework' : 'frameworks'}
                  </p>
                  {bundle.control_mapping.length === 0 ? (
                    <p className="text-[10.5px] leading-relaxed text-slate-500">
                      The bundle carried no framework mappings.
                    </p>
                  ) : (
                    <ul className="flex flex-wrap gap-1.5">
                      {bundle.control_mapping.map((f) => (
                        <li
                          key={f.framework}
                          className="rounded-md border border-hairline bg-canvas px-2 py-0.5 text-[10.5px] text-slate-400"
                          title={`${f.reference} · ${f.clauses.length} clause${f.clauses.length === 1 ? '' : 's'} — provides evidence for`}
                        >
                          {f.framework}{' '}
                          <span className="tabular text-slate-500">({f.clauses.length})</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="flex items-start gap-2 rounded-lg border border-staged/25 bg-staged/5 px-3 py-2 text-[10.5px] leading-relaxed text-slate-400">
                  <ShieldAlert size={13} className="mt-0.5 shrink-0 text-staged" />
                  <span>{bundle.disclaimer}</span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void exportComp(bundle)}
                    className="btn-ghost"
                    title="Copy the full evidence bundle JSON for an auditor / external verifier"
                  >
                    {compCopied ? <Check size={13} /> : <ClipboardCheck size={13} />}
                    {compCopied ? 'Copied' : 'Copy evidence JSON'}
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadComp()}
                    disabled={compState.phase === 'loading'}
                    className="btn-ghost !px-1.5 !py-1"
                    title="Re-read /v1/admin/compliance/evidence"
                  >
                    {compState.phase === 'loading' ? (
                      <Loader2 size={12} className="animate-spin" />
                    ) : (
                      <RefreshCw size={12} />
                    )}
                  </button>
                </div>
              </>
            ) : (
              <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
                {compState.phase === 'loading' ? (
                  <Loader2 size={14} className="mt-0.5 shrink-0 animate-spin" />
                ) : (
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                )}
                <span>
                  {compState.phase === 'loading' ? (
                    'Assembling the compliance-evidence bundle…'
                  ) : (
                    <>
                      <span className="font-semibold">Evidence bundle unavailable. </span>
                      The connected gateway did not serve it (a pre-endpoint build), or the console
                      holds no CAP_DIRECTORY_ADMIN credential for the read. Nothing is fabricated.
                    </>
                  )}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}

/* --- Chain integrity — folded into the Audit Ledger screen (below the feed) ---
   The former standalone 'integrity' sub-tab. Its live signed-epoch verdict, the
   verify action, and the portable attestation/evidence exports live here now.
   Only ever rendered while the gateway is live (Events guards mode first). The
   redundant Chain-status / First-bad-epoch tiles were dropped — the verdict
   banner below already states intact/tampered + the first bad epoch. --------- */
function ChainIntegritySection({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { chain, run } = useChainVerify(gateway);

  // Freshest real reading wins: the 5s auto-poll (gateway.audit), else the
  // manual runner's result. Both null ⇒ no verdict exists — render that.
  const result = gateway.audit ?? chain.result;
  const intact = result?.intact ?? null;
  const firstBad = result?.first_bad_epoch ?? null;
  const m = gateway.metrics;

  return (
    <div className="flex flex-col gap-3">
      <div className="grid shrink-0 grid-cols-2 gap-3 sm:grid-cols-3">
        <MetricTile
          label="WORM sequence"
          value={m.wormSequence !== null ? `#${m.wormSequence}` : '—'}
        />
        <MetricTile label="Sealed epoch" value={m.wormEpoch !== null ? `#${m.wormEpoch}` : '—'} />
        <MetricTile label="Gateway" value="Live" tone="verified" sub={gateway.apiHost} />
      </div>

      <Panel className="shrink-0">
        <PanelHeader
          icon={ShieldCheck}
          title="Integrity check"
          right={gateway.audit !== null ? 'signed epoch chain · auto-verified every 5s' : 'signed epoch chain'}
        />
        <div className="space-y-4 px-5 py-4">
          {intact === null ? (
            chain.state === 'unavailable' ? (
              <div className="space-y-1.5">
                <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                  <span>
                    <span className="font-semibold">
                      /v1/audit/verify is not mounted on this gateway.
                    </span>{' '}
                    Chain verification over HTTP is a sandbox affordance.
                  </span>
                </div>
                <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
                  Export the ledger with{' '}
                  <span className="font-mono text-[10.5px]">mcpip export-audit</span> and verify it
                  with the external verifier.
                </p>
              </div>
            ) : (
              <div className="flex items-center gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] text-slate-400">
                <ShieldCheck size={14} className="shrink-0" />
                No verification result yet — run a check below, or wait for the auto-poll.
              </div>
            )
          ) : intact ? (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11.5px] leading-relaxed ${TONE_BANNER.verified}`}>
              <ShieldCheck size={14} className="mt-0.5 shrink-0" />
              <span>
                <span className="font-semibold">Chain intact.</span> Every sealed epoch root
                recomputed and the Ed25519 root chain verified back to genesis.
                {chain.checkedAt !== null ? (
                  <span className="font-mono text-[10.5px]"> · last manual check {clock(chain.checkedAt)}</span>
                ) : null}
              </span>
            </div>
          ) : (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[11.5px] leading-relaxed ${TONE_BANNER.denied}`}>
              <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              <span>
                <span className="font-semibold">
                  Chain TAMPERED — first bad epoch {firstBad !== null ? `#${firstBad}` : 'unknown'}.
                </span>{' '}
                Epochs sealed before it still verify; the break starts there. Preserve the store
                and export the ledger for forensics.
              </span>
            </div>
          )}

          <button
            type="button"
            onClick={() => void run()}
            disabled={chain.state === 'running'}
            className="btn-primary"
          >
            {chain.state === 'running' ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <ShieldCheck size={13} />
            )}
            Verify chain now
          </button>

          <Hint>
            A verify seals the open tail epoch first, so even a decision made moments ago is
            covered.
          </Hint>
        </div>
      </Panel>

      {/* Portable attestation (production-available) + the CAP_DIRECTORY_ADMIN
          compliance-evidence bundle, merged into ONE export panel. */}
      <AttestationEvidence gateway={gateway} />
    </div>
  );
}

/* --- Root -------------------------------------------------------------------- */

export function WormLedger({ gateway, subtab }: { gateway: GatewayLive; subtab: string }): JSX.Element {
  // The session buffer accumulates at the view root, so the feed keeps being
  // observed while the operator scrolls to the chain-integrity section (the buffer
  // itself lives in lib/ledger's module store and survives remounts either way).
  const ledger = useWormLedger(gateway);

  // Two child tabs (Ledger → Events | Integrity): the decision feed and the
  // chain-integrity instrument each get a whole screen. Unknown ids fall back
  // to Events, so a stale deep-link never crashes.
  return subtab === 'integrity' ? (
    <Integrity gateway={gateway} />
  ) : (
    <Events gateway={gateway} ledger={ledger} />
  );
}
