import { useEffect, useState } from 'react';
import {
  ArrowUpRight,
  Check,
  Copy,
  Fingerprint,
  MousePointerClick,
  PlugZap,
  Radio,
  SquareTerminal,
  Waves,
} from 'lucide-react';
import type { StreamEvent } from '../lib/types';
import { formatClock, truncateId } from '../lib/format';
import { Badge, Detail, EmptyState, Panel, PanelHeader } from './ui';

/* ---------------------------------------------------------------------------
   Decision stream — the live tail of the gateway's own
   /v1/admin/decisions/recent feed (every agent's traffic for the tenant, up
   to the 50 newest rows). Every cell is a REAL projected WORM field,
   including the per-row worm_sequence; the old fabricated per-row latency
   column is gone for good (the feed has no such measurement, so the console
   does not print one). Rows update instantly — data at rest never animates.

   `inspect` turns on the master-detail mode used by the dedicated sub-tab:
   click a row to pin its full projection in the right-hand inspector (the
   selection is a held snapshot, so it survives the row scrolling out of the
   window — flagged honestly as "out of window" when it does).

   Offline or idle renders the standard honest empty state — never mock rows.
--------------------------------------------------------------------------- */

/** Deep-link into another (view, sub-tab) via the app-level nav event. */
function navigate(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

/** Full-precision local timestamp for the inspector (ms — the honest floor;
    the feed's ns stamp exceeds JS float precision, so we never print it). */
function fmtTs(ts: number): string {
  const d = new Date(ts);
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes(),
  )}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function Row({
  e,
  selected,
  onSelect,
}: {
  e: StreamEvent;
  selected?: boolean;
  onSelect?: (e: StreamEvent) => void;
}): JSX.Element {
  const allow = e.decision === 'allow';
  const body = (
    <>
      <span className="tabular whitespace-nowrap text-slate-500">{formatClock(e.ts)}</span>
      <span
        className={`h-1.5 w-1.5 rounded-full ${allow ? 'bg-verified' : 'bg-denied'}`}
        aria-hidden="true"
      />
      <span className="min-w-0 truncate">
        <span className="text-ink">{e.alias}</span>
        {e.agent ? <span className="ml-2 text-slate-400">{e.agent}</span> : null}
        <span className="ml-2 text-slate-500">{e.tenant}</span>
        {!allow && e.reason ? (
          <span className="ml-2 text-denied">{e.reason}</span>
        ) : (
          <span className="ml-2 text-slate-500">{e.transport}</span>
        )}
      </span>
      <span className="flex items-center gap-2.5">
        <span className="tabular hidden text-slate-400 sm:inline">#{e.wormSequence}</span>
        <Badge tone={allow ? 'verified' : 'denied'}>{e.decision}</Badge>
        <span className="hidden text-slate-500 lg:inline">{truncateId(e.correlationId, 6, 4)}</span>
      </span>
    </>
  );

  const cls =
    'grid w-full grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-2.5 border-b border-hairline/60 px-3 py-1.5 text-left font-mono text-[11px] last:border-0';

  if (onSelect) {
    return (
      <button
        type="button"
        onClick={() => onSelect(e)}
        className={`${cls} ${selected ? 'bg-canvas' : 'hover:bg-canvas'} transition-colors focus:outline-none focus-visible:shadow-focus-ring`}
      >
        {body}
      </button>
    );
  }
  return <div className={cls}>{body}</div>;
}

function InspectorEmpty(): JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      <MousePointerClick size={22} className="text-slate-600" />
      <p className="text-[12.5px] font-medium text-slate-400">Select a decision</p>
      <p className="max-w-[230px] text-[11.5px] leading-relaxed text-slate-500">
        Every inspector field is the real WORM projection for that row — worm_sequence and event id
        included.
      </p>
    </div>
  );
}

function Inspector({ e, inWindow }: { e: StreamEvent; inWindow: boolean }): JSX.Element {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) {
      return;
    }
    const t = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(t);
  }, [copied]);

  const copyCorr = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(e.correlationId);
      setCopied(true);
    } catch {
      /* clipboard unavailable (permissions / insecure context) — nothing to fake */
    }
  };

  const deny = e.decision === 'deny';

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-2.5 border-b border-hairline px-4 py-3">
        <Fingerprint size={15} className="text-slate-500" />
        <span className="text-[13px] font-semibold text-ink">Decision detail</span>
        <Badge tone={deny ? 'denied' : 'verified'}>{e.decision}</Badge>
        {!inWindow ? (
          <span className="ml-auto text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
            out of window
          </span>
        ) : null}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="Correlation id" mono span>
            {e.correlationId}
          </Detail>
          <Detail label="WORM event id" mono span>
            {e.eventId ?? (
              <span className="font-sans text-slate-400">not exposed by this gateway</span>
            )}
          </Detail>
          <Detail label="Recorded" mono>
            {fmtTs(e.ts)}
          </Detail>
          <Detail label="WORM sequence" mono>
            #{e.wormSequence}
          </Detail>
          <Detail label="Tenant" mono>
            {e.tenant}
          </Detail>
          <Detail label="Agent" mono>
            {e.agent ?? '—'}
          </Detail>
          <Detail label="Alias" mono>
            {e.alias}
          </Detail>
          <Detail label="Transport" mono>
            {e.transport}
          </Detail>
          <Detail label="Source dialect" mono>
            {e.sourceFormat ?? '—'}
          </Detail>
          <Detail label="Risk tier" mono>
            {e.riskTier ?? '—'}
          </Detail>
          <Detail label="Classification" mono>
            {e.classification ?? '—'}
          </Detail>
          <Detail label="Deny reason" tone={deny && e.reason !== null ? 'denied' : 'muted'}>
            {e.reason ?? '—'}
          </Detail>
          {e.transactionRef ? (
            <Detail label="Transaction ref" mono span>
              {e.transactionRef}
            </Detail>
          ) : null}
        </dl>
        {deny ? (
          <p className="mt-3 text-[10.5px] leading-relaxed text-slate-500">
            The concrete reason above is operator-visible only — at the agent boundary this call
            received an opaque error plus the correlation id.
          </p>
        ) : null}
      </div>

      <div className="flex shrink-0 items-center gap-2 border-t border-hairline px-4 py-3">
        <button
          type="button"
          onClick={() => {
            void copyCorr();
          }}
          className="btn-ghost flex-1"
        >
          {copied ? <Check size={13} className="text-verified" /> : <Copy size={13} />}
          {copied ? 'Copied' : 'Copy correlation id'}
        </button>
        <button type="button" onClick={() => navigate('ledger', 'events')} className="btn-ghost flex-1">
          Audit Ledger <ArrowUpRight size={13} />
        </button>
      </div>
    </div>
  );
}

interface StreamPanelProps {
  /** Newest-first REAL feed rows (up to 50) — [] when idle or offline. */
  events: StreamEvent[];
  live: boolean;
  /** Master-detail mode: row selection + the right-hand inspector pane. */
  inspect?: boolean;
  /**
   * tenant_id this console is connected as. The feed is tenant-scoped, so an
   * empty stream is ambiguous without it: traffic may exist on the gateway
   * under a DIFFERENT tenant and correctly not be shown here. Naming the
   * tenant turns "nothing happened" into "nothing happened for this tenant".
   */
  tenant?: string | null;
}

export function StreamPanel({
  events,
  live,
  inspect = false,
  tenant = null,
}: StreamPanelProps): JSX.Element {
  const [selected, setSelected] = useState<StreamEvent | null>(null);

  const list = (
    <Panel className="h-full">
      <PanelHeader
        title="Decision stream"
        icon={Waves}
        right={
          live ? (
            <span className="flex items-center gap-2">
              {/* pulse = reserved liveness semantics: the poll is genuinely running */}
              <span
                className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-verified"
                aria-hidden="true"
              />
              <span className="tabular">{events.length} in window</span>
            </span>
          ) : (
            'offline'
          )
        }
      />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {events.length === 0 ? (
          live ? (
            <EmptyState
              icon={Radio}
              title={tenant ? `No decisions yet for ${tenant}` : 'No decisions yet'}
              detail={
                tenant
                  ? `This is the gateway's own /v1/admin/decisions/recent feed, scoped to tenant ${tenant} — every agent's traffic for THAT tenant lands here as it is decided. Traffic authorized under a different tenant is deliberately not visible here, so if you ran the live walkthrough or the CLI under another tenant its decisions will not appear. Fire the Authorize Probe to watch one arrive.`
                  : "This is the gateway's own /v1/admin/decisions/recent feed — every agent's traffic for your tenant lands here as it is decided. Fire the Authorize Probe to watch one arrive."
              }
              action={
                <button
                  type="button"
                  onClick={() => navigate('command', 'probe')}
                  className="btn-ghost"
                >
                  <SquareTerminal size={13} /> Open the Authorize Probe
                </button>
              }
            />
          ) : (
            <EmptyState
              icon={Radio}
              title="No gateway connected"
              detail="The stream renders only real decision receipts — nothing is fabricated offline. Connect a gateway to start it."
              action={
                <button
                  type="button"
                  onClick={() => navigate('gateway', 'connection')}
                  className="btn-primary"
                >
                  <PlugZap size={13} /> Connect a gateway
                </button>
              }
            />
          )
        ) : (
          events.map((e) => (
            <Row
              key={e.id}
              e={e}
              selected={inspect && selected?.id === e.id}
              onSelect={inspect ? setSelected : undefined}
            />
          ))
        )}
      </div>
    </Panel>
  );

  if (!inspect) {
    return list;
  }

  const stillVisible = selected !== null && events.some((x) => x.id === selected.id);

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      {list}
      <div className="panel hidden min-h-0 overflow-hidden xl:flex xl:flex-col">
        {selected ? <Inspector e={selected} inWindow={stillVisible} /> : <InspectorEmpty />}
      </div>
    </div>
  );
}
