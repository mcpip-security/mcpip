/* ---------------------------------------------------------------------------
   Community Extensions — the author-your-own-skill/gate workflow as a LIVE
   surface, not a brochure. Two real roles against the REAL endpoints:

     • Contributor (left)  — ANY authenticated principal, NO capability. Authors
       an `mcpip-extension/1` manifest and submits it via POST /v1/extensions/submit
       (deliberately OFF /v1/admin/*). The console computes the manifest's `sha256`
       self-pin byte-identically to the gateway (canonical_manifest_bytes) so a real
       submit round-trips; a refusal is the opaque MCPIPDenied, surfaced honestly.
     • Reviewer (right)    — the DISTINCT CAP_CATALOG_REVIEWER. Reads the tenant's
       PENDING queue (GET /v1/admin/extensions/pending) and approves/rejects each
       submission. Approve re-runs every authoritative check fail-closed and mints
       through the SAME hardened overlay path as a register; reject applies nothing.

   Community SKILLS are shipped fully. Community GATES are Phase 2: the schema +
   the deny-only seam ship, but the CEL parse/evaluate RUNTIME is DEFERRED — a gate
   can be submitted + stored PENDING but can NEVER be approved/enforced until a CEL
   engine is registered (docs/EXTENSIBILITY.md §8). The queue's `approvable` flag
   says so honestly, and the gate approve action is disabled with that reason.

   NOTHING is mocked. Offline → the standard connect state. A gateway with no
   sandbox dev-token minter (production) cannot mint the contributor/reviewer
   identities, so both sides render their honest "unavailable" state — never a
   fabricated queue or a faked success.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Blocks,
  Check,
  ChevronRight,
  FileCode,
  Fingerprint,
  Gavel,
  Inbox,
  Loader2,
  PlugZap,
  Send,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  X,
} from 'lucide-react';
import { Badge, EmptyState, Field, Input, Panel, PanelHeader } from '../ui';
import { formatRelative, truncateId } from '../../lib/format';
import { useCompanyConfig } from '../../lib/companyConfig';
import { GATE_CONTEXT_FIELDS, MAX_GATE_COST } from '../../lib/protocol';
import {
  approveExtension,
  buildGateManifest,
  buildSkillManifest,
  CONTRIBUTOR_AGENT_ID,
  listPendingExtensions,
  rejectExtension,
  REVIEWER_AGENT_ID,
  submitCommunityExtension,
} from '../../lib/extensions';
import type { ExtensionKind, PendingExtension } from '../../lib/types';
import type { GatewayLive } from '../../lib/useGatewayLive';

const POLL_MS = 5000;

/** Turn a plain-language description into a safe alias/target slug (mirrors AliasRegistry). */
function slugify(text: string, sep: '_' | '.'): string {
  const s = text.toLowerCase().replace(/[^a-z0-9]+/g, sep);
  return s.replace(new RegExp(`^\\${sep}+|\\${sep}+$`, 'g'), '');
}

function navigateTo(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

/* --------------------------------------------------------------------------- */

export function CommunityExtensions({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { mode, apiBase, tenant } = gateway;
  const { config } = useCompanyConfig();
  // The tenant every submit/review targets — cross-tenant approve is structurally
  // impossible server-side, so both identities are minted for exactly this tenant.
  const reviewTenant = tenant ?? config?.tenant ?? null;
  const live = mode === 'live';

  // undefined = first read in flight · null = review unavailable (no reviewer
  // credential / opaque 403 / offline) · [] = a genuinely empty queue.
  const [pending, setPending] = useState<PendingExtension[] | null | undefined>(undefined);
  const [bump, setBump] = useState(0);
  const reload = useCallback(() => setBump((b) => b + 1), []);

  useEffect(() => {
    if (!live || !reviewTenant) {
      setPending(undefined);
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const tick = async (): Promise<void> => {
      const rows = await listPendingExtensions(apiBase, reviewTenant, controller.signal);
      if (!cancelled) setPending(rows);
    };
    void tick();
    const id = window.setInterval(() => void tick(), POLL_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [live, apiBase, reviewTenant, bump]);

  if (!live) {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={Blocks}
          title="No gateway connected"
          detail="Connect a gateway to submit and review community extensions."
          action={
            <button type="button" className="btn-primary" onClick={() => navigateTo('gateway', 'connection')}>
              <PlugZap size={13} /> Connect a gateway
            </button>
          }
        />
      </Panel>
    );
  }

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,440px)_1fr]">
        <SubmitPanel
          apiBase={apiBase}
          tenant={reviewTenant}
          defaultAuthor={config?.name?.trim() || 'community-console'}
          onSubmitted={reload}
        />
        <ReviewPanel
          apiBase={apiBase}
          tenant={reviewTenant}
          pending={pending}
          onChanged={reload}
        />
      </div>
    </div>
  );
}

/* --- contributor: submit a manifest ---------------------------------------- */

function SubmitPanel({
  apiBase,
  tenant,
  defaultAuthor,
  onSubmitted,
}: {
  apiBase: string;
  tenant: string | null;
  defaultAuthor: string;
  onSubmitted: () => void;
}): JSX.Element {
  const [kind, setKind] = useState<ExtensionKind>('skill');
  const [author, setAuthor] = useState(defaultAuthor);
  const [advanced, setAdvanced] = useState(false);

  // Skill fields.
  const [description, setDescription] = useState('');
  const [alias, setAlias] = useState('');
  const [target, setTarget] = useState('');
  const [aliasTouched, setAliasTouched] = useState(false);
  const [targetTouched, setTargetTouched] = useState(false);
  const [sensitive, setSensitive] = useState(false);

  // Gate fields.
  const [gateName, setGateName] = useState('');
  const [source, setSource] = useState('');
  const [refFields, setRefFields] = useState<Set<string>>(new Set());
  const [maxCost, setMaxCost] = useState('100');

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [pin, setPin] = useState<string | null>(null);

  const derivedAlias = description.trim() ? `skill_${slugify(description, '_')}` : '';
  const derivedTarget = description.trim() ? `rest.${slugify(description, '.')}` : '';
  const effectiveAlias = (aliasTouched ? alias : derivedAlias).trim();
  const effectiveTarget = (targetTouched ? target : derivedTarget).trim();
  const riskTier: 'auto' | 'pin_required' = sensitive ? 'pin_required' : 'auto';
  const classification: 'unclassified' | 'restricted' = sensitive ? 'restricted' : 'unclassified';

  const gateId = gateName.trim() ? `gate_${slugify(gateName, '_')}` : '';
  const parsedCost = Number.parseInt(maxCost, 10);
  const costValid = Number.isInteger(parsedCost) && parsedCost >= 1 && parsedCost <= MAX_GATE_COST;

  const authorOk = author.trim().length > 0;
  const skillValid = authorOk && effectiveAlias.length > 1 && effectiveTarget.length > 0;
  const gateValid = authorOk && gateId.length > 1 && source.trim().length > 0 && costValid;
  const valid = kind === 'skill' ? skillValid : gateValid;

  // Live self-pin preview — the SAME digest the gateway re-derives at submit. Async
  // (SubtleCrypto), so it is recomputed on every substantive field change and only
  // set when it is still the latest computation.
  const seq = useRef(0);
  useEffect(() => {
    const mine = ++seq.current;
    if (!valid) {
      setPin(null);
      return;
    }
    void (async () => {
      const manifest =
        kind === 'skill'
          ? await buildSkillManifest({
              id: effectiveAlias,
              author: author.trim(),
              alias: effectiveAlias,
              target: effectiveTarget,
              risk_tier: riskTier,
              classification,
            })
          : await buildGateManifest({
              id: gateId,
              author: author.trim(),
              source: source.trim(),
              referenced_context_fields: [...refFields],
              max_cost: parsedCost,
            });
      if (seq.current === mine) setPin(manifest.sha256);
    })();
  }, [
    kind, valid, author, effectiveAlias, effectiveTarget, riskTier, classification,
    gateId, source, refFields, parsedCost,
  ]);

  const resetAfterSubmit = useCallback((): void => {
    setDescription('');
    setAlias('');
    setTarget('');
    setAliasTouched(false);
    setTargetTouched(false);
    setSensitive(false);
    setGateName('');
    setSource('');
    setRefFields(new Set());
    setMaxCost('100');
  }, []);

  const submit = async (): Promise<void> => {
    if (!valid || busy || !tenant) return;
    setBusy(true);
    setError(null);
    setNote(null);
    const manifest =
      kind === 'skill'
        ? await buildSkillManifest({
            id: effectiveAlias,
            author: author.trim(),
            alias: effectiveAlias,
            target: effectiveTarget,
            risk_tier: riskTier,
            classification,
          })
        : await buildGateManifest({
            id: gateId,
            author: author.trim(),
            source: source.trim(),
            referenced_context_fields: [...refFields],
            max_cost: parsedCost,
          });
    const res = await submitCommunityExtension(apiBase, tenant, manifest, undefined);
    if (res) {
      setNote(
        kind === 'skill'
          ? `Submitted for review · ${truncateId(res.submission_id, 8, 4)}. A reviewer must approve it before the alias becomes authorizable.`
          : `Gate submitted for review · ${truncateId(res.submission_id, 8, 4)}. It is stored PENDING but cannot be approved/enforced until a CEL engine is registered.`,
      );
      resetAfterSubmit();
      onSubmitted();
    } else {
      setError(
        'Submission denied — the gateway validates fail-closed, and the concrete reason lives only in the audit log.',
      );
    }
    setBusy(false);
  };

  const toggleRef = (field: string): void =>
    setRefFields((prev) => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });

  return (
    <Panel>
      <PanelHeader
        title="Submit a manifest"
        icon={Send}
        right={<span className="font-mono text-[10.5px]">as {CONTRIBUTOR_AGENT_ID}</span>}
      />

      <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto px-4 py-4">
        {kind === 'skill' ? (
          <>
            <p className="text-[11.5px] leading-relaxed text-slate-500">
              Describe the tool — the console names and pins a new alias (additive only, never a
              repoint).
            </p>
            <Field label="What should this tool do?">
              <Input
                value={description}
                onChange={(e) => {
                  setDescription(e.target.value);
                  setError(null);
                }}
                placeholder="e.g. Read the sales pipeline"
              />
            </Field>
            {effectiveAlias ? (
              <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[11px]">
                <p className="text-slate-500">The agent will call</p>
                <p className="mt-0.5 break-all font-mono text-[12px] text-ink">{effectiveAlias}</p>
              </div>
            ) : null}
            <label className="flex items-start gap-2.5 rounded-lg border border-hairline bg-canvas px-3 py-2.5">
              <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} className="mt-0.5 accent-ink" />
              <span className="text-[11.5px] leading-relaxed text-slate-500">
                <span className="font-medium text-ink">Sensitive action</span> — restricted + require a one-time PIN
                (the overlay forces <span className="font-mono text-[10.5px]">restricted ⇒ pin_required</span>).
              </span>
            </label>
          </>
        ) : null}

        {/* Gate authoring is experimental: enforcement is deferred until a CEL engine
            is registered, so it sits behind a toggle rather than on the primary path.
            Opening it switches the submit to gate-manifest mode; closing returns to skill. */}
        <div className="rounded-lg border border-hairline bg-canvas">
          <button
            type="button"
            aria-expanded={kind === 'gate'}
            onClick={() => {
              setKind(kind === 'gate' ? 'skill' : 'gate');
              setError(null);
              setNote(null);
            }}
            className="flex w-full items-center gap-1.5 px-3 py-2 text-[11px] font-medium text-slate-500 transition-colors hover:text-ink"
          >
            <ChevronRight
              size={12}
              className={`shrink-0 transition-transform ${kind === 'gate' ? 'rotate-90' : ''}`}
            />
            <FileCode size={12} className="shrink-0" />
            Author a policy gate
            <Badge tone="staged">experimental</Badge>
          </button>
          {kind === 'gate' ? (
          <div className="space-y-3.5 border-t border-hairline px-3 py-3">
            <div className="flex items-start gap-2 rounded-lg border border-staged/30 bg-staged/5 px-3 py-2 text-[11px] leading-relaxed text-staged">
              <ShieldAlert size={13} className="mt-0.5 shrink-0" />
              <span>
                Gates are stored pending and cannot be approved or enforced until a CEL engine is
                registered.
              </span>
            </div>
            <Field label="Gate name">
              <Input
                value={gateName}
                onChange={(e) => {
                  setGateName(e.target.value);
                  setError(null);
                }}
                placeholder="e.g. business-hours-only"
              />
            </Field>
            {gateId ? (
              <p className="break-all font-mono text-[11px] text-slate-500">
                id · <span className="text-ink">{gateId}</span>
              </p>
            ) : null}
            <Field label="CEL predicate (deny when true is decided by the engine)">
              <textarea
                value={source}
                onChange={(e) => {
                  setSource(e.target.value);
                  setError(null);
                }}
                rows={3}
                spellCheck={false}
                placeholder={"risk_tier == 'pin_required' && classification == 'restricted'"}
                className="w-full resize-y rounded-lg border border-hairline bg-canvas px-3 py-2 font-mono text-[12px] leading-relaxed text-ink placeholder:text-slate-500 focus:border-ink/30 focus:outline-none focus:shadow-focus-ring"
              />
            </Field>
            <div>
              <span className="mb-1 block text-[10.5px] font-medium uppercase tracking-[0.1em] text-slate-500">
                Referenced context fields
              </span>
              <div className="flex flex-wrap gap-1.5">
                {GATE_CONTEXT_FIELDS.map((f) => {
                  const on = refFields.has(f);
                  return (
                    <button
                      key={f}
                      type="button"
                      onClick={() => toggleRef(f)}
                      aria-pressed={on}
                      className={`rounded-md border px-2 py-1 font-mono text-[11px] transition-colors ${
                        on ? 'border-ink/25 bg-elevated text-ink' : 'border-hairline bg-surface text-slate-400 hover:text-ink'
                      }`}
                    >
                      {f}
                    </button>
                  );
                })}
              </div>
              <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">
                The fixed topology-free whitelist — never <span className="font-mono text-[10px]">target</span>, a secret,
                or identity.
              </p>
            </div>
            <Field label={`Declared static cost (1..${MAX_GATE_COST.toLocaleString()})`}>
              <Input
                mono
                value={maxCost}
                onChange={(e) => {
                  setMaxCost(e.target.value);
                  setError(null);
                }}
                inputMode="numeric"
                placeholder="100"
              />
            </Field>
            {maxCost.trim() !== '' && !costValid ? (
              <p className="text-[10.5px] text-denied">Cost must be a whole number in 1..{MAX_GATE_COST.toLocaleString()}.</p>
            ) : null}
          </div>
          ) : null}
        </div>

        {/* Advanced — author label + raw skill alias/target override. */}
        <button
          type="button"
          onClick={() => setAdvanced((v) => !v)}
          className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-slate-500 transition-colors hover:text-ink"
        >
          <ChevronRight size={11} className={`transition-transform ${advanced ? 'rotate-90' : ''}`} /> Advanced
        </button>
        {advanced ? (
          <div className="space-y-3 rounded-lg border border-hairline bg-canvas p-3">
            <Field label="Author · manifest label">
              <Input
                value={author}
                onChange={(e) => {
                  setAuthor(e.target.value);
                  setError(null);
                }}
                placeholder="community-console"
              />
            </Field>
            {kind === 'skill' ? (
              <>
                <Field label="Alias · what the agent calls">
                  <Input
                    mono
                    value={effectiveAlias}
                    onChange={(e) => {
                      setAliasTouched(true);
                      setAlias(e.target.value);
                      setError(null);
                    }}
                    placeholder="skill_sales_pipeline"
                    spellCheck={false}
                  />
                </Field>
                <Field label="Target · the internal system it reaches">
                  <Input
                    mono
                    value={effectiveTarget}
                    onChange={(e) => {
                      setTargetTouched(true);
                      setTarget(e.target.value);
                      setError(null);
                    }}
                    placeholder="rest.sales.pipeline"
                    spellCheck={false}
                  />
                </Field>
              </>
            ) : null}
          </div>
        ) : null}

        {/* Self-pin preview — the exact digest the gateway re-derives fail-closed. */}
        {pin ? (
          <div className="flex items-center gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px]">
            <Fingerprint size={13} className="shrink-0 text-slate-500" />
            <span className="text-slate-500">sha256 self-pin</span>
            <span className="ml-auto break-all font-mono text-[10.5px] text-ink">{truncateId(pin, 10, 8)}</span>
          </div>
        ) : null}

        {note ? (
          <p className="flex items-start gap-2 rounded-lg border border-verified/30 bg-verified/5 px-2.5 py-2 text-[11px] leading-relaxed text-verified">
            <Check size={13} className="mt-0.5 shrink-0" />
            <span>{note}</span>
          </p>
        ) : null}
        {error ? (
          <p className="flex items-start gap-2 rounded-lg border border-denied/30 bg-denied/5 px-2.5 py-2 text-[11px] leading-relaxed text-denied">
            <ShieldAlert size={13} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </p>
        ) : null}
      </div>

      <div className="shrink-0 border-t border-hairline px-4 py-3">
        <button
          type="button"
          onClick={() => void submit()}
          disabled={!valid || busy || !tenant}
          className="btn-primary w-full justify-center"
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
          {busy ? 'Submitting…' : 'Submit for review'}
        </button>
      </div>
    </Panel>
  );
}

/* --- reviewer: pending queue ----------------------------------------------- */

function ReviewPanel({
  apiBase,
  tenant,
  pending,
  onChanged,
}: {
  apiBase: string;
  tenant: string | null;
  pending: PendingExtension[] | null | undefined;
  onChanged: () => void;
}): JSX.Element {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const pendingCount = Array.isArray(pending) ? pending.length : null;

  const label = (row: PendingExtension): string =>
    row.kind === 'skill' ? row.alias : row.gate_id;

  const doApprove = async (row: PendingExtension): Promise<void> => {
    if (!tenant) return;
    setBusy(row.submission_id);
    setError(null);
    setNote(null);
    const res = await approveExtension(apiBase, tenant, row.submission_id);
    if (res) {
      setNote(`Approved · ${res.approved} is now an authorizable alias for ${tenant}.`);
      onChanged();
    } else {
      setError(
        `Approval refused for ${label(row)}. The gateway re-runs every authoritative check fail-closed — an alias conflict, a failed self-pin, the overlay ceiling, or (for a gate) the deferred CEL prover all deny opaquely.`,
      );
    }
    setBusy(null);
  };

  const doReject = async (row: PendingExtension): Promise<void> => {
    if (!tenant) return;
    setBusy(row.submission_id);
    setError(null);
    setNote(null);
    const ok = await rejectExtension(apiBase, tenant, row.submission_id);
    if (ok) {
      setNote(`Rejected · ${label(row)} — nothing was applied to the catalog.`);
      onChanged();
    } else {
      setError(`Reject failed for ${label(row)} — the gateway refused the change or is unreachable.`);
    }
    setBusy(null);
  };

  return (
    <Panel>
      <PanelHeader
        title="Pending review"
        icon={Gavel}
        right={
          <span className="flex items-center gap-2">
            {pendingCount !== null ? (
              <Badge tone={pendingCount > 0 ? 'ink' : 'muted'}>{pendingCount} pending</Badge>
            ) : null}
            <span className="font-mono text-[10.5px]">
              {REVIEWER_AGENT_ID} · CAP_CATALOG_REVIEWER
            </span>
          </span>
        }
      />

      {note ? (
        <div className="flex items-start gap-2 border-b border-hairline/60 bg-verified/5 px-4 py-2 text-[11px] leading-relaxed text-verified">
          <Check size={13} className="mt-0.5 shrink-0" />
          <span className="min-w-0 flex-1">{note}</span>
          <button type="button" onClick={() => setNote(null)} className="shrink-0 text-verified/70 hover:text-verified">
            <X size={13} />
          </button>
        </div>
      ) : null}
      {error ? (
        <div className="flex items-start gap-2 border-b border-hairline/60 bg-denied/5 px-4 py-2 text-[11px] leading-relaxed text-denied">
          <ShieldAlert size={13} className="mt-0.5 shrink-0" />
          <span className="min-w-0 flex-1">{error}</span>
          <button type="button" onClick={() => setError(null)} className="shrink-0 text-denied/70 hover:text-denied">
            <X size={13} />
          </button>
        </div>
      ) : null}

      {pending === undefined ? (
        <div className="px-4 py-3 text-[11px] text-slate-500">Reading the pending queue…</div>
      ) : pending === null ? (
        <div className="space-y-1.5 px-4 py-3">
          <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
            <ShieldAlert size={13} className="mt-0.5 shrink-0" />
            <span>
              <span className="font-semibold">Review unavailable. </span>
              <span className="font-mono text-[10.5px]">GET /v1/admin/extensions/pending</span> did not answer.
            </span>
          </div>
          <p className="pl-6 text-[10.5px] leading-relaxed text-slate-500">
            The console holds no <span className="font-mono text-[10px]">CAP_CATALOG_REVIEWER</span> credential —
            production mounts no sandbox token minter, so the reviewer identity cannot be minted here.
          </p>
        </div>
      ) : pending.length === 0 ? (
        <EmptyState
          icon={Inbox}
          title="No submissions awaiting review"
          detail="Nothing is pending for this tenant. Submit a manifest on the left and it appears here for a CAP_CATALOG_REVIEWER to approve or reject."
        />
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto">
          {pending.map((row) => (
            <ReviewRow
              key={row.submission_id}
              row={row}
              busy={busy === row.submission_id}
              onApprove={() => void doApprove(row)}
              onReject={() => void doReject(row)}
            />
          ))}
        </div>
      )}

      <div className="mt-auto shrink-0 border-t border-hairline px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
        Approve re-runs every authoritative check fail-closed and WORM-records the decision BEFORE it applies; a skill
        mints through the same hardened overlay path as a register. A gate can only be rejected here until a CEL engine
        is registered.
      </div>
    </Panel>
  );
}

function ReviewRow({
  row,
  busy,
  onApprove,
  onReject,
}: {
  row: PendingExtension;
  busy: boolean;
  onApprove: () => void;
  onReject: () => void;
}): JSX.Element {
  const isGate = row.kind === 'gate';
  const approveBlocked = isGate && !row.approvable;
  return (
    <div className="border-b border-hairline/50 px-4 py-3 last:border-0">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={isGate ? 'staged' : 'ink'}>
              {isGate ? <FileCode size={10} /> : <Blocks size={10} />} {row.kind}
            </Badge>
            <span className="truncate font-mono text-[12.5px] text-ink">
              {row.kind === 'skill' ? row.alias : row.gate_id}
            </span>
            {row.kind === 'skill' && row.conflicts_existing_alias ? (
              <Badge tone="denied">
                <ShieldAlert size={10} /> alias conflict
              </Badge>
            ) : null}
            {row.submitter_is_reviewer ? (
              <Badge tone="denied">
                <UserCheck size={10} /> self-submitted
              </Badge>
            ) : null}
            {isGate ? (
              <Badge tone={row.approvable ? 'verified' : 'muted'}>
                {row.approvable ? 'approvable' : 'engine deferred'}
              </Badge>
            ) : null}
          </div>

          <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1 text-[10.5px] text-slate-500">
            {row.kind === 'skill' ? (
              <>
                <span className="col-span-2 break-all">
                  target · <span className="font-mono text-slate-400">{row.target}</span>
                </span>
                <span>
                  risk · <span className={row.risk_tier === 'pin_required' ? 'text-staged' : 'text-verified'}>{row.risk_tier}</span>
                </span>
                <span>class · {row.classification}</span>
              </>
            ) : (
              <>
                <span>lang · {row.language}</span>
                <span>cost · {row.max_cost ?? '—'}</span>
                <span className="col-span-2 break-all">
                  reads · <span className="font-mono text-slate-400">{row.referenced_context_fields.join(', ') || 'none'}</span>
                </span>
              </>
            )}
            <span className="break-all">
              by · <span className="font-mono text-slate-400">{row.submitter_agent_id || row.author || '—'}</span>
            </span>
            <span>{row.created_at ? formatRelative(row.created_at) : '—'}</span>
            <span className="col-span-2 flex items-center gap-1.5">
              <Fingerprint size={10} className="shrink-0" />
              <span className="break-all font-mono text-[10px]">{truncateId(row.manifest_sha256, 10, 8)}</span>
            </span>
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-stretch gap-1.5">
          <button
            type="button"
            onClick={onApprove}
            disabled={busy || approveBlocked}
            title={
              approveBlocked
                ? 'Gate approval is refused until a CEL engine is registered (no approve-without-proof)'
                : 'Approve — WORM-record then mint through the hardened overlay path'
            }
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-verified/30 bg-verified/5 px-2.5 py-1.5 text-[11.5px] font-medium text-verified transition-colors hover:bg-verified/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />} Approve
          </button>
          <button
            type="button"
            onClick={onReject}
            disabled={busy}
            title="Reject — WORM-record; nothing is applied to the catalog"
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-hairline bg-surface px-2.5 py-1.5 text-[11.5px] font-medium text-slate-500 transition-colors hover:border-denied/40 hover:text-denied disabled:opacity-40"
          >
            <X size={12} /> Reject
          </button>
        </div>
      </div>
    </div>
  );
}
