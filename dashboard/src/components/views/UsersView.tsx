import { useCallback, useEffect, useRef, useState } from 'react';
import {
  UserPlus,
  Users,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  PlugZap,
  Unplug,
  X,
} from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
import { Badge, EmptyState, Field, Input, Panel, PanelHeader, Select } from '../ui';
import {
  operatorUsers,
  inviteOperatorUser,
  updateOperatorUser,
  removeOperatorUser,
} from '../../lib/api';
import type { OperatorRole, OperatorStatus, OperatorUser } from '../../lib/api';

/**
 * Agents & Users → Users. The admin-managed operator/team roster, on the REAL
 * `/v1/admin/users` endpoints — invite by email, change the role LABEL, enable /
 * disable, remove. No mock data, and — the harder half — no FALSE emptiness: a
 * roster the gateway refused to disclose is not a roster of zero people, and the
 * two render differently (see `Roster` below). The `role` is a management label
 * (it authorizes nothing); the invite returns a one-time reference link to send.
 */

const ROLES: ReadonlyArray<OperatorRole> = ['admin', 'member', 'viewer'];

const STATUS_LABEL: Record<OperatorStatus, string> = {
  invited: 'Invited',
  active: 'Active',
  disabled: 'Disabled',
};

const STATUS_TONE: Record<OperatorStatus, 'verified' | 'denied' | 'staged'> = {
  invited: 'staged',
  active: 'verified',
  disabled: 'denied',
};

/**
 * Four states, never three. 'no-credential' (the console holds no
 * CAP_DIRECTORY_ADMIN token) and 'read-failed' (the gateway refused or the read
 * broke) both used to collapse into an empty array, which rendered "0 members /
 * No team members yet" over a LIVE gateway — a fabricated fact in the one
 * console whose thesis is that state is never fabricated. Only 'ok' may claim a
 * count, and only 'ok' with an empty list may say the roster is empty.
 */
type Roster =
  | { kind: 'loading' }
  | { kind: 'no-credential' }
  | { kind: 'read-failed' }
  | { kind: 'ok'; users: OperatorUser[]; count: number; cursor: string };

function navigateToConnection(): void {
  window.dispatchEvent(
    new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
  );
}

/**
 * The honest degraded state for an admin read the console could not perform.
 * In production the sandbox /v1/dev/token minter is 404 by design (identity
 * sovereignty), so this is the EXPECTED posture there — stated plainly, never
 * dressed up as "nobody on the team yet".
 */
function AdminReadUnavailable({ reason }: { reason: 'no-credential' | 'read-failed' }): JSX.Element {
  return (
    <div className="space-y-1.5 px-5 py-4">
      <p className="flex items-center gap-2 text-[11.5px] font-medium text-staged">
        <ShieldAlert size={14} className="shrink-0" /> Roster unavailable —{' '}
        {reason === 'no-credential' ? 'no admin credential.' : 'the admin read failed.'}
      </p>
      <p className="max-w-3xl pl-6 text-[11px] leading-relaxed text-slate-500">
        {reason === 'no-credential' ? (
          <>
            The console could not obtain a{' '}
            <span className="font-mono text-[10.5px]">CAP_DIRECTORY_ADMIN</span> credential
            (production gateways disable the sandbox{' '}
            <span className="font-mono text-[10.5px]">/v1/dev/token</span> minter).
          </>
        ) : (
          <>
            The gateway refused or could not answer{' '}
            <span className="font-mono text-[10.5px]">GET /v1/admin/users</span>. A denial is opaque
            by design — the reason is in the WORM log, not here.
          </>
        )}{' '}
        The real membership is unknown, so nothing is shown. This is not a statement that the roster
        is empty.
      </p>
    </div>
  );
}

export function UsersView({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { ensureAdminToken, apiBase, mode } = gateway;
  const [roster, setRoster] = useState<Roster>({ kind: 'loading' });
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<OperatorRole>('member');
  const [inviteErr, setInviteErr] = useState<string | null>(null);
  const [lastInvite, setLastInvite] = useState<{ email: string; token: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const tokenRef = useRef<string | null>(null);

  const token = useCallback(
    async (signal?: AbortSignal): Promise<string | null> => {
      if (tokenRef.current) return tokenRef.current;
      const t = await ensureAdminToken(signal);
      tokenRef.current = t;
      return t;
    },
    [ensureAdminToken],
  );

  const load = useCallback(
    async (from = '0', signal?: AbortSignal): Promise<void> => {
      setLoading(true);
      const t = await token(signal);
      if (!t) {
        setRoster({ kind: 'no-credential' });
        setLoading(false);
        return;
      }
      const page = await operatorUsers(t, from, 100, { base: apiBase, signal });
      if (page === null) {
        setRoster({ kind: 'read-failed' });
        setLoading(false);
        return;
      }
      setRoster((prev) => ({
        kind: 'ok',
        users:
          from === '0' || prev.kind !== 'ok' ? page.users : [...prev.users, ...page.users],
        count: page.count,
        cursor: page.next_cursor,
      }));
      setLoading(false);
    },
    [token, apiBase],
  );

  useEffect(() => {
    if (mode !== 'live') return;
    const ac = new AbortController();
    tokenRef.current = null;
    setRoster({ kind: 'loading' });
    void load('0', ac.signal);
    return () => ac.abort();
    // Re-run when the connection mode flips (offline → live).
  }, [load, mode]);

  const doInvite = useCallback(async (): Promise<void> => {
    setInviteErr(null);
    setLastInvite(null);
    const trimmed = email.trim();
    if (!trimmed) return;
    setBusy('invite');
    const t = await token();
    if (!t) {
      setInviteErr('No admin credential — connect a gateway.');
      setBusy(null);
      return;
    }
    const result = await inviteOperatorUser(t, trimmed, role, { base: apiBase });
    setBusy(null);
    if (result === null) {
      setInviteErr('Could not invite — the email may already be on the roster or is invalid.');
      return;
    }
    setEmail('');
    setLastInvite({ email: result.user.email, token: result.invite_token });
    void load('0');
  }, [email, role, token, apiBase, load]);

  const changeRole = useCallback(
    async (u: OperatorUser, next: OperatorRole): Promise<void> => {
      if (next === u.role) return;
      setBusy(u.email);
      const t = await token();
      if (t) await updateOperatorUser(t, u.email, { role: next }, { base: apiBase });
      setBusy(null);
      void load('0');
    },
    [token, apiBase, load],
  );

  const toggleStatus = useCallback(
    async (u: OperatorUser): Promise<void> => {
      const next: OperatorStatus = u.status === 'disabled' ? 'active' : 'disabled';
      setBusy(u.email);
      const t = await token();
      if (t) await updateOperatorUser(t, u.email, { status: next }, { base: apiBase });
      setBusy(null);
      void load('0');
    },
    [token, apiBase, load],
  );

  const doRemove = useCallback(
    async (u: OperatorUser): Promise<void> => {
      setBusy(u.email);
      const t = await token();
      if (t) await removeOperatorUser(t, u.email, { base: apiBase });
      setBusy(null);
      setConfirmRemove(null);
      void load('0');
    },
    [token, apiBase, load],
  );

  const copyLink = useCallback((invite: { email: string; token: string }) => {
    const link = `${window.location.origin}/invite#token=${invite.token}`;
    void navigator.clipboard?.writeText(link).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1600);
      },
      () => undefined,
    );
  }, []);

  // Offline is the standard honest empty state with a connect CTA — the roster
  // lives on the gateway, so with no gateway there is nothing to be honest about.
  if (mode !== 'live') {
    return (
      <div className="mx-auto flex h-full max-w-5xl flex-col">
        <Panel className="h-full">
          <EmptyState
            icon={Unplug}
            title="No gateway connected"
            detail="The operator roster is served by the gateway's /v1/admin/users endpoints. Nothing about your team is stored in, or invented by, this console."
            action={
              <button type="button" onClick={navigateToConnection} className="btn-primary">
                <PlugZap size={13} /> Connect a gateway
              </button>
            }
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className="mx-auto flex h-full max-w-5xl flex-col gap-5">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[19px] font-semibold tracking-tightest text-ink">Users</h2>
          <p className="mt-1 text-[13px] text-slate-500">
            Your console team. Invite by email, set a role, enable or disable access.
            <span className="text-slate-400"> Roles are a management label — authorization is by capability.</span>
          </p>
        </div>
        {/* Only a gateway that ANSWERED may be quoted a count. */}
        <span className="rounded-full border border-hairline bg-surface px-3 py-1 font-mono text-[11.5px] text-slate-500">
          {roster.kind === 'ok'
            ? `${roster.count} ${roster.count === 1 ? 'member' : 'members'}`
            : roster.kind === 'loading'
              ? 'reading…'
              : 'membership unknown'}
        </span>
      </div>

      {/* Invite */}
      <Panel>
        <PanelHeader title="Invite a teammate" icon={UserPlus} />
        <div className="flex flex-wrap items-end gap-3 p-4">
          <div className="min-w-[220px] flex-1">
            <Field label="Invite by email">
              <Input
                mono
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void doInvite();
                }}
                placeholder="teammate@company.com"
              />
            </Field>
          </div>
          <div className="w-[140px]">
            <Field label="Role">
              <Select
                value={role}
                onChange={(e) => setRole(e.target.value as OperatorRole)}
                className="capitalize"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <button
            type="button"
            onClick={() => void doInvite()}
            disabled={busy === 'invite' || !email.trim()}
            className="btn-primary"
          >
            {busy === 'invite' ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <UserPlus size={13} />
            )}{' '}
            {busy === 'invite' ? 'Inviting…' : 'Invite'}
          </button>
          {inviteErr ? <p className="w-full text-[12px] text-denied">{inviteErr}</p> : null}
          {lastInvite ? (
            <div className="flex w-full flex-wrap items-center gap-3 rounded-lg border border-verified/25 bg-verified/8 px-3 py-2">
              <ShieldCheck size={15} className="text-verified" />
              <span className="text-[12.5px] text-ink">
                Invited <span className="font-mono">{lastInvite.email}</span>. Send them this one-time link:
              </span>
              <button
                type="button"
                onClick={() => copyLink(lastInvite)}
                className="btn-ghost border-verified/30 text-verified"
              >
                {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy invite link'}
              </button>
              <button
                type="button"
                onClick={() => setLastInvite(null)}
                className="ml-auto text-slate-500 transition-colors hover:text-ink focus:outline-none focus-visible:shadow-focus-ring"
                aria-label="Dismiss"
              >
                <X size={14} />
              </button>
            </div>
          ) : null}
        </div>
      </Panel>

      {/* Roster */}
      <Panel className="min-h-0 flex-1">
        <PanelHeader
          title="Roster"
          icon={Users}
          right={roster.kind === 'ok' ? `${roster.users.length} shown` : null}
        />
        {roster.kind === 'loading' ? (
          <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-2 px-6 py-12 text-center">
            <Loader2 size={20} className="animate-spin text-slate-500" />
            <p className="text-[12.5px] font-medium text-slate-400">Reading the roster</p>
            <p className="max-w-sm text-[11.5px] leading-relaxed text-slate-500">
              An admin credential is being minted so the gateway itself authorizes the read.
            </p>
          </div>
        ) : roster.kind !== 'ok' ? (
          <AdminReadUnavailable reason={roster.kind} />
        ) : roster.users.length === 0 ? (
          // Wrapped so EmptyState's h-full resolves against the flex-sized
          // remainder under the panel header.
          <div className="min-h-0 flex-1">
            <EmptyState
              icon={Users}
              title="No team members yet"
              detail="The gateway answered with an empty roster — that is a real zero, not a failed read. Invite your first teammate by email above."
            />
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead className="sticky top-0 bg-surface">
                <tr className="border-b border-hairline text-left">
                  <th className="px-4 py-2.5 text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">Email</th>
                  <th className="px-4 py-2.5 text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">Role</th>
                  <th className="px-4 py-2.5 text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">Status</th>
                  <th className="px-4 py-2.5 text-right text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">Manage</th>
                </tr>
              </thead>
              <tbody>
                {roster.users.map((u) => {
                  const rowBusy = busy === u.email;
                  return (
                    <tr key={u.email} className="border-b border-hairline last:border-b-0">
                      <td className="px-4 py-2.5 font-mono text-ink">{u.email}</td>
                      <td className="px-4 py-2.5">
                        <Select
                          value={u.role}
                          disabled={rowBusy}
                          onChange={(e) => void changeRole(u, e.target.value as OperatorRole)}
                          className="w-[128px] capitalize"
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </Select>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge tone={STATUS_TONE[u.status]}>{STATUS_LABEL[u.status]}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            disabled={rowBusy}
                            onClick={() => void toggleStatus(u)}
                            className="btn-ghost"
                          >
                            {u.status === 'disabled' ? 'Enable' : 'Disable'}
                          </button>
                          {confirmRemove === u.email ? (
                            <button
                              type="button"
                              disabled={rowBusy}
                              onClick={() => void doRemove(u)}
                              className="btn-ghost border-denied/40 bg-denied/8 font-semibold text-denied"
                            >
                              Confirm
                            </button>
                          ) : (
                            <button
                              type="button"
                              disabled={rowBusy}
                              onClick={() => setConfirmRemove(u.email)}
                              className="btn-ghost text-denied hover:border-denied/40"
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {roster.cursor !== '0' ? (
              <div className="border-t border-hairline p-3 text-center">
                <button
                  type="button"
                  onClick={() => void load(roster.cursor)}
                  disabled={loading}
                  className="btn-ghost"
                >
                  {loading ? <Loader2 size={13} className="animate-spin" /> : null}{' '}
                  {loading ? 'Loading…' : 'Load more'}
                </button>
              </div>
            ) : null}
          </div>
        )}
      </Panel>
    </div>
  );
}
