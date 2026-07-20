import { useCallback, useEffect, useRef, useState } from 'react';
import { UserPlus, Users, Copy, Check, ShieldCheck, X } from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
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
 * disable, remove. No mock data: with no reachable gateway or admin credential it
 * shows an honest empty/connect state. The `role` is a management label (it
 * authorizes nothing); the invite returns a one-time reference link to send.
 */

const ROLES: ReadonlyArray<OperatorRole> = ['admin', 'member', 'viewer'];

const STATUS_STYLE: Record<OperatorStatus, { label: string; dot: string; text: string }> = {
  invited: { label: 'Invited', dot: 'bg-staged', text: 'text-staged' },
  active: { label: 'Active', dot: 'bg-verified', text: 'text-verified' },
  disabled: { label: 'Disabled', dot: 'bg-denied', text: 'text-denied' },
};

export function UsersView({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { ensureAdminToken, apiBase, mode } = gateway;
  const [users, setUsers] = useState<OperatorUser[] | null>(null);
  const [count, setCount] = useState(0);
  const [cursor, setCursor] = useState('0');
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
        setUsers([]);
        setLoading(false);
        return;
      }
      const page = await operatorUsers(t, from, 100, { base: apiBase, signal });
      if (page === null) {
        setUsers([]);
        setLoading(false);
        return;
      }
      setUsers((prev) => (from === '0' ? page.users : [...(prev ?? []), ...page.users]));
      setCount(page.count);
      setCursor(page.next_cursor);
      setLoading(false);
    },
    [token, apiBase],
  );

  useEffect(() => {
    const ac = new AbortController();
    tokenRef.current = null;
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

  const list = users ?? [];

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
        <span className="rounded-full border border-hairline bg-surface px-3 py-1 font-mono text-[11.5px] text-slate-500">
          {count} {count === 1 ? 'member' : 'members'}
        </span>
      </div>

      {/* Invite */}
      <div className="rounded-xl border border-hairline bg-surface p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[220px]">
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-slate-500">
              Invite by email
            </span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void doInvite();
              }}
              placeholder="teammate@company.com"
              className="w-full rounded-lg border border-hairline bg-canvas px-3 py-2 font-mono text-[13px] text-ink outline-none transition-colors focus:border-slate-400 focus-visible:shadow-focus-ring"
            />
          </label>
          <label>
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-slate-500">
              Role
            </span>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as OperatorRole)}
              className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[13px] capitalize text-ink outline-none focus:border-slate-400"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void doInvite()}
            disabled={busy === 'invite' || !email.trim()}
            className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-[13px] font-medium text-surface transition-opacity disabled:opacity-40"
          >
            <UserPlus size={15} /> {busy === 'invite' ? 'Inviting…' : 'Invite'}
          </button>
        </div>
        {inviteErr ? <p className="mt-2 text-[12px] text-denied">{inviteErr}</p> : null}
        {lastInvite ? (
          <div className="mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-verified bg-verified/10 px-3 py-2">
            <ShieldCheck size={15} className="text-verified" />
            <span className="text-[12.5px] text-ink">
              Invited <span className="font-mono">{lastInvite.email}</span>. Send them this one-time link:
            </span>
            <button
              type="button"
              onClick={() => copyLink(lastInvite)}
              className="inline-flex items-center gap-1.5 rounded-md border border-verified bg-surface px-2.5 py-1 text-[11.5px] font-medium text-verified"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy invite link'}
            </button>
            <button
              type="button"
              onClick={() => setLastInvite(null)}
              className="ml-auto text-slate-500 hover:text-ink"
              aria-label="Dismiss"
            >
              <X size={14} />
            </button>
          </div>
        ) : null}
      </div>

      {/* Roster */}
      <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-hairline bg-surface">
        {loading && list.length === 0 ? (
          <div className="flex h-full items-center justify-center text-[13px] text-slate-500">Loading roster…</div>
        ) : list.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 p-10 text-center">
            <Users size={20} className="text-slate-500" />
            <p className="text-[13px] font-medium text-ink">No team members yet</p>
            <p className="max-w-xs text-[12px] text-slate-500">
              Invite your first teammate by email above. With no gateway connected this list stays
              honestly empty.
            </p>
          </div>
        ) : (
          <div className="h-full overflow-y-auto">
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
                {list.map((u) => {
                  const st = STATUS_STYLE[u.status];
                  const rowBusy = busy === u.email;
                  return (
                    <tr key={u.email} className="border-b border-hairline last:border-b-0">
                      <td className="px-4 py-2.5 font-mono text-ink">{u.email}</td>
                      <td className="px-4 py-2.5">
                        <select
                          value={u.role}
                          disabled={rowBusy}
                          onChange={(e) => void changeRole(u, e.target.value as OperatorRole)}
                          className="rounded-md border border-hairline bg-canvas px-2 py-1 text-[12.5px] capitalize text-ink outline-none focus:border-slate-400 disabled:opacity-50"
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex items-center gap-1.5 font-medium ${st.text}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${st.dot}`} /> {st.label}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            disabled={rowBusy}
                            onClick={() => void toggleStatus(u)}
                            className="rounded-md border border-hairline px-2.5 py-1 text-[11.5px] font-medium text-slate-500 transition-colors hover:text-ink disabled:opacity-50"
                          >
                            {u.status === 'disabled' ? 'Enable' : 'Disable'}
                          </button>
                          {confirmRemove === u.email ? (
                            <button
                              type="button"
                              disabled={rowBusy}
                              onClick={() => void doRemove(u)}
                              className="rounded-md border border-denied bg-denied/10 px-2.5 py-1 text-[11.5px] font-semibold text-denied disabled:opacity-50"
                            >
                              Confirm
                            </button>
                          ) : (
                            <button
                              type="button"
                              disabled={rowBusy}
                              onClick={() => setConfirmRemove(u.email)}
                              className="rounded-md border border-hairline px-2.5 py-1 text-[11.5px] font-medium text-denied transition-colors hover:border-denied disabled:opacity-50"
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
            {cursor !== '0' ? (
              <div className="border-t border-hairline p-3 text-center">
                <button
                  type="button"
                  onClick={() => void load(cursor)}
                  disabled={loading}
                  className="rounded-lg border border-hairline px-4 py-1.5 text-[12.5px] font-medium text-slate-500 hover:text-ink disabled:opacity-50"
                >
                  {loading ? 'Loading…' : 'Load more'}
                </button>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
