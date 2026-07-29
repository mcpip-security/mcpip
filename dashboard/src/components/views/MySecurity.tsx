import { useCallback, useEffect, useState } from 'react';
import { Check, Copy, KeyRound, Loader2, ShieldCheck, Smartphone, Trash2 } from 'lucide-react';
import { Badge, EmptyState, Field, Input, Panel, PanelHeader } from '../ui';
import type { GatewayLive } from '../../lib/useGatewayLive';
import {
  authnAdminDisable,
  authnConfirm,
  authnDisable,
  authnEnroll,
  authnEnrollments,
  authnStatus,
  mintDevToken,
  type AuthnEnrollmentRow,
  type AuthnProvisioning,
  type AuthnStatus,
} from '../../lib/api';
import { CAP_DIRECTORY_ADMIN } from '../../lib/protocol';
import { loadCompanyConfig } from '../../lib/companyConfig';

/*
 * Two-factor authentication — USER-BASED 2FA for step-up approvals.
 *
 * Enrollment binds a standard authenticator app (Google Authenticator, 1Password,
 * Authy — plain RFC 6238 TOTP) to THIS operator principal. Once enrolled, a staged
 * PIN_REQUIRED action's one-time code is released only against a fresh code from
 * the enrolled app (Monitor → Probe, or POST /v1/authenticator/reveal).
 *
 * Honest-state discipline: everything here is a REAL gateway round-trip; when the
 * sandbox token minter is absent (production, by design) the panel says so instead
 * of pretending.
 */

const OPERATOR_AGENT_ID = 'operator-console';

function useOperatorToken(gateway: GatewayLive): () => Promise<string | null> {
  return useCallback(async () => {
    try {
      const company = loadCompanyConfig();
      const claims: { tenant_id?: string; agent_id: string } = { agent_id: OPERATOR_AGENT_ID };
      if (company?.tenant) {
        claims.tenant_id = company.tenant;
      }
      return await mintDevToken(claims, { base: gateway.apiBase });
    } catch {
      return null;
    }
  }, [gateway.apiBase]);
}

function CopyValue({ label, value }: { label: string; value: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2">
      <div className="min-w-0 flex-1">
        <p className="eyebrow text-slate-500">{label}</p>
        <p className="break-all font-mono text-[11.5px] text-ink">{value}</p>
      </div>
      <button
        type="button"
        aria-label={`Copy ${label}`}
        className="btn shrink-0 border border-hairline bg-surface text-slate-500 hover:text-ink"
        onClick={() => {
          void navigator.clipboard.writeText(value).then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1400);
          });
        }}
      >
        {copied ? <Check size={13} className="text-verified" /> : <Copy size={13} />}
      </button>
    </div>
  );
}

function EnrollmentCeremony({
  provisioning,
  onConfirm,
  busy,
}: {
  provisioning: AuthnProvisioning;
  onConfirm: (code: string) => void;
  busy: boolean;
}): JSX.Element {
  const [code, setCode] = useState('');
  return (
    <div className="space-y-3">
      <p className="text-[12px] leading-relaxed text-slate-500">
        Add this key to your authenticator app, then enter the 6-digit code it shows.
      </p>
      <CopyValue label="Setup key · enter manually" value={provisioning.secret} />
      <CopyValue label="otpauth:// URI · for apps that import links" value={provisioning.provisioning_uri} />
      <div className="flex items-end gap-2">
        <div className="flex-1">
          <Field label="Code from your app">
            <Input
              mono
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              aria-label="6-digit authenticator code"
            />
          </Field>
        </div>
        <button
          type="button"
          className="btn-primary"
          disabled={busy || code.length !== provisioning.digits}
          onClick={() => onConfirm(code)}
        >
          {busy ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
          Activate
        </button>
      </div>
    </div>
  );
}

export function MySecurity({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const mintToken = useOperatorToken(gateway);
  const [status, setStatus] = useState<AuthnStatus | null | 'unavailable'>(null);
  const [provisioning, setProvisioning] = useState<AuthnProvisioning | null>(null);
  const [disableCode, setDisableCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [roster, setRoster] = useState<AuthnEnrollmentRow[] | null | 'unavailable'>(null);

  const refresh = useCallback(async (): Promise<void> => {
    const token = await mintToken();
    if (token === null) {
      setStatus('unavailable');
      setRoster('unavailable');
      return;
    }
    setStatus(await authnStatus(token, { base: gateway.apiBase }));
    const company = loadCompanyConfig();
    try {
      const admin = await mintDevToken(
        {
          ...(company?.tenant ? { tenant_id: company.tenant } : {}),
          agent_id: 'operator-directory-admin',
          capabilities: [CAP_DIRECTORY_ADMIN],
        },
        { base: gateway.apiBase },
      );
      setRoster(await authnEnrollments(admin, { base: gateway.apiBase }));
    } catch {
      setRoster('unavailable');
    }
  }, [gateway.apiBase, mintToken]);

  useEffect(() => {
    if (gateway.mode === 'live') {
      void refresh();
    }
  }, [gateway.mode, refresh]);

  if (gateway.mode !== 'live') {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={ShieldCheck}
          title="No gateway connected"
          detail="Two-factor enrollment is live-only — it binds an authenticator app to your principal on the connected gateway."
        />
      </Panel>
    );
  }

  const enroll = async (): Promise<void> => {
    setBusy(true);
    setNotice(null);
    const token = await mintToken();
    const prov = token === null ? null : await authnEnroll(token, { base: gateway.apiBase });
    if (prov === null) {
      setNotice('Enrollment refused — an active authenticator may already exist for this principal.');
    } else {
      setProvisioning(prov);
    }
    setBusy(false);
  };

  const confirm = async (code: string): Promise<void> => {
    setBusy(true);
    setNotice(null);
    const token = await mintToken();
    const ok = token !== null && (await authnConfirm(token, code, { base: gateway.apiBase }));
    if (ok) {
      setProvisioning(null);
      setNotice(null);
      await refresh();
    } else {
      setNotice('Code not accepted — codes are single-use; wait for the next code and try again.');
    }
    setBusy(false);
  };

  const turnOff = async (): Promise<void> => {
    setBusy(true);
    setNotice(null);
    const token = await mintToken();
    const ok =
      token !== null && (await authnDisable(token, disableCode, { base: gateway.apiBase }));
    if (ok) {
      setDisableCode('');
      await refresh();
    } else {
      setNotice('Turn-off refused — a valid current code is required to remove your authenticator.');
    }
    setBusy(false);
  };

  const removeEnrollment = async (agentId: string): Promise<void> => {
    const company = loadCompanyConfig();
    try {
      const admin = await mintDevToken(
        {
          ...(company?.tenant ? { tenant_id: company.tenant } : {}),
          agent_id: 'operator-directory-admin',
          capabilities: [CAP_DIRECTORY_ADMIN],
        },
        { base: gateway.apiBase },
      );
      await authnAdminDisable(admin, agentId, { base: gateway.apiBase });
      await refresh();
    } catch {
      /* roster stays as-is; the read path reports unavailable honestly */
    }
  };

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel className="h-full">
        <PanelHeader
          title="Two-factor authentication"
          icon={Smartphone}
          right={
            status !== null && status !== 'unavailable' && status.enrolled ? (
              <Badge tone="verified">enrolled</Badge>
            ) : (
              <Badge tone="muted">off</Badge>
            )
          }
        />
        <div className="flex-1 space-y-3 overflow-y-auto p-4">
          <p className="text-[12px] leading-relaxed text-slate-500">
            Approve step-up actions with a code from your phone's authenticator app.
          </p>

          {status === 'unavailable' ? (
            <p className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-500">
              This console holds no identity for this gateway (the sandbox token minter is
              absent in production). Enroll with your operator token via{' '}
              <span className="font-mono text-[10.5px]">POST /v1/authenticator/enroll</span>.
            </p>
          ) : provisioning !== null ? (
            <EnrollmentCeremony provisioning={provisioning} onConfirm={(c) => void confirm(c)} busy={busy} />
          ) : status !== null && status.enrolled ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 rounded-lg border border-verified/25 bg-verified/5 px-3 py-2.5">
                <ShieldCheck size={15} className="shrink-0 text-verified" />
                <p className="text-[12px] text-verified">
                  Authenticator active
                  {status.enrolled_at !== null
                    ? ` since ${new Date(status.enrolled_at * 1000).toLocaleDateString()}`
                    : ''}
                  . Step-up codes are released only against a fresh code from your app.
                </p>
              </div>
              <div className="flex items-end gap-2">
                <div className="flex-1">
                  <Field label="Current code · required to turn off">
                    <Input
                      mono
                      inputMode="numeric"
                      maxLength={6}
                      placeholder="000000"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ''))}
                      aria-label="Current authenticator code"
                    />
                  </Field>
                </div>
                <button
                  type="button"
                  className="btn border border-denied/25 bg-surface text-denied hover:bg-denied/5"
                  disabled={busy || disableCode.length !== 6}
                  onClick={() => void turnOff()}
                >
                  Turn off
                </button>
              </div>
            </div>
          ) : status !== null && status.pending ? (
            <p className="text-[11.5px] leading-relaxed text-slate-500">
              An enrollment was started but not confirmed. Start again to mint a fresh key.
              <button type="button" className="btn-primary ml-2" disabled={busy} onClick={() => void enroll()}>
                <KeyRound size={13} /> Restart enrollment
              </button>
            </p>
          ) : (
            <button type="button" className="btn-primary" disabled={busy || status === null} onClick={() => void enroll()}>
              {busy ? <Loader2 size={13} className="animate-spin" /> : <KeyRound size={13} />}
              Enable two-factor
            </button>
          )}

          {notice !== null ? (
            <p className="text-[11.5px] leading-relaxed text-denied">{notice}</p>
          ) : null}
        </div>
      </Panel>

      <Panel className="h-full">
        <PanelHeader title="Enrolled principals" icon={ShieldCheck} right={<span className="font-mono text-[10.5px]">tenant-wide</span>} />
        <div className="flex-1 overflow-y-auto p-4">
          {roster === 'unavailable' || roster === null ? (
            <p className="text-[11.5px] leading-relaxed text-slate-500">
              Roster unavailable — reading it requires a CAP_DIRECTORY_ADMIN token.
            </p>
          ) : roster.length === 0 ? (
            <p className="text-[11.5px] leading-relaxed text-slate-500">
              No authenticators enrolled in this tenant yet.
            </p>
          ) : (
            <ul className="divide-y divide-hairline">
              {roster.map((row) => (
                <li key={row.agent_id} className="flex items-center gap-3 py-2">
                  <span className="min-w-0 flex-1 break-all font-mono text-[11.5px] text-ink">{row.agent_id}</span>
                  <Badge tone={row.state === 'active' ? 'verified' : 'muted'}>{row.state}</Badge>
                  <button
                    type="button"
                    aria-label={`Remove ${row.agent_id}'s authenticator`}
                    title="Lost device — remove this enrollment"
                    className="btn shrink-0 border border-hairline bg-surface text-slate-500 hover:text-denied"
                    onClick={() => void removeEnrollment(row.agent_id)}
                  >
                    <Trash2 size={13} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Panel>
    </div>
  );
}
