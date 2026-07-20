import { GitCommitVertical, Check, FileText } from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
import { loadReleaseHistory } from '../../lib/changelog';
import type { ReleaseEntry } from '../../lib/changelog';
import { EDITION } from '../../lib/consoleConfig';

/**
 * Docs → Release Notes + Version History.
 *
 * The release notes are the REAL repository CHANGELOG.md (bundled at build via
 * `__CHANGELOG__`, parsed by `lib/changelog.ts`) — one source, never a second
 * copy to drift. The running/build/edition provenance is read LIVE: the running
 * version from the gateway (`/healthz`), the console build from `__APP_VERSION__`,
 * the edition from the build. Nothing here is fabricated — an absent changelog or
 * an offline gateway each render an honest empty/unknown state.
 */

// Parsed once at module load — the changelog is a build constant. An empty
// "Unreleased" heading (present in every Keep-a-Changelog file but often with no
// entries yet) is dropped so it never renders as a bare, contentless card.
const RELEASES: ReleaseEntry[] = loadReleaseHistory().filter(
  (e) => !(e.isUnreleased && e.summary === null && e.sections.length === 0),
);

function KV({
  label,
  value,
  tone = 'plain',
}: {
  label: string;
  value: string;
  tone?: 'plain' | 'ok' | 'warn';
}): JSX.Element {
  const toneCls =
    tone === 'ok' ? 'text-verified' : tone === 'warn' ? 'text-staged' : 'text-ink';
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline py-2 last:border-b-0">
      <span className="text-[11.5px] text-slate-500">{label}</span>
      <span className={`font-mono text-[12px] ${toneCls}`}>{value}</span>
    </div>
  );
}

function ReleaseCard({ entry, running }: { entry: ReleaseEntry; running: string | null }): JSX.Element {
  const isRunning = running !== null && entry.version === running;
  return (
    <article className="relative flex gap-4 pb-7 last:pb-0">
      {/* timeline rail */}
      <div className="relative flex flex-col items-center">
        <span
          className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ring-4 ring-canvas ${
            isRunning ? 'bg-verified' : entry.isUnreleased ? 'bg-slate-600' : 'bg-slate-500'
          }`}
        />
        <span className="mt-1 w-px flex-1 bg-hairline" aria-hidden="true" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <h3 className="font-mono text-[15px] font-semibold text-ink">{entry.version}</h3>
          {isRunning ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-verified px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-verified">
              <Check size={10} /> running
            </span>
          ) : null}
          {entry.date ? (
            <span className="font-mono text-[11.5px] text-slate-500">{entry.date}</span>
          ) : null}
        </div>

        {entry.summary ? (
          <p className="mt-2 max-w-[68ch] text-[13px] leading-relaxed text-slate-400">
            {entry.summary}
          </p>
        ) : null}

        {entry.sections.map((section, i) => (
          <div key={i} className="mt-3">
            {section.heading ? (
              <p className="font-mono text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">
                {section.heading}
              </p>
            ) : null}
            <ul className="mt-1.5 space-y-1.5">
              {section.items.map((item, j) => (
                <li key={j} className="flex gap-2 text-[12.5px] leading-relaxed text-slate-300">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-600" />
                  <span className="min-w-0">{item}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </article>
  );
}

export function DocsView({ gateway }: { gateway: GatewayLive; subtab: string }): JSX.Element {
  const running = gateway.health?.version ?? null;
  const build = __APP_VERSION__;
  const versionsMatch = running !== null && running === build;

  if (RELEASES.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="max-w-sm rounded-xl border border-hairline bg-surface p-8 text-center">
          <FileText size={20} className="mx-auto text-slate-500" />
          <p className="mt-3 text-[13px] font-medium text-ink">Release history unavailable</p>
          <p className="mt-1 text-[12px] text-slate-500">
            No CHANGELOG.md was bundled with this build. Release notes appear once the console is
            built from a repository that ships one.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto grid max-w-6xl gap-6 lg:grid-cols-[1fr_300px]">
      {/* Release notes timeline */}
      <section className="min-w-0">
        <div className="mb-5">
          <h2 className="text-[19px] font-semibold tracking-tightest text-ink">Release notes</h2>
          <p className="mt-1 text-[13px] text-slate-500">
            The shipped history of MCPIP, straight from the repository changelog.
          </p>
        </div>
        <div className="rounded-xl border border-hairline bg-surface p-5 md:p-6">
          {RELEASES.map((entry) => (
            <ReleaseCard key={entry.version} entry={entry} running={running} />
          ))}
        </div>
      </section>

      {/* Version & provenance + history rail */}
      <aside className="space-y-4">
        <div className="rounded-xl border border-hairline bg-surface p-5">
          <div className="mb-2 flex items-center gap-2">
            <GitCommitVertical size={15} className="text-slate-500" />
            <h3 className="text-[13px] font-semibold text-ink">Version &amp; provenance</h3>
          </div>
          <KV label="Running (gateway)" value={running ?? 'offline'} tone={running ? 'plain' : 'warn'} />
          <KV label="Console build" value={`v${build}`} />
          <KV
            label="Reconciled"
            value={running === null ? 'unknown' : versionsMatch ? 'in sync' : 'skew'}
            tone={running === null ? 'warn' : versionsMatch ? 'ok' : 'warn'}
          />
          <KV label="Edition" value={EDITION} />
          <p className="mt-3 text-[11.5px] leading-relaxed text-slate-500">
            The running version is read live from the gateway; the build is compiled in. When they
            disagree, upgrade is a signed redeploy — the console never fabricates a match.
          </p>
        </div>

        <div className="rounded-xl border border-hairline bg-surface p-5">
          <h3 className="mb-3 text-[13px] font-semibold text-ink">Version history</h3>
          <ul className="space-y-0.5">
            {RELEASES.map((entry) => {
              const isRunning = running !== null && entry.version === running;
              return (
                <li
                  key={entry.version}
                  className="flex items-center justify-between gap-3 rounded-md px-1.5 py-1.5"
                >
                  <span className="flex items-center gap-2 font-mono text-[12px] text-ink">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        isRunning ? 'bg-verified' : 'bg-slate-600'
                      }`}
                    />
                    {entry.version}
                  </span>
                  <span className="font-mono text-[11px] text-slate-500">
                    {entry.date ?? '—'}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      </aside>
    </div>
  );
}
