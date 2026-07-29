/* ---------------------------------------------------------------------------
   TabbedCommand — the one-glance quick start: a single code card with tab
   pills (curl · Python · TypeScript · …), one command or minimal block per
   tab, and a copy button. Same instrument treatment as CodeSnippet (hairline
   frame, mono on canvas, quiet copy affordance); the clipboard always gets
   the EXACT code string of the active tab — display and copy never diverge.
--------------------------------------------------------------------------- */

import { useEffect, useState } from 'react';
import { Check, Copy } from 'lucide-react';

export interface CommandTab {
  id: string;
  /** Pill label ("curl", "Python", …). */
  label: string;
  /** The exact text rendered AND copied for this tab. */
  code: string;
  /** Shell tab: render a muted `$` prompt in front of each command line. */
  prompt?: boolean;
}

/** Lines that get a `$` prompt: command starts only — never comments, blanks,
    or backslash-continuations of the previous line. */
function promptedLines(code: string): ReadonlyArray<{ text: string; prompt: boolean; comment: boolean }> {
  const lines = code.split('\n');
  let continuation = false;
  return lines.map((text) => {
    const trimmed = text.trim();
    const comment = trimmed.startsWith('#');
    const blank = trimmed === '';
    const prompt = !comment && !blank && !continuation;
    continuation = !comment && !blank && trimmed.endsWith('\\');
    return { text, prompt, comment };
  });
}

export function TabbedCommand({
  tabs,
  className = '',
}: {
  tabs: ReadonlyArray<CommandTab>;
  className?: string;
}): JSX.Element | null {
  const [activeId, setActiveId] = useState<string>(tabs[0]?.id ?? '');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(t);
  }, [copied]);

  const active = tabs.find((t) => t.id === activeId) ?? tabs[0];
  if (!active) return null;

  const copy = (): void => {
    navigator.clipboard
      .writeText(active.code)
      .then(() => setCopied(true))
      .catch(() => {
        /* clipboard unavailable (permissions / insecure context) — nothing to fake */
      });
  };

  return (
    <div className={`overflow-hidden rounded-lg border border-hairline bg-surface ${className}`}>
      <div className="flex items-center justify-between gap-2 border-b border-hairline/60 px-2 py-1.5">
        <div className="flex min-w-0 items-center gap-1 overflow-x-auto">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => {
                setActiveId(t.id);
                setCopied(false);
              }}
              aria-pressed={t.id === active.id}
              className={`shrink-0 rounded-md px-2 py-0.5 font-mono text-[10.5px] transition-colors focus:outline-none focus-visible:shadow-focus-ring ${
                t.id === active.id
                  ? 'bg-elevated font-semibold text-ink'
                  : 'text-slate-500 hover:text-ink'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <button
          type="button"
          title="Copy to clipboard"
          onClick={copy}
          className="flex shrink-0 items-center gap-1 text-[10px] font-medium text-slate-500 transition-colors hover:text-ink focus:outline-none focus-visible:shadow-focus-ring"
        >
          {copied ? <Check size={11} className="text-verified" /> : <Copy size={11} />}
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      <pre className="overflow-x-auto bg-canvas px-3 py-2.5 font-mono text-[11px] leading-relaxed">
        <code>
          {active.prompt
            ? promptedLines(active.code).map((l, i) => (
                <span key={i} className="block whitespace-pre">
                  {l.prompt ? <span className="select-none text-slate-500">$ </span> : null}
                  <span className={l.comment ? 'text-slate-500' : 'text-ink'}>{l.text}</span>
                </span>
              ))
            : <span className="text-ink">{active.code}</span>}
        </code>
      </pre>
    </div>
  );
}
