/* ---------------------------------------------------------------------------
   CodeSnippet — the console's ONE treatment for copyable code and wire
   payloads (shell commands, config files, SDK examples, raw responses).

   Charter terminal rules apply: mono 11px on canvas inside a hairline-framed
   surface, sans only in the header chrome, no CRT cosplay, instant updates
   (code is data-at-rest — nothing types itself out). The copy affordance is
   the same quiet tertiary action as the directory's CopyId — a brief ✓ flash,
   no toast — and always copies the EXACT `code` string: snippets carry
   payload-lock-sensitive JSON and auth headers, so display and clipboard must
   never diverge. Wide lines scroll inside the block, never the page.
--------------------------------------------------------------------------- */

import { useEffect, useState } from 'react';
import { Check, Copy } from 'lucide-react';

export function CodeSnippet({
  code,
  label,
  className = '',
}: {
  /** The exact text rendered AND placed on the clipboard, byte-for-byte. */
  code: string;
  /** Mono tag naming the dialect or file (".mcp.json", "bash", "python"). */
  label?: string;
  className?: string;
}): JSX.Element {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(t);
  }, [copied]);

  const copy = (): void => {
    navigator.clipboard
      .writeText(code)
      .then(() => setCopied(true))
      .catch(() => {
        /* clipboard unavailable (permissions / insecure context) — nothing to fake */
      });
  };

  return (
    <div className={`overflow-hidden rounded-lg border border-hairline bg-surface ${className}`}>
      <div className="flex items-center justify-between gap-2 border-b border-hairline/60 px-2.5 py-1">
        <span className="truncate font-mono text-[10px] text-slate-500">{label ?? ''}</span>
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
      <pre className="overflow-x-auto bg-canvas px-3 py-2.5 font-mono text-[11px] leading-relaxed text-ink">
        <code>{code}</code>
      </pre>
    </div>
  );
}
