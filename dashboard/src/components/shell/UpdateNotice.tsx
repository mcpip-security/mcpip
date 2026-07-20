import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  ArrowUpCircle,
  ShieldCheck,
  AlertTriangle,
  FileText,
  SlidersHorizontal,
  X,
  Sparkles,
} from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
import {
  deriveUpdateStatus,
  dismissUpdate,
  howToApply,
  isDismissed,
  readDismissedKey,
  releaseHighlights,
} from '../../lib/updateStatus';

/**
 * Global update-available notice — the Claude-style "there's a new version"
 * affordance, in the shell header. It appears ONLY when the shared update verdict
 * (lib/updateStatus) says an update is available and the operator hasn't dismissed
 * that specific target version. Clicking opens a popover with what's new, the
 * signed provenance, exactly how to apply it, and the operator's controls.
 *
 * MCPIP never auto-installs — this is a notifier. Every action is the operator's:
 * read the notes, apply a signed redeploy on their own change-control, or dismiss
 * (a newer version re-surfaces the notice). Nothing here downloads or runs code.
 */

/** Deep-link helper — the shell's cross-view navigation bus. */
function navigate(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

export function UpdateNotice({ gateway }: { gateway: GatewayLive }): JSX.Element | null {
  const consoleV = __APP_VERSION__;
  const status = useMemo(() => deriveUpdateStatus(consoleV, gateway), [consoleV, gateway]);

  const [open, setOpen] = useState(false);
  const [dismissedKey, setDismissedKey] = useState<string | null>(() => readDismissedKey());
  const rootRef = useRef<HTMLDivElement>(null);

  // Close on outside click + Escape while the popover is open.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent): void => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const highlights = useMemo(
    () => releaseHighlights(status.targetVersion, 5),
    [status.targetVersion],
  );

  // Nothing to show: only surface for a genuine, non-dismissed update.
  if (status.severity !== 'update' || isDismissed(status, dismissedKey)) return null;

  const verified = status.releaseVerified;
  const steps = howToApply(status);

  const onDismiss = (): void => {
    dismissUpdate(status);
    setDismissedKey(readDismissedKey());
    setOpen(false);
  };

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="dialog"
        aria-expanded={open}
        title={status.headline}
        className="flex items-center gap-1.5 rounded-full border border-staged/30 bg-staged/8 px-2.5 py-1 text-[11.5px] font-medium text-staged transition-colors hover:bg-staged/12 focus:outline-none focus-visible:shadow-focus-ring"
      >
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-staged/60" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-staged" />
        </span>
        <ArrowUpCircle size={13} className="hidden sm:block" />
        <span className="hidden md:inline">Update available</span>
      </button>

      <AnimatePresence>
        {open ? (
          <motion.div
            role="dialog"
            aria-label="Software update"
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.32, 0.72, 0, 1] }}
            className="absolute right-0 top-[calc(100%+8px)] z-50 w-[340px] overflow-hidden rounded-xl border border-hairline bg-surface shadow-panel"
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-3 border-b border-hairline bg-canvas px-4 py-3">
              <div className="flex items-start gap-2.5">
                <Sparkles size={16} className="mt-0.5 shrink-0 text-staged" />
                <div className="min-w-0">
                  <p className="text-[13px] font-semibold text-ink">
                    {status.kind === 'feed' ? 'A new MCPIP release is available' : status.headline}
                  </p>
                  {status.targetVersion ? (
                    <p className="mt-0.5 flex items-center gap-1.5 font-mono text-[11px] text-slate-500">
                      <span className="text-slate-400">
                        {status.gatewayVersion ?? consoleV}
                      </span>
                      <span aria-hidden>→</span>
                      <span className="font-semibold text-ink">v{status.targetVersion}</span>
                      {verified === true ? (
                        <span className="inline-flex items-center gap-0.5 text-verified">
                          <ShieldCheck size={11} /> signed
                        </span>
                      ) : verified === false ? (
                        <span className="inline-flex items-center gap-0.5 text-denied">
                          <AlertTriangle size={11} /> unverified
                        </span>
                      ) : null}
                    </p>
                  ) : null}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close"
                className="-mr-1 shrink-0 rounded-md p-1 text-slate-500 transition-colors hover:bg-elevated hover:text-ink"
              >
                <X size={14} />
              </button>
            </div>

            <div className="max-h-[min(60vh,420px)] overflow-y-auto px-4 py-3">
              {/* What's new — from the bundled changelog when the target is known there */}
              {highlights.length > 0 ? (
                <>
                  <p className="eyebrow mb-2">What&rsquo;s new</p>
                  <ul className="space-y-1.5">
                    {highlights.map((item, i) => (
                      <li key={i} className="flex gap-2 text-[11.5px] leading-relaxed text-slate-500">
                        <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-staged" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="text-[11.5px] leading-relaxed text-slate-500">{status.detail}</p>
              )}

              {/* How to apply — always the operator's own signed redeploy */}
              <p className="eyebrow mb-2 mt-4">How to apply</p>
              <ol className="space-y-1.5">
                {steps.map((step, i) => (
                  <li key={i} className="flex gap-2 text-[11.5px] leading-relaxed text-slate-500">
                    <span className="mt-px flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-hairline bg-canvas font-mono text-[9px] text-slate-400">
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>

              <p className="mt-3 flex items-start gap-1.5 rounded-lg border border-hairline bg-canvas px-2.5 py-2 text-[10.5px] leading-relaxed text-slate-500">
                <ShieldCheck size={12} className="mt-px shrink-0 text-slate-500" />
                <span>
                  MCPIP never auto-installs. You apply an immutable, signed artifact on your own
                  change-control — the console only notifies.
                </span>
              </p>
            </div>

            {/* Actions — the operator's controls */}
            <div className="flex items-center justify-between gap-2 border-t border-hairline bg-canvas px-3 py-2.5">
              <button
                type="button"
                onClick={onDismiss}
                className="rounded-md px-2 py-1 text-[11.5px] font-medium text-slate-500 transition-colors hover:text-ink"
              >
                Dismiss
              </button>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    navigate('docs', 'releases');
                    setOpen(false);
                  }}
                  className="btn-ghost !px-2.5 !py-1 !text-[11.5px]"
                >
                  <FileText size={12} /> Release notes
                </button>
                <button
                  type="button"
                  onClick={() => {
                    navigate('gateway', 'updates');
                    setOpen(false);
                  }}
                  className="btn-primary !px-2.5 !py-1 !text-[11.5px]"
                >
                  <SlidersHorizontal size={12} /> Manage
                </button>
              </div>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
