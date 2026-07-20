import { motion } from 'framer-motion';
import { prefersReducedMotion } from '../lib/format';

const EASE = [0.22, 1, 0.36, 1] as const;

interface LogoProps {
  size?: number;
  animated?: boolean;
  className?: string;
}

/**
 * The MCPIP logomark — U+25D0 half-disc rendered as SVG.
 * Surface-filled circle (ink stroke) with the LEFT half filled solid ink.
 * Both fills are theme tokens (rgb(var(--c-surface)) / rgb(var(--c-ink))) so the
 * glyph inverts with the console theme instead of staying white-on-white in dark.
 */
const SURFACE = 'rgb(var(--c-surface))';
const INK = 'rgb(var(--c-ink))';

export function Logomark({ size = 24, animated = false, className }: LogoProps): JSX.Element {
  const reduced = prefersReducedMotion();
  const doAnimate = animated && !reduced;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      {doAnimate ? (
        <>
          <motion.circle
            cx="12"
            cy="12"
            r="10"
            style={{ fill: SURFACE, stroke: INK }}
            strokeWidth="1.5"
            initial={{ pathLength: 0, opacity: 0.4 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: 1, ease: EASE }}
          />
          <motion.path
            d="M12 2 A 10 10 0 0 0 12 22 Z"
            style={{ fill: INK }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.9, ease: EASE }}
          />
        </>
      ) : (
        <>
          <circle cx="12" cy="12" r="10" style={{ fill: SURFACE, stroke: INK }} strokeWidth="1.5" />
          <path d="M12 2 A 10 10 0 0 0 12 22 Z" style={{ fill: INK }} />
        </>
      )}
    </svg>
  );
}

