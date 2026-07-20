import { useEffect } from 'react';
import { animate, useMotionValue, useTransform, motion } from 'framer-motion';
import { prefersReducedMotion } from '../lib/format';

/** House curve — slow, expensive, never bouncy. */
const EASE = [0.32, 0.72, 0, 1] as const;

interface AnimatedNumberProps {
  value: number;
  /** Decimal places to display. */
  decimals?: number;
  className?: string;
}

/**
 * Tweens the displayed number toward `value` when it changes — motion
 * narrating a real state change, never ambient. On first mount it renders the
 * final value immediately (no count-up theater), and under reduced motion it
 * snaps on every change. Callers must include `.tabular` in className so
 * ticking digits never jitter the layout.
 */
export function AnimatedNumber({
  value,
  decimals = 0,
  className,
}: AnimatedNumberProps): JSX.Element {
  const reduced = prefersReducedMotion();
  const mv = useMotionValue(value);
  const text = useTransform(mv, (v) =>
    v.toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals,
    }),
  );

  useEffect(() => {
    if (reduced) {
      mv.set(value);
      return;
    }
    const controls = animate(mv, value, { duration: 0.3, ease: EASE });
    return () => controls.stop();
  }, [value, mv, reduced]);

  return <motion.span className={className}>{text}</motion.span>;
}
