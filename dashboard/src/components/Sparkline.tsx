import { useId } from 'react';

interface SparklineProps {
  /** The genuinely recorded series to draw, oldest → newest. */
  data: ReadonlyArray<number>;
  width?: number;
  height?: number;
  /**
   * Color comes from CSS `currentColor` — pass a theme text class
   * (e.g. "text-ink") instead of re-hardcoding hex next to the tokens.
   */
  className?: string;
}

/**
 * Minimal SVG area sparkline. Normalizes `data` to the box and draws a
 * polyline with a soft fade beneath it. Purely presentational and honest:
 * with fewer than two REAL points it renders an empty box (reserved space,
 * never a placeholder shape), and a flat series sits on the midline instead
 * of collapsing to the floor.
 */
export function Sparkline({
  data,
  width = 200,
  height = 24,
  className,
}: SparklineProps): JSX.Element {
  // useId is unique per instance but contains ':' (invalid inside url(#…));
  // strip to the alphanumeric core, which stays unique.
  const gradId = `spark-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const n = data.length;
  if (n < 2) {
    return <svg width={width} height={height} className={className} aria-hidden="true" />;
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min;
  const stepX = width / (n - 1);
  const pad = 3;
  const usableH = height - pad * 2;

  const points = data.map((v, i) => {
    const x = i * stepX;
    const y = span === 0 ? height / 2 : pad + usableH - ((v - min) / span) * usableH;
    return [x, y] as const;
  });

  const line = points
    .map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`)
    .join(' ');
  const area = `${line} L ${width} ${height} L 0 ${height} Z`;
  const last = points[points.length - 1];

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.1" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gradId})`} stroke="none" />
      <path
        d={line}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {last ? <circle cx={last[0]} cy={last[1]} r="2.2" fill="currentColor" /> : null}
    </svg>
  );
}
