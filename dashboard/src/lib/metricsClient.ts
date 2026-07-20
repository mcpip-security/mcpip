/* ---------------------------------------------------------------------------
   GET /metrics client — the gateway's REAL Prometheus telemetry, parsed.

   Source of truth for every series: core/metrics.py (label discipline enforced
   by construction — labels are closed-enum literals, never tenant/agent/alias
   data, so the endpoint is safe to poll and parse client-side). Parsed series:

     mcpip_authorize_decisions_total{decision}                counter
       (coarse outcome only — the concrete deny_reason is WORM-only, never a
        label on this unauthenticated surface; see core/metrics.py)
     mcpip_authorize_latency_seconds{decision}                histogram
       (buckets 0.005 … 15.0 s + +Inf, per app-side ALL-agent traffic — the
        console's only honest fleet-wide latency source)
     mcpip_requests_shed_total{cause}                         counter
     mcpip_worm_epoch / mcpip_worm_sequence                   gauges

   Honesty rules:
     • Unreachable / non-200 / non-Prometheus body → null (never zeros). The
       content-type guard rejects an SPA fallback page answering instead of
       the gateway.
     • A series family that exists but has no samples yet (labeled collectors
       are lazy) is an honest ZERO for counters and an honest null for the
       latency quantiles (no observations → no quantile), never invented.
     • p50/p95 use the standard Prometheus bucket interpolation
       (histogram_quantile), aggregated across the `decision` label; when the
       quantile lands in +Inf the highest finite bucket bound is returned,
       exactly like PromQL.
--------------------------------------------------------------------------- */

import type { GatewayClientOptions } from './api';
import { API_BASE } from './api';

/** Cumulative authorize-decision counters since gateway start (fleet-wide). */
export interface DecisionTotals {
  total: number;
  allow: number;
  deny: number;
  staged: number;
}

/** Gateway-side latency quantiles (ms) interpolated from the histogram. */
export interface LatencyQuantiles {
  /** null when the histogram has zero observations. */
  p50Ms: number | null;
  p95Ms: number | null;
  /** Total observations across all decision labels. */
  count: number;
}

/** One successful parse of GET /metrics. Absent series stay null — never faked. */
export interface MetricsScrape {
  decisions: DecisionTotals | null;
  latency: LatencyQuantiles | null;
  /** cause → cumulative edge-shed count, or null when the family is absent. */
  shedByCause: Readonly<Record<string, number>> | null;
  /** Last sealed audit epoch (gauge), or null when absent. */
  wormEpoch: number | null;
  /** Monotonic WORM event-sequence height (gauge), or null when absent. */
  wormSequence: number | null;
}

interface Sample {
  name: string;
  labels: Readonly<Record<string, string>>;
  value: number;
}

/** Parse the label block `k1="v1",k2="v2"` (escaped per Prometheus text 0.0.4). */
function parseLabels(inner: string): Record<string, string> {
  const labels: Record<string, string> = {};
  const re = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) {
    const key = m[1];
    const raw = m[2];
    if (key === undefined || raw === undefined) {
      continue;
    }
    labels[key] = raw.replace(/\\(["\\n])/g, (_all, ch: string) => (ch === 'n' ? '\n' : ch));
  }
  return labels;
}

/** Parse a Prometheus sample value ('42.0', '1e+05', '+Inf'). NaN → dropped upstream. */
function parseValue(token: string): number {
  if (token === '+Inf') return Infinity;
  if (token === '-Inf') return -Infinity;
  return Number(token);
}

/** Parse one exposition line into a sample, or null for comments/blank/unparseable. */
function parseSampleLine(raw: string): Sample | null {
  const line = raw.trim();
  if (line === '' || line.startsWith('#')) {
    return null;
  }
  let name: string;
  let labels: Record<string, string> = {};
  let rest: string;
  const brace = line.indexOf('{');
  if (brace !== -1) {
    const close = line.indexOf('}', brace);
    if (close === -1) {
      return null;
    }
    name = line.slice(0, brace);
    labels = parseLabels(line.slice(brace + 1, close));
    rest = line.slice(close + 1).trim();
  } else {
    const sp = line.search(/\s/);
    if (sp === -1) {
      return null;
    }
    name = line.slice(0, sp);
    rest = line.slice(sp).trim();
  }
  const valueToken = rest.split(/\s+/)[0]; // an optional trailing timestamp is ignored
  if (!name || valueToken === undefined || valueToken === '') {
    return null;
  }
  const value = parseValue(valueToken);
  return Number.isNaN(value) ? null : { name, labels, value };
}

/**
 * Prometheus `histogram_quantile` over cumulative buckets (le → cumulative
 * count, already aggregated across the decision label). Returns SECONDS.
 */
function histogramQuantile(q: number, buckets: ReadonlyMap<number, number>): number | null {
  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
  if (sorted.length === 0) {
    return null;
  }
  const last = sorted[sorted.length - 1];
  const total = last === undefined ? 0 : last[1];
  if (total <= 0) {
    return null;
  }
  const rank = q * total;
  let prevLe = 0;
  let prevCum = 0;
  let highestFinite = 0;
  for (const [le, cum] of sorted) {
    if (Number.isFinite(le)) {
      highestFinite = le;
    }
    if (cum >= rank) {
      if (!Number.isFinite(le)) {
        // Quantile falls in the +Inf bucket: PromQL returns the highest finite bound.
        return highestFinite > 0 ? highestFinite : null;
      }
      if (cum === prevCum) {
        return le;
      }
      return prevLe + (le - prevLe) * ((rank - prevCum) / (cum - prevCum));
    }
    prevLe = Number.isFinite(le) ? le : prevLe;
    prevCum = cum;
  }
  return highestFinite > 0 ? highestFinite : null;
}

function roundMs(seconds: number): number {
  return Math.round(seconds * 1000 * 10) / 10;
}

/** Parse a full exposition body. Exported for reuse; scrapeMetrics wraps the fetch. */
export function parseMetricsText(body: string): MetricsScrape {
  const families = new Set<string>();
  const samples: Sample[] = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('# TYPE ')) {
      const fam = trimmed.slice('# TYPE '.length).split(/\s+/)[0];
      if (fam !== undefined && fam !== '') {
        families.add(fam);
      }
      continue;
    }
    const sample = parseSampleLine(line);
    if (sample !== null) {
      samples.push(sample);
    }
  }

  let decisionsSeen = families.has('mcpip_authorize_decisions_total');
  const decisions: { total: number; allow: number; deny: number; staged: number } = {
    total: 0,
    allow: 0,
    deny: 0,
    staged: 0,
  };

  let latencySeen = families.has('mcpip_authorize_latency_seconds');
  const bucketByLe = new Map<number, number>(); // le → cumulative count, summed across decision labels
  let latencyCount = 0;

  let shedSeen = families.has('mcpip_requests_shed_total');
  const shedByCause: Record<string, number> = {};

  let wormEpoch: number | null = null;
  let wormSequence: number | null = null;

  for (const s of samples) {
    if (s.name === 'mcpip_authorize_decisions_total') {
      decisionsSeen = true;
      decisions.total += s.value;
      const d = s.labels['decision'];
      if (d === 'allow') decisions.allow += s.value;
      else if (d === 'deny') decisions.deny += s.value;
      else if (d === 'staged') decisions.staged += s.value;
    } else if (s.name === 'mcpip_authorize_latency_seconds_bucket') {
      latencySeen = true;
      const leRaw = s.labels['le'];
      if (leRaw !== undefined) {
        const le = leRaw === '+Inf' ? Infinity : Number(leRaw);
        if (!Number.isNaN(le)) {
          bucketByLe.set(le, (bucketByLe.get(le) ?? 0) + s.value);
        }
      }
    } else if (s.name === 'mcpip_authorize_latency_seconds_count') {
      latencySeen = true;
      latencyCount += s.value;
    } else if (s.name === 'mcpip_requests_shed_total') {
      shedSeen = true;
      const cause = s.labels['cause'];
      if (cause !== undefined) {
        shedByCause[cause] = (shedByCause[cause] ?? 0) + s.value;
      }
    } else if (s.name === 'mcpip_worm_epoch') {
      wormEpoch = s.value;
    } else if (s.name === 'mcpip_worm_sequence') {
      wormSequence = s.value;
    }
  }

  const p50 = histogramQuantile(0.5, bucketByLe);
  const p95 = histogramQuantile(0.95, bucketByLe);
  return {
    decisions: decisionsSeen ? decisions : null,
    latency: latencySeen
      ? {
          p50Ms: p50 === null ? null : roundMs(p50),
          p95Ms: p95 === null ? null : roundMs(p95),
          count: latencyCount,
        }
      : null,
    shedByCause: shedSeen ? shedByCause : null,
    wormEpoch,
    wormSequence,
  };
}

/**
 * GET /metrics — fetch + parse the gateway's Prometheus exposition (text
 * 0.0.4). Open endpoint (no JWT). Fails soft: returns null when unreachable,
 * non-200, or the body is not a Prometheus exposition (content-type guard —
 * an SPA fallback page must never parse as telemetry). Never throws.
 */
export async function scrapeMetrics(opts: GatewayClientOptions = {}): Promise<MetricsScrape | null> {
  try {
    const base = opts.base ?? API_BASE;
    const init: RequestInit = { method: 'GET' };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${base}/metrics`, init);
    if (!res.ok) {
      return null;
    }
    const contentType = res.headers.get('content-type') ?? '';
    if (!contentType.includes('text/plain')) {
      return null;
    }
    return parseMetricsText(await res.text());
  } catch {
    return null;
  }
}
