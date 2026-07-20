/**
 * Parses the repository CHANGELOG.md (Keep-a-Changelog format, injected into the
 * bundle as `__CHANGELOG__` by Vite) into structured release entries the Docs →
 * Release Notes view renders. Pure + deterministic — no I/O, no React — so it is
 * trivially testable and the same text the repo ships is the same text shown.
 *
 * Recognized shape:
 *   ## [3.0.0] - 2026-07-17        → version "3.0.0", date "2026-07-17"
 *   ## [Unreleased]                → version "Unreleased", isUnreleased=true
 *   **Bold intro paragraph.**      → summary (leading non-heading prose)
 *   ### Added                      → a section heading
 *   - item                         → an item under the current section
 */

export interface ReleaseSection {
  heading: string;
  items: string[];
}

export interface ReleaseEntry {
  /** "3.0.0", or "Unreleased". */
  version: string;
  /** ISO date string as written, or null (Unreleased / undated). */
  date: string | null;
  isUnreleased: boolean;
  /** Leading prose before the first `###` heading, lightly de-marked. Null if none. */
  summary: string | null;
  /** `### Heading` groups with their `-`/`*` bullet items. */
  sections: ReleaseSection[];
}

/** Strip the inline markdown we don't render structurally — bold/italic/code
 * markers and blockquote carets — leaving readable text. Links become their label. */
export function stripInlineMarkdown(line: string): string {
  return line
    .replace(/^>\s?/, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/(^|[^*])\*([^*]+)\*/g, '$1$2')
    .trim();
}

/** Parse the version header line body (the text after `## `). Returns null if it
 * is not a version header (so the `# Changelog` preamble block is skipped). */
function parseHeader(line: string): { version: string; date: string | null } | null {
  const m = line.match(/^\[([^\]]+)\]\s*(?:-\s*(.+))?$/);
  if (!m) return null;
  const version = m[1]!.trim();
  const date = m[2] ? m[2].trim() : null;
  return { version, date };
}

/**
 * Parse the full changelog into entries, newest first (source order). Blocks that
 * are not `## [version]` headers (the file preamble) are ignored. An empty or
 * absent changelog yields `[]` — the caller renders an honest empty state.
 */
export function parseChangelog(raw: string): ReleaseEntry[] {
  if (!raw || !raw.trim()) return [];
  // Split on level-2 headings while keeping the heading text. Leading "## " on the
  // very first line (rare) is handled by the padding newline.
  const blocks = `\n${raw}`.split(/\n## /).slice(1);
  const entries: ReleaseEntry[] = [];

  for (const block of blocks) {
    const lines = block.split('\n');
    const header = parseHeader(lines[0]!.trim());
    if (!header) continue;

    const summaryParts: string[] = [];
    const sections: ReleaseSection[] = [];
    let current: ReleaseSection | null = null;

    for (const rawLine of lines.slice(1)) {
      const line = rawLine.trimEnd();
      if (!line.trim()) continue;
      const heading = line.match(/^###\s+(.*)$/);
      if (heading) {
        current = { heading: heading[1]!.trim(), items: [] };
        sections.push(current);
        continue;
      }
      const bullet = line.match(/^\s*[-*]\s+(.*)$/);
      if (bullet) {
        const text = stripInlineMarkdown(bullet[1]!);
        if (!text) continue;
        if (current) current.items.push(text);
        else {
          // A top-level bullet before any `###` — treat as its own group so it
          // is never dropped.
          current = { heading: '', items: [text] };
          sections.push(current);
        }
        continue;
      }
      // Prose line: part of the summary only while we're still above the first
      // `###` section AND before any bullets (avoids swallowing note paragraphs).
      if (sections.length === 0) summaryParts.push(stripInlineMarkdown(line));
    }

    entries.push({
      version: header.version,
      date: header.date,
      isUnreleased: header.version.toLowerCase() === 'unreleased',
      summary: summaryParts.length ? summaryParts.join(' ') : null,
      sections,
    });
  }

  return entries;
}

/** The parsed release history from the bundled changelog. Empty array if absent. */
export function loadReleaseHistory(): ReleaseEntry[] {
  const raw = typeof __CHANGELOG__ === 'string' ? __CHANGELOG__ : '';
  return parseChangelog(raw);
}
