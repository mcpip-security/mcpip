import { LayoutDashboard, ShieldCheck, Settings, CodeXml } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import {
  ALL_EDITIONS,
  EDITION,
  sectionState,
  type FeaturePosture,
  type GateState,
  type SectionGate,
} from './consoleConfig';

/**
 * Flat operator-console navigation: **Section → Sub-tab**, collapsed from the
 * previous 8-section / 26-sub-tab fan-out to **4 one-word sections** (17 primary
 * tabs, 24 routable destinations counting in-view children).
 *
 * The old shape re-exposed a single view component's internal switch as top-bar
 * navigation (AdminInfra was reached from 7 sub-tabs across 3 sections; the skill
 * view from 4; the directory from 3), which the operator had to mentally
 * reconcile. Here each section is one of the operator's four jobs —
 *   • **Monitor**    — see that agents are governed (live flow + audit proof)
 *   • **Governance** — control who and what is allowed
 *   • **Settings**   — run and administer the gateway (section id stays
 *                      'gateway' so every existing deep-link keeps resolving)
 *   • **Developers** — connect your agents
 * — every category label is ONE word, ordered by the operator's flow (watch →
 * search → analyze → prove; connect → identity → company → updates → license).
 * Sub-tabs that genuinely aggregate several panels (Skills, Principals,
 * Connection, Identity) carry `children`: an in-view secondary segmented nav,
 * NOT another top-bar level. Every child still dispatches to the existing view
 * component (unchanged) via its `component` key, so the collapse re-parents
 * without touching a single view's render logic.
 */

/** The existing view components a sub-tab can dispatch to (render logic unchanged). */
export type ComponentKey =
  | 'command'
  | 'analytics'
  | 'ledger'
  | 'history'
  | 'skills'
  | 'directory'
  | 'gateway'
  | 'developers'
  | 'docs'
  | 'users';

/** The flat top-level sections — the operator's four jobs. */
export type SectionId = 'monitor' | 'governance' | 'gateway' | 'developers';

/** A tab as the segmented bars need it (id + label). */
export interface SubTab {
  id: string;
  label: string;
}

/** A routable child of a primary sub-tab. Its `id` is the SAME id the target
 *  component expects as its internal sub-tab, so dispatch is a direct pass-through. */
export interface ChildTab extends SubTab {
  component: ComponentKey;
}

/**
 * A top-bar (primary) sub-tab. When `children` is present the primary is a GROUP:
 * it is never routed to directly — its children are the routable destinations and
 * render as an in-view secondary nav. When `children` is absent the primary IS the
 * routable destination, and its `id` is the component's internal sub-tab id.
 */
export interface PrimaryTab extends SubTab {
  component: ComponentKey;
  children?: ReadonlyArray<ChildTab>;
}

export interface Section {
  id: SectionId;
  label: string;
  icon: LucideIcon;
  /** Ordered; the first routable tab is the default when the section is opened. */
  subtabs: ReadonlyArray<PrimaryTab>;
  /**
   * The three-layer visibility gate (edition · tier · live posture) from the
   * config spine. Every currently-shipped section is available in every edition
   * and at every tier (honest: we ship them all today), so the gate is a no-op
   * until one declares `minTier`/`requires`/a narrower `editions`.
   */
  gate: SectionGate;
}

/** The honest default gate: shipped in every edition, no tier/feature floor. */
const ALWAYS: SectionGate = { editions: ALL_EDITIONS, whenGated: 'hide' };

/**
 * The flat IA. Four one-word sections. Nothing is dropped — the former Chain
 * Integrity, Cloud IAM, Secret Vault, Health, and License sub-tabs live on as
 * children or folded panels; every view component is still reachable.
 */
export const SECTIONS: ReadonlyArray<Section> = [
  {
    id: 'monitor',
    label: 'Monitor',
    icon: LayoutDashboard,
    subtabs: [
      { id: 'overview', label: 'Live', component: 'command' },
      { id: 'history', label: 'History', component: 'history' },
      { id: 'analytics', label: 'Analytics', component: 'analytics' },
      {
        id: 'ledger',
        label: 'Audit log',
        component: 'ledger',
        children: [
          { id: 'events', label: 'Events', component: 'ledger' },
          { id: 'integrity', label: 'Integrity', component: 'ledger' },
        ],
      },
    ],
    gate: ALWAYS,
  },
  {
    id: 'governance',
    label: 'Governance',
    icon: ShieldCheck,
    subtabs: [
      {
        id: 'skills',
        label: 'Skills',
        component: 'skills',
        children: [
          { id: 'registry', label: 'Registry', component: 'skills' },
          { id: 'canaries', label: 'Tripwires', component: 'skills' },
          { id: 'separation', label: 'Separation', component: 'skills' },
          { id: 'community', label: 'Community', component: 'skills' },
        ],
      },
      {
        id: 'principals',
        label: 'Principals',
        component: 'directory',
        children: [
          { id: 'hierarchy', label: 'Hierarchy', component: 'directory' },
          { id: 'licensing', label: 'Licensing', component: 'directory' },
          { id: 'entitlements', label: 'Entitlements', component: 'directory' },
        ],
      },
      { id: 'users', label: 'Users', component: 'users' },
      { id: 'policy', label: 'Policy', component: 'gateway' },
    ],
    gate: ALWAYS,
  },
  {
    id: 'gateway',
    label: 'Settings',
    icon: Settings,
    subtabs: [
      {
        id: 'connection-health',
        label: 'Connection',
        component: 'gateway',
        children: [
          { id: 'connection', label: 'Connection', component: 'gateway' },
          { id: 'health', label: 'Health', component: 'gateway' },
        ],
      },
      {
        id: 'identity-secrets',
        label: 'Identity',
        component: 'gateway',
        children: [
          { id: 'cloud', label: 'Cloud', component: 'gateway' },
          { id: 'vault', label: 'Vault', component: 'gateway' },
          { id: 'security', label: '2FA', component: 'gateway' },
        ],
      },
      { id: 'company', label: 'Company', component: 'gateway' },
      { id: 'updates', label: 'Updates', component: 'gateway' },
      { id: 'software', label: 'License', component: 'gateway' },
    ],
    gate: ALWAYS,
  },
  {
    id: 'developers',
    label: 'Developers',
    icon: CodeXml,
    subtabs: [
      {
        id: 'connect-group',
        label: 'Connect',
        component: 'developers',
        children: [
          { id: 'connect', label: 'Connect', component: 'developers' },
          { id: 'protocol', label: 'Protocol', component: 'developers' },
        ],
      },
      { id: 'console', label: 'Console', component: 'developers' },
      { id: 'probe', label: 'Probe', component: 'command' },
      { id: 'releases', label: 'Releases', component: 'docs' },
    ],
    gate: ALWAYS,
  },
];

/** The default landing section. */
export const DEFAULT_SECTION: SectionId = 'monitor';

export function section(id: SectionId): Section {
  return SECTIONS.find((s) => s.id === id) ?? SECTIONS[0]!;
}

/** The routable tabs of a section — childless primaries plus every child. A primary
 *  WITH children is a group (never routed to directly); its children are routable. */
export function routableTabs(sec: Section): ReadonlyArray<ChildTab> {
  return sec.subtabs.flatMap((p) => (p.children ? p.children : [{ id: p.id, label: p.label, component: p.component }]));
}

/** The default (first routable) sub-tab id for a section. */
export function defaultSubtab(id: SectionId): string {
  return routableTabs(section(id))[0]!.id;
}

/** The primary a routable sub-tab belongs to (for highlighting + the child nav). */
export function activePrimary(sec: Section, subtabId: string): PrimaryTab {
  return (
    sec.subtabs.find((p) =>
      p.children ? p.children.some((c) => c.id === subtabId) : p.id === subtabId,
    ) ?? sec.subtabs[0]!
  );
}

/** The default routable id when a primary is selected in the top bar. */
export function primaryDefault(p: PrimaryTab): string {
  return p.children ? p.children[0]!.id : p.id;
}

/** The in-view secondary nav for the active sub-tab — the active primary's children
 *  when it has more than one; otherwise empty (no secondary bar rendered). */
export function childTabs(sec: Section, subtabId: string): ReadonlyArray<ChildTab> {
  const p = activePrimary(sec, subtabId);
  return p.children && p.children.length > 1 ? p.children : [];
}

/** Which component renders (section, subtab), and the sub-tab id to hand it. */
export function componentFor(
  sectionId: SectionId,
  subtabId: string,
): { component: ComponentKey; subtab: string } {
  const tabs = routableTabs(section(sectionId));
  const t = tabs.find((x) => x.id === subtabId) ?? tabs[0]!;
  return { component: t.component, subtab: t.id };
}

/**
 * Resolve a deep-link `{view, subtab}` to a concrete `(section, subtab)`. Accepts
 * BOTH new section ids AND the legacy component-key `view` values existing
 * `mcpip:navigate` dispatchers emit (e.g. `{view:'gateway', subtab:'connection'}`,
 * `{view:'directory', subtab:'hierarchy'}`, `{view:'docs', subtab:'releases'}`), so
 * nothing that deep-links today breaks. Returns null for an unresolvable link.
 *
 * Order matters where a name is both a section id and a component key (`gateway`):
 * an exact section+subtab match wins, then a component+subtab match, then the
 * section/component first-tab fallbacks.
 */
export function resolveNav(
  view: string,
  subtab?: string,
): { section: SectionId; subtab: string } | null {
  const asSection = SECTIONS.find((s) => s.id === view);
  // A: exact section + valid routable subtab
  if (asSection && subtab && routableTabs(asSection).some((t) => t.id === subtab)) {
    return { section: asSection.id, subtab };
  }
  // B: component-key view + exact subtab
  if (subtab) {
    for (const s of SECTIONS) {
      const t = routableTabs(s).find((x) => x.component === view && x.id === subtab);
      if (t) return { section: s.id, subtab: t.id };
    }
  }
  // C: section id, subtab absent/invalid → first routable tab
  if (asSection) return { section: asSection.id, subtab: routableTabs(asSection)[0]!.id };
  // D: component-key view, subtab absent/invalid → first section hosting it
  for (const s of SECTIONS) {
    const t = routableTabs(s).find((x) => x.component === view);
    if (t) return { section: s.id, subtab: t.id };
  }
  return null;
}

/**
 * The gate state (`show` | `lock` | `hide`) of ONE section under the active build
 * edition and the live feature posture. Fail-closed: an unknown posture treats
 * every feature as off and every tier as unlicensed.
 */
export function sectionGateState(sec: Section, posture: FeaturePosture): GateState {
  return sectionState(sec.gate, EDITION, posture);
}

/** The sections VISIBLE (not `hide`) in this edition under `posture`, in order. */
export function visibleSections(posture: FeaturePosture): ReadonlyArray<Section> {
  return SECTIONS.filter((s) => sectionGateState(s, posture) !== 'hide');
}

/** The first non-hidden section — the safe landing when the active one is gated out. */
export function firstVisibleSection(posture: FeaturePosture): SectionId {
  return visibleSections(posture)[0]?.id ?? DEFAULT_SECTION;
}
