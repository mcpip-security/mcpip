import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Sidebar } from './components/shell/Sidebar';
import { TopHeader } from './components/shell/TopHeader';
import { SubTabBar } from './components/shell/SubTabBar';
import { CommandCenter } from './components/views/CommandCenter';
import { WormLedger } from './components/views/WormLedger';
import { ActivityHistory } from './components/views/ActivityHistory';
import { Analytics } from './components/views/Analytics';
import { SkillsAccess } from './components/views/SkillsAccess';
import { PrincipalDirectory } from './components/views/PrincipalDirectory';
import { AdminInfra } from './components/views/AdminInfra';
import { Developers } from './components/views/Developers';
import { DocsView } from './components/views/DocsView';
import { UsersView } from './components/views/UsersView';
import { Onboarding } from './components/Onboarding';
import {
  DEFAULT_SECTION,
  activePrimary,
  childTabs,
  componentFor,
  defaultSubtab,
  firstVisibleSection,
  primaryDefault,
  resolveNav,
  routableTabs,
  section as sectionOf,
  sectionGateState,
} from './lib/nav';
import type { ComponentKey, SectionId } from './lib/nav';
import { useGatewayLive } from './lib/useGatewayLive';
import { useCompanyConfig } from './lib/companyConfig';
import { deriveFeaturePosture, UNKNOWN_POSTURE } from './lib/posture';
import type { DeploymentStats } from './lib/api';
import { Lock } from 'lucide-react';
import { EmptyState } from './components/ui';

/** House curve — slow, expensive, never bouncy. */
const EASE = [0.32, 0.72, 0, 1] as const;

/**
 * MCPIP operator console — sidebar-driven enterprise application.
 *
 * Navigation is a flat two-level model (Section → Sub-tab, `lib/nav.ts`): the
 * sidebar lists sections only; each section's sub-tabs live in the top segmented
 * bar. A section groups sub-tabs by the operator's mental model, dispatching each
 * to the existing view component that renders it — so the flatten re-parents the
 * old tree without touching any view's internals. The shell is a fixed-height
 * frame: sidebar and header never scroll; only the content region does. Fully
 * responsive — the sidebar collapses to a slide-over drawer below `lg`, the
 * sub-tab bar scrolls horizontally. Every view runs on REAL gateway data; with no
 * node reachable it renders its honest empty/connect state — nothing is mocked.
 */
export default function App(): JSX.Element {
  const gateway = useGatewayLive();
  const company = useCompanyConfig();
  const [section, setSection] = useState<SectionId>(DEFAULT_SECTION);
  const [subtab, setSubtab] = useState<string>(defaultSubtab(DEFAULT_SECTION));
  const [mobileNav, setMobileNav] = useState(false);
  const [stats, setStats] = useState<DeploymentStats | null>(null);

  // Pull the honest deployment posture (edition/tier/feature) that resolves the
  // config-spine section gates. Fail-closed: offline / unauthorized yields the
  // UNKNOWN_POSTURE (unlicensed, every feature off), so a gated section stays
  // gated until the gateway confirms otherwise — never fabricated "on".
  useEffect(() => {
    if (gateway.mode !== 'live') {
      setStats(null);
      return;
    }
    const ctrl = new AbortController();
    void gateway.fetchDeploymentStats(ctrl.signal).then((s) => {
      if (!ctrl.signal.aborted) setStats(s);
    });
    return () => ctrl.abort();
    // Depend on the STABLE fetcher (a useCallback), not the whole `gateway`
    // object — useGatewayLive returns a fresh object every render, so `[gateway]`
    // would re-fire this effect on every render and poll stats in a tight loop.
  }, [gateway.mode, gateway.fetchDeploymentStats]);
  const posture = useMemo(
    () => (gateway.mode === 'live' ? deriveFeaturePosture(stats) : UNKNOWN_POSTURE),
    [gateway.mode, stats],
  );

  // Guard: never strand the operator on a section the active edition/posture
  // gates OUT — land on the first visible section instead of a blank frame.
  useEffect(() => {
    if (sectionGateState(sectionOf(section), posture) === 'hide') {
      const next = firstVisibleSection(posture);
      setSection(next);
      setSubtab(defaultSubtab(next));
    }
  }, [section, posture]);

  // Cross-view navigation: any panel can deep-link to a destination — e.g. an
  // offline empty state's "Connect gateway" CTA — without prop-drilling setters.
  // `resolveNav` accepts BOTH the new section ids and the legacy component-key
  // `view` values the existing dispatchers emit, so every deep-link keeps working;
  // an unresolvable link is ignored rather than misrouted.
  useEffect(() => {
    const onNavigate = (e: Event): void => {
      const detail = (e as CustomEvent<{ view?: string; subtab?: string }>).detail;
      if (!detail?.view) return;
      const target = resolveNav(detail.view, detail.subtab);
      if (!target) return;
      setSection(target.section);
      setSubtab(target.subtab);
      setMobileNav(false);
    };
    window.addEventListener('mcpip:navigate', onNavigate);
    return () => window.removeEventListener('mcpip:navigate', onNavigate);
  }, []);

  // First run: the animated setup "landing" until the operator completes it.
  if (!company.setupComplete) {
    return <Onboarding gateway={gateway} onComplete={company.save} />;
  }

  const active = sectionOf(section);
  const activeState = sectionGateState(active, posture);
  const activePrim = activePrimary(active, subtab);
  const children = childTabs(active, subtab);
  // Breadcrumb shows the routable tab's own label (the child when in a group).
  const subtabLabel = routableTabs(active).find((s) => s.id === subtab)?.label ?? activePrim.label;
  const { component, subtab: compSub } = componentFor(section, subtab);

  const selectSection = (id: SectionId): void => {
    setSection(id);
    setSubtab(defaultSubtab(id));
    setMobileNav(false);
  };
  // Selecting a PRIMARY lands on its default routable child (or itself, if childless).
  const selectPrimary = (primaryId: string): void => {
    const p = active.subtabs.find((x) => x.id === primaryId);
    if (p) setSubtab(primaryDefault(p));
    setMobileNav(false);
  };
  const selectSubtab = (id: string): void => {
    setSubtab(id);
    setMobileNav(false);
  };

  // Dispatch the resolved (section, subtab) to the existing view component that
  // owns it, handing it the component's internal sub-tab id (== the section
  // sub-tab id by construction). The view's render logic is unchanged.
  const RENDER: Record<ComponentKey, JSX.Element> = {
    command: <CommandCenter gateway={gateway} subtab={compSub} />,
    analytics: <Analytics gateway={gateway} />,
    ledger: <WormLedger gateway={gateway} subtab={compSub} />,
    history: <ActivityHistory gateway={gateway} />,
    skills: <SkillsAccess gateway={gateway} subtab={compSub} />,
    directory: <PrincipalDirectory gateway={gateway} subtab={compSub} />,
    gateway: <AdminInfra gateway={gateway} subtab={compSub} />,
    developers: <Developers gateway={gateway} subtab={compSub} />,
    docs: <DocsView gateway={gateway} subtab={compSub} />,
    users: <UsersView gateway={gateway} />,
  };

  return (
    <div className="flex h-screen overflow-hidden bg-canvas">
      <Sidebar
        section={section}
        live={gateway.mode === 'live'}
        posture={posture}
        onSelectSection={selectSection}
        mobileOpen={mobileNav}
        onCloseMobile={() => setMobileNav(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopHeader
          item={active}
          subtabLabel={subtabLabel}
          gateway={gateway}
          onOpenMobileNav={() => setMobileNav(true)}
        />

        {/* Primary sub-tab bar — the top-level destinations of the active section. */}
        {active.subtabs.length > 1 ? (
          <div className="shrink-0 border-b border-hairline bg-surface px-4 py-2 md:px-6">
            <SubTabBar subtabs={active.subtabs} active={activePrim.id} onSelect={selectPrimary} />
          </div>
        ) : null}

        <main className="flex min-h-0 flex-1 flex-col overflow-hidden px-4 py-4 md:px-6 md:py-5">
          {/* In-view secondary nav — only for sub-tabs that genuinely group several
              panels (Skills, Principals, Connection & Health, Identity & Secrets). */}
          {children.length > 0 ? (
            <div className="mb-4 shrink-0">
              <SubTabBar subtabs={children} active={subtab} onSelect={selectSubtab} />
            </div>
          ) : null}
          <motion.div
            key={`${section}:${subtab}`}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.22, ease: EASE }}
            className="min-h-0 flex-1 overflow-y-auto"
          >
            {activeState === 'lock' ? (
              <div className="panel flex h-full flex-col overflow-hidden">
                <EmptyState
                  icon={Lock}
                  title={`${active.label} is not included in this plan`}
                  detail="This section is gated by the deployment's license tier or a feature that isn't enabled on this gateway. It stays visible so the capability is discoverable — upgrade the plan or enable the backing feature to unlock it. Nothing here is fabricated: the gate reflects the gateway's own honest posture."
                />
              </div>
            ) : (
              RENDER[component]
            )}
          </motion.div>
        </main>
      </div>
    </div>
  );
}
