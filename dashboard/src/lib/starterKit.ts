/* ---------------------------------------------------------------------------
   Starter-kit generator — "describe your company, get a starting set of tools".

   Standing up a real deployment by hand is tedious: a finance company alone has a
   dozen disciplines. This turns a free-text description ("a fintech with engineering,
   finance and support teams") into a SENSIBLE STARTER — teams (compartments) and a
   base set of skills per team — that the operator then approves and edits. It is a
   deterministic mapping over a curated base library modelled on MCPIP's own reference
   catalog (an overview read every company gets, team-scoped reads, and a guarded
   write), NOT a call to any external service — so it works offline and never invents
   a real target. The operator improves it from here; nothing is locked in.

   Naming convention: skill_{platform-or-domain}_{tool} — never a _read/_write alias
   suffix. The access level is the STRUCTURED `access` field ('read'/'write'), paired
   with a human `service` label; both are advisory display metadata the permission
   table groups by (service listed once, Read/Write as controls).
--------------------------------------------------------------------------- */

export interface StarterSkill {
  alias: string;
  /** Team name this skill is scoped to, or 'company' for a company-wide skill. */
  team: string;
  description: string;
  risk: 'auto' | 'pin_required';
  /** Human service label the permission table groups by (e.g. 'General ledger'). */
  service: string;
  /** Structured access level — display metadata, decoupled from the alias name. */
  access: 'read' | 'write';
  /** A plausible internal target the operator will repoint at their real system. */
  target: string;
}

export interface Starter {
  teams: string[];
  skills: StarterSkill[];
}

interface TeamArchetype {
  /** Canonical display name. */
  name: string;
  /** Keywords (lowercase) that select this team from the description. */
  match: string[];
  /** Skills seeded for this team: [tool suffix, description, risk, service, access]. */
  skills: Array<
    [
      suffix: string,
      description: string,
      risk: 'auto' | 'pin_required',
      service: string,
      access: 'read' | 'write',
    ]
  >;
}

// Base library — modelled on the reference catalog (read / team-read / guarded write).
const ARCHETYPES: TeamArchetype[] = [
  {
    name: 'Engineering',
    match: ['engineer', 'eng', 'dev', 'platform', 'infra', 'sre', 'devops', 'backend', 'frontend'],
    skills: [
      ['roadmap', 'Read the engineering roadmap', 'auto', 'Engineering roadmap', 'read'],
      ['deploy_status', 'Read deployment / build status', 'auto', 'Deployments', 'read'],
      ['prod_deploy', 'Trigger a production deploy', 'pin_required', 'Deployments', 'write'],
    ],
  },
  {
    name: 'Finance',
    match: ['finance', 'financial', 'account', 'payroll', 'treasury', 'billing', 'fintech', 'bank', 'wage'],
    skills: [
      ['wage_sheet', 'Read the payroll / wage sheet', 'auto', 'Payroll wage sheet', 'read'],
      ['ledger', 'Read the general ledger', 'auto', 'General ledger', 'read'],
      ['ledger_post', 'Post a journal entry to the ledger', 'pin_required', 'General ledger', 'write'],
      ['wire_transfer', 'Create a wire transfer', 'pin_required', 'Wire transfers', 'write'],
    ],
  },
  {
    name: 'Support',
    match: ['support', 'success', 'service', 'helpdesk', 'customer'],
    skills: [
      ['ticket_lookup', 'Look up a support ticket', 'auto', 'Support tickets', 'read'],
      ['customer_lookup', 'Look up a customer record', 'auto', 'Customer records', 'read'],
      ['refund_issue', 'Issue a customer refund', 'pin_required', 'Refunds', 'write'],
    ],
  },
  {
    name: 'Sales',
    match: ['sales', 'revenue', 'account executive', 'crm', 'pipeline'],
    skills: [
      ['pipeline', 'Read the sales pipeline', 'auto', 'Sales pipeline', 'read'],
      ['quote_create', 'Create a customer quote', 'auto', 'Quotes', 'write'],
      ['discount_approve', 'Approve a non-standard discount', 'pin_required', 'Discounts', 'write'],
    ],
  },
  {
    name: 'People',
    match: ['hr', 'people', 'recruit', 'talent', 'human resources'],
    skills: [
      ['directory', 'Read the employee directory', 'auto', 'Employee directory', 'read'],
      ['compensation', 'Read a compensation record', 'auto', 'Compensation records', 'read'],
      ['offer_send', 'Send an employment offer', 'pin_required', 'Employment offers', 'write'],
    ],
  },
  {
    name: 'Data',
    match: ['data', 'analytics', 'ml', 'ai', 'science', 'bi', 'warehouse'],
    skills: [
      ['dashboard', 'Read an analytics dashboard', 'auto', 'Analytics dashboards', 'read'],
      ['query_run', 'Run a warehouse query', 'auto', 'Warehouse queries', 'read'],
      ['pii_export', 'Export a PII dataset', 'pin_required', 'PII datasets', 'read'],
    ],
  },
  {
    name: 'Security',
    match: ['security', 'infosec', 'soc', 'trust', 'compliance', 'grc'],
    skills: [
      ['alerts', 'Read security alerts', 'auto', 'Security alerts', 'read'],
      ['audit_export', 'Export an audit log', 'auto', 'Audit logs', 'read'],
      ['access_revoke', 'Revoke a principal / credential', 'pin_required', 'Access control', 'write'],
    ],
  },
  {
    name: 'Operations',
    match: ['ops', 'operation', 'it', 'logistics', 'supply', 'facilities'],
    skills: [
      ['status', 'Read operational status', 'auto', 'Operational status', 'read'],
      ['inventory', 'Read inventory levels', 'auto', 'Inventory', 'read'],
      ['order_adjust', 'Adjust a fulfillment order', 'pin_required', 'Fulfillment orders', 'write'],
    ],
  },
];

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

/**
 * Turn a free-text company description into a starter set of teams + skills. Always
 * returns a usable general starter — if nothing matches, it seeds Engineering /
 * Finance / Operations so the operator has a concrete thing to edit.
 */
export function generateStarter(description: string): Starter {
  const text = ` ${description.toLowerCase()} `;
  const matched: TeamArchetype[] = ARCHETYPES.filter((a) =>
    a.match.some((kw) => text.includes(kw)),
  );

  const chosen = matched.length > 0
    ? matched
    : ARCHETYPES.filter((a) => ['Engineering', 'Finance', 'Operations'].includes(a.name));

  const skills: StarterSkill[] = [
    {
      alias: 'skill_company_overview',
      team: 'company',
      description: 'Read the company overview',
      risk: 'auto',
      service: 'Company overview',
      access: 'read',
      target: 'rest.company.overview.get',
    },
    // Default data tool for EVERY company: read-only access to the shared data
    // lake — the useful-out-of-the-box skill all teams get, regardless of brief.
    {
      alias: 'skill_data_lake',
      team: 'company',
      description: 'Query the company data lake (read-only)',
      risk: 'auto',
      service: 'Data lake',
      access: 'read',
      target: 'rest.datalake.query.get',
    },
  ];
  for (const team of chosen) {
    const teamSlug = slug(team.name);
    for (const [suffix, desc, risk, service, access] of team.skills) {
      skills.push({
        alias: `skill_${teamSlug}_${suffix}`,
        team: team.name,
        description: desc,
        risk,
        service,
        access,
        target: `rest.${teamSlug}.${suffix.replace(/_/g, '.')}`,
      });
    }
  }

  return { teams: chosen.map((t) => t.name), skills };
}
