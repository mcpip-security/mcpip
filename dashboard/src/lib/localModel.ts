/* ---------------------------------------------------------------------------
   Local-model workspace draft — the SLIM, SELF-HOSTED inference contract for the
   packaged workspace model. A small open-source model turns a company brief into a
   WorkspacePlan, entirely inside the perimeter.

   Why local-only: the brief describes the customer's own company — it must never
   leave the boundary. So MCPIP never calls a hosted/cloud model. Instead the operator
   runs a small open-source model (e.g. Ollama `llama3.2:1b`, or any OpenAI-compatible
   endpoint — llama.cpp, vLLM, LM Studio) called directly, client-side. The gateway
   stays inference-free (a hard invariant).

   The model only DRAFTS. Its output is normalized and then re-validated by the gateway's
   authoritative rules and reviewed by a human before anything applies — a small model
   that returns a rough plan is caught by the same guardrail as a hand-typed one.

   Contract of record: SYSTEM_PROMPT here is the canonical prompt the packaged model is
   trained against — scripts/gen_workspace_dataset.py and tests/test_workspace_model_assets.py
   bind to it, so this file is the single source of truth for that contract. Workspace
   generation itself now lives in the setup/onboarding flow (a deterministic, offline
   starter draft — see lib/starterKit.ts + services/workspace_plan.py); this drafting
   client is retained for the packaged model toolchain, not wired into a console panel.
--------------------------------------------------------------------------- */

import type { WorkspacePlan, PlanSkill } from './api';

const SETTINGS_KEY = 'mcpip.workspace.model.v1';

export interface ModelSettings {
  /** OpenAI-compatible base URL. Ollama: http://localhost:11434/v1 */
  endpoint: string;
  /** Model tag, e.g. llama3.2:1b, qwen2.5:1.5b, phi3:mini. */
  model: string;
  /** When false, the panel uses the deterministic draft only. */
  enabled: boolean;
}

export const DEFAULT_MODEL_SETTINGS: ModelSettings = {
  endpoint: 'http://localhost:11434/v1',
  model: 'llama3.2:1b',
  enabled: true,
};

export function loadModelSettings(): ModelSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_MODEL_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<ModelSettings>;
    return {
      endpoint: typeof parsed.endpoint === 'string' && parsed.endpoint ? parsed.endpoint : DEFAULT_MODEL_SETTINGS.endpoint,
      model: typeof parsed.model === 'string' && parsed.model ? parsed.model : DEFAULT_MODEL_SETTINGS.model,
      enabled: parsed.enabled !== false,
    };
  } catch {
    return { ...DEFAULT_MODEL_SETTINGS };
  }
}

export function saveModelSettings(s: ModelSettings): void {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* non-fatal */
  }
}

// The contract asked of the model. Kept tight so a 1B model can satisfy it.
const SYSTEM_PROMPT = `You design a workspace for a zero-trust security gateway.
Given a company description, output ONLY a JSON object (no prose, no markdown) of this exact shape:
{"teams":["Team Name", ...],
 "skills":[{"alias":"skill_<team>_<action>","target":"rest.<team>.<action>","risk_tier":"auto"|"pin_required","classification":"unclassified"|"restricted"}]}
Rules:
- alias: lowercase letters, digits, underscores only; start with "skill_".
- Reads/queries: risk_tier "auto", classification "unclassified".
- Writes/mutations (create/update/delete/post/approve/deploy): risk_tier "pin_required".
- Sensitive-domain writes (finance, payroll, hr, security, legal, health): classification "restricted" AND risk_tier "pin_required".
- Never use classification "restricted" with risk_tier "auto".
- 2-4 skills per team; at most 24 skills total. Output JSON only.`;

const _ALIAS_OK = /^[a-z0-9_]+$/;

function _slugAlias(s: string): string {
  const cleaned = s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return cleaned.startsWith('skill_') ? cleaned : `skill_${cleaned}`;
}

/**
 * Normalize a raw model object into a valid WorkspacePlan. Pure + defensive: it coerces
 * loose small-model output into policy-safe shape (valid alias charset, risk/classification
 * enums, restricted⇒PIN), drops anything unrecoverable, and caps the size. The gateway
 * still re-validates authoritatively — this only raises the odds a draft passes cleanly.
 */
export function normalizePlan(raw: unknown, company: string, tenant: string): WorkspacePlan {
  const obj = (raw && typeof raw === 'object') ? (raw as Record<string, unknown>) : {};
  const rawTeams = Array.isArray(obj.teams) ? obj.teams : [];
  const teams = rawTeams
    .filter((t): t is string => typeof t === 'string' && t.trim().length > 0)
    .slice(0, 24)
    .map((label) => ({ id: `team-${_slugAlias(label).replace(/^skill_/, '')}`, label: label.trim().slice(0, 120), compartment: '' }));

  const rawSkills = Array.isArray(obj.skills) ? obj.skills : [];
  const seen = new Set<string>();
  const skills: PlanSkill[] = [];
  for (const s of rawSkills) {
    if (!s || typeof s !== 'object') continue;
    const r = s as Record<string, unknown>;
    let alias = typeof r.alias === 'string' ? r.alias.trim().toLowerCase() : '';
    if (!alias) continue;
    if (!_ALIAS_OK.test(alias)) alias = _slugAlias(alias);
    if (!alias.startsWith('skill_') || seen.has(alias)) continue;
    let risk = r.risk_tier === 'pin_required' ? 'pin_required' : 'auto';
    let classification = r.classification === 'restricted' ? 'restricted' : 'unclassified';
    // A restricted skill must be PIN-gated (the sender-constraint policy) — coerce, never drop.
    if (classification === 'restricted') risk = 'pin_required';
    const target = typeof r.target === 'string' && r.target.trim() && !r.target.includes('\n')
      ? r.target.trim().slice(0, 512)
      : `rest.${alias.replace(/^skill_/, '').replace(/_/g, '.')}`;
    seen.add(alias);
    skills.push({ alias, target, risk_tier: risk, classification });
    if (skills.length >= 64) break;
  }

  const tn = (tenant || 'my-company').trim();
  const label = (company || 'My Company').trim();
  return { company: label, tenant: tn, org_units: [{ id: tn, label, tenant: tn, teams }], skills };
}

/** Pull the first JSON object out of a model completion (handles ```json fences / prose). */
export function extractJson(text: string): unknown | null {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced && fenced[1] ? fenced[1] : text;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

export interface LocalDraftResult {
  plan: WorkspacePlan | null;
  error: string | null;
}

/**
 * Draft a WorkspacePlan by calling the operator's local, OpenAI-compatible model. Returns
 * {plan, error}: on any transport/parse failure `plan` is null and `error` explains it, so
 * the caller can fall back to the deterministic draft and show a clear message.
 */
export async function draftWithLocalModel(
  settings: ModelSettings,
  brief: string,
  company: string,
  tenant: string,
  signal?: AbortSignal,
): Promise<LocalDraftResult> {
  const base = settings.endpoint.replace(/\/+$/, '');
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 60_000);
  const onAbort = (): void => controller.abort();
  signal?.addEventListener('abort', onAbort);
  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: settings.model,
        temperature: 0.2,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: `Company: ${company || 'a company'}\nBrief: ${brief || 'a small company'}` },
        ],
        // Honored by Ollama / many OpenAI-compatible servers; ignored gracefully by others.
        response_format: { type: 'json_object' },
        stream: false,
      }),
    });
    if (!res.ok) {
      return { plan: null, error: `model endpoint returned HTTP ${res.status}` };
    }
    const body = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const content = body.choices?.[0]?.message?.content ?? '';
    if (!content) return { plan: null, error: 'model returned an empty response' };
    const parsed = extractJson(content);
    if (parsed === null) return { plan: null, error: 'model did not return valid JSON' };
    const plan = normalizePlan(parsed, company, tenant);
    if (plan.skills.length === 0) return { plan: null, error: 'model produced no usable skills' };
    return { plan, error: null };
  } catch (e) {
    const msg = e instanceof DOMException && e.name === 'AbortError' ? 'model request timed out' : 'could not reach the model endpoint';
    return { plan: null, error: msg };
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}
