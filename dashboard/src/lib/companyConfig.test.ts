import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  clearCompanyConfig,
  companyConfigSnapshot,
  EMPTY_COMPANY,
  saveCompanyConfig,
  subscribeCompanyConfig,
  type CompanyConfig,
} from './companyConfig';

/**
 * Regression: the "components don't synchronize" bug. useCompanyConfig() is read
 * by ~9 console components; before the fix each held its own useState and the only
 * cross-instance signal was the `storage` event — which never fires in the tab that
 * made the write. So editing the company in one panel left every other panel stale
 * until a full reload. The fix routes every instance through one external store
 * (subscribe + getSnapshot, consumed via useSyncExternalStore). These tests assert
 * that store contract directly: one write notifies ALL live subscribers in the same
 * tab and the shared snapshot updates. If the pub/sub is dropped, they fail.
 */

const company = (name: string): CompanyConfig => ({
  ...EMPTY_COMPANY,
  name,
  tenant: name.toLowerCase(),
  setupComplete: true,
});

afterEach(() => {
  clearCompanyConfig();
});

describe('companyConfig external store', () => {
  it('notifies EVERY same-tab subscriber on a single write', () => {
    const a = vi.fn();
    const b = vi.fn();
    const unsubA = subscribeCompanyConfig(a);
    const unsubB = subscribeCompanyConfig(b);

    saveCompanyConfig(company('Acme'));

    // Both instances hear the same write — no reload, no cross-tab `storage` event.
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    // And they read the SAME fresh snapshot.
    expect(companyConfigSnapshot()?.name).toBe('Acme');

    unsubA();
    unsubB();
  });

  it('stops notifying after unsubscribe, and clear resets + notifies', () => {
    const live = vi.fn();
    const gone = vi.fn();
    subscribeCompanyConfig(live);
    const unsub = subscribeCompanyConfig(gone);
    unsub();

    saveCompanyConfig(company('Beta'));
    expect(live).toHaveBeenCalledTimes(1);
    expect(gone).not.toHaveBeenCalled();

    clearCompanyConfig();
    expect(live).toHaveBeenCalledTimes(2);
    expect(companyConfigSnapshot()).toBeNull();
  });
});
