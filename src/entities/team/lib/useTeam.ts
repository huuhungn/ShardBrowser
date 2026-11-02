import { create } from "zustand";
import { t } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";
import { teamProfilesStatus, teamStatus } from "../model/api";
import type { TeamProfilesStatus, TeamStatus } from "../model/types";

/**
 * Fleet status, fetched once and shared.
 *
 * Every profile row asks whether team actions apply, so this is cached rather
 * than invoked per row. `refresh` is called after enrolment changes it.
 */
type TeamState = {
  status: TeamStatus | null;
  loaded: boolean;
  refresh: () => Promise<void>;
};

export const useTeam = create<TeamState>((set) => ({
  status: null,
  loaded: false,
  refresh: async () => {
    try {
      set({ status: await teamStatus(), loaded: true });
    } catch {
      // No team configured is the normal case, not an error worth a toast.
      set({ status: null, loaded: true });
    }
  },
}));

/** True when this device is enrolled and able to sync profiles. */
export const canSyncProfiles = (s: TeamState) =>
  !!s.status?.is_enrolled && !!s.status?.can_sync;

/**
 * Why sync is unavailable, or undefined when it works.
 *
 * A device enrolled before sync existed reports `is_enrolled` but not
 * `can_sync`. Hiding the menu entry silently leaves the user with no way to
 * discover that re-enrolling is what fixes it.
 */
export const syncBlockedReason = (s: TeamState): string | undefined => {
  if (!s.loaded) return t("team.syncChecking");
  if (!s.status?.is_enrolled) return undefined;
  if (!s.status.can_sync) {
    return t("team.syncEnrolledBeforeSync");
  }
  return undefined;
};

/**
 * Every binding's sync state and every custodian alert, for the Team page.
 *
 * Read on mount and on a manual refresh only: the backend opens the team
 * database inline for each call, so this is never polled.
 */
type TeamProfilesState = {
  status: TeamProfilesStatus | null;
  error: string | null;
  busy: boolean;
  refresh: () => Promise<void>;
};

// A refresh asked for during a read (say, right after an action) reads again
// once that read lands, since the read in flight may predate the change.
let rerun = false;

export const useTeamProfiles = create<TeamProfilesState>((set, get) => ({
  status: null,
  error: null,
  busy: false,
  refresh: async () => {
    if (get().busy) { rerun = true; return; }
    set({ busy: true });
    try {
      do {
        rerun = false;
        try {
          set({ status: await teamProfilesStatus(), error: null });
        } catch (e) {
          set({ error: safeUiError(e) });
        }
      } while (rerun);
    } finally {
      set({ busy: false });
    }
  },
}));
