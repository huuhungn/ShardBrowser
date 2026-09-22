import { invoke } from "@tauri-apps/api/core";
import type { Project, RunReport } from "./types";

export const automationList = () => invoke<Project[]>("automation_list");
export const automationGet = (id: string) => invoke<Project>("automation_get", { id });
export const automationSave = (project: Project) =>
  invoke<Project>("automation_save", { project });
export const automationDelete = (id: string) => invoke("automation_delete", { id });

/**
 * Run a saved project against a profile that is already running.
 *
 * The launcher refuses to start a browser for a run, so the caller is
 * expected to have started the profile itself.
 */
export const automationRun = (
  projectId: string,
  profileId: string,
  variables: Record<string, string> = {},
) => invoke<RunReport>("automation_run", { projectId, profileId, variables });
