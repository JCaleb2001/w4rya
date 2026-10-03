// Shapes returned by the /vulnbox Blueprint (services/api/vulnbox/routes.py).
// Keep in sync with the backend dicts — this is an API contract.

import { Service } from "../../types";

export type JobKind = "preflight" | "recon" | "backup";
export type JobState = "running" | "done" | "error";

export interface Job<R> {
  id: string;
  kind: JobKind;
  state: JobState;
  started_by: string;
  started_at: string;
  finished_at: string | null;
  result: R | null;
  error: string | null;
}

export interface KeyStatus {
  exists: boolean;
  public_key?: string;
  fingerprint?: string | null;
  created_at?: string | null;
}

export interface VulnboxTarget {
  host: string | null;
  port: number | null;
  user: string | null;
  services_path: string | null;
  /** Set when the target can't be resolved (e.g. vm_ip not configured). */
  error: string | null;
  /** The vulnbox_service_ports setting ("9000-9999,31337"); "" = every published port. */
  service_ports: string;
}

export type CheckStatus = "ok" | "fail" | "skipped";

export interface PreflightCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface PreflightResult {
  host: string;
  checks: PreflightCheck[];
}

export interface ReconContainer {
  name: string;
  image: string;
  ports: number[];
}

export interface ReconService {
  name: string;
  ports: number[];
  /** The published ports inside the configured service-port ranges. */
  service_ports: number[];
  containers: ReconContainer[];
}

export interface ReconResult {
  host: string;
  services: ReconService[];
  notes: string[];
}

export type BackupStatus = "created" | "updated" | "unchanged" | "error";
export type LocalStatus = "cloned" | "pulled" | "up to date" | "error" | "skipped";

export interface BackupService {
  name: string;
  status: BackupStatus;
  commit: string;
  files: number;
  detail: string;
  skipped: { path: string; bytes: number }[];
  local: LocalStatus;
  local_detail: string;
}

export interface BackupResult {
  host: string;
  fatal: string | null;
  services: BackupService[];
}

export interface VulnboxOverview {
  target: VulnboxTarget;
  key: KeyStatus;
  jobs: {
    current: Job<unknown> | null;
    last: {
      preflight?: Job<PreflightResult>;
      recon?: Job<ReconResult>;
      backup?: Job<BackupResult>;
    };
  };
  presets: PresetInfo[];
}

/** A named bundle of /config values for one game (services/api/vulnbox/presets.py). */
export interface PresetInfo {
  id: string;
  name: string;
  values: Record<string, string | number>;
  /** True when /config already holds every value of this preset. */
  applied: boolean;
}

export interface ImportResult {
  services: Service[];
  added: number;
  updated: number;
}

export interface PresetResult {
  preset: string;
  applied: Record<string, string | number>;
  /** The same values as .env lines — the assembler reads them at boot. */
  env: Record<string, string>;
}
