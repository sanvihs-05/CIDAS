/** Shared TypeScript types mirroring the daemon Pydantic models. */

export enum Decision {
  ALLOW = "ALLOW",
  WARN  = "WARN",
  BLOCK = "BLOCK",
}

export interface PillarScore {
  score: number;
  confidence: number;
  flags: string[];
  metadata: Record<string, unknown>;
}

export interface ScanResponse {
  package_name: string;
  version: string | null;
  decision: Decision;
  risk_score: number;
  contextify: PillarScore;
  sentinel: PillarScore;
  shield: PillarScore;
  alternatives: string[];
  explanation: string;
  latency_ms: number;
  policy_file?: string | null;
  requires_confirmation?: boolean;
}

export interface PackageScanRequest {
  package_name: string;
  version?: string;
  project_path: string;
  ai_suggested?: boolean;
  requesting_tool?: string;
}

export interface CidasConfig {
  daemonPort: number;
  autoScan: boolean;
  blockInstalls: boolean;
}

export type StatusState = "idle" | "scanning" | "blocked" | "warned" | "error";
