/**
 * ReleaseGateProvider — agent-local policy evaluator for the
 * `promote.prod` lifecycle stage.
 *
 * Previously this provider called the backend `securityPolicyDecision`
 * GraphQL resolver. That coupled the gate to wspace-security-svc and
 * forced every agent to round-trip through the workspace gateway just
 * to learn whether a build was promotable.
 *
 * The agent-local model: the meta plugin's `SecurityManager` enriches
 * the scan input for `promote.prod` runs with the upstream scan's
 * findings + summary (read from the local SQLite cache). This provider
 * evaluates a small, deterministic rego-equivalent policy in TypeScript
 * and returns a NormalizedFinding[] for any deny reason.
 *
 * Rules evaluated (mirror the rego in vibecontrols-specs/security/stage-10-promote-prod.md):
 *   - DENY if any upstream finding is severity "critical" and status "open".
 *   - DENY if the upstream scan has no recorded summary (build didn't run).
 *   - DENY if input.config.requireSignedArtifact is true and config.signature is missing.
 *   - DENY if input.config.maxHighOpen is set and high+open count exceeds it.
 *   - ALLOW otherwise.
 *
 * Deny reasons map 1:1 to NormalizedFinding entries with category "policy"
 * + severity "high", so the standard findings UI surfaces them naturally.
 */
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { normalizeOpaDecision } from "@vibecontrols/vibe-plugin-security/normalizer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

const POLICY_VERSION = 2;
const POLICY_ID = "vibecontrols.security.release";

interface UpstreamFindingInput {
  fingerprint: string;
  ruleId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  status: string;
  cve?: string;
  packageName?: string;
}

interface ReleaseGateConfig {
  upstreamScanRunId?: string;
  upstreamFindings?: UpstreamFindingInput[];
  upstreamSummary?: SecurityScanSummary;
  requireSignedArtifact?: boolean;
  signature?: { verified?: boolean };
  maxHighOpen?: number;
}

interface PolicyDecision {
  allow: boolean;
  denyReasons: string[];
  evaluatedAt: string;
  policyVersion: number;
  policyId: string;
  input: {
    summary: SecurityScanSummary;
    openCriticalCount: number;
    openHighCount: number;
    upstreamScanRunId?: string;
  };
}

export class ReleaseGateProvider implements SecurityProvider {
  readonly name = "opa-release-gate";
  readonly stage: SecurityStage = "promote.prod";
  readonly toolVersion = `agent-local-policy@${POLICY_ID}/v${POLICY_VERSION}`;

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Pure-JS provider — no external binary to install.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config ?? {}) as ReleaseGateConfig;

    input.onProgress?.({ pct: 10, message: "Loading upstream scan data" });

    const upstreamFindings = cfg.upstreamFindings ?? [];
    const upstreamSummary: SecurityScanSummary = cfg.upstreamSummary ?? {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    input.onProgress?.({ pct: 40, message: "Evaluating release gate policy" });

    const decision = evaluatePolicy(upstreamFindings, upstreamSummary, cfg);

    input.onProgress?.({ pct: 70, message: "Building deny[] -> findings" });

    // Normalize deny reasons via the meta plugin's OPA normalizer so the
    // findings table renders them identically to a real OPA decision.
    const opaResultDoc = JSON.stringify({
      result: {
        allow: decision.allow,
        deny: decision.denyReasons,
      },
    });
    const findings: NormalizedFinding[] = normalizeOpaDecision(opaResultDoc, this.name);

    // Persist the full decision JSON as evidence.
    const evidencePath = path.join(input.workdir, "opa-decision.json");
    const evidenceJson = JSON.stringify(decision, null, 2);
    await fs.writeFile(evidencePath, evidenceJson, "utf-8");
    const stat = await fs.stat(evidencePath);
    const sha256 = createHash("sha256").update(evidenceJson).digest("hex");

    const evidence: ScanEvidenceArtifact[] = [
      {
        type: "opa-decision",
        localPath: evidencePath,
        sha256,
        sizeBytes: stat.size,
      },
    ];

    input.onProgress?.({ pct: 100, message: "Release gate evaluated" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }

  async cancel(_runId: string): Promise<void> {
    // No subprocess — nothing to cancel.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "sdk", "mcp", "mobile", "container", "iac"],
      toolVersion: this.toolVersion,
      description: "Agent-local release-gate policy for the promote.prod stage. No backend.",
    };
  }
}

function evaluatePolicy(
  upstreamFindings: UpstreamFindingInput[],
  summary: SecurityScanSummary,
  cfg: ReleaseGateConfig,
): PolicyDecision {
  const denyReasons: string[] = [];

  const openCriticals = upstreamFindings.filter(
    (f) => f.severity === "critical" && f.status === "open",
  );
  const openHighs = upstreamFindings.filter((f) => f.severity === "high" && f.status === "open");

  if (openCriticals.length > 0) {
    denyReasons.push(
      `${openCriticals.length} critical finding(s) open: ${openCriticals
        .slice(0, 3)
        .map((f) => f.ruleId)
        .join(", ")}${openCriticals.length > 3 ? "..." : ""}`,
    );
  }

  if (
    !cfg.upstreamScanRunId &&
    summary.critical === 0 &&
    summary.high === 0 &&
    summary.medium === 0 &&
    summary.low === 0 &&
    summary.info === 0
  ) {
    denyReasons.push("No upstream scan recorded — build stage must run before promote.prod");
  }

  if (cfg.requireSignedArtifact && !cfg.signature?.verified) {
    denyReasons.push("Required signature is missing or not verified");
  }

  if (typeof cfg.maxHighOpen === "number" && openHighs.length > cfg.maxHighOpen) {
    denyReasons.push(
      `${openHighs.length} open high-severity finding(s) exceeds maxHighOpen=${cfg.maxHighOpen}`,
    );
  }

  return {
    allow: denyReasons.length === 0,
    denyReasons,
    evaluatedAt: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    policyId: POLICY_ID,
    input: {
      summary,
      openCriticalCount: openCriticals.length,
      openHighCount: openHighs.length,
      upstreamScanRunId: cfg.upstreamScanRunId,
    },
  };
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
