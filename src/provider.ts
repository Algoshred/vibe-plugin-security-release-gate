/**
 * ReleaseGateProvider — calls backend `securityPolicyDecision(scanRunId)`
 * via `hostServices.workspaceQuery` and maps the OPA `deny[]` output
 * into NormalizedFinding[]. No subprocess execution.
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

const POLICY_QUERY = `
  query SecurityPolicyDecision($scanRunId: ID!) {
    securityPolicyDecision(scanRunId: $scanRunId) {
      allow
      denyReasons
      evaluatedAt
      policyVersion
      input
    }
  }
`;

interface ReleaseGateConfig {
  upstreamScanRunId?: string;
}

export class ReleaseGateProvider implements SecurityProvider {
  readonly name = "opa-release-gate";
  readonly stage: SecurityStage = "promote.prod";
  readonly toolVersion = "opa-wspace-sidecar+rego/vibecontrols.security.release";

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // OPA lives in the backend sidecar; nothing to install on the agent.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    if (!this.host?.workspaceQuery) {
      throw new Error("release-gate: workspaceQuery unavailable on host");
    }
    const startedAt = Date.now();
    const cfg = (input.config as ReleaseGateConfig) ?? {};
    // The release gate evaluates an *upstream* scan run (typically the
    // build-stage SBOM run that produced the artifact being promoted).
    // If the caller didn't pass one explicitly via config, fall back to
    // the current runId so the policy still has something to evaluate
    // — useful for smoke tests of the gate.
    const targetScanRunId = cfg.upstreamScanRunId ?? input.runId;

    input.onProgress?.({ pct: 10, message: "Calling backend policy decision" });

    const res = await this.host.workspaceQuery<{
      securityPolicyDecision: {
        allow: boolean;
        denyReasons: string[];
        evaluatedAt: string;
        policyVersion: number;
        input?: unknown;
      };
    }>(POLICY_QUERY, { scanRunId: targetScanRunId });

    if (res.errors && res.errors.length > 0) {
      return errored(
        input.runId,
        startedAt,
        `policy decision errors: ${res.errors.map((e) => e.message).join("; ")}`,
      );
    }
    const decision = res.data?.securityPolicyDecision;
    if (!decision) {
      return errored(input.runId, startedAt, "missing securityPolicyDecision in response");
    }

    input.onProgress?.({ pct: 70, message: "Normalizing OPA deny[]" });

    // Build an OPA-shaped result document for normalizer compatibility.
    const opaResultDoc = JSON.stringify({
      result: {
        allow: decision.allow,
        deny: decision.denyReasons,
      },
    });
    const findings: NormalizedFinding[] = normalizeOpaDecision(opaResultDoc, this.name);

    // Persist the full decision JSON as evidence.
    const evidencePath = path.join(input.workdir, "opa-decision.json");
    const evidenceJson = JSON.stringify(
      {
        scanRunId: targetScanRunId,
        decision,
      },
      null,
      2,
    );
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
      description: "OPA release gate for the promote.prod stage.",
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

function errored(runId: string, startedAt: number, reason: string): SecurityScanResult {
  return {
    runId,
    status: "errored",
    findings: [],
    evidence: [],
    durationMs: Date.now() - startedAt,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    errorReason: reason,
  };
}
