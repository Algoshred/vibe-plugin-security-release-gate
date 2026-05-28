import { describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { ReleaseGateProvider } from "../src/provider.js";

const baseInput = (workdir: string, config: Record<string, unknown> = {}) => ({
  runId: "r1",
  vibeId: "v1",
  workspaceId: "w1",
  repoUrl: "x",
  repoLocalPath: "/tmp",
  commit: "c",
  stage: "promote.prod" as const,
  profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
  policyLevel: "block" as const,
  config,
  workdir,
});

describe("ReleaseGateProvider (agent-local)", () => {
  test("name + stage are stable identifiers", () => {
    const p = new ReleaseGateProvider();
    expect(p.name).toBe("opa-release-gate");
    expect(p.stage).toBe("promote.prod");
  });

  test("metadata includes mobile + container profiles (broad scope)", () => {
    const m = new ReleaseGateProvider().metadata();
    expect(m.supportedProfiles).toContain("mobile");
    expect(m.supportedProfiles).toContain("container");
  });

  test("toolVersion is the agent-local policy identifier", () => {
    const p = new ReleaseGateProvider();
    expect(p.toolVersion).toContain("agent-local-policy@vibecontrols.security.release");
  });

  test("DENY when upstream has open critical findings", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    const result = await p.run(
      baseInput(workdir, {
        upstreamScanRunId: "build-run-1",
        upstreamSummary: { critical: 2, high: 0, medium: 0, low: 0, info: 0 },
        upstreamFindings: [
          {
            fingerprint: "fp1",
            ruleId: "cve-2026-1234",
            title: "Critical RCE",
            severity: "critical",
            category: "vuln",
            status: "open",
          },
          {
            fingerprint: "fp2",
            ruleId: "cve-2026-5678",
            title: "Critical SQLi",
            severity: "critical",
            category: "vuln",
            status: "open",
          },
        ],
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].category).toBe("policy");
    expect(result.evidence.length).toBe(1);
    expect(result.evidence[0].type).toBe("opa-decision");
  });

  test("ALLOW when no upstream criticals and upstream run id present", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    const result = await p.run(
      baseInput(workdir, {
        upstreamScanRunId: "build-run-2",
        upstreamSummary: { critical: 0, high: 1, medium: 3, low: 0, info: 0 },
        upstreamFindings: [],
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(0);
    expect(result.evidence.length).toBe(1);
  });

  test("DENY when no upstream scan recorded", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    const result = await p.run(baseInput(workdir, {}));
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].title).toMatch(/upstream scan/i);
  });

  test("DENY when requireSignedArtifact and signature missing", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    const result = await p.run(
      baseInput(workdir, {
        upstreamScanRunId: "build-run-3",
        upstreamSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        upstreamFindings: [],
        requireSignedArtifact: true,
      }),
    );
    expect(result.findings.some((f) => /signature/i.test(f.title))).toBe(true);
  });

  test("DENY when maxHighOpen exceeded", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    const result = await p.run(
      baseInput(workdir, {
        upstreamScanRunId: "build-run-4",
        upstreamSummary: { critical: 0, high: 3, medium: 0, low: 0, info: 0 },
        upstreamFindings: [
          {
            fingerprint: "h1",
            ruleId: "x",
            title: "x",
            severity: "high",
            category: "vuln",
            status: "open",
          },
          {
            fingerprint: "h2",
            ruleId: "y",
            title: "y",
            severity: "high",
            category: "vuln",
            status: "open",
          },
          {
            fingerprint: "h3",
            ruleId: "z",
            title: "z",
            severity: "high",
            category: "vuln",
            status: "open",
          },
        ],
        maxHighOpen: 2,
      }),
    );
    expect(result.findings.some((f) => /maxHighOpen/i.test(f.title))).toBe(true);
  });
});
