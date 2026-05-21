import { describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { ReleaseGateProvider } from "../src/provider.js";

describe("ReleaseGateProvider", () => {
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

  test("errored when host has no workspaceQuery", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({});
    await expect(
      p.run({
        runId: "r1",
        vibeId: "v1",
        workspaceId: "w1",
        repoUrl: "x",
        repoLocalPath: "/tmp",
        commit: "c",
        stage: "promote.prod",
        profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
        policyLevel: "block",
        config: {},
        workdir,
      }),
    ).rejects.toThrow(/workspaceQuery unavailable/);
  });

  test("maps OPA deny[] into NormalizedFinding[] with category=policy", async () => {
    const p = new ReleaseGateProvider();
    const workdir = await fs.mkdtemp(path.join(tmpdir(), "release-gate-test-"));
    await p.init({
      workspaceQuery: async () => ({
        data: {
          securityPolicyDecision: {
            allow: false,
            denyReasons: ["1 critical secret finding is open", "SBOM missing for artifact digest"],
            evaluatedAt: "2026-05-21T00:00:00Z",
            policyVersion: 1,
          },
        },
      }),
    });
    const result = await p.run({
      runId: "r2",
      vibeId: "v1",
      workspaceId: "w1",
      repoUrl: "x",
      repoLocalPath: "/tmp",
      commit: "c",
      stage: "promote.prod",
      profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
      policyLevel: "block",
      config: { upstreamScanRunId: "build-run-1" },
      workdir,
    });
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(2);
    expect(result.findings[0].category).toBe("policy");
    expect(result.evidence.length).toBe(1);
    expect(result.evidence[0].type).toBe("opa-decision");
  });
});
