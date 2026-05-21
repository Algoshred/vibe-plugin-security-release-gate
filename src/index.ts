/**
 * @vibecontrols/vibe-plugin-security-release-gate
 *
 * OPA-backed release gate for the `promote.prod` lifecycle stage.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { ReleaseGateProvider } from "./provider.js";

const PLUGIN_NAME = "security-release-gate";
const PLUGIN_VERSION = "2026.521.1";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new ReleaseGateProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.release-gate.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      new ProviderRegistry(host).registerProvider("security.release", "opa-release-gate", provider);
      telemetry.emit("security.release-gate.registered", {
        provider: "opa-release-gate",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description: "OPA Rego release-gate provider for the promote.prod stage.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      audit: true,
      telemetry: true,
      gateway: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { ReleaseGateProvider } from "./provider.js";
