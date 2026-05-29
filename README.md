# @vibecontrols/vibe-plugin-security-release-gate

OPA-backed release gate for the `promote.prod` lifecycle stage in [VibeControls](https://vibecontrols.com). Does **not** shell out — it calls the backend's `securityPolicyDecision(scanRunId)` GraphQL resolver, which in turn POSTs to the existing `opa-wspace:8181` ACA sidecar with the appropriate Rego bundle.

Registers as a `security.release` provider (name `opa-release-gate`) with the [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) meta plugin.

## Decision input

The backend resolver loads:

- the scan run's `summary` (severity counts)
- open `SecurityFinding[]` (joined to active `SecurityException[]`)
- the workspace + per-vibe `SecurityPolicy` (level: `advisory` / `warn` / `block`)
- artifact metadata (signed? SBOM present? pinned by digest?)

It POSTs the document to `POST {OPA_URL}/v1/data/vibecontrols/security/release/allow` and caches the decision in Valkey for 5 minutes keyed by `(scanRunId, policyVersion)`.

## Provider output

- `NormalizedFinding[]` — one row per `deny[]` entry with `category: "policy"` and severity derived from the policy expression
- Evidence: a single `opa-decision` JSON document containing the input + decision (uploaded to S3 for the audit trail)

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **Open Policy Agent (Rego inspiration)** — <https://www.openpolicyagent.org/>

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

**Note**: this plugin is open source under MIT. The `@vibecontrols/agent` runtime that loads and orchestrates plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
