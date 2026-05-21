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

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
