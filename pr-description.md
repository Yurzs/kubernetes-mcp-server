# feat: add field-level redaction for `denied_resources`

## Problem

When using kubernetes-mcp-server with AI agents, `denied_resources` is all-or-nothing — you either block an entire resource type or allow full access to it.

This is a problem for resources like Secrets: blocking them entirely means the agent can't see that a Secret exists, what keys it contains, its type, ownership, or annotations. But allowing full access exposes the actual secret values to the LLM context.

The same applies to any resource with sensitive fields — CRDs with embedded credentials, ConfigMaps used for secrets, etc.

## Solution

Add two new optional fields to `denied_resources` entries: `redacted_fields` and `redaction_mode`.

When `redacted_fields` is set, the resource is **not denied** at the access control layer — instead, the specified fields have their values replaced with a redaction marker before being returned to the agent.

### Configuration

```toml
# Secret: expose metadata and key names, redact values
[[denied_resources]]
group = ""
version = "v1"
kind = "Secret"
redacted_fields = ["data.*", "stringData.*"]
redaction_mode = "hashed"
```

### Path syntax

Fields are specified as dot-separated paths with `*` wildcard support. The wildcard adapts to the type it encounters — iterates keys in a map, iterates items in an array.

| Path | Behavior |
|------|----------|
| `data.*` | Redact all values in a map (keeps keys visible) |
| `spec.credentials` | Redact a single field |
| `spec.template.spec.containers.*.env.*.value` | Traverse arrays and maps to reach nested fields |

### Redaction modes

- **`opaque`** (default): replaces values with `[REDACTED]`
- **`hashed`**: replaces values with `[REDACTED:gen_<id>:<hash>]`

Hashed mode uses HMAC-SHA256 with a random salt generated once at server startup. This allows the agent to detect when two different resources reference the same value (e.g. "these two services use the same connection string") without exposing the actual content.

The salt is never persisted — it lives only in memory and changes on restart. A generation ID is included in the output so consumers can detect when the salt changed and know that hashes from different generations are not comparable.

### Config validation

- `redacted_fields` requires `kind` to be set — field-level redaction on an entire group/version is not supported
- `redaction_mode` must be `"opaque"`, `"hashed"`, or empty (defaults to `"opaque"`)
- Invalid values are rejected at config load time

## Example output

### Secret (hashed mode)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: web-ui
  namespace: production
type: Opaque
data:
  client_secret: '[REDACTED:gen_ee128e09:df2e09b64a1c8f37]'
  jira_api_token: '[REDACTED:gen_ee128e09:3f2501db82e4a90c]'
  sentry_dsn: '[REDACTED:gen_ee128e09:039c47e8f15b6d2a]'
```

The agent can see: the Secret exists, it has 3 keys (`client_secret`, `jira_api_token`, `sentry_dsn`), it's type `Opaque`, and it's owned by a SealedSecret controller. It cannot see any actual values.

### Other use cases

The same mechanism works for any resource type:

```toml
# ConfigMap with sensitive data
[[denied_resources]]
group = ""
version = "v1"
kind = "ConfigMap"
redacted_fields = ["data.*"]

# CRD with embedded credentials
[[denied_resources]]
group = "db.example.com"
version = "v1"
kind = "DatabaseConnection"
redacted_fields = ["spec.credentials.*", "spec.connectionString"]
```

## Changes

### New package: `pkg/redaction/`

| File | Purpose |
|------|---------|
| `salt.go` | Random HMAC salt with generation ID, created once at startup via `sync.Once`, never persisted. Hash output is 16 hex chars (64 bits). |
| `redact.go` | `Redactor` with type-aware path walker: `walkValue` dispatches to `walkMap` or `walkSlice` based on runtime type, so `*` correctly iterates map keys or array items. |
| `salt_test.go` | Hash consistency, salt uniqueness, singleton behavior |
| `redact_test.go` | Secrets, Deployments with env arrays, init containers, hashed mode, lists, nil safety, missing paths, GVK mismatch |

### Modified files

| File | Change |
|------|--------|
| `pkg/api/config.go` | Added `RedactedFields` and `RedactionMode` to `GroupVersionKind`, added `RedactedResourcesProvider` interface |
| `pkg/config/config.go` | Added `GetRedactedResources()` to filter entries with `redacted_fields`. Added `validateRedactedResources()` for config validation. |
| `pkg/kubernetes/accesscontrol_round_tripper.go` | Entries with `redacted_fields` skip the full deny — allowed through for redaction at handler level |
| `pkg/toolsets/core/resources.go` | Redaction applied in `resourcesGet`, `resourcesList`, and `resourcesCreateOrUpdate` |
| `pkg/toolsets/core/pods.go` | Redaction applied in `podsGet`, `podsListInAllNamespaces`, `podsListInNamespace`, and `podsRun` |
| `pkg/kubernetes/accesscontrol_round_tripper_test.go` | Test that `redacted_fields` entries are not fully denied |
| `pkg/config/validate_test.go` | Tests for `validateRedactedResources()`: missing kind rejected, invalid mode rejected, valid configs accepted |

## Design decisions

**Why extend `denied_resources` instead of a new config section?**
Both control what the agent can access. Without `redacted_fields`, an entry blocks entirely; with it, the entry allows access but redacts. This keeps related rules together and avoids a separate config section.

**Why per-startup salt instead of persistent or configurable?**
A persistent salt would allow building lookup tables over time. A per-startup random salt means hashes are only comparable within a single server session, which is sufficient for an agent to correlate values across resources during a conversation. Zero configuration required.

**Why 16 hex chars (64 bits) for the hash?**
With 8 hex chars (32 bits), the birthday bound gives ~50% collision chance at 65K values, and brute-force of low-entropy values (like `"true"` or `"3000"`) would be trivial. 64 bits makes both significantly harder.

**Why redact at the tool handler level, not at the HTTP round-tripper?**
The round-tripper sees raw HTTP responses before deserialization. Redaction requires structured access to walk field paths in the parsed unstructured object, so it's applied after the K8s API returns the response.

**Why require `kind` when `redacted_fields` is set?**
Without `kind`, a `denied_resources` entry matches an entire group/version. Skipping such an entry in `isAllowed` (to allow it through for redaction) would effectively remove the deny for all resource types in that group/version — a security risk. Requiring `kind` ensures the scope is explicit.

## Testing

```bash
go test ./pkg/redaction/... -v
go test ./pkg/kubernetes/... -v -run TestAccessControl
go test ./pkg/config/... -v
```

Tested against a live cluster with Secrets and Deployments confirming correct redaction behavior.
