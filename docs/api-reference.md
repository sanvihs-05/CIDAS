# CIDAS Daemon API Reference

Base URL: `http://127.0.0.1:7355/api/v1`

Interactive Swagger UI: `http://127.0.0.1:7355/docs`

All endpoints except `GET /health` require a Bearer token (`Authorization: Bearer <token>`).
The token is stored at `~/.cidas/daemon.token` (mode 0600) and is generated on first daemon start.

Every response includes an `X-CIDAS-Latency-Ms` header with server-side processing time.

---

## GET /health

Liveness probe — no authentication required.

**Response 200**
```json
{ "status": "ok", "version": "0.1.0" }
```

---

## POST /scan

Screen an npm package before installation. Auth required.

**Request body**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "project_path": "/home/user/my-project",
  "ai_suggested": false,
  "requesting_tool": "npm-shim",
  "scan_transitive": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `package_name` | string | **Yes** | npm package name |
| `version` | string \| null | No | Specific version; `null` = latest |
| `project_path` | string | **Yes** | Absolute path used by Contextify pillar |
| `ai_suggested` | boolean | No | `true` triggers full hallucination-risk analysis in Sentinel |
| `requesting_tool` | string \| null | No | Caller identifier, e.g. `"npm-shim"` |
| `scan_transitive` | boolean | No | When `true`, resolve and screen transitive dependencies (Sentinel only) |

**Response 200**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "decision": "ALLOW",
  "risk_score": 2.7,
  "contextify": {
    "score": 0.0,
    "confidence": 0.7,
    "flags": [],
    "metadata": { "similarity": 0.91 }
  },
  "sentinel": {
    "score": 0.0,
    "confidence": 0.9,
    "flags": [],
    "metadata": { "ai_suggested": false, "hallucination_check": "skipped" }
  },
  "shield": {
    "score": 0.0,
    "confidence": 0.8,
    "flags": [],
    "metadata": { "script_score": 0, "injection_score": 0 }
  },
  "direct_dependencies": [
    { "name": "some-dep", "version_range": "^1.2.3" }
  ],
  "alternatives": [],
  "explanation": "Package passed all checks (risk score 3/100).",
  "latency_ms": 42.1,
  "tarball_url": null,
  "file_scan_summary": null,
  "trust_flags": [],
  "policy_file": null,
  "requires_confirmation": false,
  "transitive_risks": [],
  "transitive_risk_detected": false,
  "flags": [],
  "disk_footprint": null
}
```

**Response fields**

| Field | Type | Description |
|---|---|---|
| `decision` | `"ALLOW"` \| `"WARN"` \| `"BLOCK"` | Final verdict |
| `risk_score` | float 0–100 | Weighted aggregate score |
| `contextify` / `sentinel` / `shield` | PillarScore | Per-pillar score, confidence, flags, and raw metadata |
| `direct_dependencies` | array | Direct deps declared in the package's `package.json` |
| `alternatives` | array | Safer package suggestions (populated on BLOCK/WARN) |
| `explanation` | string | Human-readable decision summary |
| `latency_ms` | float | Total server-side scan time |
| `tarball_url` | string \| null | Tarball URL downloaded by Shield's file scan |
| `file_scan_summary` | object \| null | Shield file-scan stats: `files_scanned`, `flags`, `skipped` |
| `trust_flags` | array | `"trust_tamper_detected"` or `"trust_legacy_no_mac"` when applicable |
| `policy_file` | string \| null | Absolute path of the `.cidas/policy.json` applied, or `null` |
| `requires_confirmation` | boolean | `true` when policy sets `warn_requires_confirmation: true` |
| `transitive_risks` | array | Sentinel results for transitive deps (populated when `scan_transitive=true`) |
| `transitive_risk_detected` | boolean | `true` when any transitive dep Sentinel score ≥ 50 |
| `flags` | array | Top-level scan flags, e.g. `"insufficient_disk_space"` |
| `disk_footprint` | object \| null | Estimated install size when `DISK_CHECK_ENABLED=true` |

**Decision thresholds**

| Decision | Risk score | Meaning |
|---|---|---|
| `ALLOW` | < 40 | Safe to proceed |
| `WARN` | 40–79 | Proceed with caution |
| `BLOCK` | ≥ 80 | Install blocked by default |

---

## POST /trust

Add a package to the local HMAC-protected trust bypass list. Future scans return `ALLOW` without pillar analysis. Auth required.

**Request body**
```json
{ "package_name": "my-internal-lib" }
```

**Response 200**
```json
{ "trusted": "my-internal-lib" }
```

**Response 422** — `package_name` missing from body.

---

## GET /trust/verify

Audit every trust-list row and report HMAC verification results. Auth required.

**Response 200**
```json
{
  "total": 3,
  "verified": 2,
  "legacy_no_mac": 0,
  "tampered": 1,
  "tampered_packages": [
    { "package_name": "my-internal-lib", "verification": "tampered" }
  ],
  "entries": [...]
}
```

`tampered > 0` means a SQLite row was edited directly outside the daemon. The event is also logged at `CRITICAL` level in the daemon log.

---

## DELETE /cache

Purge all expired scan cache entries. Auth required.

**Response 200**
```json
{ "purged": 3 }
```

---

## POST /cache/invalidate

Emergency per-package cache eviction — forces a fresh scan on the next install attempt. Use immediately after a malicious-package disclosure. Auth required.

**Request body**
```json
{ "package_name": "axios", "version": "*" }
```

`version` is required. Use `"*"` to evict all cached versions of the package.

**Response 200**
```json
{ "invalidated": 2, "package_name": "axios", "version": "*" }
```

**Response 422** — `package_name` or `version` missing from body.

---

## GET /audit

Query structured scan records from the audit log. Auth required.

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `verdict` | string | No | Filter by verdict: `ALLOW`, `WARN`, or `BLOCK` |
| `package` | string | No | Filter by package name (without version) |
| `since` | string | No | Return only records newer than this ISO-8601 timestamp |
| `last` | integer | No | Maximum records to return (default `100`, max `1000`) |

**Response 200**

```json
{
  "events": [
    {
      "ts": "2026-05-14T10:00:00+00:00",
      "package": "lodash@4.17.21",
      "verdict": "ALLOW",
      "score": 2.7,
      "signals": [],
      "ai_suggested": false,
      "project_path": "/home/user/myapp",
      "cached": false
    }
  ],
  "total": 1
}
```

**Response 422** — `verdict` is not one of `ALLOW`, `WARN`, `BLOCK`.

---

## POST /audit/override

Record a user "Proceed Anyway" or "Cancel" event. Called by the VS Code extension. Auth required.

**Request body**

```json
{
  "package_name": "lodahs",
  "version": "1.0.0",
  "verdict_was": "WARN",
  "event": "user_override"
}
```

`event` defaults to `"user_override"`; the VS Code extension also sends `"user_cancel_intent"`.

**Response 200**

```json
{ "logged": true, "package": "lodahs@1.0.0", "event": "user_override" }
```

**Response 422** — `package_name` missing from body.

---

## GET /policy

Return the resolved project policy for a given path. Auth required.

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `project_path` | string | **Yes** | Absolute path of the project to resolve policy for |

**Response 200**

```json
{
  "project_path": "/home/user/myapp",
  "policy_file": "/home/user/myapp/.cidas/policy.json",
  "resolved": {
    "block_list": ["bad-pkg"],
    "trust_list": [],
    "warn_requires_confirmation": true
  }
}
```

`policy_file` is `null` when no `.cidas/policy.json` was found in any ancestor directory.

---

## Error format

```json
{ "detail": "error description" }
```

Common status codes: `401` (missing/invalid token), `422` (missing required field), `500` (daemon error).
