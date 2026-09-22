# CIDAS Policy Engine

## 1. Overview

The CIDAS Policy Engine lets security leads encode per-project package-safety rules in a versioned JSON file (`.cidas/policy.json`) that lives alongside the source code. CIDAS policies travel with the repository, are version-controlled with the code they protect, and take unconditional precedence over all pillar scores — including the per-machine trust list.

## 2. Policy file format

Policy files must conform to `.cidas/policy.schema.json`. Every field is optional; an empty `{}` is a valid (no-op) policy. Files with unknown keys or wrong value types are silently discarded (safe fallback), and `policy_file` in the scan response is set to `null` to signal that no policy was applied.

```json
{
  "version": 1,
  "block_list": ["bad-pkg", "known-malware"],
  "trust_list": ["our-internal-lib", "@company/sdk"],
  "min_monthly_downloads": 10000,
  "require_repository_link": true,
  "warn_requires_confirmation": false,
  "contextify_weight": 0.30
}
```

| Field | Type | Allowed values | Description |
|---|---|---|---|
| `version` | integer | `1` | Schema version — currently must be `1` |
| `block_list` | string[] | Any npm package names | Always blocked, regardless of pillar scores or trust list |
| `trust_list` | string[] | Any npm package names | Always allowed, skipping all pillar analysis |
| `min_monthly_downloads` | integer | ≥ 0 | AI-suggested packages below this threshold receive a +15 risk-score penalty |
| `require_repository_link` | boolean | `true` / `false` | Packages with no repository link receive a +10 risk-score penalty |
| `warn_requires_confirmation` | boolean | `true` / `false` | When `true`, the npm shim prompts the developer to type `proceed` before continuing past a WARN verdict |
| `contextify_weight` | float | 0.0–0.5 | Override the Contextify pillar weight; remainder is split between Sentinel and Shield proportionally |

## 3. Discovery mechanism

When a scan request arrives with a `project_path`, the engine traverses ancestor directories:

1. Check `<project_path>/.cidas/policy.json`.
2. If absent or invalid, move to the parent directory and try again.
3. Repeat up to **ten levels** (depth cap prevents runaway traversal on deep trees).
4. The first valid file found is used; traversal stops immediately.
5. If no file is found anywhere in the chain, all fields fall back to daemon defaults.

**Closest-ancestor wins.** A file at `/projects/myapp/.cidas/policy.json` takes precedence over `/projects/.cidas/policy.json`. This lets a monorepo root define a baseline policy while individual packages can tighten it without affecting siblings.

## 4. Merge precedence

Rules are resolved in three layers, highest-priority last:

```
Layer 1  Daemon defaults        (.env / config.py)
Layer 2  Admin config           (~/.cidas/config.json)      overrides layer 1
Layer 3  Project policy         (.cidas/policy.json)         overrides layers 1–2
```

**Worked example:**

| Setting | Daemon default | Admin config | Project policy | **Resolved** |
|---|---|---|---|---|
| `warn_requires_confirmation` | `false` | *(absent)* | `true` | **`true`** |
| `package_file_scan` | `true` | `false` | *(absent)* | **`false`** |
| `block_list` | `[]` | *(N/A)* | `["bad-pkg"]` | **`["bad-pkg"]`** |
| `contextify_weight` | `0.30` | `0.20` | *(absent)* | **`0.20`** |

`block_list` and `trust_list` are not merged across layers — the project policy's lists are used wholesale. This prevents a parent policy from silently populating a child project's allow list.

## 5. Security features

### block_list

Packages on `block_list` return `BLOCK` with `risk_score=100` **before any pillar runs**. The local trust list, the SQLite scan cache, and all three analysis pillars are bypassed. A security lead can add a newly-disclosed malicious package to `block_list`, commit the change, and all developers pulling the update are immediately protected on their next install attempt — no daemon restart required.

### trust_list

Packages on `trust_list` return `ALLOW` with `risk_score=0` and the flag `policy_trust`, bypassing all pillar analysis. The result is also mirrored to the offline cache (`~/.cidas/offline-cache.json`) so the npm shim can serve the allow verdict silently when the daemon is unreachable.

### warn_requires_confirmation

When `true`, the npm shim prompts the developer to type the word `proceed` before continuing past any WARN verdict. The prompt fires on both the terminal shim and the VS Code extension dialog. It is automatically suppressed in non-TTY environments (CI pipelines, piped input) to prevent hanging unattended runs.

### contextify_weight override

Allows a project to tune how much the Contextify pillar (project-context scoring) contributes to the final risk score. A team working on a polyglot monorepo may want to reduce Contextify's influence if the project fingerprint is too broad; a team with a well-defined dependency surface may want to increase it to make out-of-context packages more visible. The value is clamped to [0.0, 0.5] so Sentinel and Shield always retain at least 50% collective weight.

## 6. Research claim

**Claim:** CIDAS is the first npm dependency screening tool to implement a hierarchical, ancestor-directory policy-discovery mechanism with a defined three-layer merge precedence and unconditional block_list enforcement above all other signals.

**Prior art and distinction:**

- **`.npmrc` deny lists** — not hierarchically discovered, not version-controlled in the repository by default, and cannot express risk-score penalties or developer-confirmation requirements.
- **Network-layer firewalls / Artifactory block lists** — block domains globally; cannot discriminate between package versions, enforce per-project overrides, or apply conditional penalties.
- **Other npm audit tools** (e.g., `npm audit`, Socket.dev) — scan results are advisory; there is no mechanism for a security lead to encode binding per-project installation rules that travel with the repository.

CIDAS combines all three properties — **versioned**, **hierarchically resolved**, and **unconditionally enforced** — in a single, repository-portable policy mechanism.
