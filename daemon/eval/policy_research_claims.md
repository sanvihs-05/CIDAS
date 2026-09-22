# Policy Engine — Research Claims

Structured novelty claims for the CIDAS policy engine, each formatted with: what CIDAS does, what prior tools do instead, why CIDAS's approach is better, and supporting test evidence.

---

## Claim 1: Hierarchical ancestor-directory policy discovery

**What CIDAS does**
When a scan request arrives with a `project_path`, CIDAS walks ancestor directories (up to ten levels) looking for `.cidas/policy.json`, using the closest ancestor's file. A file at `/projects/myapp/.cidas/policy.json` is preferred over `/projects/.cidas/policy.json`. If no file is found, all policy fields fall back to daemon defaults without error.

**What prior tools do instead**
`.npmrc` is read from the current directory or the global home directory — no ancestor traversal occurs. Network-layer controls (firewalls, Artifactory block lists) are applied globally, not per-project or per-directory. There is no mechanism in the npm ecosystem for a tool to discover per-project security rules by walking up the directory tree.

**Why CIDAS's approach is better**
Project-specific policies travel with the repository and require no manual setup on developer machines. The closest-ancestor semantics are intuitive and consistent with how `.gitignore`, `tsconfig.json`, and `pyproject.toml` behave. Monorepo root policies provide a baseline that individual packages can tighten without affecting siblings.

**Supporting test evidence**
- `test_policy_resolved_from_ancestor_directory`
- `test_policy_child_overrides_parent`
- `test_policy_depth_cap_stops_at_ten_levels`
- `test_policy_no_file_returns_empty_defaults`

---

## Claim 2: Three-layer merge precedence correctness

**What CIDAS does**
Resolved policy is the deterministic result of a three-layer merge: project policy (`.cidas/policy.json`) overrides admin config (`~/.cidas/config.json`) overrides daemon defaults (`.env` / `config.py`). A field present in a higher-priority layer is never shadowed by a lower-priority layer. `block_list` and `trust_list` are not merged across layers — the project policy's lists are used as-is to prevent unexpected inheritance.

**What prior tools do instead**
Most tools have a single configuration layer (a global config file or environment variables). There is no standard npm-ecosystem mechanism to compose per-project overrides on top of machine-scoped settings.

**Why CIDAS's approach is better**
Security leads can enforce block lists at the project level without touching machine configuration. Platform engineers can set machine-level defaults that projects can tighten (by adding to `block_list`) but cannot trivially remove. The three-layer design also cleanly separates concerns: project policy is security-lead controlled, admin config is IT-controlled, daemon defaults are deployment-controlled.

**Supporting test evidence**
- `test_project_policy_overrides_admin_config`
- `test_admin_config_overrides_daemon_defaults`
- `test_merge_precedence_all_three_layers`
- `test_empty_project_policy_falls_through_to_admin_config`

---

## Claim 3: block_list overrides all pillars unconditionally

**What CIDAS does**
A package on the project `block_list` receives `decision=BLOCK, risk_score=100` before any pillar, trust-list check, or SQLite cache lookup runs. The block is unconditional: even a package the user has manually added to the per-machine trust list cannot bypass a `block_list` entry. The audit log records the block with `cached=false` regardless, providing an accurate security trail.

**What prior tools do instead**
Most tools apply deny lists as post-scan filters — the scan still runs and the deny list merely overrides the final verdict. This means the deny list check can be raced by a cached ALLOW result, and expensive network calls are still made even for known-bad packages.

**Why CIDAS's approach is better**
Pre-scan unconditional enforcement is both faster (no pillar calls, no cache lookup) and more secure (no race condition between newly-added block_list entries and stale cache hits). A security lead can add a newly-disclosed malicious package to `block_list`, commit the change, and all developers pulling the update are immediately protected — no cache invalidation or daemon restart required.

**Supporting test evidence**
- `test_scan_policy_block_list_returns_block` (daemon/tests/test_router.py)
- `test_block_list_overrides_trust_list`
- `test_block_list_fires_before_cache_lookup`
- `test_block_list_fires_before_pillar_scan`

---

## Claim 4: Graceful fallback on invalid or malformed policy

**What CIDAS does**
If `.cidas/policy.json` contains invalid JSON, fields of the wrong type, or unknown keys, the Policy Engine silently discards the file and continues with daemon defaults (empty `block_list`, empty `trust_list`, no penalties). The `policy_file` field in the scan response is set to `null` to make the problem visible to the caller without interrupting the install.

**What prior tools do instead**
Many tools fail loudly on configuration errors, blocking all installs until the file is fixed — a DoS on developer workflow. Others silently accept unknown keys, making it easy to introduce a typo (e.g. `blocklist` instead of `block_list`) that disables the intended protection with no warning.

**Why CIDAS's approach is better**
Silent discard of invalid files maintains developer workflow continuity while the `policy_file=null` signal in the API response and VS Code panel makes the problem visible without requiring the developer to read a daemon log. The JSON Schema at `.cidas/policy.schema.json` allows editors to catch typos before commit, closing the silent-failure loop at authoring time rather than at install time.

**Supporting test evidence**
- `test_invalid_json_policy_returns_empty_defaults`
- `test_unknown_key_in_policy_causes_file_to_be_ignored`
- `test_wrong_type_for_block_list_returns_empty_policy`
- `test_policy_file_null_when_policy_invalid`
