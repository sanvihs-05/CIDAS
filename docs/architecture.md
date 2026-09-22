# CIDAS Architecture

## System overview

```
Developer workstation
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Terminal                        VS Code                         │
│  ┌────────────────┐              ┌──────────────────────────────┐│
│  │ npm install    │              │ Extension (TypeScript)        ││
│  │   <pkg>        │              │  ┌────────────────────────┐  ││
│  └──────┬─────────┘              │  │ Interceptor            │  ││
│         │                        │  │ SentinelHook (AI)      │  ││
│  ┌──────▼─────────┐              │  │ StatusBarManager       │  ││
│  │ npm-shim.js    │              │  │ NotificationUI         │  ││
│  │ (intercept/)   │              │  └──────────┬─────────────┘  ││
│  └──────┬─────────┘              └─────────────│────────────────┘│
│         │  HTTP POST /api/v1/scan              │                  │
│         └─────────────────────────────────────┘                  │
│                              │                                   │
│              ┌───────────────▼──────────────────┐               │
│              │  CIDAS Daemon  (FastAPI/Uvicorn)  │               │
│              │  localhost:7355                   │               │
│              │                                   │               │
│              │  ┌─────────────────────────────┐  │               │
│              │  │ SQLite  — scan cache +       │  │               │
│              │  │          HMAC trust list     │  │               │
│              │  └─────────────────────────────┘  │               │
│              │                                   │               │
│              │  Pillars (run concurrently):      │               │
│              │   Contextify ─ embedding cosine   │               │
│              │   Sentinel   ─ NPM registry       │               │
│              │   Shield     ─ scripts + AST diff │               │
│              │   Aggregator ─ weighted scoring   │               │
│              └──────────────────────────────────┘               │
│                         │             │                          │
└─────────────────────────│─────────────│──────────────────────────┘
                          │             │
                          ▼             ▼
              registry.npmjs.org    Ollama (optional, local)
              api.npmjs.org/downloads
```

## Component responsibilities

### npm-shim.js
Transparent `npm` replacement installed earlier on `PATH`. Intercepts `npm install <pkg>` calls, POSTs each package to `/api/v1/scan`, and exits 1 on `BLOCK`. SHA-256 self-integrity check on every invocation. Fails open if the daemon is unreachable.

### VS Code Extension
- **DaemonClient** — typed HTTP client; returns safe ALLOW on daemon offline.
- **SentinelHook** — tracks AI-suggested packages via VS Code terminal data events; sets `ai_suggested=true` in scan requests.
- **Interceptor** — `FileSystemWatcher` on `package.json` diffs; scans newly-added dependencies automatically.
- **StatusBarManager** — colour-coded status bar with auto-reset.
- **NotificationUI** — WARN/BLOCK dialogs and a Webview details panel showing per-pillar breakdown.

### CIDAS Daemon
FastAPI app on port 7355. All three analysis pillars run concurrently with `asyncio.gather`. Results are cached in SQLite (1-hour TTL). Policy resolution, trust-list bypass, and cache lookups are checked before pillars run.

### Pillar: Contextify (weight 30%)
1. Walk JS/TS source files in the project; extract existing import names.
2. Embed the existing imports using **sentence-transformers** (`all-MiniLM-L6-v2`).
3. Embed the candidate package description from the npm registry.
4. Cosine similarity → inverted risk score.
5. **Floor rule:** packages with similarity < 0.05 receive a flat +20 penalty regardless of weight, so an alien package combined with even modest signals from other pillars reaches WARN.

Embeddings are computed in-memory per request. ChromaDB persistence is a planned optimisation for repeat scans.

### Pillar: Sentinel (weight 35%)
Runs for every package. The depth of analysis depends on `ai_suggested`:

**All packages:**
- Registry existence check (nonexistent package → score ≥ 85, always BLOCKed regardless of other pillars)
- Levenshtein edit-distance ≤ 2 against a bundled top-50 list → `typosquat_detected`
- For existing, non-typosquat packages: zero/very-low downloads, missing repository link

When `scan_transitive=true` in the scan request, Sentinel is also run on each transitive dependency (up to 30, shallowest-first). Results appear in `transitive_risks`; `transitive_risk_detected` is set when any transitive score ≥ 50.

**AI-suggested packages additionally:**
- Full hallucination-risk analysis: package age, download count, maintainer count
- Stricter scoring thresholds (very-new-package +35, zero-downloads +20, typosquat +40)

### Pillar: Shield (weight 35%)
1. Fetch lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) from registry metadata.
2. Pattern scan: `eval`, `curl`/`wget`, base64 decode, `process.env.*TOKEN`, obfuscated hex, crypto-miner strings.
3. Download tarball; extract up to 50 files; apply the same patterns at a reduced weight (0.6×) to avoid false positives from minified bundles.
4. **Cross-version diff:** compare AST capability sets between the candidate version and the previous release; flag newly-introduced `process.env` access, network calls, or dangerous imports not present before (catches event-stream-style attacks).
5. **README injection scan:** regex scan for known prompt-injection phrases.
6. **LLM second pass (optional):** when `LLM_VERIFICATION_ENABLED=true` and the primary injection score exceeds the threshold, forwards README text to a local Ollama instance. README is passed as data (not instructions), so the model cannot be primed by embedded injection tokens. Falls back silently if Ollama is unreachable.

### Aggregator
```
risk_score = 0.30 × contextify.score
           + 0.35 × sentinel.score
           + 0.35 × shield.score
```
Weights are read from `.env` at call time and can be overridden per-machine (`~/.cidas/config.json`) or per-project (`.cidas/policy.json`). `contextify_weight` is clamped to [0.0, 0.5]; the remainder is split between Sentinel and Shield proportionally.

| Score | Decision | Behaviour |
|---|---|---|
| 0–39 | ALLOW | Silent pass |
| 40–79 | WARN | Warning dialog, install continues |
| 80–100 | BLOCK | Install aborted |

Special rules:
- `package_not_found` in Sentinel flags → score floored to `BLOCK_THRESHOLD` unconditionally.
- Contextify floor penalty (+20) applies before clamping.
- Policy `block_list` → `BLOCK` with `risk_score=100`, no pillars run.
- Policy `trust_list` / local trust list → `ALLOW` with `risk_score=0`, no pillars run.

### Policy Engine
Resolves `.cidas/policy.json` by walking up ancestor directories (capped at 10 levels). `block_list` and `trust_list` bypass all pillars. `warn_requires_confirmation` propagates to both the npm shim and VS Code dialog. See [policy-engine.md](policy-engine.md).

## Project structure

```
cidas/
├── daemon/                   Python FastAPI daemon
│   ├── pillars/
│   │   ├── contextify.py     Embedding-based project context
│   │   ├── sentinel.py       Registry reputation & typosquat
│   │   ├── shield.py         Script scanning, tarball AST, version diff
│   │   └── aggregator.py     Weighted scoring & verdict
│   ├── utils/
│   │   ├── audit_log.py      Append-only JSONL audit log with rotation
│   │   ├── policy.py         .cidas/policy.json discovery + validation
│   │   ├── offline_cache.py  name@version offline-allow cache (shim fallback)
│   │   ├── npm_registry.py   Registry lookups + tarball download
│   │   ├── embeddings.py     Sentence embedding helpers
│   │   ├── diff_analyzer.py  Cross-version diff: new imports, env, network calls
│   │   ├── llm_verifier.py   Optional Ollama second-pass for README text
│   │   ├── transitive.py     Recursive npm dependency resolution
│   │   ├── disk_checker.py   Install footprint + available disk estimation
│   │   └── logger.py         Structured logging
│   ├── tests/                357 pytest tests (91% coverage)
│   ├── auth.py               Bearer token generation & verification
│   ├── cli.py                `python -m daemon.cli audit …`
│   ├── config.py             Pydantic settings from .env
│   ├── database.py           SQLite scan cache & HMAC trust list
│   ├── models.py             Shared Pydantic request/response models
│   ├── router.py             FastAPI endpoints
│   └── main.py               App factory & uvicorn entry point
├── extension/                VS Code extension (TypeScript)
│   └── src/
│       ├── daemonClient.ts   HTTP client with fail-open fallback
│       ├── interceptor.ts    package.json watcher & dep diffing
│       ├── sentinelHook.ts   Terminal listener for AI-suggested packages
│       ├── statusBar.ts      Colour-coded status bar manager
│       ├── notificationUI.ts Warn/block/allow dialogs & webview panel
│       └── extension.ts      Activation & command registration
├── intercept/                npm shim (cross-platform)
│   ├── npm-shim.js           Transparent npm wrapper with SHA-256 self-check
│   ├── install-shim.sh       macOS/Linux installer
│   ├── install-shim.ps1      Windows installer (user-scope PATH)
│   ├── uninstall-shim.sh     macOS/Linux removal
│   ├── uninstall-shim.ps1    Windows removal
│   └── sign-shim.sh          Re-sign shim after update (macOS/Linux)
├── scripts/
│   ├── start-daemon.sh       Daemon launcher with venv bootstrap (macOS/Linux)
│   ├── start-daemon.ps1      Daemon launcher (Windows)
│   └── run-tests.sh          Combined pytest + vitest runner
└── .cidas/
    └── policy.schema.json    JSON Schema for project policy files
```

## Data flow — `npm install some-pkg`

1. Shim intercepts; sends `POST /api/v1/scan {package_name, project_path, ai_suggested}`.
2. Router resolves `.cidas/policy.json` (walks ancestor directories).
3. If `package_name` in `block_list` → immediate `BLOCK`, no further steps.
4. If `package_name` in `trust_list` → immediate `ALLOW`, mirror to offline cache.
5. Check SQLite trust list with HMAC verification → `ALLOW` if verified; `WARN` if legacy (no MAC).
6. Check SQLite scan cache → return cached result if hit.
7. `asyncio.gather(contextify.score, sentinel.score, shield.score)` — all three pillars run concurrently.
8. `Aggregator.aggregate()` → `(risk_score, explanation)`.
9. Apply policy penalties (`min_monthly_downloads`, `require_repository_link`).
10. Map score → decision; store result in SQLite; mirror `ALLOW` to offline cache.
11. Append direct dependencies, transitive Sentinel results, and disk footprint to response.
12. Append record to `~/.cidas/audit.log`.
13. Shim receives response: `ALLOW` → continues; `BLOCK` → exits 1.
14. VS Code extension independently shows a notification based on the same response.
