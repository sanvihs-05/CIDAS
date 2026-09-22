# CIDAS — Context-Informed Dependency Analysis System

**Screens npm packages *before* they are installed** — catching typosquats, malicious install scripts, compromised updates, and AI-hallucinated package names, entirely on your machine.

A local Python daemon does the analysis. A transparent `npm` shim and a VS Code extension deliver the verdict. Nothing leaves your machine except ordinary registry lookups.

```
npm install <pkg>
      │
      ▼
npm shim (intercept/)
      │ POST /api/v1/scan
      ▼
Python daemon (localhost:7355)
  ├── Contextify   — does this package fit this project?
  ├── Sentinel     — registry reputation + typosquat + hallucination guard
  ├── Shield       — lifecycle script scan, tarball AST, cross-version diff
  └── Aggregator   — ALLOW / WARN / BLOCK
      │
      ▼
VS Code extension — inline verdict + notification
```

---

## Why this exists alongside npm audit, Socket, and Snyk

`npm audit` only catches known CVEs, after a vulnerability is reported and after install. Socket.dev detects malicious install scripts pre-install but has no awareness of *your* project or of AI-suggested package names. `npq` runs pre-install heuristics but is stateless and context-blind.

| Capability | npm audit | Socket | npq | Snyk | CIDAS |
|---|---|---|---|---|---|
| Pre-install interception | ✗ | ✓ | ✓ | ✗ | ✓ |
| Lifecycle script scan | ✗ | ✓ | ✗ | ✗ | ✓ |
| Tarball AST file scan | ✗ | ✗ | ✗ | ✗ | ✓ |
| Typosquat detection | ✗ | ✓ | ✗ | ✗ | ✓ |
| Project context scoring | ✗ | ✗ | ✗ | ✗ | ✓ |
| AI suggestion provenance | ✗ | ✗ | ✗ | ✗ | ✓ |
| Hallucination guard | ✗ | ✗ | ✗ | ✗ | ✓ |
| Cross-version diff analysis | ✗ | ✗ | ✗ | ✗ | ✓ |
| Adversarial README detection | ✗ | ✗ | ✗ | ✗ | ✓ |
| Fully on-device | ✓ | ✗ | ✓ | ✗ | ✓ |
| VS Code integration | ✗ | ✗ | ✗ | ✓* | ✓ |
| Per-project policy file | ✗ | ✗ | ✗ | ✗ | ✓ |

<sub>*Snyk's VS Code plugin surfaces post-install findings only.</sub>

### The five gaps CIDAS fills

1. **Project-context scoring** — no other tool asks whether a package makes sense *for your project*. A crypto-mining library is flagged identically whether it lands in a children's game or a trading system. CIDAS scores each candidate against your project's existing dependency fingerprint.
2. **AI suggestion provenance** — when an assistant suggests a package name that doesn't exist, an attacker can register it with malicious code. CIDAS watches VS Code language-model events and applies a stricter guard (registry existence, age, download count) to AI-suggested names; human-typed names get the lighter check.
3. **Cross-version differential analysis** — `event-stream` (2018), `ua-parser-js` (2021), and `node-ipc` (2022) followed one pattern: a benign package's *next* version hid a payload. CIDAS diffs AST capability sets against the previous release, flagging new dangerous imports, new `process.env` access, and new network calls.
4. **Adversarial scanner manipulation** — LLM-based scanners can be talked out of a flag by a crafted README. CIDAS's optional local verifier evaluates README content as *data*, never as instructions.
5. **Repository-committable policy** — teams commit `.cidas/policy.json` alongside the code: block lists, trust lists, download minimums, weight overrides. Policy travels with the repo and overrides global config.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |
| VS Code | 1.89+ |

> **Windows:** run the bash commands in Git Bash or WSL2. The daemon itself runs natively via PowerShell.

## Quickstart

**1. Clone and configure**
```bash
git clone https://github.com/sanvihs-05/CIDAS.git cidas
cd cidas
cp .env.example .env     # defaults work out of the box
```

**2. Start the daemon**
```bash
bash scripts/start-daemon.sh        # macOS / Linux / WSL
.\scripts\start-daemon.ps1          # Windows PowerShell
```
Verify:
```bash
curl http://127.0.0.1:7355/api/v1/health
# → {"status":"ok","version":"0.1.0"}
```

**3. Install the VS Code extension**
```bash
cd extension && npm install && npm run compile
```
Open the project folder in VS Code and press **F5**. The status bar should read `$(shield) CIDAS ready`.

**4. Install the npm shim**
```bash
bash intercept/install-shim.sh && source ~/.bashrc   # macOS / Linux / WSL
.\intercept\install-shim.ps1                         # Windows PowerShell
```
Verify with `which npm` → `~/.cidas/npm`.

---

## Try it

```bash
npm install lodash
# [CIDAS ALLOW] Package passed screening (risk score ~8/100)

npm install lodahs
# [CIDAS WARNING] typosquat_detected — similar to lodash
```

A hallucinated name, straight against the API:
```bash
TOKEN=$(cat ~/.cidas/daemon.token)
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"totally-fake-pkg-xyz999","project_path":".","ai_suggested":true}' \
  | python3 -m json.tool
# "decision": "BLOCK", risk_score >= 80
```

Emergency bypass, if CIDAS blocks something you know is fine:
```bash
CIDAS_BYPASS=1 npm install <package>
```

---

## How decisions are made

Each scan produces a weighted 0–100 risk score across three pillars, compared against two thresholds.

| Score | Decision | Behaviour |
|---|---|---|
| 0–39 | **ALLOW** | Silent pass |
| 40–79 | **WARN** | Warning dialog, install continues |
| 80–100 | **BLOCK** | Install aborted |

| Pillar | Weight | What it checks |
|---|---|---|
| **Contextify** | 30% | Semantic similarity to your project's existing dependencies (`all-MiniLM-L6-v2`, CPU-only, local) |
| **Sentinel** | 35% | Registry reputation, package age, download count, typosquat detection, AI hallucination guard |
| **Shield** | 35% | Lifecycle scripts, tarball AST scan, prompt injection in README, cross-version capability diff |

On top of the weighted score, a set of deterministic gates supply a score *floor* — a package that doesn't exist, matches a known incident, or whose requested version can't be resolved is escalated regardless of how the weights fall.

---

## Trust list and policy

Trust a package permanently:
```bash
TOKEN=$(cat ~/.cidas/daemon.token)
curl -s -X POST http://127.0.0.1:7355/api/v1/trust \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib"}'
```

Or commit a per-project policy at `.cidas/policy.json`:
```json
{
  "version": 1,
  "block_list": ["known-bad-package"],
  "trust_list": ["my-internal-lib"],
  "warn_requires_confirmation": true
}
```
Policy is discovered by walking up ancestor directories. Unrecognized fields are a hard error rather than a silent no-op, so a typo can't quietly disable a rule. Full schema: [`docs/policy-engine.md`](docs/policy-engine.md).

---

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `BLOCK_THRESHOLD` | 80 | Risk score that triggers BLOCK |
| `WARN_THRESHOLD` | 40 | Risk score that triggers WARN |
| `CONTEXT_WEIGHT` | 0.30 | Contextify pillar weight |
| `SENTINEL_WEIGHT` | 0.35 | Sentinel pillar weight |
| `SHIELD_WEIGHT` | 0.35 | Shield pillar weight |
| `LLM_VERIFICATION_ENABLED` | false | Enable the Ollama README second pass |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `phi3:mini` | Local model to use |
| `DISK_CHECK_ENABLED` | true | Enable disk footprint analysis |
| `DRIFT_MONITORING_ENABLED` | true | Report score drift in `/health` |

Optional local LLM verification — install [Ollama](https://ollama.com), then:
```bash
ollama pull phi3:mini
# .env: LLM_VERIFICATION_ENABLED=true
```
If Ollama isn't running, CIDAS falls back to regex-only injection detection automatically.

---

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | None | Liveness check + drift level |
| POST | `/api/v1/scan` | Bearer | Screen a package |
| POST | `/api/v1/trust` | Bearer | Add a trust-list entry |
| GET | `/api/v1/trust/verify` | Bearer | Audit trust-list HMAC integrity |
| DELETE | `/api/v1/cache` | Bearer | Purge expired cache entries |
| POST | `/api/v1/cache/invalidate` | Bearer | Force re-scan of a version |
| GET | `/api/v1/audit` | Bearer | Query the scan log |
| POST | `/api/v1/audit/override` | Bearer | Record a manual override |
| GET | `/api/v1/policy` | Bearer | Resolve the project policy |

Swagger UI: http://127.0.0.1:7355/docs · Details: [`docs/api-reference.md`](docs/api-reference.md)

---

## Security properties

- **Fail-open** — daemon offline means ALLOW with a logged warning. CIDAS never becomes the reason you can't ship.
- **Bearer token auth** — every mutating endpoint requires the token at `~/.cidas/daemon.token` (mode 0600).
- **HMAC trust integrity** — direct SQLite edits are detected and logged at CRITICAL.
- **Shim self-integrity** — SHA-256 verified on every invocation; a tampered shim exits immediately.
- **Tarball path-traversal guard** — extraction refuses entries that escape the temp directory.
- **Append-only audit log** — JSONL at `~/.cidas/audit.log`; every verdict, bypass, and override recorded.

---

## Project layout

```
daemon/          FastAPI service — the analysis engine
  pillars/       contextify.py · sentinel.py · shield.py · aggregator.py
  utils/         registry client, AST diff, drift monitor, OSV client, policy, audit log
  eval/          corpus builder, evaluation harness, ablation study
  tests/         pytest suite
extension/       VS Code extension (TypeScript + vitest)
intercept/       cross-platform npm shim + install/uninstall/sign scripts
scripts/         daemon start + test runner (bash and PowerShell)
docs/            architecture · threat model · policy engine · API reference
.cidas/          policy JSON schema
```

## Running tests

```bash
bash scripts/run-tests.sh                              # everything

source daemon/.venv/bin/activate                       # daemon only
pytest daemon/tests/ -v --cov=daemon

cd extension && npx vitest run --coverage              # extension only
cd intercept && npx jest --coverage                    # shim only
```

This tree carries **540 daemon tests**, **99 extension tests**, and **55 shim tests**.

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Policy engine](docs/policy-engine.md)
- [API reference](docs/api-reference.md)

---

## Authors

Gayathri Sunil Nambiar · Nitya Sharma · Sanvi H S · Yuva T · Sriram Velumuri

Departments of Computer Science & Engineering and Artificial Intelligence & Machine Learning, **RV College of Engineering**, Bengaluru. Built under the RVCE Experiential Learning programme as an SDG-9-aligned infrastructure project, with guidance from Dr. Vijayalakshmi M N.

## License

[Apache License 2.0](LICENSE)
