"""build_corpus.py — generate the four benchmark JSONL corpus files.

This is the canonical source of truth for the corpus files. Rerunning the
script overwrites them. No network calls — every record is hardcoded from
publicly disclosed npm supply-chain incidents and well-known top packages.

Schema (per JSONL line)
-----------------------
    package_name (str)
    version       (str or "latest")
    ai_suggested  (bool)
    ground_truth  ("malicious" | "benign" | "typosquat" | "hallucinated")
    attack_type   ("install_script_exec" | "dependency_hijack" |
                   "protestware" | "credential_theft" | "typosquat" |
                   "account_takeover" | "worm_propagation" |
                   "ci_pipeline_compromise" | "none")

    ``worm_propagation`` vs. ``account_takeover`` vs. ``ci_pipeline_compromise``:
    these three are easy to conflate under a single "supply-chain incident"
    label but describe genuinely different propagation mechanisms, which
    matters for per-attack-type recall breakdowns —
      - ``worm_propagation``: the compromise is self-replicating with no
        further attacker action per hop (steals the victim's own npm/cloud
        tokens, auto-publishes malicious versions to every package that
        token can reach, repeats). Only campaigns with a confirmed automated
        propagation loop get this tag (e.g. Shai-Hulud).
      - ``account_takeover``: a single maintainer's publishing credentials
        are stolen (phishing, RAT-delivered credential theft, etc.) and the
        attacker manually publishes malicious versions of packages that
        account owns. No self-replication loop.
      - ``ci_pipeline_compromise``: the attacker hijacks a project's own
        CI/CD publish workflow (e.g. a malicious commit merged under a
        fabricated identity, executed through the project's legitimate
        GitHub Actions/OIDC trusted-publisher flow) rather than stealing
        credentials directly.
    source        (dataset / advisory ID or "synthetic")
    notes         (free-text human annotation)

Typosquat records carry an extra ``npm_registered: bool`` field encoding
whether the generated name is (to author's knowledge) actually published
on the npm registry. False = the name is a pure invented typosquat.
"""
from __future__ import annotations

import json
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"


# ────────────────────────────────────────────────────────────────────────────
# Malicious corpus — disclosed npm supply-chain incidents.
#
# Each entry: (package_name, version, attack_type, source, notes)
# All entries are sourced from public advisories / post-mortems. Versions
# match the disclosed compromised release where known; "*" means every
# released version was affected by the underlying compromise.
# ────────────────────────────────────────────────────────────────────────────
_MALICIOUS_RECORDS: list[tuple[str, str, str, str, str]] = [
    # event-stream / flatmap-stream (Nov 2018) — maintainer transferred control,
    # injected payload targeting the Copay Bitcoin wallet.
    ("event-stream", "3.3.6", "dependency_hijack", "npm-advisory-737",
     "Maintainer handed over control; published version pulled flatmap-stream which exfiltrated wallet keys."),
    ("flatmap-stream", "0.1.1", "install_script_exec", "npm-advisory-737",
     "Injected payload of the event-stream incident; ran on require to harvest Copay wallets."),
    ("flatmap-stream", "0.1.2", "install_script_exec", "npm-advisory-737",
     "Followup release of the malicious flatmap-stream payload."),

    # eslint-scope (July 2018) — npm token stolen via phishing, malicious
    # release stole .npmrc credentials.
    ("eslint-scope", "3.7.2", "account_takeover", "eslint-postmortem-2018-07",
     "Stolen-credentials publish; postinstall harvested ~/.npmrc to remote server."),
    ("eslint-config-eslint", "5.0.2", "account_takeover", "eslint-postmortem-2018-07",
     "Same incident as eslint-scope 3.7.2 — credential-stealing payload."),

    # ua-parser-js (Oct 2021) — three versions published from a hijacked
    # account; cryptominer + DanaBot infostealer.
    ("ua-parser-js", "0.7.29", "account_takeover", "github-advisory-GHSA-pjwm-rvh2-c87w",
     "Hijacked-account publish; preinstall delivered XMRig miner and Windows infostealer."),
    ("ua-parser-js", "0.8.0", "account_takeover", "github-advisory-GHSA-pjwm-rvh2-c87w",
     "Hijacked-account publish; same payload as 0.7.29."),
    ("ua-parser-js", "1.0.0", "account_takeover", "github-advisory-GHSA-pjwm-rvh2-c87w",
     "Hijacked-account publish; same payload as 0.7.29."),

    # coa (Nov 2021) — same actor as ua-parser-js, multiple version pushes.
    ("coa", "2.0.3", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack — same actor as ua-parser-js Oct 2021 attack."),
    ("coa", "2.0.4", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack continuation."),
    ("coa", "2.1.1", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack continuation."),
    ("coa", "2.1.3", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack continuation."),
    ("coa", "3.0.1", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack continuation."),
    ("coa", "3.1.3", "account_takeover", "github-advisory-GHSA-73qr-pfmq-6rp8",
     "coa hijack continuation."),

    # rc (Nov 2021) — same actor / family as coa + ua-parser-js.
    ("rc", "1.2.9", "account_takeover", "github-advisory-GHSA-g2q5-5433-rhrf",
     "rc hijack — same actor as coa / ua-parser-js."),
    ("rc", "1.3.9", "account_takeover", "github-advisory-GHSA-g2q5-5433-rhrf",
     "rc hijack continuation."),
    ("rc", "2.3.9", "account_takeover", "github-advisory-GHSA-g2q5-5433-rhrf",
     "rc hijack continuation."),

    # node-ipc protestware (March 2022) — author shipped peacenotwar payload
    # that wiped files on machines geolocated to RU/BY.
    ("node-ipc", "10.1.1", "protestware", "github-advisory-GHSA-97m3-w2cp-4xx6",
     "Author-introduced wiper; deleted files when geoIP matched Russia/Belarus."),
    ("node-ipc", "10.1.2", "protestware", "github-advisory-GHSA-97m3-w2cp-4xx6",
     "Same author protestware variant."),
    ("node-ipc", "10.1.3", "protestware", "github-advisory-GHSA-97m3-w2cp-4xx6",
     "Same author protestware variant."),
    ("peacenotwar", "*", "protestware", "github-advisory-GHSA-97m3-w2cp-4xx6",
     "Separately-published peacenotwar payload pulled in by node-ipc."),

    # colors / faker self-sabotage (Jan 2022).
    ("colors", "1.4.1", "protestware", "snyk-SNYK-JS-COLORS-2331906",
     "Author intentionally introduced infinite loop / non-functional code."),
    ("colors", "1.4.2", "protestware", "snyk-SNYK-JS-COLORS-2331906",
     "Same self-sabotage as 1.4.1."),
    ("faker", "6.6.6", "protestware", "snyk-SNYK-JS-FAKER-2331904",
     "Author emptied the package contents and bumped the version."),

    # Typosquat-malware cluster (Aug 2017 / 2018).
    ("crossenv", "6.1.1", "typosquat", "npm-blog-2017-08",
     "Typosquat of cross-env; postinstall exfiltrated environment vars."),
    ("cross-env.js", "*", "typosquat", "npm-blog-2017-08",
     "Typosquat of cross-env; same payload family."),
    ("mongose", "*", "typosquat", "npm-blog-2017-08",
     "Typosquat of mongoose."),
    ("babelcli", "*", "typosquat", "npm-blog-2017-08",
     "Typosquat of babel-cli; env exfil postinstall."),

    # Credential-theft cluster (May 2018) — getcookies family.
    ("getcookies", "*", "credential_theft", "npm-advisory-2018-05",
     "Backdoored package pulled by mailparser-mit; exfiltrated request cookies."),
    ("http-fetch-cookies", "*", "credential_theft", "npm-advisory-2018-05",
     "Wrapper of getcookies; same exfil chain."),
    ("http-fetch-cookies-2", "*", "credential_theft", "npm-advisory-2018-05",
     "Wrapper of getcookies; same exfil chain."),
    ("nodefetch", "*", "credential_theft", "npm-advisory-2018-05",
     "Backdoored mailparser dependency; cookie exfil."),
    ("mailparser-mit", "*", "credential_theft", "npm-advisory-2018-05",
     "Vector for getcookies backdoor — pulled malicious dep at install."),
    ("mongoose-getstats", "*", "credential_theft", "npm-advisory-2018-05",
     "Same getcookies family; presented itself as a mongoose helper."),

    # Discord token stealers (2020-2021).
    ("fallguys", "*", "credential_theft", "sonatype-2020-fallguys",
     "Pretended to be a Fall Guys API wrapper; stole Discord tokens & local files."),
    ("discordi.js", "*", "typosquat", "snyk-SNYK-JS-DISCORDIJS-1080999",
     "Typosquat of discord.js; harvested Discord auth tokens."),
    ("discord-selfbot-v14", "*", "credential_theft", "phylum-2023-discord",
     "Discord-themed token stealer surfaced via deceptive name."),

    # Long-tail typosquats of major tooling.
    ("electorn", "*", "typosquat", "snyk-electorn",
     "Typosquat of electron; published cryptominer."),
    ("ffmepg", "*", "typosquat", "snyk-ffmepg",
     "Typosquat of ffmpeg; credential exfil postinstall."),

    # ── Shai-Hulud (Sept 2025) — genuine self-propagating worm ─────────────
    # Verified: Socket.dev "tinycolor-supply-chain-attack-affects-40-packages";
    # CISA alert 2025/09/23; mechanism corroborated by CISA, Wiz, Unit 42,
    # Securelist. Malicious postinstall ran TruffleHog to harvest secrets,
    # checked cloud IMDS endpoints, exfiltrated to a public GitHub repo, then
    # auto-published to every further package the harvested npm token could
    # reach — no attacker action required per hop. This is a partial list;
    # the full ~40-package set is at Socket's original post, pulled directly
    # rather than guessed at from a truncated retrieval.
    ("angulartics2", "14.1.2", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025); CISA alert 2025/09/23",
     "Republished with Shai-Hulud worm payload after maintainer's npm token was harvested via a prior "
     "compromised dependency and reused to auto-publish to every package that maintainer could update."),
    ("@ctrl/tinycolor", "4.1.1", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025)",
     "Reportedly the initial/index package in this wave per Socket's original report title; same "
     "stolen-token auto-publish mechanism."),
    ("@ctrl/tinycolor", "4.1.2", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025)",
     "Second malicious version published within the same window."),
    ("@ctrl/deluge", "7.2.2", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025)",
     "Automated republish via stolen maintainer npm token; part of the same @ctrl/* family cascade."),
    ("koa2-swagger-ui", "5.11.2", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025)",
     "Automated republish via stolen maintainer npm token."),
    ("json-rules-engine-simplified", "0.2.4", "worm_propagation",
     "Socket.dev: tinycolor-supply-chain-attack-affects-40-packages (Sept 2025)",
     "Automated republish via stolen maintainer npm token."),

    # ── qix / chalk-debug compromise (Sept 2025) — account takeover, NOT a
    # worm: single maintainer phished, attacker manually published these
    # versions directly. No self-propagation loop was documented. Limited
    # here to the two headline package/version pairs independently confirmed
    # across Wiz, nodejs-security.com, Endor Labs, and Checkmarx — a broader
    # ~18-package list exists but exact versions for most of it were only
    # single-sourced (nodejs-security.com), so it's deliberately excluded
    # pending cross-verification against the npm registry / GHSA entries.
    ("debug", "4.4.2", "account_takeover",
     "Wiz Threat Center: Qix npm package supply chain compromise; nodejs-security.com advisory (Sept 9 2025)",
     "Maintainer 'qix' phished via a fake npmjs.help domain requesting a 2FA reset; attacker published "
     "this version directly using stolen credentials plus a live TOTP code — no self-propagation."),
    ("chalk", "5.6.1", "account_takeover",
     "Wiz Threat Center: Qix npm package supply chain compromise; nodejs-security.com advisory (Sept 9 2025)",
     "Same compromised-account mechanism as debug@4.4.2; fixed in chalk@5.6.2."),

    # ── "Mini Shai-Hulud" / TanStack compromise (May 2026) — CI/CD pipeline
    # compromise, not a worm and not a stolen-token takeover: a malicious
    # commit was merged under a fabricated identity impersonating the
    # Anthropic Claude GitHub App, and publish executed through TanStack's
    # own legitimate GitHub Actions OIDC trusted-publisher workflow.
    # Verified via GHSA-g7cv-rxg3-hmpx, CVE-2026-45321 (NVD), and independent
    # corroboration (Snyk, StepSecurity, SentinelOne, Endor Labs, Tenable).
    ("@tanstack/react-router", "1.169.5", "ci_pipeline_compromise",
     "GHSA-g7cv-rxg3-hmpx (github.com/TanStack/router/security/advisories); CVE-2026-45321 (NVD)",
     "Malicious commit merged under a fabricated identity impersonating the Anthropic Claude GitHub App; "
     "published via TanStack's own legitimate GitHub Actions OIDC trusted-publisher workflow."),
    ("@tanstack/react-router", "1.169.8", "ci_pipeline_compromise",
     "GHSA-g7cv-rxg3-hmpx; CVE-2026-45321",
     "Second malicious version in the same publish window (fixed in 1.169.9)."),
    ("@tanstack/router-core", "1.169.5", "ci_pipeline_compromise",
     "GHSA-g7cv-rxg3-hmpx; SentinelOne CVE-2026-45321 vulnerability entry",
     "Same CI-workflow-hijack mechanism as react-router; part of the same 42-package/84-version batch."),
    ("@tanstack/arktype-adapter", "1.166.12", "ci_pipeline_compromise",
     "GHSA-g7cv-rxg3-hmpx",
     "Same publish batch; fixed in 1.166.16."),
    ("@tanstack/history", "1.161.9", "ci_pipeline_compromise",
     "GHSA-g7cv-rxg3-hmpx",
     "Same publish batch; fixed in 1.161.13."),

    # ── Axios compromise (March 2026) — account takeover, NOT a worm: lead
    # maintainer's long-lived npm token stolen via RAT delivered through
    # targeted social engineering; attacker manually published, bypassing
    # axios's normal GitHub Actions OIDC trusted-publisher flow entirely.
    # Verified via axios/axios GitHub Issue #10636 (maintainers' own
    # postmortem) plus CISA, Microsoft, Sophos, Trend Micro, StepSecurity,
    # Huntress, SANS, and Arctic Wolf.
    ("axios", "1.14.1", "account_takeover",
     "axios/axios GitHub Issue #10636 (official postmortem, March 31 2026); CISA alert 2026/04/20",
     "Lead maintainer's npm publishing credentials stolen via RAT delivered through targeted social "
     "engineering; attacker manually published this version, bypassing the project's OIDC trusted-"
     "publisher flow. Fixed/safe version: axios@1.14.0."),
    ("axios", "0.30.4", "account_takeover",
     "axios/axios GitHub Issue #10636; CISA alert 2026/04/20",
     "Same compromised-account mechanism; legacy 0.x release line, published in the same ~3-hour window "
     "as 1.14.1. Fixed/safe version: axios@0.30.3."),
    ("plain-crypto-js", "4.2.1", "account_takeover",
     "Microsoft Security Blog (Apr 1 2026); StepSecurity technical analysis (Mar 31 2026)",
     "Injected as a new, never-imported dependency of the malicious axios versions; its postinstall hook "
     "was the actual RAT dropper for macOS/Windows/Linux, while axios's own source was left unmodified."),
    ("plain-crypto-js", "4.2.0", "account_takeover",
     "Huntress blog (Mar 31 2026); Trend Micro (Mar 31 2026)",
     "Decoy/seed version published ~18 hours before the malicious 4.2.1 release, from a separate "
     "throwaway npm account, to build clean publishing history and reduce automated-scanner suspicion."),
]


def _record_malicious(name: str, version: str, attack: str, source: str, notes: str) -> dict:
    return {
        "package_name": name,
        "version": version if version != "*" else "latest",
        "ai_suggested": False,
        "ground_truth": "malicious",
        "attack_type": attack,
        "source": source,
        "notes": notes,
    }


# ────────────────────────────────────────────────────────────────────────────
# Typosquat corpus — synthetic near-miss variants of the top-10 packages.
# Mutation strategies: deletion, insertion, qwerty-adjacent substitution,
# homoglyph (l→1, o→0, i→l), prefix/suffix addition.
# ────────────────────────────────────────────────────────────────────────────
#
# Each tuple: (name, target, mutation, npm_registered)
#   target       — the legitimate package being squatted
#   mutation     — which transform produced this name (for analytic slicing)
#   npm_registered — author's knowledge of whether the name is actually
#                    published on npm. Conservative default is False.
_TYPOSQUAT_RECORDS: list[tuple[str, str, str, bool]] = [
    # react ──────────────────────────────────────────────────────────────────
    ("rect",             "react",      "deletion",   False),
    ("reactt",           "react",      "insertion",  False),
    ("teact",            "react",      "qwerty_swap", False),  # r→t adjacent
    ("react-js",         "react",      "suffix",     True),
    ("node-react",       "react",      "prefix",     False),

    # lodash ─────────────────────────────────────────────────────────────────
    ("lodsh",            "lodash",     "deletion",   False),
    ("lodashx",          "lodash",     "insertion",  False),
    ("l0dash",           "lodash",     "homoglyph",  False),  # o→0
    ("1odash",           "lodash",     "homoglyph",  False),  # l→1
    ("lodash-util",      "lodash",     "suffix",     False),

    # express ────────────────────────────────────────────────────────────────
    ("exprss",           "express",    "deletion",   False),
    ("expresss",         "express",    "insertion",  False),
    ("exoress",          "express",    "qwerty_swap", False),  # p→o adjacent
    ("express-js",       "express",    "suffix",     False),
    ("node-express",     "express",    "prefix",     False),

    # axios ──────────────────────────────────────────────────────────────────
    ("axos",             "axios",      "deletion",   False),
    ("axioss",           "axios",      "insertion",  False),
    ("axlos",            "axios",      "homoglyph",  False),  # i→l
    ("axios-js",         "axios",      "suffix",     False),
    ("node-axios",       "axios",      "prefix",     False),

    # webpack ────────────────────────────────────────────────────────────────
    ("webpck",           "webpack",    "deletion",   False),
    ("webpackk",         "webpack",    "insertion",  False),
    ("weboack",          "webpack",    "qwerty_swap", False),  # p→o adjacent
    ("webpack-js",       "webpack",    "suffix",     False),
    ("node-webpack",     "webpack",    "prefix",     False),

    # typescript ─────────────────────────────────────────────────────────────
    ("typescrpt",        "typescript", "deletion",   False),
    ("typescripts",      "typescript", "insertion",  False),
    ("typescrlpt",       "typescript", "homoglyph",  False),  # i→l
    ("typescript-js",    "typescript", "suffix",     False),
    ("node-typescript",  "typescript", "prefix",     False),

    # moment ─────────────────────────────────────────────────────────────────
    ("momnt",            "moment",     "deletion",   False),
    ("momentt",          "moment",     "insertion",  False),
    ("m0ment",           "moment",     "homoglyph",  False),  # o→0
    ("moment-util",      "moment",     "suffix",     False),
    ("node-moment",      "moment",     "prefix",     False),

    # chalk ──────────────────────────────────────────────────────────────────
    ("chak",             "chalk",      "deletion",   False),
    ("chalkk",           "chalk",      "insertion",  False),
    ("cha1k",            "chalk",      "homoglyph",  False),  # l→1
    ("chalk-js",         "chalk",      "suffix",     False),
    ("node-chalk",       "chalk",      "prefix",     False),

    # commander ──────────────────────────────────────────────────────────────
    ("commnder",         "commander",  "deletion",   False),
    ("commanderr",       "commander",  "insertion",  False),
    ("c0mmander",        "commander",  "homoglyph",  False),  # o→0
    ("commander-util",   "commander",  "suffix",     False),
    ("node-commander",   "commander",  "prefix",     False),

    # uuid ───────────────────────────────────────────────────────────────────
    ("uud",              "uuid",       "deletion",   False),
    ("uuidx",            "uuid",       "insertion",  False),
    ("uu1d",             "uuid",       "homoglyph",  False),  # i→1
    ("uuid-js",          "uuid",       "suffix",     True),   # actually published
    ("node-uuid",        "uuid",       "prefix",     True),   # legacy deprecated package
]


def _record_typosquat(name: str, target: str, mutation: str, npm_registered: bool) -> dict:
    return {
        "package_name": name,
        "version": "latest",
        "ai_suggested": False,
        "ground_truth": "typosquat",
        "attack_type": "typosquat",
        "source": "synthetic",
        "notes": f"Mutation={mutation}; target={target}; npm_registered={npm_registered}",
        "npm_registered": npm_registered,
        "target": target,
        "mutation": mutation,
    }


# ────────────────────────────────────────────────────────────────────────────
# Hallucinated corpus — plausibly-named packages that (to author's
# knowledge) do not exist on npm. Tests the AI-hallucination path: each
# record is marked ai_suggested=True.
# ────────────────────────────────────────────────────────────────────────────
_HALLUCINATED_NAMES: list[tuple[str, str]] = [
    ("react-query-utils",         "Plausible utility extension of react-query"),
    ("express-middleware-chain",  "Sounds like a middleware composition helper"),
    ("lodash-async",              "Plausible async-aware lodash variant"),
    ("axios-retry-handler",       "Plausible retry middleware for axios"),
    ("webpack-config-helper",     "Plausible webpack config builder"),
    ("typescript-types-resolver", "Plausible TS namespace resolver"),
    ("moment-timezone-converter", "Plausible moment-timezone adjunct"),
    ("chalk-rainbow-formatter",   "Plausible rainbow text helper"),
    ("commander-prompt-builder",  "Plausible interactive prompt extension"),
    ("uuid-namespace-helper",     "Plausible namespace-id helper"),
    ("react-state-hooks",         "Plausible hooks library name"),
    ("express-validator-async",   "Plausible async wrapper of express-validator"),
    ("lodash-deep-merger",        "Plausible deep-merge utility"),
    ("axios-cache-middleware",    "Plausible response cache for axios"),
    ("webpack-plugin-loader",     "Plausible plugin discovery helper"),
    ("node-stream-utils",         "Plausible Node stream helper bundle"),
    ("fastify-cors-helper",       "Plausible cors plugin for fastify"),
    ("nest-auth-decorator",       "Plausible NestJS auth decorator"),
    ("mongoose-soft-delete-plugin", "Plausible soft-delete plugin"),
    ("typeorm-migration-runner",  "Plausible CLI runner for TypeORM migrations"),
    ("socket-io-cluster-adapter", "Plausible cluster adapter for socket.io"),
    ("jest-mock-factory",         "Plausible test mock helper"),
    ("prettier-config-resolver",  "Plausible prettier config locator"),
]


def _record_hallucinated(name: str, notes: str) -> dict:
    return {
        "package_name": name,
        "version": "latest",
        "ai_suggested": True,
        "ground_truth": "hallucinated",
        "attack_type": "none",
        "source": "synthetic",
        "notes": notes,
    }


# ────────────────────────────────────────────────────────────────────────────
# Benign corpus — well-known packages from the top-500 by download count.
# ────────────────────────────────────────────────────────────────────────────
_BENIGN_PACKAGES: list[str] = [
    # 20 listed in the task spec
    "react", "lodash", "express", "axios", "typescript", "webpack", "jest",
    "prettier", "eslint", "moment", "chalk", "uuid", "dotenv", "cors",
    "helmet", "morgan", "passport", "jsonwebtoken", "bcrypt", "socket.io",
    # 30 more from top-500 npm packages by download count
    "react-dom", "vue", "next", "svelte", "classnames",
    "redux", "react-redux", "redux-thunk", "redux-saga",
    "mongoose", "mongodb", "mysql2", "pg", "sequelize", "sqlite3",
    "ioredis", "redis", "nodemailer", "body-parser", "cookie-parser",
    "express-session", "multer", "sharp", "joi", "yup", "zod", "ajv",
    "lru-cache", "ws", "node-fetch",
]


def _record_benign(name: str) -> dict:
    return {
        "package_name": name,
        "version": "latest",
        "ai_suggested": False,
        "ground_truth": "benign",
        "attack_type": "none",
        "source": "npm_top_500",
        "notes": "Known-safe baseline package; weekly downloads in millions.",
    }


# ────────────────────────────────────────────────────────────────────────────
# Writer
# ────────────────────────────────────────────────────────────────────────────

def _write_jsonl(name: str, records: list[dict]) -> int:
    path = CORPUS_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    return len(records)


def main() -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    counts = {
        "malicious":    _write_jsonl("malicious",    [_record_malicious(*t) for t in _MALICIOUS_RECORDS]),
        "typosquat":    _write_jsonl("typosquat",    [_record_typosquat(*t) for t in _TYPOSQUAT_RECORDS]),
        "hallucinated": _write_jsonl("hallucinated", [_record_hallucinated(*t) for t in _HALLUCINATED_NAMES]),
        "benign":       _write_jsonl("benign",       [_record_benign(n) for n in _BENIGN_PACKAGES]),
    }

    print("Corpus build summary:")
    for name, count in counts.items():
        print(f"  corpus/{name}.jsonl  : {count} records")


if __name__ == "__main__":
    main()
