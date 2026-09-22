#!/usr/bin/env node
/**
 * CIDAS npm shim — transparent wrapper around the real npm binary.
 *
 * When `npm install [pkg...]` or `npm i [pkg...]` is detected:
 *   1. Each explicit package name is POSTed to the CIDAS daemon at
 *      http://127.0.0.1:7355/api/v1/scan.
 *   2. BLOCK → print a red error and exit(1) (respects CIDAS_BYPASS=1 escape hatch).
 *   3. WARN  → print a yellow warning and continue.
 *   4. ALLOW → print a green confirmation and continue.
 *
 * If the daemon is unreachable the shim ALWAYS passes through — it fails open
 * to avoid breaking developer workflows when the daemon is stopped.
 *
 * Configuration (environment variables):
 *   CIDAS_DAEMON_URL  — override daemon base URL (default http://127.0.0.1:7355)
 *   CIDAS_BYPASS=1    — skip all checks (emergency escape hatch; audited)
 *   CIDAS_REAL_NPM    — path to the real npm binary (auto-detected if unset)
 *
 * Admin configuration (~/.cidas/config.json):
 *   bypass_disabled: true            — prevents CIDAS_BYPASS=1 (CI enforcement)
 *   warn_requires_confirmation: true — on every WARN, prompt the developer
 *                                       to type 'proceed' before continuing
 *                                       (interactive TTY only; no-op in CI)
 *
 * Project policy (.cidas/policy.json) may also set warn_requires_confirmation
 * — the daemon surfaces it on the ScanResponse as ``requires_confirmation: true``,
 * which forces the prompt regardless of local config.
 */
"use strict";

const IS_WIN = process.platform === "win32";

/**
 * Compute the canonical self-hash of this file.
 *
 * Reads as UTF-8 and normalises CRLF → LF before hashing so a single shim
 * file produces the same SHA-256 regardless of how git checked it out
 * (autocrlf=true on Windows would otherwise change the hash). Used by both
 * the self-integrity check and the `--sign` subcommand below.
 */
function _computeSelfHash(filePath) {
  const _crypto = require("crypto");
  const _fs = require("fs");
  const text = _fs.readFileSync(filePath, "utf8").replace(/\r\n/g, "\n");
  return _crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

// `--sign` subcommand — write the current SHA-256 of this file to
// ~/.cidas/shim.sha256 and exit. Must run *before* the integrity check
// because resigning a deliberately-updated shim has to be possible even
// when the previously-stored hash no longer matches.
if (process.argv[2] === "--sign") {
  const _fs = require("fs");
  const _path = require("path");
  const _os = require("os");

  const hash = _computeSelfHash(__filename);
  const cidasDir = _path.join(_os.homedir(), ".cidas");
  try { _fs.mkdirSync(cidasDir, { recursive: true }); } catch { /**/ }
  const hashFile = process.env.CIDAS_HASH_FILE || _path.join(cidasDir, "shim.sha256");
  _fs.writeFileSync(hashFile, `${hash}  ${__filename}\n`);
  // chmod is a no-op on Windows; wrap so a permissions failure on a non-POSIX
  // FS doesn't kill the sign step.
  try { _fs.chmodSync(hashFile, 0o600); } catch { /**/ }
  process.stdout.write(`[CIDAS] Shim signed: ${hashFile}\n[CIDAS] SHA-256: ${hash}\n`);
  process.exit(0);
}

// Self-integrity check — runs synchronously before any other logic.
// Compares the SHA-256 of this file against ~/.cidas/shim.sha256 (written by
// sign-shim.sh / sign-shim.ps1 / `node npm-shim.js --sign` at install time).
// Exits 1 on mismatch; warns and continues when the hash file is absent
// (first-run / CI environments).
(function _integrityCheck() {
  const _fs0    = require("fs");
  const _path0  = require("path");
  const _os0    = require("os");

  const hashFile = process.env.CIDAS_HASH_FILE ||
    _path0.join(_os0.homedir(), ".cidas", "shim.sha256");

  let expected;
  try {
    // sha256sum / shasum format: "<hex>  <path>" — take the first token
    expected = _fs0.readFileSync(hashFile, "utf8").trim().split(/\s+/)[0];
  } catch {
    process.stderr.write(
      "\x1b[33m[CIDAS]\x1b[0m Shim hash file not found — run sign-shim.sh " +
      "(or `node npm-shim.js --sign` on Windows) to enable integrity " +
      "verification. Proceeding without check.\n"
    );
    return;
  }

  const actual = _computeSelfHash(__filename);

  if (actual !== expected) {
    process.stderr.write(
      "\x1b[31m[CIDAS] Shim integrity check FAILED — the shim file may have been " +
      "tampered with. Aborting to protect your system.\x1b[0m\n" +
      `  Expected: ${expected}\n` +
      `  Actual:   ${actual}\n`
    );
    process.exit(1);
  }
})();

const { spawnSync } = require("child_process");
const http  = require("http");
const https = require("https");
const path  = require("path");
const os    = require("os");
const fs    = require("fs");

const DAEMON_URL = process.env.CIDAS_DAEMON_URL || "http://127.0.0.1:7355";
const BYPASS     = Boolean(process.env.CIDAS_BYPASS);
const REAL_NPM   = process.env.CIDAS_REAL_NPM || _findRealNpm();
const TOKEN_PATH = process.env.CIDAS_TOKEN_FILE ||
  path.join(os.homedir(), ".cidas", "daemon.token");

// ── Helpers ───────────────────────────────────────────────────────────────────

function _findRealNpm() {
  // On Windows, npm ships as npm.cmd (sometimes npm.exe). The saved path
  // is written by install-shim.{sh,ps1}; if it happens to lack an extension
  // (older Linux installs being copied to a Windows machine, etc.) we tack
  // .cmd on so spawnSync can find it.
  const saved = path.join(os.homedir(), ".cidas", "real-npm");
  try {
    let p = fs.readFileSync(saved, "utf8").trim();
    if (IS_WIN && p && !/\.(cmd|exe|bat|ps1)$/i.test(p)) p += ".cmd";
    if (p) return p;
  } catch { /**/ }

  // Fall back to scanning PATH. On Windows we probe known launcher names
  // in the order Node's own resolver does; on POSIX, just 'npm'.
  const candidateNames = IS_WIN ? ["npm.cmd", "npm.exe", "npm"] : ["npm"];
  const shimDir = path.dirname(process.argv[1]);
  for (const dir of (process.env.PATH || "").split(path.delimiter).filter((d) => d !== shimDir)) {
    for (const name of candidateNames) {
      const cand = path.join(dir, name);
      try { fs.accessSync(cand, fs.constants.F_OK); return cand; } catch { /**/ }
    }
  }
  return IS_WIN ? "npm.cmd" : "npm";
}

/** Read ~/.cidas/config.json; returns {} when the file is absent or invalid JSON. */
function _readCidasConfig() {
  const configPath = path.join(os.homedir(), ".cidas", "config.json");
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Look up a package in ~/.cidas/offline-cache.json (written by the daemon
 * after every ALLOW verdict). Returns the cache entry when it is a valid,
 * unexpired ALLOW; null otherwise. Used only when the daemon is unreachable.
 */
function _checkOfflineCache(packageName, version) {
  const cachePath = path.join(os.homedir(), ".cidas", "offline-cache.json");
  let cache;
  try {
    cache = JSON.parse(fs.readFileSync(cachePath, "utf8"));
  } catch {
    return null;
  }
  // Key format matches the daemon's record_allow: "name@version" (or "name@latest").
  const cacheKey = `${packageName}@${version || "latest"}`;
  const entry = cache && cache[cacheKey];
  if (!entry || entry.verdict !== "ALLOW") return null;

  const ts = Date.parse(entry.timestamp);
  if (!Number.isFinite(ts)) return null;
  const ageHours = (Date.now() - ts) / 3_600_000;
  const ttlHours = Number(entry.ttl_hours);
  if (!Number.isFinite(ttlHours) || ageHours > ttlHours) return null;

  return entry;
}

/**
 * Append one structured JSON line to ~/.cidas/audit.log.
 * Creates the directory if it does not exist; silently swallows write errors
 * so a log failure never blocks an install.
 */
function _writeAuditLog(packageNames) {
  const cidasDir = path.join(os.homedir(), ".cidas");
  try { fs.mkdirSync(cidasDir, { recursive: true }); } catch { /**/ }
  const entry = JSON.stringify({
    timestamp:     new Date().toISOString(),
    package_names: packageNames,
    bypass_reason: "env_var",
    user:          process.env.USER || process.env.USERNAME || "unknown",
    cwd:           process.cwd(),
  });
  try {
    fs.appendFileSync(path.join(cidasDir, "audit.log"), entry + "\n");
  } catch (err) {
    process.stderr.write(`\x1b[33m[CIDAS]\x1b[0m Warning: could not write audit log: ${err.message}\n`);
  }
}

/**
 * Handle a CIDAS_BYPASS=1 request.
 *
 * If the admin config has bypass_disabled: true, print an error and exit 1.
 * Otherwise, write an audit log entry, print a visible warning, and return
 * so the caller can proceed with the passthrough.
 */
function _handleBypass(packageNames) {
  const config = _readCidasConfig();
  if (config.bypass_disabled) {
    process.stderr.write(
      "\x1b[31m[CIDAS]\x1b[0m CIDAS_BYPASS is disabled by admin configuration. " +
      "Contact your security team or remove bypass_disabled from ~/.cidas/config.json.\n"
    );
    process.exit(1);
    return; // unreachable; keeps static analysers happy
  }
  _writeAuditLog(packageNames);
  process.stderr.write(
    "\x1b[33m[CIDAS BYPASS]\x1b[0m Install proceeding without security check. " +
    "Logged to ~/.cidas/audit.log\n"
  );
}

/**
 * Read ~/.cidas/daemon.token (written at first daemon start). Returns null
 * when the file is absent; callers decide how to react. Whitespace and a
 * trailing newline are stripped so the bearer header is well-formed.
 */
function _readDaemonToken() {
  try {
    const t = fs.readFileSync(TOKEN_PATH, "utf8").trim();
    return t || null;
  } catch {
    return null;
  }
}

function _scan(name, version) {
  return new Promise((resolve, reject) => {
    const url    = new URL("/api/v1/scan", DAEMON_URL);
    const body   = JSON.stringify({
      package_name: name,
      version: version || null,
      project_path: process.cwd(),
      ai_suggested: false,
      requesting_tool: "npm-shim",
      scan_transitive: true,
    });
    const lib    = url.protocol === "https:" ? https : http;
    const token  = _readDaemonToken();
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
    };
    const options = {
      hostname: url.hostname,
      port: Number(url.port) || (url.protocol === "https:" ? 443 : 80),
      path: url.pathname,
      method: "POST",
      headers,
      timeout: 60_000,
    };
    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Invalid JSON from daemon: ${data.slice(0, 200)}`)); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Daemon request timed out after 60 s")); });
    req.write(body);
    req.end();
  });
}

function _passthrough() {
  // shell:true is required on Windows so cmd.exe can interpret npm.cmd /
  // npm.bat — without it, Node's CreateProcess call rejects the .cmd file
  // with ENOENT. On POSIX shell:false keeps the original argv plumbing
  // (no extra shell, no quoting surprises).
  const result = spawnSync(REAL_NPM, args, { stdio: "inherit", shell: IS_WIN });
  process.exit(result.status ?? 0);
}

/**
 * Print a structured disk-footprint block plus any size/space warnings.
 *
 * Writes an aligned key : value table to stdout showing all seven fields
 * returned by the daemon so the developer can see the full picture at a
 * glance. Warnings (large install, insufficient space, high dep count) go
 * to stderr so they stand out alongside other risk signals.
 *
 * Silent when disk_footprint is null (check disabled) or when the check
 * failed on the daemon side (disk_check_unavailable flag).
 */
function _printDiskFootprint(disk) {
  if (!disk) return;
  const flags = Array.isArray(disk.flags) ? disk.flags : [];
  if (flags.includes("disk_check_unavailable")) return;

  const KW  = 22;
  const row = (key, val) => `  ${key.padEnd(KW)}: ${val}`;

  const sizeVal    = flags.includes("size_unknown") ? "unknown" : String(disk.estimated_install_mb);
  const fitColor   = disk.will_fit ? "\x1b[32m" : "\x1b[31m";
  const fitMark    = disk.will_fit ? "✓" : "✗";
  const score      = disk.disk_risk_score || 0;
  const scoreColor = score >= 100 ? "\x1b[31m" : score >= 30 ? "\x1b[33m" : "\x1b[32m";
  const flagsStr   = flags.length ? `\x1b[33m${JSON.stringify(flags)}\x1b[0m` : "[]";

  process.stdout.write([
    `\x1b[36m[CIDAS]\x1b[0m Disk footprint:`,
    row("estimated_install_mb", sizeVal),
    row("available_disk_mb",    String(disk.available_disk_mb || 0)),
    row("node_modules_bytes",   String(disk.node_modules_bytes || 0)),
    row("dep_count",            String(disk.dep_count || 0)),
    row("will_fit",             `${fitColor}${fitMark} ${disk.will_fit}\x1b[0m`),
    row("flags",                flagsStr),
    row("disk_risk_score",      `${scoreColor}${score}\x1b[0m`),
    "",
  ].join("\n"));

  if (!disk.will_fit) {
    process.stderr.write(
      `\x1b[31m[CIDAS DISK WARNING]\x1b[0m Insufficient disk space — ` +
      `install requires ~${disk.estimated_install_mb} MB but only ` +
      `~${Math.round(disk.available_disk_mb || 0)} MB is free.\n`
    );
  } else if (flags.includes("very_large_install")) {
    process.stderr.write(
      `\x1b[33m[CIDAS DISK]\x1b[0m Very large install (~${disk.estimated_install_mb} MB). ` +
      `Verify you have sufficient disk space before proceeding.\n`
    );
  } else if (flags.includes("large_install")) {
    process.stderr.write(
      `\x1b[33m[CIDAS DISK]\x1b[0m Large install (~${disk.estimated_install_mb} MB).\n`
    );
  }

  if (flags.includes("high_dep_count")) {
    process.stderr.write(
      `\x1b[33m[CIDAS DISK]\x1b[0m High dependency count: ${disk.dep_count} transitive deps.\n`
    );
  }
}

/**
 * Decide whether the shim should prompt the user before continuing past a
 * WARN. Returns true when the policy/config asks for confirmation AND the
 * shell is interactive — non-TTY environments (CI, scripts) skip the prompt
 * so unattended runs don't hang.
 */
function _shouldPromptForWarn(scanResult, isTTY) {
  if (!isTTY) return false;
  if (scanResult && scanResult.requires_confirmation === true) return true;
  const config = _readCidasConfig();
  return config.warn_requires_confirmation === true;
}

/**
 * Prompt on stderr for a confirmation. Resolves true only when the user types
 * "proceed" (case-insensitive). Any other input resolves false. Ctrl-C while
 * the prompt is open exits with code 1 so unattended kills are unambiguous.
 */
function _promptProceed() {
  const readline = require("readline");
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input:  process.stdin,
      output: process.stderr,
    });
    rl.on("SIGINT", () => {
      rl.close();
      process.stderr.write("\n\x1b[31m[CIDAS]\x1b[0m Install cancelled by user.\n");
      process.exit(1);
    });
    rl.question(
      "[CIDAS] Type 'proceed' to continue or press Ctrl-C to cancel: ",
      (answer) => {
        rl.close();
        resolve(String(answer).trim().toLowerCase() === "proceed");
      },
    );
  });
}

// ── Main execution (skipped when require()'d by tests) ────────────────────────

const args = process.argv.slice(2);

function _main() {
  const subcmd    = args[0];
  const isInstall = subcmd === "install" || subcmd === "i" || subcmd === "add";

  if (!isInstall) {
    _passthrough();
  }

  // Parse packages before the bypass check so the audit log captures them.
  const packages = args
    .slice(1)
    .filter((a) => !a.startsWith("-") && a !== "install" && a !== "i");

  if (BYPASS) {
    _handleBypass(packages); // exits 1 if bypass_disabled; otherwise logs + returns
    _passthrough();
  }

  if (packages.length === 0) {
    // Bare `npm install` — installs from package.json; nothing to screen
    _passthrough();
  }

  // Refuse to proceed unauthenticated — a missing token means the daemon
  // has never run, so we can't actually screen anything anyway.
  if (!_readDaemonToken()) {
    process.stderr.write(
      "\x1b[31m[CIDAS]\x1b[0m Daemon token not found at " + TOKEN_PATH + ".\n" +
      "  Start the daemon at least once (it generates the token on first run).\n" +
      "  Refusing to install without authenticated screening.\n"
    );
    process.exit(1);
  }

  (async () => {
    let blocked = false;

    for (const pkg of packages) {
      // Handle scoped packages: @scope/name@version → split on last @
      const lastAt = pkg.lastIndexOf("@");
      const name    = lastAt > 0 ? pkg.slice(0, lastAt) : pkg;
      const version = lastAt > 0 ? pkg.slice(lastAt + 1) : null;

      process.stdout.write(`\x1b[36m[CIDAS]\x1b[0m Scanning \x1b[1m${pkg}\x1b[0m…\n`);

      let result;
      try {
        result = await _scan(name, version);
      } catch (err) {
        // Daemon unreachable — try the offline cache before failing open.
        const cached = _checkOfflineCache(name, version);
        if (cached) {
          // Known-good package within TTL; proceed silently.
          continue;
        }
        process.stderr.write(
          `\x1b[33m[CIDAS WARNING]\x1b[0m ⚠  Daemon offline AND no cached verdict for \x1b[1m${pkg}\x1b[0m. ` +
          `Proceeding without security check — verify this package manually before using it.\n`
        );
        continue;
      }

      const { decision, risk_score, explanation } = result;

      if (decision === "BLOCK") {
        process.stderr.write(`\x1b[31m[CIDAS BLOCKED]\x1b[0m ${explanation}\n`);
        blocked = true;
      } else if (decision === "WARN") {
        process.stderr.write(`\x1b[33m[CIDAS WARNING]\x1b[0m ${explanation}\n`);
        if (_shouldPromptForWarn(result, process.stdin.isTTY)) {
          const proceeded = await _promptProceed();
          if (!proceeded) {
            process.stderr.write(
              "\x1b[31m[CIDAS]\x1b[0m Install aborted: confirmation required " +
              "but user did not type 'proceed'.\n"
            );
            process.exit(1);
          }
        }
      } else {
        process.stdout.write(`\x1b[32m[CIDAS ALLOW]\x1b[0m ${explanation}\n`);
      }

      // Show direct dependencies
      const directDeps = result.direct_dependencies || [];
      if (directDeps.length > 0) {
        process.stdout.write(
          `\x1b[36m[CIDAS]\x1b[0m \x1b[1m${name}\x1b[0m requires ${directDeps.length} direct dependenc${directDeps.length === 1 ? "y" : "ies"}:\n`
        );
        for (const dep of directDeps) {
          process.stdout.write(`  \x1b[2m+\x1b[0m ${dep.name}  \x1b[2m${dep.version_range}\x1b[0m\n`);
        }
      }

      // Warn about risky transitive dependencies
      const riskyTransitive = (result.transitive_risks || []).filter(
        (r) => r.sentinel_score >= 50
      );
      if (riskyTransitive.length > 0) {
        process.stderr.write(
          `\x1b[33m[CIDAS]\x1b[0m \x1b[1m${riskyTransitive.length}\x1b[0m transitive dependenc${riskyTransitive.length === 1 ? "y" : "ies"} flagged as risky:\n`
        );
        for (const dep of riskyTransitive) {
          const flagStr = dep.flags.length ? `  [${dep.flags.join(", ")}]` : "";
          process.stderr.write(
            `  \x1b[33m!\x1b[0m ${dep.name}@${dep.version}  depth=${dep.depth}  score=${dep.sentinel_score}${flagStr}\n`
          );
        }
      }

      // Show disk footprint estimate
      _printDiskFootprint(result.disk_footprint || null);
    }

    if (blocked) {
      process.stderr.write(
        "\x1b[31m[CIDAS]\x1b[0m Install aborted. " +
        "Set \x1b[1mCIDAS_BYPASS=1\x1b[0m to override (not recommended).\n"
      );
      process.exit(1);
    }

    _passthrough();
  })();
}

if (require.main === module) {
  _main();
}

module.exports = {
  _readCidasConfig,
  _writeAuditLog,
  _handleBypass,
  _checkOfflineCache,
  _readDaemonToken,
  _scan,
  _shouldPromptForWarn,
  _promptProceed,
  _printDiskFootprint,
};
