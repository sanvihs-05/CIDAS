/**
 * DaemonClient — HTTP client for the local CIDAS daemon.
 *
 * If the daemon is unreachable every method fails open: scan() returns a
 * safe ALLOW response with a warning flag rather than throwing, ensuring
 * that a stopped daemon never blocks the developer's workflow.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { Decision, PackageScanRequest, ScanResponse } from "./types";

function _daemonUrl(port: number): string {
  return `http://127.0.0.1:${port}/api/v1`;
}

const TOKEN_PATH = process.env.CIDAS_TOKEN_FILE
  || path.join(os.homedir(), ".cidas", "daemon.token");

/**
 * Read the daemon's bearer token from disk. Returns null when the file is
 * absent (daemon hasn't started yet) so callers can decide how to react.
 * Cached after first successful read to avoid hitting the FS per request.
 */
let _tokenCache: string | null | undefined;
function _readToken(): string | null {
  if (_tokenCache !== undefined) return _tokenCache;
  try {
    const t = fs.readFileSync(TOKEN_PATH, "utf8").trim();
    _tokenCache = t || null;
  } catch {
    _tokenCache = null;
  }
  return _tokenCache;
}

function _authHeader(): Record<string, string> {
  const t = _readToken();
  return t ? { "Authorization": `Bearer ${t}` } : {};
}

function _safeAllow(packageName: string, reason: string): ScanResponse {
  const zeroPillar = { score: 0, confidence: 0, flags: ["daemon_offline"], metadata: {} };
  return {
    package_name: packageName,
    version: null,
    decision: Decision.ALLOW,
    risk_score: 0,
    contextify: zeroPillar,
    sentinel: zeroPillar,
    shield: zeroPillar,
    alternatives: [],
    explanation: `CIDAS daemon unreachable — failing open. Reason: ${reason}`,
    latency_ms: 0,
  };
}

export class DaemonClient {
  private readonly port: number;

  // Tracks the most recently observed daemon reachability so consumers
  // (e.g. a status-bar indicator) can react without re-probing.
  private _offline = false;
  private readonly _stateListeners: Array<(online: boolean) => void> = [];
  private _pollingTimer: ReturnType<typeof setInterval> | undefined;

  constructor(port: number) {
    this.port = port;
  }

  /** Screen a package; returns a safe ALLOW if the daemon is offline. */
  async scan(request: PackageScanRequest): Promise<ScanResponse> {
    try {
      const resp = await fetch(`${_daemonUrl(this.port)}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ..._authHeader() },
        body: JSON.stringify(request),
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => String(resp.status));
        throw new Error(`HTTP ${resp.status}: ${text}`);
      }
      this._setOffline(false);
      return (await resp.json()) as ScanResponse;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this._setOffline(true);
      vscode.window.showWarningMessage(`CIDAS: daemon unreachable during scan — ${msg}`);
      return _safeAllow(request.package_name, msg);
    }
  }

  /** Returns true when the daemon responds to the health endpoint. */
  async health(): Promise<boolean> {
    let alive = false;
    try {
      const resp = await fetch(`${_daemonUrl(this.port)}/health`);
      alive = resp.ok;
    } catch {
      alive = false;
    }
    this._setOffline(!alive);
    return alive;
  }

  /** Returns true when the most recent probe found the daemon unreachable. */
  isOffline(): boolean {
    return this._offline;
  }

  /**
   * Subscribe to daemon reachability changes. The listener fires when the
   * online/offline state flips — not on every probe — so the listener can
   * map directly to a UI state transition.
   */
  onStatusChange(listener: (online: boolean) => void): vscode.Disposable {
    this._stateListeners.push(listener);
    return {
      dispose: () => {
        const idx = this._stateListeners.indexOf(listener);
        if (idx >= 0) this._stateListeners.splice(idx, 1);
      },
    };
  }

  /**
   * Start polling /health at ``intervalMs`` cadence. Returns a Disposable
   * that stops the polling. An immediate probe runs on call so the first
   * status update happens promptly.
   */
  startHealthPolling(intervalMs: number = 30_000): vscode.Disposable {
    if (this._pollingTimer) {
      clearInterval(this._pollingTimer);
    }
    // Fire-and-forget the first probe so the indicator updates immediately.
    void this.health();
    this._pollingTimer = setInterval(() => { void this.health(); }, intervalMs);
    return {
      dispose: () => {
        if (this._pollingTimer) {
          clearInterval(this._pollingTimer);
          this._pollingTimer = undefined;
        }
      },
    };
  }

  private _setOffline(offline: boolean): void {
    if (offline === this._offline) return;
    this._offline = offline;
    for (const listener of this._stateListeners) {
      try { listener(!offline); } catch { /* listener errors must not propagate */ }
    }
  }

  /** Add a package to the daemon's local trust bypass list. */
  async trust(packageName: string): Promise<void> {
    const resp = await fetch(`${_daemonUrl(this.port)}/trust`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ..._authHeader() },
      body: JSON.stringify({ package_name: packageName }),
    });
    if (!resp.ok) {
      throw new Error(`Trust call failed: HTTP ${resp.status}`);
    }
  }

  /** Purge expired entries from the daemon scan cache. */
  async clearCache(): Promise<void> {
    const resp = await fetch(`${_daemonUrl(this.port)}/cache`, {
      method: "DELETE",
      headers: { ..._authHeader() },
    });
    if (!resp.ok) {
      throw new Error(`Cache clear failed: HTTP ${resp.status}`);
    }
  }

  /**
   * Record a user "Proceed Anyway" override in the daemon audit log.
   * Failures are swallowed — a logging error must not interrupt the install.
   */
  async reportOverride(packageName: string, version?: string | null, verdictWas = "WARN"): Promise<void> {
    await this._postAuditEvent(packageName, version, verdictWas, "user_override");
  }

  /**
   * Record a user "Cancel install" intent.  The shim install runs out-of-process
   * and cannot be stopped from VS Code; this just preserves the audit trail.
   */
  async reportCancel(packageName: string, version?: string | null, verdictWas = "WARN"): Promise<void> {
    await this._postAuditEvent(packageName, version, verdictWas, "user_cancel_intent");
  }

  private async _postAuditEvent(
    packageName: string,
    version: string | null | undefined,
    verdictWas: string,
    event: string,
  ): Promise<void> {
    try {
      await fetch(`${_daemonUrl(this.port)}/audit/override`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ..._authHeader() },
        body: JSON.stringify({
          package_name: packageName,
          version: version ?? null,
          verdict_was: verdictWas,
          event,
        }),
      });
    } catch {
      // best-effort — never surface to user
    }
  }
}
