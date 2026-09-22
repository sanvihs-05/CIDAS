/**
 * StatusBarManager — manages the CIDAS status bar item.
 *
 * States: idle → "CIDAS ready", scanning → "scanning…",
 *         blocked → red background, warned → yellow background,
 *         error → grey "daemon offline".
 *
 * After a verdict state (blocked/warned) the bar auto-resets to idle after 5 s.
 */
import * as vscode from "vscode";
import { StatusState } from "./types";

const _RESET_DELAY_MS = 5_000;

export class StatusBarManager implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  // Independent persistent indicator that surfaces when the daemon is
  // unreachable. Kept separate from `item` because that one auto-resets
  // and cycles through scan states; the offline warning must stay visible
  // until the daemon recovers.
  private readonly offlineItem: vscode.StatusBarItem;
  private resetTimer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, -100);
    this.item.command = "cidas.openDashboard";
    this.setState("idle");
    this.item.show();

    this.offlineItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, -101);
    this.offlineItem.text = "$(warning) CIDAS offline — installs unprotected";
    this.offlineItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    this.offlineItem.tooltip =
      "The CIDAS daemon is unreachable. New npm installs are not being scanned. " +
      "Start the daemon: bash scripts/start-daemon.sh";
    this.offlineItem.command = "cidas.openDashboard";
    // Hidden until the daemon is observed to be offline.
  }

  /**
   * Show / hide the persistent offline indicator. Idempotent — safe to call
   * on every health probe even when the state has not changed.
   */
  setDaemonOnline(online: boolean): void {
    if (online) {
      this.offlineItem.hide();
    } else {
      this.offlineItem.show();
    }
  }

  setState(state: StatusState, tooltip?: string): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = undefined;
    }

    switch (state) {
      case "idle":
        this.item.text = "$(shield) CIDAS ready";
        this.item.backgroundColor = undefined;
        this.item.tooltip = tooltip ?? "CIDAS Security — click to open dashboard";
        break;
      case "scanning":
        this.item.text = "$(sync~spin) CIDAS scanning…";
        this.item.backgroundColor = undefined;
        this.item.tooltip = tooltip ?? "Scanning package…";
        break;
      case "blocked":
        this.item.text = "$(error) CIDAS BLOCKED";
        this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
        this.item.tooltip = tooltip ?? "Package blocked by CIDAS";
        this._scheduleReset();
        break;
      case "warned":
        this.item.text = "$(warning) CIDAS warned";
        this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
        this.item.tooltip = tooltip ?? "Package flagged by CIDAS";
        this._scheduleReset();
        break;
      case "error":
        this.item.text = "$(shield) CIDAS: daemon offline";
        this.item.backgroundColor = undefined;
        this.item.tooltip = tooltip ?? "CIDAS daemon is not running";
        break;
    }
  }

  private _scheduleReset(): void {
    this.resetTimer = setTimeout(() => {
      this.setState("idle");
    }, _RESET_DELAY_MS);
  }

  dispose(): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
    }
    this.item.dispose();
    this.offlineItem.dispose();
  }
}
