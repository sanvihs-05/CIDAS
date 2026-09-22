/**
 * Interceptor — watches package.json changes to detect newly added dependencies
 * and triggers a scan before the developer runs npm install.
 *
 * TODO(phase-2): full shell shim integration — hook the terminal task provider
 * to intercept `npm install` commands before they execute, rather than relying
 * on file-system events which are reactive rather than preventive.
 */
import * as vscode from "vscode";
import { DaemonClient } from "./daemonClient";
import { showAllowNotification, showBlockNotification, showWarnNotification } from "./notificationUI";
import { SentinelHook } from "./sentinelHook";
import { StatusBarManager } from "./statusBar";
import { Decision, PackageScanRequest } from "./types";

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export function _parseDeps(raw: string): Set<string> {
  try {
    const pkg = JSON.parse(raw) as PackageJson;
    return new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

export class Interceptor implements vscode.Disposable {
  private readonly _client: DaemonClient;
  private readonly _sentinel: SentinelHook;
  private readonly _statusBar: StatusBarManager;
  private readonly _prevDeps: Map<string, Set<string>> = new Map();
  private readonly _disposables: vscode.Disposable[] = [];

  constructor(client: DaemonClient, sentinel: SentinelHook, statusBar: StatusBarManager) {
    this._client = client;
    this._sentinel = sentinel;
    this._statusBar = statusBar;
  }

  activate(context: vscode.ExtensionContext): void {
    const watcher = vscode.workspace.createFileSystemWatcher("**/package.json", false, false, true);
    watcher.onDidCreate(this._onChange, this, this._disposables);
    watcher.onDidChange(this._onChange, this, this._disposables);
    context.subscriptions.push(watcher, ...this._disposables);
  }

  private _onChange = async (uri: vscode.Uri): Promise<void> => {
    if (uri.fsPath.includes("node_modules")) {
      return;
    }
    const cfg = vscode.workspace.getConfiguration("cidas");
    if (!cfg.get<boolean>("autoScan", true)) {
      return;
    }

    let raw: string | null;
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      raw = Buffer.from(bytes).toString("utf-8");
    } catch {
      raw = null;
    }
    if (!raw) {
      return;
    }

    const newDeps = _parseDeps(raw);
    const prev = this._prevDeps.get(uri.fsPath) ?? new Set<string>();
    const added = [...newDeps].filter((d) => !prev.has(d));
    this._prevDeps.set(uri.fsPath, newDeps);

    const projectPath =
      vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath ??
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ??
      "";

    for (const dep of added) {
      await this._scanDep(dep, projectPath);
    }
  };

  private async _scanDep(packageName: string, projectPath: string): Promise<void> {
    this._statusBar.setState("scanning", `Scanning ${packageName}…`);

    const req: PackageScanRequest = {
      package_name: packageName,
      project_path: projectPath,
      ai_suggested: this._sentinel.isAiSuggested(packageName),
      requesting_tool: "vscode-extension",
    };

    const response = await this._client.scan(req);

    switch (response.decision) {
      case Decision.ALLOW:
        showAllowNotification(packageName);
        this._statusBar.setState("idle");
        break;
      case Decision.WARN:
        this._statusBar.setState("warned", response.explanation);
        await showWarnNotification(response, {
          onProceed: () => this._client.reportOverride(response.package_name, response.version, "WARN"),
          onCancel:  () => this._client.reportCancel(response.package_name, response.version, "WARN"),
        });
        break;
      case Decision.BLOCK:
        this._statusBar.setState("blocked", response.explanation);
        await showBlockNotification(response);
        break;
    }
  }

  dispose(): void {
    this._disposables.forEach((d) => d.dispose());
  }
}
