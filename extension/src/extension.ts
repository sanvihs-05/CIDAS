/**
 * CIDAS VS Code extension entry point.
 *
 * Activates on startup, instantiates all components, checks daemon health,
 * and registers the three user-facing commands.
 */
import * as vscode from "vscode";
import { DaemonClient } from "./daemonClient";
import { Interceptor } from "./interceptor";
import { showDetailsPanel } from "./notificationUI";
import { SentinelHook } from "./sentinelHook";
import { StatusBarManager } from "./statusBar";

let _client: DaemonClient;
let _sentinel: SentinelHook;
let _interceptor: Interceptor;
let _statusBar: StatusBarManager;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const port = vscode.workspace.getConfiguration("cidas").get<number>("daemonPort", 7355);

  _statusBar = new StatusBarManager();
  _client = new DaemonClient(port);
  _sentinel = new SentinelHook();
  _interceptor = new Interceptor(_client, _sentinel, _statusBar);

  _sentinel.activate(context);
  _interceptor.activate(context);
  context.subscriptions.push(_statusBar, _sentinel, _interceptor);

  // Reflect daemon reachability changes in the persistent offline indicator.
  context.subscriptions.push(
    _client.onStatusChange((online) => _statusBar.setDaemonOnline(online)),
    _client.startHealthPolling(30_000),
  );

  // Probe daemon health asynchronously on startup
  _checkDaemonHealth();

  context.subscriptions.push(
    vscode.commands.registerCommand("cidas.scanPackage", _cmdScanPackage),
    vscode.commands.registerCommand("cidas.openDashboard", _cmdOpenDashboard),
    vscode.commands.registerCommand("cidas.clearCache", _cmdClearCache),
  );
}

export function deactivate(): void {
  // Disposables registered in context.subscriptions are cleaned up by VS Code.
}

async function _checkDaemonHealth(): Promise<void> {
  _statusBar.setState("scanning", "Connecting to CIDAS daemon…");
  const alive = await _client.health();
  if (alive) {
    _statusBar.setState("idle");
  } else {
    _statusBar.setState("error", "CIDAS daemon is offline — run: bash scripts/start-daemon.sh");
    vscode.window.showWarningMessage(
      "CIDAS daemon is not running. Start it to enable security screening.",
      "How to start",
    ).then((choice) => {
      if (choice === "How to start") {
        vscode.env.openExternal(
          vscode.Uri.parse("https://github.com/cidas/cidas#quick-start"),
        );
      }
    });
  }
}

async function _cmdScanPackage(): Promise<void> {
  const input = await vscode.window.showInputBox({
    prompt: "npm package to scan (e.g. lodash or lodash@4.17.21)",
    placeHolder: "package-name[@version]",
  });
  if (!input) {
    return;
  }

  const atIdx = input.lastIndexOf("@");
  const name    = atIdx > 0 ? input.slice(0, atIdx) : input;
  const version = atIdx > 0 ? input.slice(atIdx + 1) : undefined;

  const projectPath =
    vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";

  _statusBar.setState("scanning", `Scanning ${name}…`);
  const response = await _client.scan({
    package_name: name,
    version,
    project_path: projectPath,
    requesting_tool: "vscode-extension",
  });

  switch (response.decision) {
    case "ALLOW":
      _statusBar.setState("idle");
      break;
    case "WARN":
      _statusBar.setState("warned", response.explanation);
      break;
    case "BLOCK":
      _statusBar.setState("blocked", response.explanation);
      break;
  }

  showDetailsPanel(response);
}

async function _cmdOpenDashboard(): Promise<void> {
  const alive = await _client.health();
  if (!alive) {
    vscode.window.showErrorMessage("CIDAS daemon is offline.");
    _statusBar.setState("error");
    return;
  }
  const port = vscode.workspace.getConfiguration("cidas").get<number>("daemonPort", 7355);
  vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${port}/docs`));
}

async function _cmdClearCache(): Promise<void> {
  try {
    await _client.clearCache();
    vscode.window.showInformationMessage("CIDAS: scan cache cleared.");
  } catch (err) {
    vscode.window.showErrorMessage(`CIDAS: cache clear failed — ${String(err)}`);
  }
}
