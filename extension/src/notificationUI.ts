/**
 * NotificationUI — user-facing dialogs and webview panel for scan results.
 */
import * as vscode from "vscode";
import { Decision, ScanResponse } from "./types";

const _SHOW_DETAILS  = "Show Details";
const _PROCEED       = "Proceed Anyway";
const _CANCEL_INSTALL = "Cancel install";
const _CANCEL        = "Cancel";

export interface WarnCallbacks {
  /** Called when the user picks "Proceed Anyway". */
  onProceed?: () => Promise<void>;
  /** Called when the user picks "Cancel install" so the daemon can record intent. */
  onCancel?:  () => Promise<void>;
}

export function showAllowNotification(packageName: string): void {
  vscode.window.setStatusBarMessage(`$(check) CIDAS: '${packageName}' passed security screening`, 4000);
}

export async function showWarnNotification(
  response: ScanResponse,
  callbacks?: WarnCallbacks,
): Promise<boolean> {
  // Order matters: VS Code renders the first action as the primary (recommended)
  // button. We deliberately put "Show Details" first so users read the warning
  // before clicking through, and "Cancel install" last as the safest fallback.
  const choice = await vscode.window.showWarningMessage(
    `CIDAS: '${response.package_name}' has a moderate risk score (${response.risk_score.toFixed(0)}/100). ${response.explanation}`,
    { modal: false },
    _SHOW_DETAILS,
    _PROCEED,
    _CANCEL_INSTALL,
  );

  if (choice === _SHOW_DETAILS) {
    showDetailsPanel(response);
    const second = await vscode.window.showWarningMessage(
      `Still install '${response.package_name}'?`,
      { modal: true },
      _CANCEL_INSTALL,
      _PROCEED,
    );
    if (second === _PROCEED) {
      await callbacks?.onProceed?.();
      return true;
    }
    if (second === _CANCEL_INSTALL) {
      await _handleCancel(response, callbacks);
    }
    return false;
  }

  if (choice === _PROCEED) {
    await callbacks?.onProceed?.();
    return true;
  }

  if (choice === _CANCEL_INSTALL) {
    await _handleCancel(response, callbacks);
  }
  return false;
}

async function _handleCancel(response: ScanResponse, callbacks?: WarnCallbacks): Promise<void> {
  await callbacks?.onCancel?.();
  // The shim install runs in a separate terminal — the extension cannot reach
  // into that subprocess to abort it.  Make the limitation explicit so the
  // user knows to Ctrl-C in their terminal as well.
  vscode.window.showInformationMessage(
    `CIDAS: cancel intent recorded for '${response.package_name}'. ` +
    `If an npm install is already running, abort it in your terminal (Ctrl-C).`,
  );
}

export async function showBlockNotification(response: ScanResponse): Promise<boolean> {
  const choice = await vscode.window.showErrorMessage(
    `CIDAS BLOCKED: '${response.package_name}' failed security screening (score ${response.risk_score.toFixed(0)}/100). ${response.explanation}`,
    { modal: true },
    _SHOW_DETAILS,
    _PROCEED,
    _CANCEL,
  );
  if (choice === _SHOW_DETAILS) {
    showDetailsPanel(response);
    const second = await vscode.window.showErrorMessage(
      `Override CIDAS and install '${response.package_name}' anyway?`,
      { modal: true },
      _PROCEED,
      _CANCEL,
    );
    return second === _PROCEED;
  }
  return choice === _PROCEED;
}

export function showDetailsPanel(response: ScanResponse): void {
  const panel = vscode.window.createWebviewPanel(
    "cidasDetails",
    `CIDAS: ${response.package_name}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  const decisionColor: Record<Decision, string> = {
    [Decision.ALLOW]: "var(--vscode-terminal-ansiGreen)",
    [Decision.WARN]:  "var(--vscode-terminal-ansiYellow)",
    [Decision.BLOCK]: "var(--vscode-terminal-ansiRed)",
  };

  const pillars = [
    { name: "Contextify", data: response.contextify },
    { name: "Sentinel",   data: response.sentinel },
    { name: "Shield",     data: response.shield },
  ];

  const pillarRows = pillars
    .map(({ name, data }) => {
      const flags = data.flags.join(", ") || "—";
      return `<tr><td>${name}</td><td>${data.score.toFixed(1)}</td><td>${data.confidence.toFixed(2)}</td><td>${flags}</td></tr>`;
    })
    .join("\n");

  const altList = response.alternatives.length
    ? `<p><strong>Alternatives:</strong> ${response.alternatives.join(", ")}</p>`
    : "";

  const policyLine = response.policy_file
    ? `<p><strong>Project policy:</strong> <code>${response.policy_file}</code></p>`
    : "";

  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
  body  { font-family: var(--vscode-font-family); padding: 16px; font-size: 13px; }
  h1    { font-size: 1.1em; margin-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; }
  th, td{ border: 1px solid var(--vscode-panel-border); padding: 5px 10px; text-align: left; }
  th    { background: var(--vscode-editor-inactiveSelectionBackground); }
  .decision { font-weight: bold; color: ${decisionColor[response.decision]}; }
</style>
</head>
<body>
<h1>CIDAS Scan Report — <code>${response.package_name}</code>${response.version ? `@${response.version}` : ""}</h1>
<p>Decision: <span class="decision">${response.decision}</span> &nbsp;|&nbsp;
   Risk score: <strong>${response.risk_score.toFixed(1)}/100</strong> &nbsp;|&nbsp;
   Latency: ${response.latency_ms.toFixed(0)} ms</p>
<p>${response.explanation}</p>
${altList}
${policyLine}
<table>
  <thead><tr><th>Pillar</th><th>Score</th><th>Confidence</th><th>Flags</th></tr></thead>
  <tbody>${pillarRows}</tbody>
</table>
<pre style="margin-top:16px;font-size:11px;opacity:0.6">${JSON.stringify(response, null, 2)}</pre>
</body>
</html>`;
}
