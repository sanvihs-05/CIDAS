/**
 * SentinelHook — tracks packages suggested by AI assistants (Copilot, chat)
 * and marks them so the daemon applies the full hallucination-risk check.
 *
 * Detection strategy
 * ------------------
 * 1. Listen for terminal write events and parse "import X from 'Y'" patterns
 *    to catch packages pasted from AI suggestions.
 * 2. Expose ``registerAiSuggested()`` for other extension components that
 *    have direct knowledge of an AI suggestion event.
 *
 * TODO(phase-2): integrate with vscode.lm onDidReceiveMessage when the
 * Copilot-specific suggestion event API becomes stable and publicly available.
 * See: https://github.com/microsoft/vscode/issues/XXXX
 */
import * as vscode from "vscode";

const _IMPORT_RE = /(?:import\s+\S+\s+from\s+|require\s*\(\s*)['"](@?[\w/-]+)['"]/g;

export class SentinelHook implements vscode.Disposable {
  private readonly _aiSuggested: Map<string, boolean> = new Map();
  private readonly _disposables: vscode.Disposable[] = [];

  activate(context: vscode.ExtensionContext): void {
    // Listen to terminal output to detect packages pasted from AI responses
    // onDidWriteTerminalData is a proposed API not yet in @types/vscode 1.89
    const win = vscode.window as unknown as {
      onDidWriteTerminalData: (cb: (e: { data: string }) => void) => vscode.Disposable;
    };
    const termListener = win.onDidWriteTerminalData((e) => {
      this._parseTerminalData(e.data);
    });
    this._disposables.push(termListener);
    context.subscriptions.push(termListener);

    // TODO(phase-2): Register handler for vscode.lm.onDidReceiveMessage when
    // the API is available to detect Copilot inline completions.
    // Example (not yet stable):
    //   const lm = (vscode as { lm?: { onDidReceiveMessage?: unknown } }).lm;
    //   if (lm?.onDidReceiveMessage) { ... }
  }

  /** Manually register a package as AI-suggested (e.g. from a Copilot event). */
  registerAiSuggested(packageName: string): void {
    this._aiSuggested.set(packageName, true);
  }

  /** Return true if this package was detected as coming from an AI suggestion. */
  isAiSuggested(packageName: string): boolean {
    return this._aiSuggested.get(packageName) === true;
  }

  private _parseTerminalData(data: string): void {
    let match: RegExpExecArray | null;
    _IMPORT_RE.lastIndex = 0;
    while ((match = _IMPORT_RE.exec(data)) !== null) {
      const pkg = match[1];
      if (pkg && !pkg.startsWith(".")) {
        this._aiSuggested.set(pkg.split("/")[0], true);
      }
    }
  }

  dispose(): void {
    this._disposables.forEach((d) => d.dispose());
  }
}
