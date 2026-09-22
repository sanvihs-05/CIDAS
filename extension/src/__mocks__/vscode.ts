/**
 * Minimal vscode API mock for Vitest.
 * Covers all APIs used across the extension source files.
 */
import { vi } from "vitest";

export enum StatusBarAlignment { Left = 1, Right = 2 }
export enum ViewColumn { Active = -1, Beside = -2, One = 1 }

export class ThemeColor {
  constructor(public readonly id: string) {}
}

export class Uri {
  constructor(public readonly fsPath: string) {}
  static parse(str: string): Uri { return new Uri(str); }
  static file(str: string):  Uri { return new Uri(str); }
  toString(): string { return this.fsPath; }
}

export const window = {
  createStatusBarItem: vi.fn(() => ({
    text: "" as string,
    tooltip: "" as string,
    backgroundColor: undefined as ThemeColor | undefined,
    command: "" as string,
    show: vi.fn(),
    hide: vi.fn(),
    dispose: vi.fn(),
  })),
  createWebviewPanel: vi.fn(() => ({
    webview: { html: "" },
    dispose: vi.fn(),
    reveal: vi.fn(),
  })),
  showWarningMessage:     vi.fn<any[], Promise<string | undefined>>().mockResolvedValue(undefined),
  showErrorMessage:       vi.fn<any[], Promise<string | undefined>>().mockResolvedValue(undefined),
  showInformationMessage: vi.fn<any[], Promise<string | undefined>>().mockResolvedValue(undefined),
  setStatusBarMessage:    vi.fn(),
  showInputBox:           vi.fn<any[], Promise<string | undefined>>().mockResolvedValue(undefined),
  onDidWriteTerminalData: vi.fn(() => ({ dispose: vi.fn() })),
};

export const workspace = {
  getConfiguration: vi.fn(() => ({
    get: vi.fn((_key: string, defaultVal: unknown) => defaultVal),
  })),
  fs: {
    readFile: vi.fn<any[], Promise<Uint8Array>>(),
  },
  createFileSystemWatcher: vi.fn(() => ({
    onDidCreate: vi.fn(() => ({ dispose: vi.fn() })),
    onDidChange: vi.fn(() => ({ dispose: vi.fn() })),
    dispose: vi.fn(),
  })),
  getWorkspaceFolder: vi.fn(),
  workspaceFolders: [] as { uri: Uri }[] | undefined,
};

export const commands = {
  registerCommand: vi.fn(() => ({ dispose: vi.fn() })),
};

export const env = {
  openExternal: vi.fn(),
};
