import { describe, it, expect, vi, beforeEach } from "vitest";
import { Decision, ScanResponse } from "./types";

/**
 * vi.mock() is hoisted above imports by Vitest. To share mock references between
 * the test file and interceptor.ts (which imports vscode independently), we use
 * vi.hoisted() to create the shared vi.fn() instances before the factories run,
 * then override 'vscode' via vi.mock() so both this file AND interceptor.ts
 * receive the exact same mock objects.
 */
const _readFile  = vi.hoisted(() => vi.fn());
const _getConfig = vi.hoisted(() =>
  vi.fn(() => ({ get: vi.fn((_k: string, d: unknown) => d) }))
);
const _createFSW = vi.hoisted(() =>
  vi.fn(() => ({
    // Implements VS Code's event emitter signature:
    // onDidXxx(listener, thisArg?, disposables?) — pushes returned Disposable into array
    onDidCreate: vi.fn((_cb: any, _th: any, arr?: any[]) => {
      const d = { dispose: vi.fn() };
      arr?.push(d);
      return d;
    }),
    onDidChange: vi.fn((_cb: any, _th: any, arr?: any[]) => {
      const d = { dispose: vi.fn() };
      arr?.push(d);
      return d;
    }),
    dispose: vi.fn(),
  }))
);

vi.mock("vscode", () => ({
  workspace: {
    getConfiguration: _getConfig,
    fs: { readFile: _readFile },
    createFileSystemWatcher: _createFSW,
    getWorkspaceFolder: vi.fn(),
    workspaceFolders: [],
  },
  window: {
    onDidWriteTerminalData: vi.fn(() => ({ dispose: vi.fn() })),
  },
}));

vi.mock("./notificationUI", () => ({
  showAllowNotification: vi.fn(),
  showWarnNotification:  vi.fn().mockResolvedValue(true),
  showBlockNotification: vi.fn().mockResolvedValue(false),
}));

import { _parseDeps, Interceptor } from "./interceptor";
import * as notifUI from "./notificationUI";

// ── _parseDeps (pure) ─────────────────────────────────────────────────────────

describe("_parseDeps", () => {
  it("extracts dependencies", () => {
    const deps = _parseDeps(JSON.stringify({ dependencies: { react: "^18", lodash: "^4" } }));
    expect(deps).toContain("react");
    expect(deps).toContain("lodash");
  });

  it("extracts devDependencies", () => {
    const deps = _parseDeps(JSON.stringify({ devDependencies: { vitest: "^1" } }));
    expect(deps).toContain("vitest");
  });

  it("merges dependencies and devDependencies", () => {
    const deps = _parseDeps(
      JSON.stringify({ dependencies: { react: "^18" }, devDependencies: { typescript: "^5" } })
    );
    expect(deps).toContain("react");
    expect(deps).toContain("typescript");
  });

  it("returns empty set for invalid JSON", () => {
    expect(_parseDeps("not-json").size).toBe(0);
  });

  it("returns empty set when both dependency fields are absent", () => {
    expect(_parseDeps(JSON.stringify({ name: "my-pkg" })).size).toBe(0);
  });

  it("returns empty set for empty string", () => {
    expect(_parseDeps("").size).toBe(0);
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

const zeroPillar = { score: 0, confidence: 0.9, flags: [], metadata: {} };

function makeScan(decision: Decision): ScanResponse {
  return {
    package_name: "lodash",
    version: null,
    decision,
    risk_score: 0,
    contextify: zeroPillar,
    sentinel:   zeroPillar,
    shield:     zeroPillar,
    alternatives: [],
    explanation: "ok",
    latency_ms: 1,
  };
}

function makeInterceptor() {
  const mockClient   = { scan: vi.fn().mockResolvedValue(makeScan(Decision.ALLOW)) } as any;
  const mockSentinel = { isAiSuggested: vi.fn().mockReturnValue(false) } as any;
  const mockStatusBar = { setState: vi.fn() } as any;
  return { interceptor: new Interceptor(mockClient, mockSentinel, mockStatusBar), mockClient, mockSentinel, mockStatusBar };
}

function makeUri(fsPath: string) {
  return { fsPath } as any;
}

// ── Interceptor._onChange ─────────────────────────────────────────────────────

describe("Interceptor._onChange", () => {
  beforeEach(() => {
    _readFile.mockReset();
    _getConfig.mockImplementation(() => ({ get: vi.fn((_k: string, d: unknown) => d) }));
    vi.mocked(notifUI.showAllowNotification).mockClear();
    vi.mocked(notifUI.showWarnNotification as any).mockClear();
    vi.mocked(notifUI.showBlockNotification as any).mockClear();
  });

  it("skips paths inside node_modules", async () => {
    const { interceptor, mockClient } = makeInterceptor();
    await (interceptor as any)._onChange(makeUri("/project/node_modules/pkg/package.json"));
    expect(mockClient.scan).not.toHaveBeenCalled();
  });

  it("skips when autoScan is disabled in config", async () => {
    _getConfig.mockReturnValue({
      get: vi.fn((key: string, def: unknown) => key === "autoScan" ? false : def),
    });
    const { interceptor, mockClient } = makeInterceptor();
    await (interceptor as any)._onChange(makeUri("/project/package.json"));
    expect(mockClient.scan).not.toHaveBeenCalled();
  });

  it("skips when the file cannot be read", async () => {
    _readFile.mockRejectedValue(new Error("ENOENT"));
    const { interceptor, mockClient } = makeInterceptor();
    await (interceptor as any)._onChange(makeUri("/project/package.json"));
    expect(mockClient.scan).not.toHaveBeenCalled();
  });

  it("scans newly added dependencies", async () => {
    const content = JSON.stringify({ dependencies: { lodash: "^4" } });
    _readFile.mockResolvedValue(Buffer.from(content));
    const { interceptor, mockClient } = makeInterceptor();
    await (interceptor as any)._onChange(makeUri("/project/package.json"));
    expect(mockClient.scan).toHaveBeenCalledOnce();
    expect(mockClient.scan.mock.calls[0][0].package_name).toBe("lodash");
  });

  it("does not re-scan unchanged deps on a second change event", async () => {
    const content = JSON.stringify({ dependencies: { lodash: "^4" } });
    _readFile.mockResolvedValue(Buffer.from(content));
    const { interceptor, mockClient } = makeInterceptor();
    const uri = makeUri("/project/package.json");
    await (interceptor as any)._onChange(uri);
    await (interceptor as any)._onChange(uri);
    expect(mockClient.scan).toHaveBeenCalledOnce();
  });

  it("scans only the newly added dep when an existing one is already known", async () => {
    const first  = JSON.stringify({ dependencies: { lodash: "^4" } });
    const second = JSON.stringify({ dependencies: { lodash: "^4", axios: "^1" } });
    _readFile
      .mockResolvedValueOnce(Buffer.from(first))
      .mockResolvedValueOnce(Buffer.from(second));
    const { interceptor, mockClient } = makeInterceptor();
    const uri = makeUri("/project/package.json");
    await (interceptor as any)._onChange(uri);
    await (interceptor as any)._onChange(uri);
    expect(mockClient.scan).toHaveBeenCalledTimes(2);
    expect(mockClient.scan.mock.calls[1][0].package_name).toBe("axios");
  });

  it("passes ai_suggested=true for packages flagged by SentinelHook", async () => {
    const content = JSON.stringify({ dependencies: { "ai-pkg": "^1" } });
    _readFile.mockResolvedValue(Buffer.from(content));
    const { interceptor, mockClient, mockSentinel } = makeInterceptor();
    mockSentinel.isAiSuggested.mockReturnValue(true);
    await (interceptor as any)._onChange(makeUri("/project/package.json"));
    expect(mockClient.scan.mock.calls[0][0].ai_suggested).toBe(true);
  });
});

// ── Interceptor._scanDep ──────────────────────────────────────────────────────

describe("Interceptor._scanDep", () => {
  beforeEach(() => {
    vi.mocked(notifUI.showWarnNotification  as any).mockResolvedValue(true);
    vi.mocked(notifUI.showBlockNotification as any).mockResolvedValue(false);
  });

  it("sets status bar to scanning before calling scan()", async () => {
    const { interceptor, mockStatusBar } = makeInterceptor();
    await (interceptor as any)._scanDep("lodash", "/project");
    expect(mockStatusBar.setState).toHaveBeenCalledWith("scanning", expect.stringContaining("lodash"));
  });

  it("ALLOW decision calls showAllowNotification and resets status bar to idle", async () => {
    const { interceptor, mockClient, mockStatusBar } = makeInterceptor();
    mockClient.scan.mockResolvedValue(makeScan(Decision.ALLOW));
    await (interceptor as any)._scanDep("lodash", "/project");
    expect(notifUI.showAllowNotification).toHaveBeenCalledWith("lodash");
    expect(mockStatusBar.setState).toHaveBeenCalledWith("idle");
  });

  it("WARN decision calls showWarnNotification and sets status bar to warned", async () => {
    const { interceptor, mockClient, mockStatusBar } = makeInterceptor();
    mockClient.scan.mockResolvedValue({ ...makeScan(Decision.WARN), explanation: "risky" });
    await (interceptor as any)._scanDep("lodash", "/project");
    expect(notifUI.showWarnNotification).toHaveBeenCalledOnce();
    expect(mockStatusBar.setState).toHaveBeenCalledWith("warned", "risky");
  });

  it("BLOCK decision calls showBlockNotification and sets status bar to blocked", async () => {
    const { interceptor, mockClient, mockStatusBar } = makeInterceptor();
    mockClient.scan.mockResolvedValue({ ...makeScan(Decision.BLOCK), explanation: "blocked!" });
    await (interceptor as any)._scanDep("lodash", "/project");
    expect(notifUI.showBlockNotification).toHaveBeenCalledOnce();
    expect(mockStatusBar.setState).toHaveBeenCalledWith("blocked", "blocked!");
  });
});

// ── Interceptor.dispose ───────────────────────────────────────────────────────

describe("Interceptor.dispose", () => {
  it("disposes all disposables registered via onDidCreate and onDidChange", () => {
    const disposedFns: (() => void)[] = [];
    // Override createFileSystemWatcher to track disposals
    _createFSW.mockReturnValueOnce({
      onDidCreate: vi.fn((_cb: any, _th: any, arr?: any[]) => {
        const d = { dispose: vi.fn(() => disposedFns.push(() => {})) };
        arr?.push(d);
        return d;
      }),
      onDidChange: vi.fn((_cb: any, _th: any, arr?: any[]) => {
        const d = { dispose: vi.fn(() => disposedFns.push(() => {})) };
        arr?.push(d);
        return d;
      }),
      dispose: vi.fn(),
    });

    const { interceptor } = makeInterceptor();
    const ctx = { subscriptions: { push: vi.fn() } } as any;
    interceptor.activate(ctx);
    interceptor.dispose();
    expect(disposedFns.length).toBe(2); // onDidCreate + onDidChange disposables
  });
});
