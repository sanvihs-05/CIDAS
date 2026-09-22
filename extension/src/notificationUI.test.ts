import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  showAllowNotification,
  showBlockNotification,
  showDetailsPanel,
  showWarnNotification,
} from "./notificationUI";
import * as vscode from "vscode";
import { Decision, ScanResponse } from "./types";

const zeroPillar = { score: 0, confidence: 0.9, flags: [], metadata: {} };

function makeResponse(decision: Decision, score = 42, flags: string[] = []): ScanResponse {
  return {
    package_name: "test-pkg",
    version: "1.0.0",
    decision,
    risk_score: score,
    contextify: { ...zeroPillar, flags },
    sentinel:   zeroPillar,
    shield:     zeroPillar,
    alternatives: [],
    explanation: "Test explanation.",
    latency_ms: 10,
  };
}

describe("showAllowNotification", () => {
  beforeEach(() => vi.clearAllMocks());

  it("calls setStatusBarMessage with the package name", () => {
    showAllowNotification("lodash");
    expect(vscode.window.setStatusBarMessage).toHaveBeenCalledOnce();
    expect(vi.mocked(vscode.window.setStatusBarMessage).mock.calls[0][0]).toContain("lodash");
  });
});

describe("showWarnNotification", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders Show Details as the primary (first) action button", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue(undefined);
    await showWarnNotification(makeResponse(Decision.WARN));
    const args = vi.mocked(vscode.window.showWarningMessage).mock.calls[0];
    // First positional after the message+options is the primary action.
    expect(args[2]).toBe("Show Details");
    expect(args[3]).toBe("Proceed Anyway");
    expect(args[4]).toBe("Cancel install");
  });

  it("returns true when user chooses Proceed Anyway", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue("Proceed Anyway" as any);
    const result = await showWarnNotification(makeResponse(Decision.WARN));
    expect(result).toBe(true);
  });

  it("returns false when user dismisses the dialog", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN));
    expect(result).toBe(false);
  });

  it("includes risk score and package name in the message", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue(undefined);
    await showWarnNotification(makeResponse(Decision.WARN, 55));
    const msg = vi.mocked(vscode.window.showWarningMessage).mock.calls[0][0] as string;
    expect(msg).toContain("test-pkg");
    expect(msg).toContain("55");
  });

  it("shows details panel and second modal when user chooses Show Details", async () => {
    vi.mocked(vscode.window.showWarningMessage)
      .mockResolvedValueOnce("Show Details" as any)
      .mockResolvedValueOnce("Proceed Anyway" as any);
    const result = await showWarnNotification(makeResponse(Decision.WARN));
    expect(vscode.window.createWebviewPanel).toHaveBeenCalledOnce();
    expect(result).toBe(true);
  });

  it("returns false when Show Details is followed by Cancel install in the modal", async () => {
    vi.mocked(vscode.window.showWarningMessage)
      .mockResolvedValueOnce("Show Details" as any)
      .mockResolvedValueOnce("Cancel install" as any);
    const result = await showWarnNotification(makeResponse(Decision.WARN));
    expect(result).toBe(false);
  });

  it("calls onProceed callback when user chooses Proceed Anyway", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue("Proceed Anyway" as any);
    const onProceed = vi.fn().mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN), { onProceed });
    expect(result).toBe(true);
    expect(onProceed).toHaveBeenCalledOnce();
  });

  it("calls onProceed callback after Show Details + Proceed", async () => {
    vi.mocked(vscode.window.showWarningMessage)
      .mockResolvedValueOnce("Show Details" as any)
      .mockResolvedValueOnce("Proceed Anyway" as any);
    const onProceed = vi.fn().mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN), { onProceed });
    expect(result).toBe(true);
    expect(onProceed).toHaveBeenCalledOnce();
  });

  it("does not call onProceed when user cancels", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue(undefined);
    const onProceed = vi.fn().mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN), { onProceed });
    expect(result).toBe(false);
    expect(onProceed).not.toHaveBeenCalled();
  });

  it("calls onCancel and shows info message when user clicks Cancel install", async () => {
    vi.mocked(vscode.window.showWarningMessage).mockResolvedValue("Cancel install" as any);
    const onCancel = vi.fn().mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN), { onCancel });
    expect(result).toBe(false);
    expect(onCancel).toHaveBeenCalledOnce();
    expect(vscode.window.showInformationMessage).toHaveBeenCalledOnce();
    const note = vi.mocked(vscode.window.showInformationMessage).mock.calls[0][0] as string;
    expect(note).toContain("cancel intent recorded");
  });

  it("calls onCancel after Show Details + Cancel install in the modal", async () => {
    vi.mocked(vscode.window.showWarningMessage)
      .mockResolvedValueOnce("Show Details" as any)
      .mockResolvedValueOnce("Cancel install" as any);
    const onCancel = vi.fn().mockResolvedValue(undefined);
    const result = await showWarnNotification(makeResponse(Decision.WARN), { onCancel });
    expect(result).toBe(false);
    expect(onCancel).toHaveBeenCalledOnce();
  });
});

describe("showBlockNotification", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns false when user cancels", async () => {
    vi.mocked(vscode.window.showErrorMessage).mockResolvedValue(undefined);
    const result = await showBlockNotification(makeResponse(Decision.BLOCK));
    expect(result).toBe(false);
  });

  it("returns true when user chooses Proceed Anyway", async () => {
    vi.mocked(vscode.window.showErrorMessage).mockResolvedValue("Proceed Anyway" as any);
    const result = await showBlockNotification(makeResponse(Decision.BLOCK));
    expect(result).toBe(true);
  });

  it("includes score and package name in the error message", async () => {
    vi.mocked(vscode.window.showErrorMessage).mockResolvedValue(undefined);
    await showBlockNotification(makeResponse(Decision.BLOCK, 88));
    const msg = vi.mocked(vscode.window.showErrorMessage).mock.calls[0][0] as string;
    expect(msg).toContain("test-pkg");
    expect(msg).toContain("88");
  });

  it("shows details panel and override modal when Show Details is chosen", async () => {
    vi.mocked(vscode.window.showErrorMessage)
      .mockResolvedValueOnce("Show Details" as any)
      .mockResolvedValueOnce("Proceed Anyway" as any);
    const result = await showBlockNotification(makeResponse(Decision.BLOCK));
    expect(vscode.window.createWebviewPanel).toHaveBeenCalledOnce();
    expect(result).toBe(true);
  });
});

describe("showDetailsPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("creates a webview panel with the package name in the title", () => {
    showDetailsPanel(makeResponse(Decision.ALLOW));
    expect(vscode.window.createWebviewPanel).toHaveBeenCalledOnce();
    const args = vi.mocked(vscode.window.createWebviewPanel).mock.calls[0];
    expect(args[1]).toContain("test-pkg");
  });

  it("sets the webview HTML containing the package name and decision", () => {
    const mockPanel = { webview: { html: "" }, dispose: vi.fn() };
    vi.mocked(vscode.window.createWebviewPanel).mockReturnValue(mockPanel as any);
    showDetailsPanel(makeResponse(Decision.BLOCK, 85));
    expect(mockPanel.webview.html).toContain("test-pkg");
    expect(mockPanel.webview.html).toContain("BLOCK");
    expect(mockPanel.webview.html).toContain("85");
  });

  it("includes version in the panel HTML when present", () => {
    const mockPanel = { webview: { html: "" }, dispose: vi.fn() };
    vi.mocked(vscode.window.createWebviewPanel).mockReturnValue(mockPanel as any);
    showDetailsPanel(makeResponse(Decision.ALLOW));
    expect(mockPanel.webview.html).toContain("1.0.0");
  });

  it("includes pillar scores in the HTML table", () => {
    const mockPanel = { webview: { html: "" }, dispose: vi.fn() };
    vi.mocked(vscode.window.createWebviewPanel).mockReturnValue(mockPanel as any);
    showDetailsPanel(makeResponse(Decision.WARN));
    expect(mockPanel.webview.html).toContain("Contextify");
    expect(mockPanel.webview.html).toContain("Sentinel");
    expect(mockPanel.webview.html).toContain("Shield");
  });

  it("shows flags when pillar has them", () => {
    const mockPanel = { webview: { html: "" }, dispose: vi.fn() };
    vi.mocked(vscode.window.createWebviewPanel).mockReturnValue(mockPanel as any);
    const response = makeResponse(Decision.WARN, 45, ["typosquat_detected"]);
    showDetailsPanel(response);
    expect(mockPanel.webview.html).toContain("typosquat_detected");
  });
});
