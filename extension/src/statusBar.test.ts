import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { StatusBarManager } from "./statusBar";
import * as vscode from "vscode";

function _makeItem(): ReturnType<typeof vscode.window.createStatusBarItem> {
  return {
    text: "",
    tooltip: "",
    backgroundColor: undefined,
    command: "",
    show: vi.fn(),
    hide: vi.fn(),
    dispose: vi.fn(),
  } as any;
}

describe("StatusBarManager", () => {
  let manager: StatusBarManager;
  let mockItem: ReturnType<typeof vscode.window.createStatusBarItem>;
  let offlineItem: ReturnType<typeof vscode.window.createStatusBarItem>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    // Two distinct items: the main scan-state item and the persistent
    // daemon-offline indicator. createStatusBarItem returns each in order.
    mockItem    = _makeItem();
    offlineItem = _makeItem();
    vi.mocked(vscode.window.createStatusBarItem)
      .mockReturnValueOnce(mockItem)
      .mockReturnValueOnce(offlineItem);
    manager = new StatusBarManager();
  });

  afterEach(() => {
    vi.useRealTimers();
    manager.dispose();
  });

  // ── constructor ──────────────────────────────────────────────────────────────

  it("creates two status bar items (main + offline indicator)", () => {
    expect(vscode.window.createStatusBarItem).toHaveBeenCalledTimes(2);
    // The main item is shown immediately; the offline item starts hidden.
    expect(mockItem.show).toHaveBeenCalledOnce();
    expect(offlineItem.show).not.toHaveBeenCalled();
  });

  it("starts in idle state", () => {
    expect(mockItem.text).toContain("CIDAS ready");
  });

  // ── setState ─────────────────────────────────────────────────────────────────

  it("idle state sets correct text and clears background", () => {
    manager.setState("idle");
    expect(mockItem.text).toContain("CIDAS ready");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("scanning state sets spinner text", () => {
    manager.setState("scanning");
    expect(mockItem.text).toContain("scanning");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("blocked state sets error background color", () => {
    manager.setState("blocked");
    expect(mockItem.text).toContain("BLOCKED");
    expect(mockItem.backgroundColor).toBeInstanceOf(vscode.ThemeColor);
    expect((mockItem.backgroundColor as vscode.ThemeColor).id).toContain("error");
  });

  it("warned state sets warning background color", () => {
    manager.setState("warned");
    expect(mockItem.text).toContain("warned");
    expect(mockItem.backgroundColor).toBeInstanceOf(vscode.ThemeColor);
    expect((mockItem.backgroundColor as vscode.ThemeColor).id).toContain("warning");
  });

  it("error state shows daemon offline message", () => {
    manager.setState("error");
    expect(mockItem.text).toContain("offline");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("custom tooltip is applied", () => {
    manager.setState("scanning", "Scanning lodash…");
    expect(mockItem.tooltip).toBe("Scanning lodash…");
  });

  it("default tooltip is used when none is supplied", () => {
    manager.setState("idle");
    expect(typeof mockItem.tooltip).toBe("string");
    expect((mockItem.tooltip as string).length).toBeGreaterThan(0);
  });

  // ── auto-reset timer ─────────────────────────────────────────────────────────

  it("blocked state auto-resets to idle after 5 seconds", () => {
    manager.setState("blocked");
    expect(mockItem.text).toContain("BLOCKED");
    vi.advanceTimersByTime(5_000);
    expect(mockItem.text).toContain("CIDAS ready");
  });

  it("warned state auto-resets to idle after 5 seconds", () => {
    manager.setState("warned");
    vi.advanceTimersByTime(5_000);
    expect(mockItem.text).toContain("CIDAS ready");
  });

  it("setting a new state before timer fires cancels the reset", () => {
    manager.setState("blocked");
    vi.advanceTimersByTime(3_000);
    manager.setState("scanning");
    vi.advanceTimersByTime(3_000); // would have fired original timer here
    expect(mockItem.text).toContain("scanning");
  });

  it("idle and error states do not schedule an auto-reset", () => {
    manager.setState("idle");
    vi.advanceTimersByTime(10_000);
    expect(mockItem.text).toContain("CIDAS ready");

    manager.setState("error");
    vi.advanceTimersByTime(10_000);
    expect(mockItem.text).toContain("offline");
  });

  // ── setDaemonOnline ──────────────────────────────────────────────────────────

  it("offline indicator is hidden by default", () => {
    expect(offlineItem.show).not.toHaveBeenCalled();
  });

  it("setDaemonOnline(false) shows the offline indicator", () => {
    manager.setDaemonOnline(false);
    expect(offlineItem.show).toHaveBeenCalledOnce();
    expect(offlineItem.hide).not.toHaveBeenCalled();
  });

  it("setDaemonOnline(true) hides the offline indicator", () => {
    manager.setDaemonOnline(false);
    manager.setDaemonOnline(true);
    expect(offlineItem.hide).toHaveBeenCalledOnce();
  });

  it("offline indicator uses error background and includes the unprotected text", () => {
    expect(offlineItem.backgroundColor).toBeInstanceOf(vscode.ThemeColor);
    expect((offlineItem.backgroundColor as vscode.ThemeColor).id).toContain("error");
    expect(offlineItem.text).toContain("CIDAS offline");
    expect(offlineItem.text).toContain("unprotected");
  });

  it("offline indicator does not auto-reset (persistent state)", () => {
    manager.setDaemonOnline(false);
    vi.advanceTimersByTime(60_000);
    // Still shown; never hidden by a timer.
    expect(offlineItem.hide).not.toHaveBeenCalled();
  });

  it("offline indicator survives a transient state change on the main item", () => {
    manager.setDaemonOnline(false);
    manager.setState("scanning");
    manager.setState("warned");
    vi.advanceTimersByTime(10_000);
    // Main item cycled, offline indicator remains shown.
    expect(offlineItem.hide).not.toHaveBeenCalled();
  });

  // ── dispose ──────────────────────────────────────────────────────────────────

  it("dispose calls dispose on both status bar items", () => {
    manager.dispose();
    expect(mockItem.dispose).toHaveBeenCalledOnce();
    expect(offlineItem.dispose).toHaveBeenCalledOnce();
  });

  it("dispose clears pending reset timer", () => {
    manager.setState("blocked");
    manager.dispose();
    // Timer fires after dispose — should not throw or mutate disposed item
    expect(() => vi.advanceTimersByTime(5_000)).not.toThrow();
  });
});
