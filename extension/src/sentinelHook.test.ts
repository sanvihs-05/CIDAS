import { describe, it, expect, vi, beforeEach } from "vitest";
import { SentinelHook } from "./sentinelHook";
import * as vscode from "vscode";

describe("SentinelHook", () => {
  let hook: SentinelHook;

  beforeEach(() => {
    hook = new SentinelHook();
    vi.clearAllMocks();
  });

  // ── registerAiSuggested / isAiSuggested ─────────────────────────────────────

  it("isAiSuggested returns false for unknown packages", () => {
    expect(hook.isAiSuggested("lodash")).toBe(false);
  });

  it("registerAiSuggested marks the package as AI-suggested", () => {
    hook.registerAiSuggested("some-pkg");
    expect(hook.isAiSuggested("some-pkg")).toBe(true);
  });

  it("registering one package does not affect others", () => {
    hook.registerAiSuggested("pkg-a");
    expect(hook.isAiSuggested("pkg-b")).toBe(false);
  });

  // ── _parseTerminalData ───────────────────────────────────────────────────────

  it("detects ES module import syntax", () => {
    (hook as any)._parseTerminalData("import React from 'react'");
    expect(hook.isAiSuggested("react")).toBe(true);
  });

  it("detects double-quoted import syntax", () => {
    (hook as any)._parseTerminalData('import _ from "lodash"');
    expect(hook.isAiSuggested("lodash")).toBe(true);
  });

  it("detects require() syntax", () => {
    (hook as any)._parseTerminalData("const axios = require('axios')");
    expect(hook.isAiSuggested("axios")).toBe(true);
  });

  it("extracts the scope root for scoped packages", () => {
    (hook as any)._parseTerminalData("import something from '@scope/package'");
    expect(hook.isAiSuggested("@scope")).toBe(true);
  });

  it("ignores relative imports", () => {
    (hook as any)._parseTerminalData("import foo from './local-module'");
    expect(hook.isAiSuggested("./local-module")).toBe(false);
    expect(hook.isAiSuggested("local-module")).toBe(false);
  });

  it("detects multiple packages in a single data chunk", () => {
    (hook as any)._parseTerminalData(
      "import React from 'react'\nimport _ from 'lodash'\nconst axios = require('axios')"
    );
    expect(hook.isAiSuggested("react")).toBe(true);
    expect(hook.isAiSuggested("lodash")).toBe(true);
    expect(hook.isAiSuggested("axios")).toBe(true);
  });

  it("does not mark packages from empty terminal data", () => {
    (hook as any)._parseTerminalData("");
    expect(hook.isAiSuggested("react")).toBe(false);
  });

  // ── activate / dispose ───────────────────────────────────────────────────────

  it("activate registers a terminal data listener", () => {
    const ctx = { subscriptions: { push: vi.fn() } } as any;
    hook.activate(ctx);
    expect(vscode.window.onDidWriteTerminalData).toHaveBeenCalledOnce();
  });

  it("dispose calls dispose on all registered disposables", () => {
    const mockDisposable = { dispose: vi.fn() };
    vi.mocked(vscode.window.onDidWriteTerminalData).mockReturnValue(mockDisposable as any);
    const ctx = { subscriptions: { push: vi.fn() } } as any;
    hook.activate(ctx);
    hook.dispose();
    expect(mockDisposable.dispose).toHaveBeenCalledOnce();
  });
});
