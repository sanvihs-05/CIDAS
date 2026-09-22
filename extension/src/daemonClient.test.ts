import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DaemonClient } from "./daemonClient";
import * as vscode from "vscode";
import { Decision } from "./types";

const PORT = 7355;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;

const zeroPillar = { score: 0, confidence: 0.9, flags: [], metadata: {} };

function makeScanResponse(decision: Decision, score = 0) {
  return {
    package_name: "lodash",
    version: null,
    decision,
    risk_score: score,
    contextify: zeroPillar,
    sentinel:   zeroPillar,
    shield:     zeroPillar,
    alternatives: [],
    explanation: "test",
    latency_ms: 5,
  };
}

function mockFetchOk(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn().mockResolvedValue(JSON.stringify(body)),
  });
}

describe("DaemonClient", () => {
  let client: DaemonClient;

  beforeEach(() => {
    client = new DaemonClient(PORT);
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── scan() ──────────────────────────────────────────────────────────────────

  it("scan() returns ALLOW response from daemon", async () => {
    vi.stubGlobal("fetch", mockFetchOk(makeScanResponse(Decision.ALLOW, 5)));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.package_name).toBe("lodash");
  });

  it("scan() returns BLOCK response from daemon", async () => {
    vi.stubGlobal("fetch", mockFetchOk(makeScanResponse(Decision.BLOCK, 90)));
    const result = await client.scan({ package_name: "evil-pkg", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.BLOCK);
    expect(result.risk_score).toBe(90);
  });

  it("scan() posts to the correct URL with JSON body", async () => {
    const fetchMock = mockFetchOk(makeScanResponse(Decision.ALLOW));
    vi.stubGlobal("fetch", fetchMock);
    await client.scan({ package_name: "lodash", project_path: "/tmp", ai_suggested: true });
    expect(fetchMock).toHaveBeenCalledWith(
      `${BASE}/scan`,
      expect.objectContaining({ method: "POST" }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.package_name).toBe("lodash");
    expect(body.ai_suggested).toBe(true);
  });

  it("scan() fails open and returns safe ALLOW when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.risk_score).toBe(0);
    expect(result.contextify.flags).toContain("daemon_offline");
  });

  it("scan() fails open on non-2xx HTTP status", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 503));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.contextify.flags).toContain("daemon_offline");
  });

  it("scan() shows a VS Code warning when failing open", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(vscode.window.showWarningMessage).toHaveBeenCalledOnce();
  });

  // ── health() ────────────────────────────────────────────────────────────────

  it("health() returns true when daemon responds 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 200));
    expect(await client.health()).toBe(true);
  });

  it("health() returns false when daemon responds non-2xx", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 503));
    expect(await client.health()).toBe(false);
  });

  it("health() returns false when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    expect(await client.health()).toBe(false);
  });

  it("health() calls the correct URL", async () => {
    const fetchMock = mockFetchOk({}, 200);
    vi.stubGlobal("fetch", fetchMock);
    await client.health();
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/health`);
  });

  // ── trust() ─────────────────────────────────────────────────────────────────

  it("trust() resolves without error on 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({ trusted: "lodash" }));
    await expect(client.trust("lodash")).resolves.toBeUndefined();
  });

  it("trust() throws on HTTP error", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 422));
    await expect(client.trust("bad-pkg")).rejects.toThrow("422");
  });

  it("trust() sends the package name in the request body", async () => {
    const fetchMock = mockFetchOk({ trusted: "lodash" });
    vi.stubGlobal("fetch", fetchMock);
    await client.trust("lodash");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.package_name).toBe("lodash");
  });

  // ── clearCache() ─────────────────────────────────────────────────────────────

  it("clearCache() resolves without error on 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({ purged: 3 }));
    await expect(client.clearCache()).resolves.toBeUndefined();
  });

  it("clearCache() sends DELETE to the cache endpoint", async () => {
    const fetchMock = mockFetchOk({ purged: 0 });
    vi.stubGlobal("fetch", fetchMock);
    await client.clearCache();
    expect(fetchMock).toHaveBeenCalledWith(
      `${BASE}/cache`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("clearCache() throws on HTTP error", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 500));
    await expect(client.clearCache()).rejects.toThrow("500");
  });

  // ── isOffline / onStatusChange ──────────────────────────────────────────────

  it("isOffline() defaults to false before any probe", () => {
    expect(client.isOffline()).toBe(false);
  });

  it("isOffline() flips to true after a failed scan", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(client.isOffline()).toBe(true);
  });

  it("isOffline() returns to false on a successful scan", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(client.isOffline()).toBe(true);

    vi.stubGlobal("fetch", mockFetchOk(makeScanResponse(Decision.ALLOW)));
    await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(client.isOffline()).toBe(false);
  });

  it("isOffline() reflects health() outcome", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("nope")));
    await client.health();
    expect(client.isOffline()).toBe(true);

    vi.stubGlobal("fetch", mockFetchOk({}, 200));
    await client.health();
    expect(client.isOffline()).toBe(false);
  });

  it("onStatusChange listener fires with online=false when daemon goes down", async () => {
    const listener = vi.fn();
    client.onStatusChange(listener);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("nope")));
    await client.health();
    expect(listener).toHaveBeenCalledWith(false);
  });

  it("onStatusChange listener fires with online=true when daemon recovers", async () => {
    const listener = vi.fn();
    // Force initial offline state
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("nope")));
    await client.health();
    client.onStatusChange(listener);

    vi.stubGlobal("fetch", mockFetchOk({}, 200));
    await client.health();
    expect(listener).toHaveBeenCalledWith(true);
  });

  it("onStatusChange listener does NOT fire when state stays the same", async () => {
    const listener = vi.fn();
    client.onStatusChange(listener);
    // Two successful probes in a row — no flip, no notification.
    vi.stubGlobal("fetch", mockFetchOk({}, 200));
    await client.health();
    await client.health();
    expect(listener).not.toHaveBeenCalled();
  });

  it("onStatusChange returns a Disposable that unsubscribes the listener", async () => {
    const listener = vi.fn();
    const sub = client.onStatusChange(listener);
    sub.dispose();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("nope")));
    await client.health();
    expect(listener).not.toHaveBeenCalled();
  });

  it("a throwing listener does not break notification of other listeners", async () => {
    const bad  = vi.fn(() => { throw new Error("boom"); });
    const good = vi.fn();
    client.onStatusChange(bad);
    client.onStatusChange(good);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("nope")));
    await client.health();
    expect(good).toHaveBeenCalledWith(false);
  });

  // ── startHealthPolling ──────────────────────────────────────────────────────

  it("startHealthPolling probes immediately and on every interval tick", async () => {
    vi.useFakeTimers();
    const fetchMock = mockFetchOk({}, 200);
    vi.stubGlobal("fetch", fetchMock);

    const sub = client.startHealthPolling(30_000);
    // Yield microtasks so the immediate probe completes
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    sub.dispose();
    vi.useRealTimers();
  });

  it("startHealthPolling Disposable stops further probes", async () => {
    vi.useFakeTimers();
    const fetchMock = mockFetchOk({}, 200);
    vi.stubGlobal("fetch", fetchMock);

    const sub = client.startHealthPolling(30_000);
    await vi.advanceTimersByTimeAsync(0);
    sub.dispose();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(fetchMock).toHaveBeenCalledTimes(1); // only the immediate probe ran
    vi.useRealTimers();
  });
});
