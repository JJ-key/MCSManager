import { EventEmitter } from "events";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// The daemon is never reached: registering the stream passport hangs, which
// keeps every browser socket in the "attaching" state a revoke can land in.
vi.mock("../remote_service", () => ({
  default: { getInstance: vi.fn(() => ({ realUrl: "http://127.0.0.1:1", config: {} })) }
}));
vi.mock("../remote_command", () => ({
  default: class {
    request() {
      return new Promise(() => {});
    }
  }
}));
vi.mock("../log", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

// Namespace import: with vi.mock in the file, a named import of systemConfig would be a stale copy.
import * as setting from "../../setting";
import { issueProxyToken } from "../gateway_token";
import { closeUserStreams, TerminalBridge } from "../terminal_bridge";

// A browser socket as the bridge sees it: events in, emit/disconnect out.
function fakeBrowserSocket() {
  const socket: any = new EventEmitter();
  socket.connected = true;
  // Outbound emits are only recorded; inbound events are fired with EventEmitter's own emit.
  socket.emit = vi.fn();
  const drop = () => {
    if (!socket.connected) return socket;
    socket.connected = false;
    EventEmitter.prototype.emit.call(socket, "disconnect");
    return socket;
  };
  socket.disconnect = vi.fn(drop);
  // closeUserStreams closes the transport; a real socket then fires "disconnect".
  socket.conn = { close: vi.fn(drop) };
  return socket;
}

// Run stream/auth on an already bound browser socket with a fresh stream token.
function auth(socket: any, instanceUuid: string, userUuid?: string) {
  const token = issueProxyToken({
    daemonId: "d1",
    instanceUuid,
    op: "stream",
    target: instanceUuid,
    userUuid
  });
  EventEmitter.prototype.emit.call(socket, "stream/auth", { data: { password: token } });
}

// Connect a browser socket with a stream token and run stream/auth.
function connect(instanceUuid: string, userUuid?: string) {
  const socket = fakeBrowserSocket();
  TerminalBridge.bindBrowserConnection(socket);
  auth(socket, instanceUuid, userUuid);
  return socket;
}

beforeAll(() => {
  setting.initSystemConfig();
});

beforeEach(() => {
  setting.systemConfig!.gatewaySecret = "test-gateway-secret-fixed-0123456789abcdef";
  closeUserStreams("user-a");
  closeUserStreams("user-b");
});

describe("closeUserStreams", () => {
  it("closes a user's browser sockets, even before the daemon client is attached", () => {
    const a = connect("inst-1", "user-a");
    const b = connect("inst-1", "user-b");
    expect(closeUserStreams("user-a")).toBe(1);
    expect(a.conn.close).toHaveBeenCalled();
    // socket.disconnect() would stop web clients from reconnecting, so it must not be used.
    expect(a.disconnect).not.toHaveBeenCalled();
    expect(b.conn.close).not.toHaveBeenCalled();
  });

  it("with instances, closes only the sockets on those instances", () => {
    const one = connect("inst-1", "user-a");
    const two = connect("inst-2", "user-a");
    expect(closeUserStreams("user-a", ["inst-1"])).toBe(1);
    expect(one.conn.close).toHaveBeenCalled();
    expect(two.conn.close).not.toHaveBeenCalled();
  });

  it("forgets a socket once it disconnects", () => {
    const a = connect("inst-1", "user-a");
    a.disconnect();
    expect(closeUserStreams("user-a")).toBe(0);
  });

  it("never closes sockets whose token carried no user", () => {
    const old = connect("inst-1");
    expect(closeUserStreams("user-a")).toBe(0);
    expect(closeUserStreams("")).toBe(0);
    expect(old.conn.close).not.toHaveBeenCalled();
  });

  it("falls back to a socket disconnect when the transport cannot be closed", () => {
    const a = connect("inst-1", "user-a");
    a.conn.close.mockImplementation(() => {
      throw new Error("already closed");
    });
    expect(closeUserStreams("user-a")).toBe(1);
    expect(a.disconnect).toHaveBeenCalledWith(true);
  });

  it("finds a socket that authed twice, whichever instance is revoked", () => {
    // Tokens for X and Y on one socket: the second auth must not hide the first.
    const x = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(x);
    auth(x, "inst-x", "user-a");
    auth(x, "inst-y", "user-a");
    expect(closeUserStreams("user-a", ["inst-x"])).toBe(1);
    expect(x.conn.close).toHaveBeenCalled();

    const y = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(y);
    auth(y, "inst-x", "user-a");
    auth(y, "inst-y", "user-a");
    expect(closeUserStreams("user-a", ["inst-y"])).toBe(1);
    expect(y.conn.close).toHaveBeenCalled();
  });

  it("closes a twice-authed socket once, and leaves it alone for other instances", () => {
    const s = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(s);
    auth(s, "inst-x", "user-a");
    auth(s, "inst-y", "user-a");
    auth(s, "inst-y", "user-a");
    expect(closeUserStreams("user-a", ["inst-z"])).toBe(0);
    expect(s.conn.close).not.toHaveBeenCalled();
    // Both grants match a full revoke, but the socket is closed (and counted) once.
    expect(closeUserStreams("user-a")).toBe(1);
    expect(s.conn.close).toHaveBeenCalledTimes(1);
  });

  it("matches a revoke on any grant of a socket that mixes users", () => {
    const s = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(s);
    auth(s, "inst-x", "user-a");
    auth(s, "inst-y", "user-b");
    expect(closeUserStreams("user-a", ["inst-y"])).toBe(0);
    expect(closeUserStreams("user-a", ["inst-x"])).toBe(1);
    expect(s.conn.close).toHaveBeenCalled();
  });

  it("forgets a twice-authed socket once it disconnects", () => {
    const s = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(s);
    auth(s, "inst-x", "user-a");
    auth(s, "inst-y", "user-a");
    s.disconnect();
    expect(closeUserStreams("user-a")).toBe(0);
  });

  it("rejects a socket with a bad token without tracking it", () => {
    const socket = fakeBrowserSocket();
    TerminalBridge.bindBrowserConnection(socket);
    EventEmitter.prototype.emit.call(socket, "stream/auth", { data: { password: "nope" } });
    expect(socket.disconnect).toHaveBeenCalled();
    expect(closeUserStreams("user-a")).toBe(0);
  });
});
