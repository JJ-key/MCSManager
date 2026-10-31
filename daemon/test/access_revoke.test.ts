import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { globalConfiguration } from "../src/entity/config";
import { missionPassport, revokeUserAccess } from "../src/service/mission_passport";
import { routerApp } from "../src/service/router_app";
import { dispatch, flush, newContext, packetsFor } from "./harness/router";

// Tests for cutting a panel user off on the daemon: the passport matching, the
// stream-socket matching, and the gate that keeps the revoke route away from
// browser stream sockets. The routers run through the harness's dispatch(), which
// runs the same gate middlewares as a real socket.

vi.mock("../src/service/log", () => {
  const f: any = () => {};
  f.info = f;
  f.debug = f;
  f.warn = f;
  f.error = f;
  return { default: f };
});

// stream/auth only needs an instance to exist and forward() to be callable.
vi.mock("../src/service/system_instance", () => ({
  default: {
    getInstance: vi.fn((uuid: string) => ({ instanceUuid: uuid })),
    forward: vi.fn(),
    stopForward: vi.fn()
  }
}));

// Register the gate (auth_router) and the routes under test on the singleton.
import "../src/routers/auth_router";
import "../src/routers/passport_router";
import "../src/routers/stream_router";

const KEY = "test-key";

// Session of the panel's key-authenticated socket.
function panelSession() {
  return { key: KEY, login: true, id: "panel-sock", type: "TOP_LEVEL", stream: {} };
}

function register(password: string, name: string, instanceUuid: string, userUuid?: string) {
  missionPassport.registerMission(password, {
    name,
    parameter: { instanceUuid },
    start: Date.now(),
    end: Date.now() + 3600000,
    userUuid
  });
}

// A browser stream socket that passed stream/auth with a passport.
async function authedStream(password: string) {
  const session: any = {};
  const { socket } = dispatch("stream/auth", { password }, { session });
  await flush();
  return { socket, session };
}

beforeEach(() => {
  globalConfiguration.config.key = KEY;
  missionPassport.missions.clear();
});

// The stream-socket registry is module state: drop sockets left over by a test.
afterEach(() => {
  for (const user of ["user-a", "user-b"]) revokeUserAccess(user);
});

describe("missionPassport.getMission", () => {
  it("does not return a passport that was consumed (isDeleted)", () => {
    register("pw-used", "download", "inst-1", "user-a");
    expect(missionPassport.getMission("pw-used", "download")).not.toBeNull();
    missionPassport.deleteMission("pw-used", "download");
    expect(missionPassport.getMission("pw-used", "download")).toBeNull();
  });
});

describe("missionPassport.revokeByUser", () => {
  beforeEach(() => {
    register("a-stream-1", "stream_channel", "inst-1", "user-a");
    register("a-stream-2", "stream_channel", "inst-2", "user-a");
    register("a-download-1", "download", "inst-1", "user-a");
    register("b-stream-1", "stream_channel", "inst-1", "user-b");
    register("old-stream-1", "stream_channel", "inst-1");
  });

  it("deletes every passport of the user and nobody else's", () => {
    expect(missionPassport.revokeByUser("user-a")).toBe(3);
    expect(missionPassport.getMission("a-stream-1", "stream_channel")).toBeNull();
    expect(missionPassport.getMission("a-stream-2", "stream_channel")).toBeNull();
    expect(missionPassport.getMission("a-download-1", "download")).toBeNull();
    expect(missionPassport.getMission("b-stream-1", "stream_channel")).not.toBeNull();
  });

  it("with instances, deletes only the passports for those instances", () => {
    expect(missionPassport.revokeByUser("user-a", ["inst-1"])).toBe(2);
    expect(missionPassport.getMission("a-stream-1", "stream_channel")).toBeNull();
    expect(missionPassport.getMission("a-download-1", "download")).toBeNull();
    expect(missionPassport.getMission("a-stream-2", "stream_channel")).not.toBeNull();
  });

  it("an empty instance list deletes nothing", () => {
    expect(missionPassport.revokeByUser("user-a", [])).toBe(0);
    expect(missionPassport.missions.size).toBe(5);
  });

  it("never touches passports that carry no user", () => {
    missionPassport.revokeByUser("user-a");
    missionPassport.revokeByUser("");
    expect(missionPassport.getMission("old-stream-1", "stream_channel")).not.toBeNull();
  });
});

describe("stream sockets", () => {
  it("stream/auth records the user; revokeUserAccess closes only that user's sockets", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    register("b-pw", "stream_channel", "inst-1", "user-b");
    const a = await authedStream("a-pw");
    const b = await authedStream("b-pw");
    expect(a.session.stream.userUuid).toBe("user-a");

    expect(revokeUserAccess("user-a")).toEqual({ sockets: 1, passports: 1 });
    expect(a.socket.conn.close).toHaveBeenCalled();
    expect(b.socket.conn.close).not.toHaveBeenCalled();
    // socket.disconnect() would stop web clients from reconnecting, so the transport is closed.
    expect(a.socket.disconnect).not.toHaveBeenCalled();
    // The passport is gone, so the same one cannot re-auth.
    const again = dispatch("stream/auth", { password: "a-pw" }, { session: {} });
    await flush();
    expect(packetsFor(again.socket, "stream/auth")[0].status).toBe(500);
    // The other user's passport still works.
    const bAgain = await authedStream("b-pw");
    expect(packetsFor(bAgain.socket, "stream/auth")[0].data).toBe(true);
  });

  it("with instances, closes only the sockets on those instances", async () => {
    register("a-pw-1", "stream_channel", "inst-1", "user-a");
    register("a-pw-2", "stream_channel", "inst-2", "user-a");
    const s1 = await authedStream("a-pw-1");
    const s2 = await authedStream("a-pw-2");

    expect(revokeUserAccess("user-a", ["inst-1"])).toEqual({ sockets: 1, passports: 1 });
    expect(s1.socket.conn.close).toHaveBeenCalled();
    expect(s2.socket.conn.close).not.toHaveBeenCalled();
  });

  it("closes a socket that authed on two instances when either one is revoked", async () => {
    register("a-pw-1", "stream_channel", "inst-1", "user-a");
    register("a-pw-2", "stream_channel", "inst-2", "user-a");
    // One socket authing twice: the registry must keep both grants.
    const { ctx } = newContext("stream/auth", { session: {} });
    routerApp.emitRouter("stream/auth", ctx, { password: "a-pw-1" });
    routerApp.emitRouter("stream/auth", ctx, { password: "a-pw-2" });
    await flush();

    expect(revokeUserAccess("user-a", ["inst-2"]).sockets).toBe(1);
    expect(ctx.socket.conn.close).toHaveBeenCalled();
  });

  it("forgets a socket once it disconnects", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const a = await authedStream("a-pw");
    for (const call of a.socket.on.mock.calls) if (call[0] === "disconnect") call[1]();
    expect(revokeUserAccess("user-a").sockets).toBe(0);
    expect(a.socket.conn.close).not.toHaveBeenCalled();
  });

  it("falls back to a socket disconnect when the transport cannot be closed", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const a = await authedStream("a-pw");
    a.socket.conn.close.mockImplementation(() => {
      throw new Error("already closed");
    });
    expect(revokeUserAccess("user-a").sockets).toBe(1);
    expect(a.socket.disconnect).toHaveBeenCalledWith(true);
  });

  it("leaves passports and sockets without a user alone", async () => {
    register("old-pw", "stream_channel", "inst-1");
    const old = await authedStream("old-pw");
    expect(revokeUserAccess("user-a")).toEqual({ sockets: 0, passports: 0 });
    expect(old.socket.conn.close).not.toHaveBeenCalled();
  });
});

describe("passport/register", () => {
  it("stores the user on the passport, and stays compatible without one", async () => {
    dispatch(
      "passport/register",
      { name: "download", password: "pw-1", parameter: { instanceUuid: "i" }, userUuid: "user-a" },
      { session: panelSession() }
    );
    dispatch(
      "passport/register",
      { name: "download", password: "pw-2", parameter: { instanceUuid: "i" } },
      { session: panelSession() }
    );
    dispatch(
      "passport/register",
      { name: "download", password: "pw-3", parameter: { instanceUuid: "i" }, userUuid: 42 },
      { session: panelSession() }
    );
    await flush();
    expect(missionPassport.getMission("pw-1", "download")?.userUuid).toBe("user-a");
    expect(missionPassport.getMission("pw-2", "download")?.userUuid).toBeUndefined();
    expect(missionPassport.getMission("pw-3", "download")?.userUuid).toBeUndefined();
  });
});

describe("passport/revoke_user gate", () => {
  it("runs for the panel's key session and returns the counts", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const a = await authedStream("a-pw");
    register("a-dl", "download", "inst-1", "user-a");

    const { socket } = dispatch(
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: ["inst-1"] },
      { session: panelSession(), uuid: "req-1" }
    );
    await flush();
    const [res] = packetsFor(socket, "passport/revoke_user");
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ sockets: 1, passports: 2 });
    expect(a.socket.conn.close).toHaveBeenCalled();
  });

  it("is refused for a browser stream socket, and revokes nothing", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    register("b-pw", "stream_channel", "inst-1", "user-b");
    const a = await authedStream("a-pw");
    const b = await authedStream("b-pw");
    expect(b.session.type).toBe("STREAM");

    // user-b's authed stream session tries to cut user-a off.
    const { socket } = dispatch(
      "passport/revoke_user",
      { userUuid: "user-a" },
      { session: b.session }
    );
    await flush();
    const [res] = packetsFor(socket, "passport/revoke_user");
    expect(res.status).toBe(500);
    expect(a.socket.conn.close).not.toHaveBeenCalled();
    expect(missionPassport.getMission("a-pw", "stream_channel")).not.toBeNull();
  });

  it("is refused for a session that is not logged in", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const { socket } = dispatch("passport/revoke_user", { userUuid: "user-a" }, { session: {} });
    await flush();
    expect(packetsFor(socket, "passport/revoke_user")[0].status).toBe(500);
    expect(missionPassport.getMission("a-pw", "stream_channel")).not.toBeNull();
  });

  it("is refused for a key session that used the wrong key", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const { socket } = dispatch(
      "passport/revoke_user",
      { userUuid: "user-a" },
      { session: { ...panelSession(), key: "some-other-key" } }
    );
    await flush();
    expect(packetsFor(socket, "passport/revoke_user")[0].status).toBe(500);
    expect(missionPassport.getMission("a-pw", "stream_channel")).not.toBeNull();
  });

  it("rejects a missing userUuid and a malformed instance list", async () => {
    register("a-pw", "stream_channel", "inst-1", "user-a");
    const bad = [{}, { userUuid: "" }, { userUuid: 7 }, { userUuid: "u", instanceUuids: "inst-1" }];
    for (const data of bad) {
      const { socket } = dispatch("passport/revoke_user", data, { session: panelSession() });
      await flush();
      expect(packetsFor(socket, "passport/revoke_user")[0].status).toBe(500);
    }
    // None of the bad calls fell back to "revoke everything".
    expect(missionPassport.getMission("a-pw", "stream_channel")).not.toBeNull();
  });
});
