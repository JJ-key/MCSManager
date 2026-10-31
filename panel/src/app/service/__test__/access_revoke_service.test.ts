import { beforeEach, describe, expect, it, vi } from "vitest";

// Heavy collaborators are mocked: this suite covers the compare logic and what
// revokeUserAccess sends to the panel side and to each daemon.
const h = vi.hoisted(() => ({
  services: new Map<string, any>(),
  request: vi.fn(),
  closeUserStreams: vi.fn(() => 2),
  revokeUserTokens: vi.fn(() => 3),
  revokeUserUploads: vi.fn(() => 4)
}));

vi.mock("../remote_service", () => ({ default: { services: h.services } }));
vi.mock("../remote_command", () => ({
  default: class {
    constructor(public svc: any) {}
    request(...args: any[]) {
      return h.request(this.svc.id, ...args);
    }
  }
}));
vi.mock("../terminal_bridge", () => ({ closeUserStreams: h.closeUserStreams }));
vi.mock("../gateway_token", () => ({ revokeUserTokens: h.revokeUserTokens }));
vi.mock("../proxy_data_plane", () => ({ revokeUserUploads: h.revokeUserUploads }));
vi.mock("../log", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import {
  computeAccessLoss,
  revokeOnAccessChange,
  revokeUserAccess,
  snapshotAccess,
  type AccessState
} from "../access_revoke_service";

const ADMIN = 10;
const USER = 1;
const BAN = -1;

function state(permission: number, ...uuids: string[]): AccessState {
  return { permission, instances: uuids.map((u) => ({ daemonId: "d1", instanceUuid: u })) };
}

// Let a fire-and-forget revoke run to the end.
async function settle() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

beforeEach(() => {
  h.services.clear();
  h.request.mockReset();
  h.request.mockResolvedValue({ sockets: 1, passports: 1 });
  h.closeUserStreams.mockClear();
  h.revokeUserTokens.mockClear();
  h.revokeUserUploads.mockClear();
});

describe("computeAccessLoss", () => {
  it("returns nothing for an edit that changes nothing", () => {
    expect(computeAccessLoss(state(USER, "a", "b"), state(USER, "a", "b"))).toBeNull();
  });

  it("returns nothing when the list is only reordered", () => {
    expect(computeAccessLoss(state(USER, "a", "b"), state(USER, "b", "a"))).toBeNull();
  });

  it("returns nothing when instances or permission only grow", () => {
    expect(computeAccessLoss(state(USER, "a"), state(USER, "a", "b"))).toBeNull();
    expect(computeAccessLoss(state(USER, "a"), state(ADMIN, "a"))).toBeNull();
  });

  it("returns nothing when there was no user before", () => {
    expect(computeAccessLoss(null, state(USER, "a"))).toBeNull();
    expect(computeAccessLoss(null, null)).toBeNull();
  });

  it("cuts a deleted user off from everything", () => {
    expect(computeAccessLoss(state(USER, "a"), null)).toEqual({ all: true, instanceUuids: [] });
  });

  it("cuts a banned user off from everything", () => {
    expect(computeAccessLoss(state(USER, "a"), state(BAN, "a"))).toEqual({
      all: true,
      instanceUuids: []
    });
  });

  it("cuts a lowered admin off from everything, including the instances they keep", () => {
    expect(computeAccessLoss(state(ADMIN), state(USER, "a"))).toEqual({
      all: true,
      instanceUuids: []
    });
  });

  it("returns only the removed instances", () => {
    expect(computeAccessLoss(state(USER, "a", "b", "c"), state(USER, "b"))).toEqual({
      all: false,
      instanceUuids: ["a", "c"]
    });
  });

  it("returns nothing when an admin's instance list shrinks", () => {
    expect(computeAccessLoss(state(ADMIN, "a", "b"), state(ADMIN))).toBeNull();
  });

  it("treats the same uuid on another daemon as a different instance", () => {
    const before: AccessState = {
      permission: USER,
      instances: [
        { daemonId: "d1", instanceUuid: "a" },
        { daemonId: "d2", instanceUuid: "a" }
      ]
    };
    const after: AccessState = {
      permission: USER,
      instances: [{ daemonId: "d2", instanceUuid: "a" }]
    };
    expect(computeAccessLoss(before, after)).toEqual({ all: false, instanceUuids: ["a"] });
  });
});

describe("snapshotAccess", () => {
  it("copies the instance list so a later edit cannot change the snapshot", () => {
    const user: any = {
      permission: USER,
      instances: [{ daemonId: "d1", instanceUuid: "a", extra: 1 }]
    };
    const snap = snapshotAccess(user)!;
    user.instances.push({ daemonId: "d1", instanceUuid: "b" });
    user.permission = BAN;
    expect(snap).toEqual({ permission: USER, instances: [{ daemonId: "d1", instanceUuid: "a" }] });
  });

  it("returns null for a missing user", () => {
    expect(snapshotAccess(undefined)).toBeNull();
  });
});

describe("revokeUserAccess", () => {
  it("closes the panel side and asks every daemon to cut the user off", async () => {
    h.services.set("d1", { id: "d1" });
    h.services.set("d2", { id: "d2" });
    await revokeUserAccess("user-a");
    expect(h.revokeUserTokens).toHaveBeenCalledWith("user-a", undefined);
    expect(h.closeUserStreams).toHaveBeenCalledWith("user-a", undefined);
    expect(h.revokeUserUploads).toHaveBeenCalledWith("user-a", undefined);
    expect(h.request).toHaveBeenCalledTimes(2);
    expect(h.request).toHaveBeenCalledWith(
      "d1",
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: undefined },
      3000
    );
    expect(h.request).toHaveBeenCalledWith(
      "d2",
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: undefined },
      3000
    );
  });

  it("passes the instance list on", async () => {
    h.services.set("d1", { id: "d1" });
    await revokeUserAccess("user-a", { instanceUuids: ["i1", "i2"] });
    expect(h.revokeUserTokens).toHaveBeenCalledWith("user-a", ["i1", "i2"]);
    expect(h.closeUserStreams).toHaveBeenCalledWith("user-a", ["i1", "i2"]);
    expect(h.revokeUserUploads).toHaveBeenCalledWith("user-a", ["i1", "i2"]);
    expect(h.request).toHaveBeenCalledWith(
      "d1",
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: ["i1", "i2"] },
      3000
    );
  });

  it("does nothing for an empty instance list or an empty user", async () => {
    h.services.set("d1", { id: "d1" });
    await revokeUserAccess("user-a", { instanceUuids: [] });
    await revokeUserAccess("");
    expect(h.request).not.toHaveBeenCalled();
    expect(h.closeUserStreams).not.toHaveBeenCalled();
    expect(h.revokeUserTokens).not.toHaveBeenCalled();
    expect(h.revokeUserUploads).not.toHaveBeenCalled();
  });

  it("logs and carries on when a daemon is offline, times out or is too old", async () => {
    h.services.set("d1", { id: "d1" });
    h.services.set("d2", { id: "d2" });
    h.services.set("d3", { id: "d3" });
    h.request.mockImplementation(async (id: string) => {
      if (id === "d1") throw new Error("daemon offline");
      if (id === "d2") throw new Error("request timed out");
      return { sockets: 0, passports: 0 };
    });
    await expect(revokeUserAccess("user-a")).resolves.toBeUndefined();
    expect(h.request).toHaveBeenCalledTimes(3);
  });

  it("still asks the daemons when the panel side throws", async () => {
    h.services.set("d1", { id: "d1" });
    h.closeUserStreams.mockImplementationOnce(() => {
      throw new Error("bridge broke");
    });
    await expect(revokeUserAccess("user-a")).resolves.toBeUndefined();
    expect(h.request).toHaveBeenCalledTimes(1);
  });
});

describe("revokeOnAccessChange", () => {
  beforeEach(() => h.services.set("d1", { id: "d1" }));

  it("revokes nothing for a no-op edit", async () => {
    revokeOnAccessChange("user-a", state(USER, "a"), state(USER, "a"));
    await settle();
    expect(h.request).not.toHaveBeenCalled();
    expect(h.closeUserStreams).not.toHaveBeenCalled();
  });

  it("revokes everything when the user is deleted", async () => {
    revokeOnAccessChange("user-a", state(USER, "a"), null);
    await settle();
    expect(h.request).toHaveBeenCalledWith(
      "d1",
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: undefined },
      3000
    );
  });

  it("revokes only the removed instances", async () => {
    revokeOnAccessChange("user-a", state(USER, "a", "b"), state(USER, "b"));
    await settle();
    expect(h.request).toHaveBeenCalledWith(
      "d1",
      "passport/revoke_user",
      { userUuid: "user-a", instanceUuids: ["a"] },
      3000
    );
  });

  it("never throws or rejects, even when every daemon fails", async () => {
    h.request.mockRejectedValue(new Error("down"));
    expect(() => revokeOnAccessChange("user-a", state(USER, "a"), null)).not.toThrow();
    await settle();
  });
});
