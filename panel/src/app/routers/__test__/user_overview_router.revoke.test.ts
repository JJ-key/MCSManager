import { beforeEach, describe, expect, it, vi } from "vitest";

// PUT /auth with a new password: the user's streams must be cut off even when the
// store write behind endSessions() fails, and the admin must still see the error.
const h = vi.hoisted(() => ({
  endSessions: vi.fn(),
  edit: vi.fn(),
  revokeUserAccess: vi.fn(),
  revokeOnAccessChange: vi.fn()
}));

vi.mock("../../i18n", () => ({ $t: (key: string) => key }));
vi.mock("../../middleware/permission", () => ({
  default: () => async (_ctx: any, next: () => Promise<void>) => next()
}));
vi.mock("../../service/user_service", () => ({
  default: {
    validatePassword: () => true,
    getInstance: () => ({ uuid: "u1", userName: "alice", permission: 1, instances: [] }),
    edit: h.edit,
    endSessions: h.endSessions,
    objects: new Map()
  }
}));
vi.mock("../../service/access_revoke_service", () => ({
  revokeOnAccessChange: h.revokeOnAccessChange,
  revokeUserAccess: h.revokeUserAccess,
  snapshotAccess: () => null
}));
vi.mock("../../service/operation_logger", () => ({
  getOperationLoggerOperator: () => ({}),
  operationLogger: { log: vi.fn() }
}));

import router from "../user_overview_router";

function putHandler(): (ctx: any) => Promise<void> {
  const layer = (router as any).stack.find(
    (l: any) => l.path.startsWith("/auth") && l.methods.includes("PUT")
  );
  return layer.stack[layer.stack.length - 1];
}

function makeCtx(config: Record<string, any>) {
  return {
    request: { body: { uuid: "u1", config } },
    body: undefined as any,
    throw(status: number, message: string) {
      throw Object.assign(new Error(message), { status });
    }
  };
}

beforeEach(() => {
  h.endSessions.mockReset().mockResolvedValue(undefined);
  h.edit.mockReset().mockResolvedValue(undefined);
  h.revokeUserAccess.mockReset().mockResolvedValue(undefined);
  h.revokeOnAccessChange.mockReset();
});

describe("PUT /auth password reset", () => {
  it("ends the sessions and cuts the user off", async () => {
    const ctx = makeCtx({ passWord: "new-secret-1A" });
    await putHandler()(ctx);
    expect(h.endSessions).toHaveBeenCalledWith("u1");
    expect(h.revokeUserAccess).toHaveBeenCalledWith("u1");
    expect(ctx.body).toBe(true);
  });

  it("still cuts the user off when endSessions throws, and the admin sees the error", async () => {
    h.endSessions.mockRejectedValue(new Error("disk full"));
    const ctx = makeCtx({ passWord: "new-secret-1A" });
    await expect(putHandler()(ctx)).rejects.toMatchObject({ status: 500, message: "disk full" });
    expect(h.revokeUserAccess).toHaveBeenCalledWith("u1");
  });

  it("does not end sessions or revoke for an edit without a password", async () => {
    await putHandler()(makeCtx({ nickName: "x" }));
    expect(h.endSessions).not.toHaveBeenCalled();
    expect(h.revokeUserAccess).not.toHaveBeenCalled();
  });
});
