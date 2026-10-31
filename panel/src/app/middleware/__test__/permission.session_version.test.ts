import { beforeEach, describe, expect, it, vi } from "vitest";

// Covers the session-version check in the permission middleware: an admin
// password reset bumps the user's sessionVersion, and older sessions must end.
const h = vi.hoisted(() => ({
  user: undefined as any,
  logout: vi.fn()
}));

vi.mock("../../i18n", () => ({ $t: (key: string) => key }));
vi.mock("../../setting", () => ({ systemConfig: {} }));
vi.mock("../../service/user_service", () => ({ default: { getInstance: () => h.user } }));
vi.mock("../../service/passport_service", () => ({
  ILLEGAL_ACCESS_KEY: "illegalAccess",
  getUuidByApiKey: vi.fn(),
  isAjax: () => true,
  logout: h.logout
}));

import permission from "../permission";

function makeCtx(session: Record<string, any>) {
  return {
    request: { header: {} },
    query: { token: "tok" },
    session: { login: true, uuid: "u1", userName: "name", token: "tok", ...session },
    status: 200,
    body: undefined as any
  } as any;
}

async function run(session: Record<string, any>) {
  const ctx = makeCtx(session);
  const next = vi.fn(async () => {});
  await permission({ level: 1, speedLimit: false })(ctx, next);
  return { ctx, next };
}

beforeEach(() => {
  h.logout.mockClear();
  h.user = { uuid: "u1", permission: 1 };
});

describe("permission: session version", () => {
  it("keeps an old session logged in when neither side has the field", async () => {
    const { next, ctx } = await run({});
    expect(next).toHaveBeenCalled();
    expect(ctx.status).toBe(200);
    expect(h.logout).not.toHaveBeenCalled();
  });

  it("accepts a session whose version matches the user's", async () => {
    h.user.sessionVersion = 3;
    const { next } = await run({ sessionVersion: 3 });
    expect(next).toHaveBeenCalled();
  });

  it("ends a session that predates a password reset", async () => {
    h.user.sessionVersion = 1;
    const { next, ctx } = await run({});
    expect(next).not.toHaveBeenCalled();
    expect(ctx.status).toBe(403);
    expect(h.logout).toHaveBeenCalledTimes(1);
  });

  it("ends a session with an older version than the user's", async () => {
    h.user.sessionVersion = 2;
    const { next, ctx } = await run({ sessionVersion: 1 });
    expect(next).not.toHaveBeenCalled();
    expect(ctx.status).toBe(403);
  });

  it("still logs a banned user out", async () => {
    h.user.permission = -1;
    const { next } = await run({});
    expect(next).not.toHaveBeenCalled();
    expect(h.logout).toHaveBeenCalledTimes(1);
  });

  it("still rejects a deleted user", async () => {
    h.user = undefined;
    const { next, ctx } = await run({});
    expect(next).not.toHaveBeenCalled();
    expect(ctx.status).toBe(403);
  });
});
