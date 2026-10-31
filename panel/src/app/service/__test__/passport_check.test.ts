import { beforeEach, describe, expect, it, vi } from "vitest";

// check() is what /auth/login asks before it logs anybody in: "does this cookie
// already hold a live session?". A session ended by a password reset, or one of a
// deleted user, must read as logged out so the login goes through and mints a new one.
const h = vi.hoisted(() => ({ users: new Map<string, any>() }));

vi.mock("../../i18n", () => ({ $t: (key: string) => key }));
vi.mock("../../setting", () => ({ systemConfig: {} }));
vi.mock("../log", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));
vi.mock("../user_service", () => ({
  default: { getInstance: (uuid: string) => h.users.get(uuid) }
}));

import { check } from "../passport_service";

function ctxWith(session: Record<string, any> | null) {
  return {
    session: session && {
      login: true,
      userName: "alice",
      uuid: "u1",
      token: "tok",
      ...session
    }
  } as any;
}

beforeEach(() => {
  h.users.clear();
  h.users.set("u1", { uuid: "u1", userName: "alice", permission: 1 });
});

describe("check", () => {
  it("is false without a session or without the login fields", () => {
    expect(check({ session: null } as any)).toBe(false);
    expect(check(ctxWith({ login: null }))).toBe(false);
    expect(check(ctxWith({ token: null }))).toBe(false);
    expect(check(ctxWith({ userName: null }))).toBe(false);
  });

  it("keeps an existing session valid when neither side has a counter", () => {
    expect(check(ctxWith({}))).toBe(true);
  });

  it("treats a missing counter as 0 on either side", () => {
    expect(check(ctxWith({ sessionVersion: 0 }))).toBe(true);
    h.users.get("u1").sessionVersion = 0;
    expect(check(ctxWith({}))).toBe(true);
  });

  it("is true while the session carries the user's current counter", () => {
    h.users.get("u1").sessionVersion = 3;
    expect(check(ctxWith({ sessionVersion: 3 }))).toBe(true);
  });

  it("is false for a session older than a password reset", () => {
    h.users.get("u1").sessionVersion = 1;
    expect(check(ctxWith({ sessionVersion: 0 }))).toBe(false);
    expect(check(ctxWith({}))).toBe(false);
  });

  it("is false when the session holds a counter the user does not have", () => {
    expect(check(ctxWith({ sessionVersion: 2 }))).toBe(false);
  });

  it("is false once the user no longer exists", () => {
    h.users.delete("u1");
    expect(check(ctxWith({}))).toBe(false);
  });

  it("is false for a session that carries no user id", () => {
    expect(check(ctxWith({ uuid: null }))).toBe(false);
  });
});
