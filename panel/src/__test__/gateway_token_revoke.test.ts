import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { initSystemConfig, systemConfig } from "../app/setting";
import { issueProxyToken, revokeUserTokens, verifyProxyToken } from "../app/service/gateway_token";

beforeAll(() => {
  initSystemConfig();
});

beforeEach(() => {
  systemConfig!.gatewaySecret = "test-gateway-secret-fixed-0123456789abcdef";
  // The nonce store is module state: drop tokens left by earlier tests.
  revokeUserTokens("user-a");
  revokeUserTokens("user-b");
});

function issue(op: "download" | "upload" | "stream", instanceUuid: string, userUuid?: string) {
  return issueProxyToken({ daemonId: "d1", instanceUuid, op, target: "t", userUuid });
}

describe("gateway tokens carry the user", () => {
  it.each(["download", "upload", "stream"] as const)("%s token returns its user", (op) => {
    const binding = verifyProxyToken(issue(op, "inst-1", "user-a"), op);
    expect(binding?.userUuid).toBe("user-a");
  });

  it("a token issued without a user still verifies, with no user on the binding", () => {
    const binding = verifyProxyToken(issue("download", "inst-1"), "download");
    expect(binding).not.toBeNull();
    expect(binding!.userUuid).toBeUndefined();
  });
});

describe("revokeUserTokens", () => {
  it("drops a user's unclaimed tokens and leaves other users' tokens working", () => {
    const a = issue("download", "inst-1", "user-a");
    const b = issue("download", "inst-1", "user-b");
    expect(revokeUserTokens("user-a")).toBe(1);
    expect(verifyProxyToken(a, "download")).toBeNull();
    expect(verifyProxyToken(b, "download")).not.toBeNull();
  });

  it("drops a stream token that is already claimed", () => {
    const token = issue("stream", "inst-1", "user-a");
    expect(verifyProxyToken(token, "stream")).not.toBeNull();
    expect(revokeUserTokens("user-a")).toBe(1);
    expect(verifyProxyToken(token, "stream")).toBeNull();
  });

  it("with instances, drops only the tokens for those instances", () => {
    const keep = issue("upload", "inst-2", "user-a");
    const drop = issue("upload", "inst-1", "user-a");
    expect(revokeUserTokens("user-a", ["inst-1"])).toBe(1);
    expect(verifyProxyToken(drop, "upload")).toBeNull();
    expect(verifyProxyToken(keep, "upload")).not.toBeNull();
  });

  it("never drops tokens that carry no user", () => {
    const untagged = issue("download", "inst-1");
    expect(revokeUserTokens("user-a")).toBe(0);
    expect(revokeUserTokens("")).toBe(0);
    expect(verifyProxyToken(untagged, "download")).not.toBeNull();
  });
});
