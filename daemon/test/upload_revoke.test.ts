import fs from "fs-extra";
import os from "os";
import path from "path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { globalConfiguration } from "../src/entity/config";
import { missionPassport } from "../src/service/mission_passport";
import uploadManager from "../src/service/upload_manager";
import { dispatch, flush, packetsFor } from "./harness/router";

// Chunked uploads after a revoke. /upload-new hands back a writer id and
// /upload-piece/:id then needs only that id, so passport/revoke_user has to stop
// the user's writers too. The real http_router handlers, the real FileWriter and a
// real temp folder are used; only the instance lookup and the logger are faked.

const sandbox = vi.hoisted(() => ({ dir: "" }));

vi.mock("../src/service/log", () => {
  const f: any = () => {};
  f.info = f;
  f.debug = f;
  f.warn = f;
  f.error = f;
  return { default: f };
});

vi.mock("../src/service/system_instance", () => ({
  default: {
    getInstance: vi.fn((uuid: string) => ({
      instanceUuid: uuid,
      config: {},
      info: { fileLock: 0 },
      absoluteCwdPath: () => sandbox.dir
    })),
    forward: vi.fn(),
    stopForward: vi.fn()
  }
}));

import "../src/routers/auth_router";
import "../src/routers/passport_router";
import httpRouter from "../src/routers/http_router";

const KEY = "test-key";

function handler(routePath: string): (ctx: any) => Promise<void> {
  const layer = (httpRouter as any).stack.find(
    (l: any) => l.path === routePath && l.methods.includes("POST")
  );
  return layer.stack[layer.stack.length - 1];
}

let passportSeq = 0;
function register(instanceUuid: string, userUuid?: string) {
  const password = `up-${passportSeq++}`;
  missionPassport.registerMission(password, {
    name: "upload",
    parameter: { uploadDir: ".", instanceUuid },
    start: Date.now(),
    end: Date.now() + 3600000,
    userUuid
  });
  return password;
}

// POST /upload-new/:key for a file of `size` bytes. Returns the writer id.
async function startUpload(passport: string, filename: string, size: number) {
  const ctx: any = { params: { key: passport }, query: { filename, size: String(size) } };
  await handler("/upload-new/:key")(ctx);
  expect(ctx.status ?? 200).toBe(200);
  return ctx.body.data.id as string;
}

// POST /upload-piece/:id with `text` at `offset`.
let pieceSeq = 0;
async function sendPiece(id: string, offset: number, text: string) {
  const filepath = path.join(sandbox.dir, `.piece-${pieceSeq++}`);
  await fs.writeFile(filepath, text);
  const ctx: any = {
    params: { id },
    query: { offset: String(offset) },
    request: { files: { file: { filepath } } }
  };
  await handler("/upload-piece/:id")(ctx);
  return ctx as { body: string; status?: number };
}

function revoke(data: any) {
  const { socket } = dispatch("passport/revoke_user", data, {
    session: { key: KEY, login: true, id: "panel-sock", type: "TOP_LEVEL", stream: {} }
  });
  return socket;
}

async function revokeAndSettle(data: any) {
  const socket = revoke(data);
  await flush();
  // The writers are stopped in the background.
  await flush();
  return packetsFor(socket, "passport/revoke_user")[0];
}

beforeAll(() => {
  sandbox.dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcs-upload-revoke-"));
});

afterAll(() => {
  fs.removeSync(sandbox.dir);
});

beforeEach(() => {
  globalConfiguration.config.key = KEY;
  missionPassport.missions.clear();
});

afterEach(async () => {
  await uploadManager.exit();
});

describe("chunked uploads and passport/revoke_user", () => {
  it("refuses a piece after the user is revoked, and the file is never finished", async () => {
    const id = await startUpload(register("inst-1", "user-a"), "big.bin", 4);
    expect((await sendPiece(id, 0, "ab")).body).toBe("OK");

    const res = await revokeAndSettle({ userUuid: "user-a" });
    expect(res.status).toBe(200);
    expect(res.data.uploads).toBe(1);

    const late = await sendPiece(id, 2, "cd");
    expect(late.status).toBe(500);
    expect(late.body).toBe("Access denied: No task found");
    expect(uploadManager.get(id)).toBeUndefined();
    // The half-written file is cleaned up instead of being completed.
    expect(fs.existsSync(path.join(sandbox.dir, "big.bin"))).toBe(false);
  });

  it("with instances, stops only the writers on those instances", async () => {
    const one = await startUpload(register("inst-1", "user-a"), "one.bin", 4);
    const two = await startUpload(register("inst-2", "user-a"), "two.bin", 4);

    const res = await revokeAndSettle({ userUuid: "user-a", instanceUuids: ["inst-1"] });
    expect(res.data.uploads).toBe(1);

    expect((await sendPiece(one, 0, "abcd")).status).toBe(500);
    const kept = await sendPiece(two, 0, "abcd");
    expect(kept.body).toBe("OK");
    expect(fs.readFileSync(path.join(sandbox.dir, "two.bin"), "utf8")).toBe("abcd");
  });

  it("leaves other users' writers and writers without a user alone", async () => {
    const other = await startUpload(register("inst-1", "user-b"), "b.bin", 2);
    const untagged = await startUpload(register("inst-1"), "none.bin", 2);

    const res = await revokeAndSettle({ userUuid: "user-a" });
    expect(res.data.uploads).toBe(0);

    expect((await sendPiece(other, 0, "xy")).body).toBe("OK");
    expect((await sendPiece(untagged, 0, "xy")).body).toBe("OK");
  });

  it("a writer id is never handed to a different user who starts the same upload", async () => {
    const first = await startUpload(register("inst-1", "user-a"), "same.bin", 4);
    // The same user resuming keeps the writer.
    expect(await startUpload(register("inst-1", "user-a"), "same.bin", 4)).toBe(first);
    // Another user (or an untagged passport) gets a new writer, so revoking user-a
    // cannot be dodged by asking for user-a's id back, nor cut the other user off.
    const second = await startUpload(register("inst-1", "user-b"), "same.bin", 4);
    expect(second).not.toBe(first);
    expect(uploadManager.get(first)).toBeUndefined();

    const res = await revokeAndSettle({ userUuid: "user-a" });
    expect(res.data.uploads).toBe(0);
    expect((await sendPiece(second, 0, "abcd")).body).toBe("OK");
  });
});
