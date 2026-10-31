import http from "http";
import { Readable, Writable } from "stream";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Proxy mode: /upload-piece/:id is forwarded by writer id alone, so the panel's id map has
// to know the user and drop their entries when access is revoked. A real loopback server
// plays the daemon; only the daemon lookup and the passport call are faked.
const h = vi.hoisted(() => ({ port: 0 }));

vi.mock("../remote_service", () => ({
  default: {
    services: new Map(),
    getInstance: vi.fn(() => ({
      config: { addr: `127.0.0.1:${h.port}`, canonicalPrefix: "" }
    }))
  }
}));
vi.mock("../remote_command", () => ({
  default: class {
    request() {
      return Promise.resolve(true);
    }
  }
}));
vi.mock("../log", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

// Namespace import: with vi.mock in the file, a named import of systemConfig would be a stale copy.
import * as setting from "../../setting";
import { revokeUserAccess } from "../access_revoke_service";
import { issueProxyToken } from "../gateway_token";
import { ProxyDataPlane } from "../proxy_data_plane";

let daemon: http.Server;
let writerSeq = 0;
let pieces: string[] = [];

beforeAll(async () => {
  setting.initSystemConfig();
  daemon = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/upload-new/")) {
        res.end(JSON.stringify({ status: 200, data: { id: `w-${++writerSeq}`, received: [] } }));
      } else if (req.url?.startsWith("/upload-piece/")) {
        pieces.push(req.url.split("/")[2].split("?")[0]);
        res.end(JSON.stringify({ status: 200, data: "OK" }));
      } else {
        res.statusCode = 404;
        res.end("{}");
      }
    });
  });
  await new Promise<void>((resolve) => daemon.listen(0, "127.0.0.1", resolve));
  h.port = (daemon.address() as any).port;
});

afterAll(async () => {
  await new Promise((resolve) => daemon.close(resolve));
});

beforeEach(() => {
  setting.systemConfig!.gatewaySecret = "test-gateway-secret-fixed-0123456789abcdef";
  pieces = [];
});

// Drive ProxyDataPlane.handle() with a POST and wait for the reply.
async function post(path: string, search = "") {
  const chunks: Buffer[] = [];
  const res: any = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(Buffer.from(chunk));
      cb();
    }
  });
  res.headersSent = false;
  res.statusCode = 200;
  res.setHeader = vi.fn();
  const finished = new Promise<void>((resolve) => res.on("finish", resolve));
  const req: any = Readable.from([]);
  req.headers = {};
  await ProxyDataPlane.handle({ method: "POST", path, search, query: {}, req, res });
  await finished;
  return { status: res.statusCode as number, text: Buffer.concat(chunks).toString() };
}

// Start an upload with a fresh upload token and return the daemon's writer id.
async function startUpload(instanceUuid: string, userUuid?: string) {
  const token = issueProxyToken({
    daemonId: "d1",
    instanceUuid,
    op: "upload",
    target: ".",
    userUuid
  });
  const r = await post(`/upload-new/${token}`, "?filename=a.bin&size=4");
  expect(r.status).toBe(200);
  return JSON.parse(r.text).data.id as string;
}

describe("proxy upload-piece after a revoke", () => {
  it("forwards pieces of a live upload", async () => {
    const id = await startUpload("inst-1", "user-a");
    expect((await post(`/upload-piece/${id}`, "?offset=0")).status).toBe(200);
    expect(pieces).toEqual([id]);
  });

  it("refuses a piece once the user is revoked, without reaching the daemon", async () => {
    const id = await startUpload("inst-1", "user-a");
    await revokeUserAccess("user-a");
    const r = await post(`/upload-piece/${id}`, "?offset=0");
    expect(r.status).toBe(403);
    expect(pieces).toEqual([]);
  });

  it("with instances, refuses only the writers on those instances", async () => {
    const one = await startUpload("inst-1", "user-a");
    const two = await startUpload("inst-2", "user-a");
    await revokeUserAccess("user-a", { instanceUuids: ["inst-1"] });
    expect((await post(`/upload-piece/${one}`, "?offset=0")).status).toBe(403);
    expect((await post(`/upload-piece/${two}`, "?offset=0")).status).toBe(200);
    expect(pieces).toEqual([two]);
  });

  it("leaves other users' writers and writers without a user alone", async () => {
    const other = await startUpload("inst-1", "user-b");
    const untagged = await startUpload("inst-1");
    await revokeUserAccess("user-a");
    expect((await post(`/upload-piece/${other}`, "?offset=0")).status).toBe(200);
    expect((await post(`/upload-piece/${untagged}`, "?offset=0")).status).toBe(200);
  });
});
