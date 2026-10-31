#!/usr/bin/env node
// End-to-end check that removing a user's access cuts them off at once.
//
// It starts the BUILT daemon and panel (panel/production/app.js, daemon/production/app.js)
// on spare loopback ports with temporary data folders, installs an admin, adds the
// daemon, creates two instances and some users, and then drives everything over real
// HTTP and socket.io: a user opens terminal streams and file links, the admin removes
// their access, and every cut-off must show within 3 seconds.
//
//   node scripts/test-revoke.mjs                 both data-plane modes
//   node scripts/test-revoke.mjs --mode=direct   one mode (direct | proxy)
//   node scripts/test-revoke.mjs --repo=<dir>    use the builds of another checkout
//   node scripts/test-revoke.mjs --keep          keep the temporary folder and its logs
//
// Build first: (cd panel && npm run build) && (cd daemon && npm run build).
// It never uses ports 23333 or 24444 and never touches a real panel's data.
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const arg = (name) => process.argv.find((a) => a.startsWith(`--${name}=`))?.split("=")[1];
const REPO = path.resolve(arg("repo") ?? path.join(here, ".."));
const MODES = arg("mode") ? [arg("mode")] : ["direct", "proxy"];
const KEEP = process.argv.includes("--keep");
const DEADLINE_MS = 3000; // every cut-off must show within this long

const requireFromPanel = createRequire(path.join(REPO, "panel", "package.json"));
const { io } = requireFromPanel("socket.io-client");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, stepMs = 50) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(stepMs);
  }
  return false;
}

// ---------------------------------------------------------------- results
const results = [];
let currentMode = "";
function check(name, ok, detail = "") {
  results.push({ mode: currentMode, name, ok });
  console.log(`${ok ? "PASS" : "FAIL"} [${currentMode}] ${name}${detail ? "  (" + detail + ")" : ""}`);
}

// ---------------------------------------------------------------- processes
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function startApp(name, appJs, cwd) {
  const logFile = path.join(cwd, `${name}.out.log`);
  const out = fs.openSync(logFile, "w");
  const proc = spawn(process.execPath, [appJs], { cwd, stdio: ["ignore", out, out] });
  return { name, proc, logFile };
}

function stopApp(app) {
  if (!app || app.proc.exitCode !== null) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(app.proc.pid), "/T", "/F"], { stdio: "ignore" });
  } else {
    app.proc.kill("SIGKILL");
  }
}

// ---------------------------------------------------------------- panel HTTP client
class Client {
  constructor(base) {
    this.base = base;
    this.cookies = new Map();
    this.token = "";
  }

  async req(method, apiPath, { query = {}, body } = {}) {
    for (let attempt = 0; attempt < 15; attempt++) {
      const url = new URL(`${this.base}/api${apiPath}`);
      for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
      if (this.token) url.searchParams.set("token", this.token);
      const headers = { "x-requested-with": "XMLHttpRequest" };
      if (this.cookies.size)
        headers.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
      if (body !== undefined) headers["content-type"] = "application/json";
      const res = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "manual"
      });
      for (const line of res.headers.getSetCookie?.() ?? []) {
        const [pair] = line.split(";");
        const eq = pair.indexOf("=");
        if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
      const text = await res.text();
      let parsed = text;
      try {
        parsed = JSON.parse(text);
      } catch {
        /* plain text body */
      }
      const enveloped = parsed && typeof parsed === "object" && "status" in parsed && "data" in parsed;
      const out = {
        http: res.status,
        status: enveloped ? parsed.status : res.status,
        data: enveloped ? parsed.data : parsed
      };
      // Some routes rate-limit per user and path; wait it out like a patient browser would.
      if (res.status === 500 && /cooldown|too many requests/i.test(String(out.data))) {
        await sleep(500);
        continue;
      }
      return out;
    }
    throw new Error(`${method} ${apiPath}: still rate limited after retries`);
  }

  async login(username, password) {
    const r = await this.req("POST", "/auth/login", { body: { username, password } });
    if (r.http !== 200 || typeof r.data !== "string") throw new Error(`login ${username} failed: ${JSON.stringify(r)}`);
    this.token = r.data;
    return this;
  }
}

// ---------------------------------------------------------------- terminal streams
// A browser-like terminal: connect, send stream/auth, then speak the stream protocol.
function openStream(info, { reconnect = false } = {}) {
  const s = {
    passport: info.password,
    info,
    details: 0,
    authOk: false,
    authFailed: false,
    droppedAt: 0,
    dropReason: ""
  };
  s.socket = io(`http://${info.addr}`, {
    path: `${info.prefix || ""}/socket.io`,
    transports: ["websocket"],
    reconnection: reconnect,
    reconnectionAttempts: 3,
    reconnectionDelay: 300,
    forceNew: true,
    timeout: 8000
  });
  // Same handlers as frontend/src/hooks/useTerminal.ts: auth on every (re)connect.
  s.socket.on("connect", () => s.socket.emit("stream/auth", { data: { password: s.passport } }));
  s.socket.on("stream/auth", (pkt) => {
    if (pkt?.data === true) {
      s.authOk = true;
      s.socket.emit("stream/detail", {});
    } else {
      s.authFailed = true;
    }
  });
  s.socket.on("stream/detail", () => s.details++);
  s.reconnects = 0;
  s.socket.io.on("reconnect_attempt", () => s.reconnects++);
  s.socket.on("disconnect", (reason) => {
    s.droppedAt ||= Date.now();
    s.dropReason = reason;
  });
  s.ready = waitFor(() => s.authOk || s.authFailed, 8000).then(() => s.authOk);
  return s;
}

// Does the stream still answer? (A stream the server cut off never does.)
async function isAlive(s) {
  if (!s.socket.connected) return false;
  const before = s.details;
  s.socket.emit("stream/detail", {});
  return waitFor(() => s.details > before, 2000);
}

// Wait for the server to cut the stream; returns how long it took, or null.
async function dropTime(s, since) {
  const dropped = await waitFor(() => !s.socket.connected, DEADLINE_MS + 1500, 20);
  return dropped ? (s.droppedAt || Date.now()) - since : null;
}

// Can a fresh connection still log in with this passport?
async function canReauth(info) {
  const s = openStream(info);
  const ok = await s.ready;
  s.socket.close();
  return ok;
}

const closeStream = (s) => s.socket.close();

// ---------------------------------------------------------------- scenario helpers
async function mintStream(client, daemonId, instanceUuid) {
  const r = await client.req("POST", "/protected_instance/stream_channel", {
    query: { daemonId, uuid: instanceUuid }
  });
  return { ok: r.http === 200 && !!r.data?.password, http: r.http, info: r.data };
}

async function mintLink(client, daemonId, instanceUuid) {
  const r = await client.req("GET", "/files/download", {
    query: { daemonId, uuid: instanceUuid, file_name: "hello.txt" }
  });
  return { ok: r.http === 200 && !!r.data?.password, http: r.http, link: r.data };
}

async function useLink(link) {
  const base = /^https?:/.test(link.addr) ? link.addr : `http://${link.addr}`;
  const url = `${base}/download/${encodeURIComponent(link.password)}/hello.txt`;
  const res = await fetch(url);
  return { status: res.status, body: await res.text() };
}

const linkWorks = (r) => r.status === 200 && r.body === "hello";

// Raw daemon socket for the panel-key session and for the gate test.
function rawDaemonSocket(daemonPort) {
  const s = { events: [], socket: null };
  s.socket = io(`http://127.0.0.1:${daemonPort}`, {
    path: "/socket.io",
    transports: ["websocket"],
    reconnection: false,
    forceNew: true
  });
  s.socket.onAny((event, pkt) => s.events.push({ event, pkt }));
  s.ready = new Promise((resolve) => s.socket.on("connect", () => resolve(true)));
  return s;
}

async function daemonCall(s, event, data, timeoutMs = 2000) {
  const uuid = crypto.randomUUID();
  s.socket.emit(event, { uuid, data });
  const got = await waitFor(
    () => s.events.some((e) => e.event === event && e.pkt?.uuid === uuid),
    timeoutMs,
    20
  );
  return got ? s.events.find((e) => e.event === event && e.pkt?.uuid === uuid).pkt : null;
}

// ---------------------------------------------------------------- one full run
async function runMode(mode) {
  currentMode = mode;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), `mcsm-revoke-${mode}-`));
  // Not named "daemon"/"panel": the panel must not auto-discover this daemon by path.
  const daemonDir = path.join(work, "daemon-data");
  const panelDir = path.join(work, "panel-data");
  fs.mkdirSync(path.join(daemonDir, "data", "Config"), { recursive: true });
  fs.mkdirSync(path.join(panelDir, "data", "SystemConfig"), { recursive: true });

  const daemonPort = await freePort();
  const panelPort = await freePort();
  if ([daemonPort, panelPort].some((p) => p === 23333 || p === 24444)) throw new Error("picked a reserved port");
  const daemonKey = crypto.randomBytes(24).toString("hex");

  // The daemon refuses to start without its external binaries (and fetches steamcmd on
  // Windows). This run never starts an instance or zips anything, so empty stubs in the
  // throwaway folder are enough; nothing is downloaded and nothing executes them.
  const exe = os.platform() === "win32" ? ".exe" : "";
  const libDir = path.join(daemonDir, "lib");
  fs.mkdirSync(libDir, { recursive: true });
  const steam = os.platform() === "win32" ? "steamcmd.exe" : `steamcmd_${os.arch()}`;
  for (const stub of [`file_zip_${os.platform()}_${os.arch()}${exe}`, steam])
    fs.writeFileSync(path.join(libDir, stub), "");

  fs.writeFileSync(
    path.join(daemonDir, "data", "Config", "global.json"),
    JSON.stringify({ version: 2, ip: "127.0.0.1", port: daemonPort, key: daemonKey, language: "en_us" })
  );
  fs.writeFileSync(
    path.join(panelDir, "data", "SystemConfig", "config.json"),
    JSON.stringify({ httpPort: panelPort, httpIp: "127.0.0.1", dataPlane: mode })
  );

  console.log(`\n== ${mode} mode: panel :${panelPort}, daemon :${daemonPort}, data ${work}`);
  const daemon = startApp("daemon", path.join(REPO, "daemon", "production", "app.js"), daemonDir);
  const panel = startApp("panel", path.join(REPO, "panel", "production", "app.js"), panelDir);
  const sockets = [];
  const trackStream = (s) => (sockets.push(s), s);
  let failed = false;

  try {
    const panelUrl = `http://127.0.0.1:${panelPort}`;
    const up = await waitFor(async () => {
      try {
        return (await fetch(`${panelUrl}/api/auth/status`)).status === 200;
      } catch {
        return false;
      }
    }, 60000, 300);
    if (!up) throw new Error("panel did not start");

    // --- admin, daemon, instances, users
    const ADMIN_PASS = "AdminPass123";
    const anon = new Client(panelUrl);
    const inst = await anon.req("POST", "/auth/install", { body: { username: "admin", password: ADMIN_PASS } });
    if (inst.http !== 200) throw new Error(`install failed: ${JSON.stringify(inst)}`);
    const admin = await new Client(panelUrl).login("admin", ADMIN_PASS);

    const added = await admin.req("POST", "/service/remote_service", {
      body: { apiKey: daemonKey, port: daemonPort, ip: "127.0.0.1", remarks: "e2e", prefix: "" }
    });
    const daemonId = added.data;
    if (added.http !== 200 || !daemonId) throw new Error(`add daemon failed: ${JSON.stringify(added)}`);
    const daemonUp = await waitFor(async () => {
      const list = await admin.req("GET", "/service/remote_services_list");
      return Array.isArray(list.data) && list.data.some((d) => d.uuid === daemonId && d.available);
    }, 30000, 300);
    if (!daemonUp) throw new Error("daemon never became available");

    const makeInstance = async (nickname) => {
      const r = await admin.req("POST", "/instance", {
        query: { daemonId },
        body: { nickname, startCommand: "node -v", stopCommand: "exit", cwd: "", ie: "utf-8", oe: "utf-8" }
      });
      if (r.http !== 200 || !r.data?.instanceUuid) throw new Error(`create instance failed: ${JSON.stringify(r)}`);
      const uuid = r.data.instanceUuid;
      const q = { daemonId, uuid };
      await admin.req("POST", "/files/touch", { query: q, body: { target: "hello.txt" } });
      await admin.req("PUT", "/files", { query: q, body: { target: "hello.txt", text: "hello" } });
      return uuid;
    };
    const I1 = await makeInstance("e2e-one");
    const I2 = await makeInstance("e2e-two");

    const USER_PASS = "UserPass123";
    const makeUser = async (name, permission, instances) => {
      const c = await admin.req("POST", "/auth", { body: { username: name, password: USER_PASS, permission } });
      const uuid = c.data?.uuid;
      if (c.http !== 200 || !uuid) throw new Error(`create user ${name} failed: ${JSON.stringify(c)}`);
      const put = await admin.req("PUT", "/auth", {
        body: { uuid, config: { instances: instances.map((instanceUuid) => ({ daemonId, instanceUuid })) } }
      });
      if (put.http !== 200) throw new Error(`assign instances to ${name} failed: ${JSON.stringify(put)}`);
      return { name, uuid, client: await new Client(panelUrl).login(name, USER_PASS) };
    };
    const control = await makeUser("control", 1, [I1, I2]);
    const uDelete = await makeUser("u_delete", 1, [I1, I2]);
    const uBan = await makeUser("u_ban", 1, [I1, I2]);
    const uLower = await makeUser("u_lower", 10, []);
    const uRemove = await makeUser("u_remove", 1, [I1, I2]);
    const uReset = await makeUser("u_reset", 1, [I1, I2]);

    // --- control user: streams on both instances, up for the whole run
    const cStream1 = trackStream(openStream((await mintStream(control.client, daemonId, I1)).info));
    const cStream2 = trackStream(openStream((await mintStream(control.client, daemonId, I2)).info));
    check("setup: control user's streams authenticate", (await cStream1.ready) && (await cStream2.ready));
    const sanity = await mintLink(control.client, daemonId, I1);
    check("setup: a file link works before any revocation", sanity.ok && linkWorks(await useLink(sanity.link)));

    const controlStillUp = async (label) => {
      const up = (await isAlive(cStream1)) && (await isAlive(cStream2));
      check(`control: other user's streams stay up after ${label}`, up);
    };

    // Open a stream plus a file link for a user on an instance, ready to be cut off.
    const arm = async (user, instanceUuid, { reconnect = false } = {}) => {
      const minted = await mintStream(user.client, daemonId, instanceUuid);
      const stream = trackStream(openStream(minted.info, { reconnect }));
      const link = await mintLink(user.client, daemonId, instanceUuid);
      const ready = await stream.ready;
      if (!minted.ok || !ready || !link.ok) throw new Error(`could not arm ${user.name} on ${instanceUuid}`);
      return { stream, link: link.link, info: minted.info };
    };

    // The four checks every cut-off must pass.
    const expectCutOff = async (label, user, instanceUuid, armed, since, { http = 403 } = {}) => {
      const took = await dropTime(armed.stream, since);
      check(`${label}: stream socket drops within ${DEADLINE_MS / 1000}s`, took !== null && took <= DEADLINE_MS, took === null ? "never dropped" : `${took} ms`);
      check(`${label}: the same passport cannot re-auth`, !(await canReauth(armed.info)));
      const minted = await mintStream(user.client, daemonId, instanceUuid);
      check(
        `${label}: HTTP is refused (${http === 403 ? "403" : ">=400"})`,
        http === 403 ? minted.http === 403 : minted.http >= 400,
        `got ${minted.http}`
      );
      const used = await useLink(armed.link);
      check(`${label}: an issued file link fails`, !linkWorks(used), `got ${used.status}`);
    };

    // --- 1. delete user (with a frontend-like reconnecting client as well)
    {
      const armed = await arm(uDelete, I1);
      // A second terminal that reconnects like the web UI does (proxy tokens are one connection each).
      const browser = trackStream(
        openStream((await mintStream(uDelete.client, daemonId, I1)).info, { reconnect: true })
      );
      await browser.ready;
      const t0 = Date.now();
      const del = await admin.req("DELETE", "/auth", { body: [uDelete.uuid] });
      check("delete user: admin request succeeds", del.http === 200, `got ${del.http}`);
      await expectCutOff("delete user", uDelete, I1, armed, t0);
      const ended = await waitFor(() => browser.authFailed, 10000, 100);
      check(
        "delete user: a reconnecting terminal ends in an auth error, not a hang",
        ended,
        `dropped: ${browser.dropReason}, connected: ${browser.socket.connected}, reconnects: ${browser.reconnects}`
      );
      await controlStillUp("delete user");
    }

    // --- 2. ban user
    {
      const armed = await arm(uBan, I1);
      const t0 = Date.now();
      const put = await admin.req("PUT", "/auth", { body: { uuid: uBan.uuid, config: { permission: -1 } } });
      check("ban user: admin request succeeds", put.http === 200, `got ${put.http}`);
      await expectCutOff("ban user", uBan, I1, armed, t0, { http: 400 });
      await controlStillUp("ban user");
    }

    // --- 3. lower permission (admin -> normal user who keeps only instance two)
    {
      const armed1 = await arm(uLower, I1);
      const armed2 = await arm(uLower, I2);
      const t0 = Date.now();
      const put = await admin.req("PUT", "/auth", {
        body: { uuid: uLower.uuid, config: { permission: 1, instances: [{ daemonId, instanceUuid: I2 }] } }
      });
      check("lower permission: admin request succeeds", put.http === 200, `got ${put.http}`);
      await expectCutOff("lower permission", uLower, I1, armed1, t0);
      const kept = await mintStream(uLower.client, daemonId, I2);
      check("lower permission: the instance they keep can be reopened", kept.ok, `got ${kept.http}`);
      console.log(`info [${mode}] lowered user's stream on the kept instance dropped too: ${!(await isAlive(armed2.stream))}`);
      await controlStillUp("lower permission");
    }

    // --- 4. remove one instance from a user's list
    {
      const armed1 = await arm(uRemove, I1);
      const armed2 = await arm(uRemove, I2);
      const t0 = Date.now();
      const put = await admin.req("PUT", "/auth", {
        body: { uuid: uRemove.uuid, config: { instances: [{ daemonId, instanceUuid: I2 }] } }
      });
      check("remove one instance: admin request succeeds", put.http === 200, `got ${put.http}`);
      await expectCutOff("remove one instance", uRemove, I1, armed1, t0);
      check("remove one instance: the stream on their other instance stays up", await isAlive(armed2.stream));
      check("remove one instance: their other instance's file link still works", linkWorks(await useLink(armed2.link)));
      await controlStillUp("remove one instance");
    }

    // --- 5. admin resets the password
    {
      const armed = await arm(uReset, I1);
      const t0 = Date.now();
      const put = await admin.req("PUT", "/auth", { body: { uuid: uReset.uuid, config: { passWord: "ResetPass456" } } });
      check("reset password: admin request succeeds", put.http === 200, `got ${put.http}`);
      await expectCutOff("reset password", uReset, I1, armed, t0);
      const old = await uReset.client.req("GET", "/auth/");
      check("reset password: the old session is refused", old.http === 403, `got ${old.http}`);
      const fresh = await new Client(panelUrl).login(uReset.name, "ResetPass456").catch(() => null);
      const reopened = fresh ? await mintStream(fresh, daemonId, I1) : { ok: false };
      check("reset password: logging in with the new password works", reopened.ok);
      await controlStillUp("reset password");
    }

    // --- 6. the control user is untouched at the end
    {
      const again = await mintStream(control.client, daemonId, I1);
      check("control: still has HTTP access at the end", again.ok, `got ${again.http}`);
      const link = await mintLink(control.client, daemonId, I1);
      check("control: a fresh file link still works at the end", link.ok && linkWorks(await useLink(link.link)));
    }

    // --- 7. a user's stream socket cannot call the daemon's revoke route
    {
      const key = rawDaemonSocket(daemonPort);
      await key.ready;
      const auth = await daemonCall(key, "auth", daemonKey);
      check("gate: the panel key session logs in on the daemon", auth?.data === true);

      const probe = await daemonCall(key, "passport/revoke_user", { userUuid: "nobody" });
      check(
        "gate: the key session can call passport/revoke_user",
        probe?.status === 200 && probe.data?.sockets === 0 && probe.data?.passports === 0,
        JSON.stringify(probe?.data)
      );

      // Two synthetic users whose streams run straight against the daemon.
      const register = (password, userUuid) =>
        daemonCall(key, "passport/register", {
          name: "stream_channel",
          password,
          parameter: { instanceUuid: I1 },
          userUuid
        });
      await register("victim-passport", "victim-user");
      await register("attacker-passport", "attacker-user");
      const direct = (password) => ({ addr: `127.0.0.1:${daemonPort}`, prefix: "", password });
      const victim = trackStream(openStream(direct("victim-passport")));
      const attacker = trackStream(openStream(direct("attacker-passport")));
      check("gate: user stream sockets authenticate on the daemon", (await victim.ready) && (await attacker.ready));

      const events = [];
      attacker.socket.onAny((event, pkt) => events.push({ event, pkt }));
      attacker.socket.emit("passport/revoke_user", { uuid: "evil-1", data: { userUuid: "victim-user" } });
      await sleep(1200);
      const answered = events.some((e) => e.event === "passport/revoke_user" && e.pkt?.status === 200);
      check("gate: a user's stream socket calling the route is refused", !answered, JSON.stringify(events.map((e) => e.event)));
      check("gate: the refused call cut nobody off", (await isAlive(victim)) && (await canReauth(direct("victim-passport"))));

      const real = await daemonCall(key, "passport/revoke_user", { userUuid: "victim-user" });
      check("gate: the same call from the key session works", real?.status === 200 && real.data?.sockets === 1, JSON.stringify(real?.data));
      const took = await dropTime(victim, Date.now() - 50);
      check("gate: ...and the victim's stream drops", took !== null);
      check("gate: the attacker's own stream is untouched", await isAlive(attacker));
      key.socket.close();
    }
  } catch (err) {
    failed = true;
    check(`run aborted: ${err.message}`, false);
  } finally {
    for (const s of sockets) {
      try {
        closeStream(s);
      } catch {
        /* already closed */
      }
    }
    stopApp(panel);
    stopApp(daemon);
    await sleep(500);
    const anyFail = failed || results.some((r) => r.mode === mode && !r.ok);
    if (KEEP || anyFail) console.log(`logs kept in ${work}`);
    else fs.rmSync(work, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- main
for (const f of ["panel/production/app.js", "daemon/production/app.js"]) {
  if (!fs.existsSync(path.join(REPO, f))) {
    console.error(`${f} is missing in ${REPO}: build the panel and daemon first.`);
    process.exit(2);
  }
}
for (const mode of MODES) await runMode(mode);

const failedChecks = results.filter((r) => !r.ok);
console.log(`\n${results.length - failedChecks.length}/${results.length} checks passed`);
for (const r of failedChecks) console.log(`  FAILED [${r.mode}] ${r.name}`);
process.exit(failedChecks.length ? 1 : 0);
