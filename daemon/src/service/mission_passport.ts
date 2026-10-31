import RouterContext from "../entity/ctx";

interface IMission {
  name: string;
  parameter: any;
  start: number;
  end: number;
  count?: number;
  isDeleted?: boolean;
  // Panel user the passport was issued to (unset for passports from an older panel).
  userUuid?: string;
}

// An authed stream socket and the (user, instance) pairs it was authed with.
interface IStreamPeer {
  socket: {
    id: string;
    on: Function;
    conn: { close: () => unknown };
    disconnect: (close?: boolean) => unknown;
  };
  grants: Array<{ userUuid: string; instanceUuid: string }>;
}

// Task passport manager
class MissionPassport {
  // temporary task passport list
  public readonly missions = new Map<string, IMission>();

  constructor() {
    // Set up to check the task expiration every hour
    setInterval(() => {
      const t = new Date().getTime();
      this.missions.forEach((m, k) => {
        if (t > m.end || m.isDeleted) this.missions.delete(k);
      });
    }, 1000 * 60);
  }

  // register task passport
  public registerMission(password: string, mission: IMission) {
    if (this.missions.has(password))
      throw new Error("Duplicate primary key, failed to create task");
    this.missions.set(password, mission);
  }

  // Get the task based on the passport and task name
  public getMission(password: string, missionName: string) {
    if (!this.missions.has(password)) return null;
    const m = this.missions.get(password);
    // A consumed passport (deleteMission) must be single-use: honor the
    // isDeleted flag immediately instead of waiting for the 60s sweeper,
    // otherwise a used download/upload/stream passport can be replayed.
    if (m?.isDeleted) return null;
    if (m?.name === missionName) return m;
    return null;
  }

  public deleteMission(password: string, missionName?: string) {
    const m = this.missions.get(password);
    if (!m) return;
    // Only the mission TYPE that actually consumed the passport may retire it.
    // Without this, a probe request against /download/<stream-passport>/... in
    // the download route's cleanup would poison a stream_channel passport and
    // cut terminal reconnects until the TTL sweeper.
    if (missionName && m.name !== missionName) return;
    m.isDeleted = true;
  }

  // Delete every passport issued to a user, or only those for the given instances.
  // Returns how many were deleted.
  public revokeByUser(userUuid: string, instanceUuids?: string[]) {
    let count = 0;
    for (const [password, m] of this.missions) {
      if (m.userUuid !== userUuid) continue;
      if (instanceUuids && !instanceUuids.includes(m.parameter?.instanceUuid)) continue;
      this.missions.delete(password);
      count++;
    }
    return count;
  }
}

const LOGIN_BY_TOP_LEVEL = "TOP_LEVEL";
const LOGIN_FROM_STREAM = "STREAM";

// This function must be executed after successful login
function loginSuccessful(ctx: RouterContext, key: string) {
  ctx.session.key = key;
  ctx.session.login = true;
  ctx.session.id = ctx.socket.id;
  ctx.session.type = LOGIN_BY_TOP_LEVEL;
  ctx.session.stream = {};
  return ctx.session;
}

function streamLoginSuccessful(ctx: RouterContext, instanceUuid: string, userUuid?: string) {
  ctx.session.id = ctx.socket.id;
  ctx.session.login = true;
  ctx.session.type = LOGIN_FROM_STREAM;
  ctx.session.stream = {
    check: true,
    instanceUuid,
    userUuid
  };
  if (userUuid) trackStream(ctx.socket, userUuid, instanceUuid);
  return ctx.session;
}

const missionPassport = new MissionPassport();

// Authed stream sockets that belong to a panel user, keyed by socket id.
// A socket can auth more than once, so it keeps every grant it was given.
const streamPeers = new Map<string, IStreamPeer>();

function trackStream(socket: IStreamPeer["socket"], userUuid: string, instanceUuid: string) {
  let peer = streamPeers.get(socket.id);
  if (!peer) {
    peer = { socket, grants: [] };
    streamPeers.set(socket.id, peer);
    socket.on("disconnect", () => streamPeers.delete(socket.id));
  }
  peer.grants.push({ userUuid, instanceUuid });
}

// Close a socket's transport instead of calling socket.disconnect(): socket.io clients
// do not reconnect after a server disconnect, so the web terminal would spin forever.
// After a transport close it reconnects, fails stream/auth and shows its error.
function closeSocket(socket: IStreamPeer["socket"]) {
  try {
    socket.conn.close();
  } catch {
    socket.disconnect(true);
  }
}

// Cut a user off: delete their passports and close their authed stream sockets.
// With instanceUuids, only the passports and sockets that touch those instances.
function revokeUserAccess(userUuid: string, instanceUuids?: string[]) {
  const passports = missionPassport.revokeByUser(userUuid, instanceUuids);
  let sockets = 0;
  for (const peer of Array.from(streamPeers.values())) {
    const matched = peer.grants.some(
      (g) => g.userUuid === userUuid && (!instanceUuids || instanceUuids.includes(g.instanceUuid))
    );
    if (!matched) continue;
    streamPeers.delete(peer.socket.id);
    closeSocket(peer.socket);
    sockets++;
  }
  return { sockets, passports };
}

export {
  missionPassport,
  IMission,
  LOGIN_BY_TOP_LEVEL,
  LOGIN_FROM_STREAM,
  loginSuccessful,
  streamLoginSuccessful,
  revokeUserAccess
};
