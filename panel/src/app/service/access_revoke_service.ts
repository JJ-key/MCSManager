import { IUserApp, ROLE, User } from "../entity/user";
import { revokeUserTokens } from "./gateway_token";
import { logger } from "./log";
import { revokeUserUploads } from "./proxy_data_plane";
import RemoteRequest from "./remote_command";
import RemoteServiceSubsystem from "./remote_service";
import { closeUserStreams } from "./terminal_bridge";

// How long to wait for one daemon before giving up on it.
const DAEMON_REVOKE_TIMEOUT_MS = 3000;

// The part of a user that decides which instances they can reach.
export interface AccessState {
  permission: number;
  instances: Array<Pick<IUserApp, "daemonId" | "instanceUuid">>;
}

// What a user lost: everything, or only the listed instances.
export interface AccessLoss {
  all: boolean;
  instanceUuids: string[];
}

export function snapshotAccess(user?: User | null): AccessState | null {
  if (!user) return null;
  return {
    permission: user.permission,
    instances: (user.instances ?? []).map((v) => ({
      daemonId: v.daemonId,
      instanceUuid: v.instanceUuid
    }))
  };
}

/**
 * Compare a user's access before and after a change. Returns what they lost,
 * or null when nothing was reduced (so a no-op edit revokes nothing).
 * `after` is null when the user was deleted.
 */
export function computeAccessLoss(
  before: AccessState | null,
  after: AccessState | null
): AccessLoss | null {
  if (!before) return null;
  // Deleted, banned (negative permission) or lowered (for example admin to normal).
  if (!after || after.permission < before.permission) return { all: true, instanceUuids: [] };
  // Admins reach every instance, so editing their list loses nothing.
  if (after.permission >= ROLE.ADMIN) return null;

  const kept = new Set(after.instances.map((v) => `${v.daemonId}::${v.instanceUuid}`));
  const removed = before.instances
    .filter((v) => !kept.has(`${v.daemonId}::${v.instanceUuid}`))
    .map((v) => v.instanceUuid);
  if (removed.length === 0) return null;
  return { all: false, instanceUuids: Array.from(new Set(removed)) };
}

/**
 * Cut a user off: close their proxy-mode terminals, drop their unclaimed
 * gateway tokens and chunked-upload writer ids, and tell every connected daemon
 * to close their streams, delete their passports and stop their upload writers.
 * With instanceUuids, only those instances.
 *
 * The panel side runs immediately. A daemon that cannot be reached, or is too
 * old to know the route, is logged and skipped. This never rejects.
 */
export async function revokeUserAccess(
  userUuid: string,
  opts: { instanceUuids?: string[] } = {}
): Promise<void> {
  const { instanceUuids } = opts;
  if (!userUuid || (instanceUuids && instanceUuids.length === 0)) return;

  try {
    const tokens = revokeUserTokens(userUuid, instanceUuids);
    const bridges = closeUserStreams(userUuid, instanceUuids);
    const uploads = revokeUserUploads(userUuid, instanceUuids);
    logger.info(
      `Access revoked for user ${userUuid}: ${tokens} gateway tokens, ${bridges} terminal bridges, ` +
        `${uploads} upload writers` +
        (instanceUuids ? `, instances ${instanceUuids.join(",")}` : "")
    );
  } catch (err: any) {
    logger.error(`Access revoke: panel side failed for user ${userUuid}:`, err?.message ?? err);
  }

  const tasks: Array<Promise<void>> = [];
  for (const [daemonId, service] of RemoteServiceSubsystem.services) {
    tasks.push(
      (async () => {
        try {
          const result = await new RemoteRequest(service).request(
            "passport/revoke_user",
            { userUuid, instanceUuids },
            DAEMON_REVOKE_TIMEOUT_MS
          );
          logger.info(
            `Access revoke: daemon ${daemonId} closed ${result?.sockets} streams, ` +
              `${result?.passports} passports, ${result?.uploads} uploads`
          );
        } catch (err: any) {
          logger.warn(
            `Access revoke: daemon ${daemonId} not reached for user ${userUuid} ` +
              `(offline, or too old for passport/revoke_user): ${err?.message ?? err}`
          );
        }
      })()
    );
  }
  await Promise.all(tasks);
}

/**
 * Revoke what a user lost between two snapshots. Fire and forget: the admin's
 * action never waits on, or fails because of, a daemon.
 */
export function revokeOnAccessChange(
  userUuid: string,
  before: AccessState | null,
  after: AccessState | null
): void {
  const loss = computeAccessLoss(before, after);
  if (!loss) return;
  void revokeUserAccess(userUuid, loss.all ? {} : { instanceUuids: loss.instanceUuids });
}
