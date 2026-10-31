import { $t } from "../i18n";
import { routerApp } from "../service/router_app";
import { missionPassport, revokeUserAccess } from "../service/mission_passport";
import * as protocol from "../service/protocol";
import uploadManager from "../service/upload_manager";

const ONE_HOUR_TIME = 3600000;
const TASK_MAX_TIME = 1;

// register temporary task passport
// For example, file upload, file download, these operations that need to bypass the Web side,
// all need to use this route
routerApp.on("passport/register", (ctx, data) => {
  const name = data.name;
  const password = data.password;
  const parameter = data.parameter;
  const count = data.count;
  const userUuid = typeof data.userUuid === "string" && data.userUuid ? data.userUuid : undefined;
  const start = new Date().getTime();
  const end = start + ONE_HOUR_TIME * TASK_MAX_TIME;
  if (!name || !password) throw new Error($t("TXT_CODE_passport_router.registerErr"));
  missionPassport.registerMission(password, {
    name,
    parameter,
    count,
    start,
    end,
    userUuid
  });
  protocol.response(ctx, true);
});

// Cut a panel user off: delete their passports and close their stream sockets.
// Only the panel's key session reaches this route: auth_router's gate rejects
// every other route for stream sockets, so a browser cannot call it.
routerApp.on("passport/revoke_user", (ctx, data) => {
  const userUuid = data?.userUuid;
  if (typeof userUuid !== "string" || !userUuid) throw new Error("userUuid is required");
  // Without instanceUuids the user is cut off from every instance.
  let instanceUuids: string[] | undefined;
  if (data.instanceUuids != null) {
    if (!Array.isArray(data.instanceUuids)) throw new Error("instanceUuids must be an array");
    instanceUuids = data.instanceUuids.map(String);
  }
  protocol.response(ctx, {
    ...revokeUserAccess(userUuid, instanceUuids),
    uploads: uploadManager.revokeByUser(userUuid, instanceUuids)
  });
});
