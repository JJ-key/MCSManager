# Access revocation fix (JustSMP fork)

Branch `justsmp`, on top of tag v10.22.0.

## The bug

An admin removed a user while that user had a terminal tab open. The user kept access.
HTTP was already fine: `permission.ts` re-reads the user on every request, so a deleted user
gets 403 and a banned user is logged out. What survived were the things the panel had
already handed out:

- **Terminal, direct mode.** `stream_channel` registers a daemon passport that lives one hour.
  The browser connects straight to the daemon and `stream/auth` never consumes the passport,
  so the socket stayed authed and a reconnect reused the cached passport.
- **Terminal, proxy mode.** The panel's `TerminalBridge` never rechecked the user, and gateway
  tokens carried no user identity, so nothing could be matched to a user.
- **File links.** Download and upload passports live one hour with no user check, and a chunked
  upload carries on by writer id alone.
- **Sessions.** Cookie-only (koa-session, no server-side list). An admin password reset could
  not end the user's other sessions.

Nothing in the panel could tell a daemon "cut this user off", and the daemon did not know
which user a socket or passport belonged to.

## What changed

Daemon

- `passport/register` takes an optional `userUuid` and stores it on the passport.
- `stream/auth` records the passport's user on the authed socket (a registry in
  `service/mission_passport.ts`; a socket that auths twice keeps both grants, and repeating the
  same grant adds nothing).
- `/upload-new` tags the `FileWriter` with the passport's user and instance. A writer that is
  found again by path is reused only for the same user tag, otherwise it is replaced, so an id is
  never handed to someone else.
- New route `passport/revoke_user` `{ userUuid, instanceUuids? }`. It deletes the user's
  passports, closes their authed stream sockets and drops their upload writers (the half-written
  file is removed), and answers `{ sockets, passports, uploads }`. Without `instanceUuids` it
  covers every instance; an empty list does nothing. Writers with no user tag are never touched.
- Sockets are cut with `socket.conn.close()`, not `socket.disconnect()`. socket.io clients do
  not reconnect after a server `disconnect()`, so the web terminal would sit on its loading
  spinner forever. After a transport close it reconnects, fails `stream/auth` and shows its
  existing error card. No frontend change was needed. A fallback to `disconnect(true)` covers a
  transport that cannot be closed.
- The gate is unchanged and is what keeps browsers off the new route: `auth_router.ts` lets only
  `auth` and `stream*` through without the panel key, and everything else needs a session whose
  `key` equals the daemon key and whose type is `TOP_LEVEL`. A stream socket's session has
  neither. Covered by a unit test (`daemon/test/access_revoke.test.ts`) and by the end-to-end
  script (a user's stream socket calls the route and is refused).

Panel

- `service/access_revoke_service.ts`: `computeAccessLoss(before, after)` (pure),
  `revokeUserAccess(userUuid, { instanceUuids? })` and `revokeOnAccessChange`.
  `revokeUserAccess` drops the user's gateway tokens and proxy-mode upload writer ids
  (`uploadIdMap` carries the user), closes their proxy-mode terminal sockets, and sends
  `passport/revoke_user` to every daemon with a 3 s timeout. An unreachable daemon, or
  one too old to know the route (the request times out; this protocol has no 404), is logged
  and skipped. Nothing rejects, and the callers do not wait for it.
- Called from `DELETE /auth` (user delete, batch), `PUT /auth` (permission, instances, password).
  What counts as a loss: user deleted; permission lowered (ban is a lowered permission); an
  instance removed from the list of a non-admin. Editing an admin's list loses nothing, and a
  no-op edit revokes nothing.
- Tagging: the stream passport, the file-link passports (direct and proxy), the admin
  create-instance upload passport, and gateway tokens all carry the issuing user's uuid. Tokens
  and passports from callers without it (API without a key owner, older panel) are untagged and
  simply cannot be revoked.
- Password reset: `User.sessionVersion` (default 0) is bumped by `PUT /auth` with `passWord`
  (`userSystem.endSessions`). Login stores the user's value in the session and `permission.ts`
  rejects a session whose value differs (logout + 403). `check()`, which `/auth/login` asks
  before logging anyone in, applies the same rule and also needs the user to exist, so an old
  cookie plus the new password starts a new session instead of answering "Logined". Users and
  sessions without the field count as 0, so nobody is logged out by the upgrade. The reset runs
  `revokeUserAccess` even when the store write in `endSessions` fails; the admin still gets the
  error.
- `TerminalBridge` tracks each verified browser socket with every (user, instance) it authed
  with, from token check on, so a revoke that lands while the daemon client is still being set up
  still finds it, and a socket that authed on two instances is cut when either is revoked. A
  socket closed during setup is not subscribed.
- `getMission` already ignores consumed (`isDeleted`) passports at v10.22.0, so no change there;
  a test pins it.

Frontend: unchanged.

## Behaviour to know

- A lowered user (for example admin to normal) loses all their open streams, including those
  on instances they keep. They reopen the terminal and get a fresh passport for what they still
  own. Cutting only the lost instances would need the daemon to take a "keep" list.
- The panel waits for nothing: the admin request returns while the daemons are still being told.
  In the end-to-end run the sockets drop within about 5 to 60 ms.
- Compatibility: new panel + old daemon logs a warning per revoke and the old behaviour remains.
  Old panel + new daemon never sends the field, so nothing is tagged or revoked.
  Passports minted before the upgrade are untagged and stay valid up to their one hour.

## Tests

- `daemon/test/access_revoke.test.ts`: passport matching, stream-socket matching (including
  repeated `stream/auth` on one socket), `stream/auth` user recording, the route gate (key
  session allowed; stream session, no session and wrong key refused; bad arguments never fall
  back to "revoke everyone").
- `daemon/test/upload_revoke.test.ts`: the real upload routes and `FileWriter` on a temp folder.
  A piece after the revoke is refused and the file is not finished; instance filter; other
  users' and untagged writers survive; a writer id is not handed to another user.
- `panel/src/app/service/__test__/access_revoke_service.test.ts`: the compare logic and what
  `revokeUserAccess` sends, including a failing daemon.
- `panel/src/app/service/__test__/proxy_upload_revoke.test.ts`: proxy-mode `/upload-piece` against
  a loopback daemon, before and after a revoke.
- `panel/src/app/service/__test__/terminal_bridge_revoke.test.ts` (including a socket that authed
  twice), `.../passport_check.test.ts`, `panel/src/app/routers/__test__/user_overview_router.revoke.test.ts`
  (password reset with a failing `endSessions`), `panel/src/__test__/gateway_token_revoke.test.ts`,
  `panel/src/app/middleware/__test__/permission.session_version.test.ts`.
- `scripts/test-revoke.mjs`: end to end. Starts the built daemon and panel on spare loopback
  ports with temporary folders (never 23333 or 24444), installs an admin, adds the daemon,
  creates two instances and users, and drives real HTTP and socket.io for delete, ban, lower
  permission, remove one instance, reset password, a control user, and the gate. It runs in
  direct and in proxy data-plane mode. The daemon needs its `lib/` binaries to start, so the
  script drops empty stubs in its temporary folder (nothing is downloaded or executed; no
  instance is started).

  Result: 118/118 checks pass (59 per mode). Run against the unpatched v10.22.0 build, 37 of the
  original 96 failed: every socket-drop, file-link and password-reset check, the daemon-route
  checks, and in direct mode the passport re-auth checks. The added chunked-upload case (a piece
  POSTed after a ban is refused, the half-written file is removed, another user's upload still
  completes) and the stale-cookie login (old cookie plus the new password gets a new session)
  fail on a build without those two fixes, 4 checks per mode. The HTTP-refusal checks already pass on the
  unpatched build (the bug was never there), and in proxy mode the re-auth check also passes
  there because a claimed gateway token cannot be used twice anyway.

  ```
  (cd common && npm run build) && (cd panel && npm run build) && (cd daemon && npm run build)
  node scripts/test-revoke.mjs                # both modes
  node scripts/test-revoke.mjs --mode=proxy --keep
  node scripts/test-revoke.mjs --repo=<other checkout with builds>
  ```

## Not closed

- Downloads and uploads that are already streaming run to the end. A chunked upload loses every
  piece after the one in flight.
- **API keys** survive a password reset (they are not sessions).
- A user changing their own password (`PUT /auth/update`) still only logs out the current
  session. The same `endSessions` call would end the rest.
- A passport requested at the same moment as the revoke can be registered after it. The window
  is the download and upload routes' instance-name lookup, a daemon round trip.
- Cookie sessions last 24 h and are only checked per request, so a session cannot be listed or
  killed except through `sessionVersion`.
- Deleting an instance removes it from every user's list without a revoke; the instance is gone
  on the daemon, so its leftover passports and sockets reach nothing.

## Process note

`AGENTS.md` asks for an OpenSpec change when a node/panel protocol changes. This one adds a
daemon route and an optional field, and was built straight from the brief; no
`openspec/changes/` entry was written.
