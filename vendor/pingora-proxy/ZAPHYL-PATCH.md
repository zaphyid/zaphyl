# Zaphyl patch to pingora-proxy 0.8.1

This is an unmodified copy of `pingora-proxy 0.8.1` (Apache-2.0, Cloudflare)
EXCEPT for a minimal fix to one function (`proxy_1to1`) in `src/proxy_h1.rs`.
Wired into the build via `[patch.crates-io]` in the workspace root `Cargo.toml`.

## What it fixes

A WebSocket (HTTP/1.1 `Upgrade`) request has no request body, so Pingora's
`proxy_1to1` duplex loop sends a `Body(None, true)` sentinel to the upstream
handler before either side has seen the `101` response. When the upstream echo
server is fast enough, the `101` can arrive and be processed by
`proxy_handle_upstream` (setting `upgraded = true` and resetting `request_done
= false`) before that queued `Body(None, true)` is drained from the channel.
When `rx.recv()` subsequently returns that stale sentinel, `send_body_to1`
marks `request_done = true`, and the pre-existing guard

    if request_done && client_session.was_upgraded() { response_done = true; }

immediately exits the upstream loop - dropping the tx sender and tearing down
the tunnel milliseconds after the `101`. Symptom: the client sees
`ResetWithoutClosingHandshake` on the first frame; the proxy logs `status=101`
with a tiny or 60-second duration depending on which race leg wins.

A secondary race in `proxy_handle_downstream` can independently close the loop:
when the `101` header task is processed without the first body frame coalesced,
calling `maybe_set_upstream_done` and `maybe_finished` in the same iteration as
the `downstream_state.reset()` can flip both state machines to "done" before
the next select tick reads any upgraded data.

## The change

Two closely related edits to `proxy_1to1` in `src/proxy_h1.rs`:

1. **`proxy_handle_upstream`**: guard the `request_done` update and the
   `response_done = true` shortcut behind `is_upgraded_task`. A stale
   pre-upgrade `Body(None, true)` that arrives after the `101` must not
   permanently disable the `rx.recv()` branch or exit the upstream loop; only
   a genuine `UpgradedBody` or a closed channel should do that.

2. **`proxy_handle_downstream`**: compute `just_upgraded` once and skip
   `maybe_set_upstream_done` and `maybe_finished` for the single iteration that
   transitions from plain HTTP to upgraded. The tunnel terminates later through
   the existing close paths.

```diff
--- src/proxy_h1.rs.orig	2026-06-20 15:17:07.833312000 +0500
+++ src/proxy_h1.rs	2026-06-20 16:27:23.356429400 +0500
@@ -239,11 +239,24 @@
                 },
 
                 body = rx.recv(), if !request_done => {
+                    // None (channel closed) or UpgradedBody signals the real end of the
+                    // tunnel. A plain Body(None, true) that was queued before the 101 was
+                    // received must not permanently finish the request side or close the
+                    // tunnel - the upgraded frames have not been forwarded yet.
+                    let is_upgraded_task =
+                        matches!(&body, Some(HttpTask::UpgradedBody(..)) | None);
                     match send_body_to1(client_session, body).await {
                         Ok(send_done) => {
-                            request_done = send_done;
-                            // An upgraded request is terminated when either side is done
-                            if request_done && client_session.was_upgraded() {
+                            // After the upgrade, only UpgradedBody or channel-close should
+                            // finish the request side. A stale pre-upgrade Body(None, true)
+                            // must not block subsequent UpgradedBody frames.
+                            if !client_session.was_upgraded() || is_upgraded_task {
+                                request_done = send_done;
+                            }
+                            // An upgraded request is terminated when either side is done,
+                            // but only when the termination came from an upgraded-body task
+                            // (or a closed channel), not from the pre-upgrade Body(None, true).
+                            if request_done && client_session.was_upgraded() && is_upgraded_task {
                                 response_done = true;
                             }
                         },
@@ -485,16 +498,24 @@
                         // set to downstream
                         let upgraded = session.was_upgraded();
                         let response_done = session.write_response_tasks(filtered_tasks).await?;
-                        if !upgraded && session.was_upgraded() && downstream_state.can_poll() {
+                        let just_upgraded = !upgraded && session.was_upgraded();
+                        if just_upgraded && downstream_state.can_poll() {
                             // just upgraded, the downstream state should be reset to continue to
                             // poll body
                             trace!("reset downstream state on upgrade");
                             downstream_state.reset();
                         }
-                        response_state.maybe_set_upstream_done(response_done);
-                        // unsuccessful upgrade response (or end of upstream upgraded conn,
-                        // which forces the body reader to complete) may force the request done
-                        downstream_state.maybe_finished(session.is_body_done());
+                        // A 101 is the START of an upgraded tunnel, not its end. Marking the
+                        // upstream response done (or re-finishing the bodyless downstream) here
+                        // races the reset above and can close the tunnel right after the 101.
+                        // Skip both when we just upgraded; the tunnel terminates later via the
+                        // normal close paths.
+                        if !just_upgraded {
+                            response_state.maybe_set_upstream_done(response_done);
+                            // unsuccessful upgrade response (or end of upstream upgraded conn,
+                            // which forces the body reader to complete) may force the request done
+                            downstream_state.maybe_finished(session.is_body_done());
+                        }
                     } else {
                         debug!("empty upstream event");
                         response_state.maybe_set_upstream_done(true);
```

## Upstream

Reported to Cloudflare: not yet filed - issue text ready at
`_local/pingora-ws-issue.md` for filing on https://github.com/cloudflare/pingora .
When a released pingora
version includes this fix, delete `vendor/pingora-proxy/`, remove the
`[patch.crates-io]` stanza and the `vendor/pingora-proxy` workspace `exclude`
entry, and bump the dependency. The `proxies_websocket_upgrade` stress test in
`crates/zaphyl/tests/websocket.rs` guards the result.

## Re-applying on a pingora update (if upstream has not fixed it)

1. Re-vendor the new `pingora-proxy` source into `vendor/pingora-proxy/`.
2. Re-apply the two-location change above (both edits are to `proxy_1to1`).
3. `cargo build` errors loudly if the patch no longer applies cleanly; nothing
   breaks silently. Run the stress test to confirm.
