# Birthday Role — Operations

## Deploy

1. **Cloudflare Tunnel ingress** — add before the catch-all:
   ```
   hostname: plugin-rolelogic.faizo.net
   path: ^/birthday-role
   service: http://localhost:8095
   ```
2. **Env** (compose reads these — see `.env.example`):
   - `POSTGRES_PASSWORD`, `DATABASE_URL`
   - `SESSION_SECRET` — must equal the Auth Gateway's value
   - `INTERNAL_API_KEY` — must equal the Auth Gateway's value
   - `BASE_URL=https://plugin-rolelogic.faizo.net/birthday-role` (no trailing slash, includes prefix)
   - `AUTH_GATEWAY_URL` — unset in prod (derived from BASE_URL); set to the
     local gateway in dev
   - optional: `RL_DASHBOARD_ORIGIN`, `ROLELOGIC_API_URL`, `TICK_MINUTES`,
     `WORKER_CONCURRENCY`, `DB_*`
3. `docker compose up -d --build`
4. Migrations run automatically on boot. For blue/green, run the dedicated
   step first: `docker compose run --rm app birthday-role migrate`.
5. Register the plugin URL in the RoleLogic dashboard exactly as `BASE_URL`.

## Health

- `GET /birthday-role/health` — 200 `{"status":"healthy"}` when the DB is
  up, 503 otherwise (liveness; there is no external API to probe).
- `GET /birthday-role/ready` — 503 once SIGTERM drains begin (LB pre-drain).
- `docker compose logs -f app` — workers log structured `guild_id`,
  `role_id`, `discord_id`.

## How roles flip on the right day

The tick worker (`TICK_MINUTES`, default 30) enqueues a de-duplicated
`config_sync` for every role link. `sync_for_role_link` recomputes the
qualifying set against **each member's local date** (`now() AT TIME ZONE
birthdays.tz`) and only calls RoleLogic when the set changed. So a
"birthday today" role appears within `TICK_MINUTES` of the member's local
midnight and is removed the following local midnight. Lower `TICK_MINUTES`
for tighter latency at the cost of more (still cheap, mostly no-op) syncs.

## Runbooks

**A role didn't appear on someone's birthday.**
1. Did they add a birthday? `SELECT * FROM birthdays WHERE discord_id='…';`
   — no row ⇒ they never visited `/verify`.
2. Timezone: the role flips at *their* local midnight. Check `tz` on the row;
   pre-`TICK_MINUTES` of local midnight it's correct that it's absent.
3. Are they a guild member per the Auth Gateway? Sync is scoped to
   `/auth/internal/guild_member_ids`. A gateway 401 in logs ⇒
   `INTERNAL_API_KEY` mismatch.
4. Force it: `INSERT INTO jobs(kind,payload) VALUES('config_sync',
   jsonb_build_object('guild_id','…','role_id','…'));` then
   `SELECT pg_notify('jobs_pending','');`

**Role assigned to everyone before the admin configured anything.**
Should be impossible — Convention 42 is enforced in `condition_eval`,
`rule_sql`, `sync_for_role_link` (early `drain_to_empty`), and the
validator. If seen, inspect `role_links.rule_tree`: the unconfigured
sentinel is `{"grant_on_any_birthday":false,"groups":[]}`.

**Dead-letter jobs.** `SELECT id,kind,last_error,payload FROM jobs WHERE
status='dead' ORDER BY completed_at DESC;` Replay: set `status='pending',
next_run_at=now(),attempts=0` and `pg_notify('jobs_pending','')`. `dead`
rows are GC'd after 7 days, `completed` after 6 hours.

**Stuck jobs.** Reaped automatically after 30 min lock TTL by any worker.

**RoleLogic deleted a role link while we were offline.** First token-authed
call returns `403 "Invalid or revoked token"` → mapped to
`RoleLinkNotFound` → the orphan `role_links` row is deleted (CASCADE clears
`role_assignments`). No action needed (Convention 47). A *paused* link is a
different 403 (`"This role link is disabled"`) and is left intact.

**Leap-year birthdays.** Feb-29 is observed on Feb-28 in non-leap years
(same rule in `services::birthday::effective_bday` and the `bday_effective`
SQL function). A Feb-29 birthday with a non-leap birth year is rejected at
input; with no year it's accepted as a recurring date.

## Backup / restore

Only `birthdays` is irreplaceable user data (`role_links` is re-driven by
RoleLogic `POST /register`, `role_assignments` is a rebuildable mirror,
`jobs` is ephemeral, `guild_settings` is small). `pg_dump` the volume on the
usual cadence; restoring `birthdays` + a tick is sufficient to reconverge.
