# Birthday Role

A RoleLogic plugin that grants Discord roles from members' **self-reported
birthdays** — timezone-aware, with a rich condition system.

There is **no external API**. The only data source is the member: they sign
in with Discord (via the centralized Auth Gateway) and type their birthday
on the `/verify` page. A background "tick" worker re-evaluates every role
link on a schedule so time-relative roles (birthday-of-the-day, birthday
week, current age) flip on their own as the calendar advances — at the right
moment for each member's timezone.

## What you can build with it

The admin config UI (embedded in the RoleLogic dashboard) offers
one-click presets plus a full AND/OR rule builder:

| Preset | Rule |
|---|---|
| Anyone who added a birthday | grant to every member who saved a birthday |
| On their birthday 🎂 | `is_birthday_today = true` (auto-removed after the day) |
| Birthday week | `is_birthday_week = true` (within 7 days) |
| Birthday month | `is_birthday_month = true` |
| By zodiac sign | `zodiac_sign in {…}` |
| Born in certain months | `birth_month in {…}` |
| Minimum age | `age_years >= N` (self-reported) |
| Advanced rule | combine any of the 16 conditions below |

### Conditions (targets)

| Target | Kind | Notes |
|---|---|---|
| `is_birthday_today` / `is_birthday_week` / `is_birthday_month` | bool | resolved in the member's timezone |
| `days_until_birthday` | int | 0 on the day |
| `age_years` / `age_turning_this_year` | int | needs a birth year; fail-closed otherwise |
| `birth_month` / `birth_day` / `birth_year` | int | `in`/`not_in`/`between`/comparisons |
| `zodiac_sign` | string | aries … pisces |
| `chinese_zodiac` | string | rat … pig (approximate — Gregorian-year based) |
| `birth_season` | string | meteorological, Northern Hemisphere |
| `birthstone` | string | traditional US list |
| `birth_weekday` | string | needs a birth year |
| `has_birthday_set` / `has_birth_year` | bool | presence guards |

Operators: `eq, neq, gt, gte, lt, lte, between, contains, regex, in, not_in`
(integers also support `in`/`not_in`, so "born in {6,7,8}" is one condition).

Rule shape is DNF: **any** OR-group matches; within a group **all**
conditions must hold. An unconfigured role link grants to **nobody**
(Convention 42).

## Architecture

Rust + Axum 0.8 + PostgreSQL 16 + SQLx. Mirrors the repo blueprint:

- **RoleLogic contract** — `POST /register`, `GET/POST/DELETE /config`
  (iframe UI mode; the dashboard embeds `/admin/{guild}/role/{role}`).
- **Auth Gateway** — Discord login + guild membership are centralized; this
  plugin only verifies the shared `rl_session` cookie and calls
  `/auth/internal/*` from sync workers. No Discord tables locally.
- **Durable job queue** (`jobs` table, `LISTEN/NOTIFY`, `FOR UPDATE SKIP
  LOCKED`) → `player_sync` (a member changed their birthday) and
  `config_sync` (rule changed, or the tick).
- **Tick worker** — every `TICK_MINUTES` (default 30) fans a de-duplicated
  `config_sync` over every role link. `sync_for_role_link` recomputes the
  qualifying set with timezone-aware SQL and skips the RoleLogic write
  entirely when the set is unchanged, so quiet days are nearly free.
- **Two evaluation paths that must agree**: `services::condition_eval`
  (per-member, Rust) and `services::rule_sql` + the `bday_*` SQL functions
  (bulk, pushed into Postgres). The leap-year / next-occurrence rules live
  once in `services::birthday` and once in migration `005`.

## Endpoints

```
/birthday-role
  POST   /register
  GET    /config            (iframe mode)
  POST   /config            (contract stub)
  DELETE /config
  GET    /admin/{guild}/role/{role}            iframe page (dual-mode)
  GET    /admin/{guild}/role/{role}/data
  POST   /admin/{guild}/role/{role}/save       (optimistic-locked)
  GET|POST /admin/{guild}/role/{role}/preview  (dry-run count)
  POST   /admin/{guild}/view-permission
  GET    /users/{guild}                        public birthdays page
  GET    /users/{guild}/data
  GET    /verify  ·  GET /verify/status
  POST   /verify/login | /verify/save | /verify/unlink
  GET    /health  ·  /ready  ·  /favicon.ico
```

## Privacy

Members provide their own birthday and choose whether the **year/age** is
shown on the public list (`show_year`, off by default). Month/day are shown
on that list to guild members per the per-guild `view_permission`
(`disabled` / `managers` / `members`). Age conditions are explicitly
self-reported and never identity-verified.

## Local development

```bash
cp .env.example .env   # fill POSTGRES_PASSWORD, SESSION_SECRET, INTERNAL_API_KEY,
                       # BASE_URL, AUTH_GATEWAY_URL (point at the local gateway)
docker compose up --build
cargo test             # pure logic: birthday math, eval, rule SQL, validator, tokens
```

`SESSION_SECRET` and `INTERNAL_API_KEY` **must** match the Auth Gateway's
values. `BASE_URL` must include the `/birthday-role` path prefix and exactly
match the URL registered in the RoleLogic dashboard.

See [OPERATIONS.md](OPERATIONS.md) for deploy, the Cloudflare Tunnel rule,
and runbooks.
