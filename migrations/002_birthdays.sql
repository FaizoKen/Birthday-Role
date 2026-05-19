-- The member's self-reported birthday. This is the plugin's entire data
-- model: there is no external API and no third-party identity — a member
-- signs in with Discord (via the Auth Gateway) and types their birthday on
-- the /verify page. One row per Discord user, keyed by discord_id.
--
-- birth_year is OPTIONAL. Many people share month/day but not the year, and
-- age-based rules are explicitly self-reported (never identity-verified).
-- When birth_year IS NULL, all age/year facts evaluate to "unknown" and
-- fail closed for numeric comparisons (mirrors the reference plugin's
-- nullable-int handling).
--
-- The static, never-changing derived facts (zodiac, season, birthstone, and
-- — when a year is given — chinese zodiac and birth weekday) are
-- denormalised here so the bulk SQL sync path filters on a plain column
-- instead of recomputing per row. They are written by `services::birthday`
-- on every insert/update so the column and the Rust evaluator never drift.
-- Time-relative facts (is_birthday_today, days_until, age, …) are NOT
-- stored — they depend on "today in the member's timezone" and are computed
-- at query time via the bday_* SQL functions (migration 005).

CREATE TABLE IF NOT EXISTS birthdays (
    discord_id      TEXT PRIMARY KEY,
    discord_name    TEXT,
    birth_month     SMALLINT NOT NULL CHECK (birth_month BETWEEN 1 AND 12),
    birth_day       SMALLINT NOT NULL CHECK (birth_day BETWEEN 1 AND 31),
    birth_year      INTEGER CHECK (birth_year IS NULL OR birth_year BETWEEN 1900 AND 2100),
    -- IANA timezone name (validated against chrono-tz on input, defaults to
    -- UTC). Used as `now() AT TIME ZONE tz` so "today" is the member's local
    -- day — a birthday role flips at THEIR midnight, not the server's.
    tz              TEXT NOT NULL DEFAULT 'UTC',
    -- Privacy: when false the public users page hides the year/age. The
    -- birthday role logic still uses the year internally regardless.
    show_year       BOOLEAN NOT NULL DEFAULT false,
    -- Denormalised static derived facts (see header).
    zodiac          TEXT NOT NULL,
    chinese_zodiac  TEXT,
    season          TEXT NOT NULL,
    birthstone      TEXT NOT NULL,
    birth_weekday   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The bulk per-role-link sync filters `discord_id = ANY($members)`; the PK
-- already covers point lookups. This partial index speeds the common
-- "born this month" admin preview without scanning the whole table.
CREATE INDEX IF NOT EXISTS idx_birthdays_month_day
    ON birthdays (birth_month, birth_day);
