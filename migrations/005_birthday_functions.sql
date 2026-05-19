-- Immutable SQL helpers for the time-relative birthday facts.
--
-- The bulk per-role-link sync (services::rule_sql) pushes rule predicates
-- down into Postgres so it filters server-side instead of loading every
-- member's birthday into memory (Convention 6 / 8). These functions are the
-- SQL mirror of the Rust evaluator in services::birthday — both must agree,
-- so the leap-year (Feb-29) rule and the "next occurrence" rule live here
-- once and are called from the generated WHERE clause.
--
-- All functions are IMMUTABLE: they never call now(). The caller passes the
-- member's *local* date (computed as `(now() AT TIME ZONE bt.tz)::date`),
-- which keeps now() out of the function so it stays inlinable/cacheable.
--
-- Feb-29 rule: a Feb-29 birthday is celebrated on Feb-28 in non-leap years
-- (matches services::birthday::effective_bday).

CREATE OR REPLACE FUNCTION bday_is_leap(p_year integer)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT p_year % 4 = 0 AND (p_year % 100 <> 0 OR p_year % 400 = 0);
$$;

CREATE OR REPLACE FUNCTION bday_effective(p_year integer, p_month integer, p_day integer)
RETURNS date LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN p_month = 2 AND p_day = 29 AND NOT bday_is_leap(p_year)
            THEN make_date(p_year, 2, 28)
        ELSE make_date(p_year, p_month, p_day)
    END;
$$;

-- Days from p_local until the next occurrence of (month, day). 0 on the
-- birthday itself. Always in 0..=365.
CREATE OR REPLACE FUNCTION bday_days_until(p_month integer, p_day integer, p_local date)
RETURNS integer LANGUAGE sql IMMUTABLE AS $$
    SELECT (
        CASE
            WHEN bday_effective(EXTRACT(YEAR FROM p_local)::int, p_month, p_day) >= p_local
                THEN bday_effective(EXTRACT(YEAR FROM p_local)::int, p_month, p_day)
            ELSE bday_effective(EXTRACT(YEAR FROM p_local)::int + 1, p_month, p_day)
        END - p_local
    );
$$;

CREATE OR REPLACE FUNCTION bday_is_today(p_month integer, p_day integer, p_local date)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT bday_days_until(p_month, p_day, p_local) = 0;
$$;

-- Completed years of age as of p_local. NULL when no birth year is known
-- (numeric comparisons against NULL fail closed — matches the Rust side).
CREATE OR REPLACE FUNCTION bday_age(p_year integer, p_month integer, p_day integer, p_local date)
RETURNS integer LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN p_year IS NULL THEN NULL ELSE
        EXTRACT(YEAR FROM p_local)::int - p_year
          - CASE WHEN bday_effective(EXTRACT(YEAR FROM p_local)::int, p_month, p_day) > p_local
                 THEN 1 ELSE 0 END
    END;
$$;

-- The age the member reaches on their *upcoming* birthday (the "turning N"
-- club). NULL when no birth year is known.
CREATE OR REPLACE FUNCTION bday_age_turning(p_year integer, p_month integer, p_day integer, p_local date)
RETURNS integer LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN p_year IS NULL THEN NULL ELSE
        (CASE WHEN bday_effective(EXTRACT(YEAR FROM p_local)::int, p_month, p_day) >= p_local
              THEN EXTRACT(YEAR FROM p_local)::int
              ELSE EXTRACT(YEAR FROM p_local)::int + 1 END) - p_year
    END;
$$;
