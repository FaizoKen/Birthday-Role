//! Pure birthday math + derived calendar facts.
//!
//! This is the single source of truth for every date rule in the plugin.
//! The Rust evaluator ([condition_eval]) uses [`compute_facts`]; the bulk
//! SQL path ([rule_sql]) uses the `bday_*` Postgres functions in migration
//! 005 — both implement the SAME leap-year and next-occurrence rules, so a
//! per-member sync and a bulk role sync always agree.
//!
//! No I/O, no async: callable from the hot path (Convention 5).

use chrono::{Datelike, NaiveDate, Utc};
use chrono_tz::Tz;

use crate::models::facts::Facts;

/// Validated, normalised birthday input — the bits we persist.
#[derive(Debug, Clone)]
pub struct BirthdayInput {
    pub birth_month: i32,
    pub birth_day: i32,
    pub birth_year: Option<i32>,
    /// Canonical IANA timezone name (already validated).
    pub tz: String,
}

/// The denormalised, never-changing derived facts stored on the row so the
/// bulk SQL filter compares a plain column instead of recomputing per row.
#[derive(Debug, Clone)]
pub struct Derived {
    pub zodiac: String,
    pub chinese_zodiac: Option<String>,
    pub season: String,
    pub birthstone: String,
    pub birth_weekday: Option<String>,
}

pub const ZODIAC_SIGNS: &[&str] = &[
    "capricorn",
    "aquarius",
    "pisces",
    "aries",
    "taurus",
    "gemini",
    "cancer",
    "leo",
    "virgo",
    "libra",
    "scorpio",
    "sagittarius",
];

pub const CHINESE_ZODIACS: &[&str] = &[
    "rat", "ox", "tiger", "rabbit", "dragon", "snake", "horse", "goat", "monkey", "rooster",
    "dog", "pig",
];

pub const SEASONS: &[&str] = &["winter", "spring", "summer", "autumn"];

pub const BIRTHSTONES: &[&str] = &[
    "garnet",
    "amethyst",
    "aquamarine",
    "diamond",
    "emerald",
    "pearl",
    "ruby",
    "peridot",
    "sapphire",
    "opal",
    "topaz",
    "turquoise",
];

pub const WEEKDAYS: &[&str] = &[
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

pub fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days in a month, treating Feb as 29 when `leap` (used for input
/// validation when no year is given so a Feb-29 birthday is accepted).
fn days_in_month(month: u32, leap: bool) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// The date a (month, day) birthday is celebrated in `year`. A Feb-29
/// birthday is observed on Feb-28 in non-leap years. Never panics — an
/// impossible (validated-away) combination clamps to the 1st of the month.
pub fn effective_bday(year: i32, month: u32, day: u32) -> NaiveDate {
    if month == 2 && day == 29 && !is_leap(year) {
        return NaiveDate::from_ymd_opt(year, 2, 28).expect("Feb 28 always valid");
    }
    NaiveDate::from_ymd_opt(year, month, day)
        .or_else(|| NaiveDate::from_ymd_opt(year, month, 1))
        .unwrap_or_else(|| NaiveDate::from_ymd_opt(year, 1, 1).expect("Jan 1 always valid"))
}

/// Validate a submitted birthday. `Err` carries a user-facing message.
pub fn validate_date(month: i32, day: i32, year: Option<i32>) -> Result<(), String> {
    if !(1..=12).contains(&month) {
        return Err("Month must be between 1 and 12.".into());
    }
    if let Some(y) = year {
        let this_year = Utc::now().year();
        if !(1900..=this_year).contains(&y) {
            return Err(format!("Year must be between 1900 and {this_year}."));
        }
    }
    // With a year, Feb-29 is only valid in a leap year. Without a year we
    // accept Feb-29 (a real recurring birthday) and observe it on Feb-28 in
    // non-leap years.
    let leap = year.map(is_leap).unwrap_or(true);
    let max = days_in_month(month as u32, leap);
    if day < 1 || day as u32 > max {
        return Err(format!(
            "Day must be between 1 and {max} for that month{}.",
            if month == 2 && year.is_some() {
                " (this year is not a leap year)"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

/// Validate + canonicalise an IANA timezone name. Empty / unknown → `UTC`.
pub fn normalize_tz(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "UTC".to_string();
    }
    match trimmed.parse::<Tz>() {
        Ok(tz) => tz.name().to_string(),
        Err(_) => "UTC".to_string(),
    }
}

/// The member's *local* calendar date right now.
pub fn local_today(tz_name: &str) -> NaiveDate {
    let tz: Tz = tz_name.parse().unwrap_or(chrono_tz::UTC);
    Utc::now().with_timezone(&tz).date_naive()
}

/// Western tropical zodiac sign for a (month, day).
pub fn zodiac(month: u32, day: u32) -> &'static str {
    match (month, day) {
        (1, d) if d <= 19 => "capricorn",
        (1, _) => "aquarius",
        (2, d) if d <= 18 => "aquarius",
        (2, _) => "pisces",
        (3, d) if d <= 20 => "pisces",
        (3, _) => "aries",
        (4, d) if d <= 19 => "aries",
        (4, _) => "taurus",
        (5, d) if d <= 20 => "taurus",
        (5, _) => "gemini",
        (6, d) if d <= 20 => "gemini",
        (6, _) => "cancer",
        (7, d) if d <= 22 => "cancer",
        (7, _) => "leo",
        (8, d) if d <= 22 => "leo",
        (8, _) => "virgo",
        (9, d) if d <= 22 => "virgo",
        (9, _) => "libra",
        (10, d) if d <= 22 => "libra",
        (10, _) => "scorpio",
        (11, d) if d <= 21 => "scorpio",
        (11, _) => "sagittarius",
        (12, d) if d <= 21 => "sagittarius",
        (12, _) => "capricorn",
        _ => "capricorn",
    }
}

/// Chinese zodiac animal for a Gregorian year. This ignores the lunar
/// new-year boundary (a January/February birthday near the cusp may differ
/// from the true lunar sign) — documented as an approximation.
pub fn chinese_zodiac(year: i32) -> &'static str {
    let idx = (year - 4).rem_euclid(12) as usize;
    CHINESE_ZODIACS[idx]
}

/// Meteorological season (Northern Hemisphere) by month.
pub fn season(month: u32) -> &'static str {
    match month {
        3..=5 => "spring",
        6..=8 => "summer",
        9..=11 => "autumn",
        _ => "winter", // 12, 1, 2
    }
}

/// Traditional (US) birthstone by month.
pub fn birthstone(month: u32) -> &'static str {
    match month {
        1 => "garnet",
        2 => "amethyst",
        3 => "aquamarine",
        4 => "diamond",
        5 => "emerald",
        6 => "pearl",
        7 => "ruby",
        8 => "peridot",
        9 => "sapphire",
        10 => "opal",
        11 => "topaz",
        12 => "turquoise",
        _ => "garnet",
    }
}

fn weekday_name(date: NaiveDate) -> &'static str {
    use chrono::Weekday::*;
    match date.weekday() {
        Mon => "monday",
        Tue => "tuesday",
        Wed => "wednesday",
        Thu => "thursday",
        Fri => "friday",
        Sat => "saturday",
        Sun => "sunday",
    }
}

/// Compute the never-changing derived facts stored on the row.
pub fn compute_derived(month: i32, day: i32, year: Option<i32>) -> Derived {
    let m = month as u32;
    let d = day as u32;
    Derived {
        zodiac: zodiac(m, d).to_string(),
        chinese_zodiac: year.map(|y| chinese_zodiac(y).to_string()),
        season: season(m).to_string(),
        birthstone: birthstone(m).to_string(),
        birth_weekday: year.map(|y| {
            let date = NaiveDate::from_ymd_opt(y, m, d)
                .unwrap_or_else(|| effective_bday(y, m, d));
            weekday_name(date).to_string()
        }),
    }
}

/// Resolve every fact for "today" in the member's timezone.
pub fn compute_facts(input: &BirthdayInput) -> Facts {
    let m = input.birth_month as u32;
    let d = input.birth_day as u32;
    let today = local_today(&input.tz);
    let this_year = today.year();

    let eff_this = effective_bday(this_year, m, d);
    let next = if eff_this >= today {
        eff_this
    } else {
        effective_bday(this_year + 1, m, d)
    };
    let days_until = (next - today).num_days();

    let (age_years, age_turning) = match input.birth_year {
        Some(by) => {
            let mut age = this_year - by;
            if eff_this > today {
                age -= 1;
            }
            let turning = next.year() - by;
            (Some(age as i64), Some(turning as i64))
        }
        None => (None, None),
    };

    let derived = compute_derived(input.birth_month, input.birth_day, input.birth_year);

    Facts {
        has_birthday: true,
        has_year: input.birth_year.is_some(),
        is_today: days_until == 0,
        is_this_week: (0..=6).contains(&days_until),
        is_this_month: today.month() == m,
        days_until,
        age_years,
        age_turning,
        birth_month: input.birth_month as i64,
        birth_day: input.birth_day as i64,
        birth_year: input.birth_year.map(|y| y as i64),
        zodiac: derived.zodiac,
        chinese_zodiac: derived.chinese_zodiac,
        season: derived.season,
        birthstone: derived.birthstone,
        weekday: derived.birth_weekday,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(m: i32, d: i32, y: Option<i32>, tz: &str) -> BirthdayInput {
        BirthdayInput {
            birth_month: m,
            birth_day: d,
            birth_year: y,
            tz: tz.to_string(),
        }
    }

    #[test]
    fn leap_rules() {
        assert!(is_leap(2000));
        assert!(is_leap(2024));
        assert!(!is_leap(1900));
        assert!(!is_leap(2023));
    }

    #[test]
    fn feb29_falls_back_to_feb28_in_non_leap_years() {
        assert_eq!(
            effective_bday(2023, 2, 29),
            NaiveDate::from_ymd_opt(2023, 2, 28).unwrap()
        );
        assert_eq!(
            effective_bday(2024, 2, 29),
            NaiveDate::from_ymd_opt(2024, 2, 29).unwrap()
        );
    }

    #[test]
    fn validate_rejects_impossible_dates() {
        assert!(validate_date(13, 1, None).is_err());
        assert!(validate_date(4, 31, None).is_err());
        assert!(validate_date(2, 29, Some(2023)).is_err()); // not a leap year
        assert!(validate_date(2, 29, Some(2024)).is_ok()); // leap year
        assert!(validate_date(2, 29, None).is_ok()); // recurring, no year
        assert!(validate_date(6, 15, Some(1990)).is_ok());
    }

    #[test]
    fn zodiac_boundaries() {
        assert_eq!(zodiac(3, 20), "pisces");
        assert_eq!(zodiac(3, 21), "aries");
        assert_eq!(zodiac(12, 21), "sagittarius");
        assert_eq!(zodiac(12, 22), "capricorn");
        assert_eq!(zodiac(1, 1), "capricorn");
    }

    #[test]
    fn chinese_zodiac_known_years() {
        assert_eq!(chinese_zodiac(2020), "rat");
        assert_eq!(chinese_zodiac(2021), "ox");
        assert_eq!(chinese_zodiac(2008), "rat");
        assert_eq!(chinese_zodiac(1900), "rat");
    }

    #[test]
    fn season_and_birthstone() {
        assert_eq!(season(1), "winter");
        assert_eq!(season(7), "summer");
        assert_eq!(birthstone(7), "ruby");
        assert_eq!(birthstone(4), "diamond");
    }

    #[test]
    fn derived_with_and_without_year() {
        let with = compute_derived(7, 4, Some(1990));
        assert_eq!(with.zodiac, "cancer");
        assert_eq!(with.chinese_zodiac.as_deref(), Some("horse"));
        assert!(with.birth_weekday.is_some());

        let without = compute_derived(7, 4, None);
        assert_eq!(without.chinese_zodiac, None);
        assert_eq!(without.birth_weekday, None);
    }

    #[test]
    fn age_is_none_without_year() {
        let f = compute_facts(&input(6, 15, None, "UTC"));
        assert_eq!(f.age_years, None);
        assert_eq!(f.age_turning, None);
        assert!(f.has_birthday);
        assert!(!f.has_year);
    }

    #[test]
    fn days_until_zero_on_birthday_utc() {
        let today = Utc::now().date_naive();
        let f = compute_facts(&input(
            today.month() as i32,
            today.day() as i32,
            None,
            "UTC",
        ));
        // Feb-29 today is impossible to assert generically; every other day
        // the local birthday is today so days_until is 0.
        if !(today.month() == 2 && today.day() == 29) {
            assert_eq!(f.days_until, 0);
            assert!(f.is_today);
            assert!(f.is_this_week);
            assert!(f.is_this_month);
        }
    }

    #[test]
    fn unknown_tz_falls_back_to_utc() {
        assert_eq!(normalize_tz("Not/AZone"), "UTC");
        assert_eq!(normalize_tz(""), "UTC");
        assert_eq!(normalize_tz("America/New_York"), "America/New_York");
    }
}
