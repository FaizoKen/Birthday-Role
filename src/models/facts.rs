//! Plain-data view of a member's birthday facts, computed for "today" in
//! that member's timezone. Built by [services::birthday::compute_facts] from
//! a `birthdays` row.
//!
//! Kept POD (no methods, no I/O) so [services::condition_eval::evaluate]
//! stays sync and fast (Convention 5). Optional fields are `None` when the
//! member didn't supply a birth year — numeric comparisons fail closed, the
//! same way the reference plugin treats a missing account-age.

#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Always true once we have a `birthdays` row (the analogue of "linked").
    pub has_birthday: bool,
    pub has_year: bool,

    // time-relative (already resolved against the member's local "today")
    pub is_today: bool,
    pub is_this_week: bool,
    pub is_this_month: bool,
    pub days_until: i64,
    pub age_years: Option<i64>,
    pub age_turning: Option<i64>,

    // literal birthday fields
    pub birth_month: i64,
    pub birth_day: i64,
    pub birth_year: Option<i64>,

    // static derived calendar facts
    pub zodiac: String,
    pub chinese_zodiac: Option<String>,
    pub season: String,
    pub birthstone: String,
    pub weekday: Option<String>,
}
