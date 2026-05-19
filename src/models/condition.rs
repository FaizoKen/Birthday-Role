//! Condition target / operator types used in the rule tree.
//!
//! - `ConditionTarget` names a birthday fact computed for a member.
//! - `ConditionOperator` names a comparison.
//! - Validity of an (target, operator) combination is enforced at save time
//!   in [services::rule_validator] using each target's `kind()`.
//!
//! Compared to the reference plugin's catalogue this is intentionally
//! *richer*: 18 targets spanning the literal date, derived calendar facts
//! (zodiac / Chinese zodiac / season / birthstone / weekday) and the
//! timezone-aware time-relative facts (today / this week / this month /
//! days-until / age / age-turning).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of data this target produces. Drives which operators are valid
/// and how the rule_validator coerces literal values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Bool,
    Int,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTarget {
    // -- presence --
    /// Member has saved a birthday at all (always true when we have a row;
    /// useful as an explicit AND-guard inside a custom rule).
    HasBirthdaySet,
    HasBirthYear,

    // -- time-relative (depend on "today" in the member's timezone) --
    IsBirthdayToday,
    IsBirthdayWeek,
    IsBirthdayMonth,
    DaysUntilBirthday,
    AgeYears,
    AgeTurningThisYear,

    // -- literal birthday fields --
    BirthMonth,
    BirthDay,
    BirthYear,

    // -- static derived calendar facts --
    ZodiacSign,
    ChineseZodiac,
    BirthSeason,
    Birthstone,
    BirthWeekday,
}

impl ConditionTarget {
    pub fn kind(self) -> TargetKind {
        use ConditionTarget::*;
        match self {
            HasBirthdaySet | HasBirthYear | IsBirthdayToday | IsBirthdayWeek | IsBirthdayMonth => {
                TargetKind::Bool
            }
            DaysUntilBirthday | AgeYears | AgeTurningThisYear | BirthMonth | BirthDay
            | BirthYear => TargetKind::Int,
            ZodiacSign | ChineseZodiac | BirthSeason | Birthstone | BirthWeekday => {
                TargetKind::String
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        use ConditionTarget::*;
        match self {
            HasBirthdaySet => "has_birthday_set",
            HasBirthYear => "has_birth_year",
            IsBirthdayToday => "is_birthday_today",
            IsBirthdayWeek => "is_birthday_week",
            IsBirthdayMonth => "is_birthday_month",
            DaysUntilBirthday => "days_until_birthday",
            AgeYears => "age_years",
            AgeTurningThisYear => "age_turning_this_year",
            BirthMonth => "birth_month",
            BirthDay => "birth_day",
            BirthYear => "birth_year",
            ZodiacSign => "zodiac_sign",
            ChineseZodiac => "chinese_zodiac",
            BirthSeason => "birth_season",
            Birthstone => "birthstone",
            BirthWeekday => "birth_weekday",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        use ConditionTarget::*;
        Some(match s {
            "has_birthday_set" => HasBirthdaySet,
            "has_birth_year" => HasBirthYear,
            "is_birthday_today" => IsBirthdayToday,
            "is_birthday_week" => IsBirthdayWeek,
            "is_birthday_month" => IsBirthdayMonth,
            "days_until_birthday" => DaysUntilBirthday,
            "age_years" => AgeYears,
            "age_turning_this_year" => AgeTurningThisYear,
            "birth_month" => BirthMonth,
            "birth_day" => BirthDay,
            "birth_year" => BirthYear,
            "zodiac_sign" => ZodiacSign,
            "chinese_zodiac" => ChineseZodiac,
            "birth_season" => BirthSeason,
            "birthstone" => Birthstone,
            "birth_weekday" => BirthWeekday,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    Regex,
    In,
    NotIn,
}

impl ConditionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            _ => return None,
        })
    }

    /// Operators that produce a meaningful predicate on each target kind.
    /// Save-time validation rejects mismatches. Note `In`/`NotIn` are valid
    /// on `Int` here (richer than the reference plugin) so "born in
    /// {3, 6, 12}" / "zodiac in {leo, virgo}" are one condition, not an
    /// OR-group per value.
    pub fn valid_for(self, kind: TargetKind) -> bool {
        use ConditionOperator::*;
        match kind {
            TargetKind::Bool => matches!(self, Eq),
            TargetKind::Int => matches!(self, Eq | Neq | Gt | Gte | Lt | Lte | Between | In | NotIn),
            TargetKind::String => matches!(self, Eq | Neq | Contains | Regex | In | NotIn),
        }
    }
}

/// A single condition row inside an AND-group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}
