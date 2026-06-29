//! Rust-side condition evaluation. Sync, fast, no I/O (Convention 5).
//!
//! Used by `services::sync::sync_for_player` to decide a single member's
//! add/remove for each of their role links. The bulk per-role-link path uses
//! [services::rule_sql::build_rule_where] instead — it pushes the same
//! predicates down into Postgres. Both must agree.

use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;

/// Evaluate the rule tree against a member's birthday facts.
///
/// - `grant_on_any_birthday = true` short-circuits to `true` (anyone who has
///   saved a birthday).
/// - Otherwise an empty `groups` slice returns `false` (Convention 42).
/// - Otherwise: ANY group matches (OR) and each group requires ALL of its
///   conditions (AND). Empty groups are FALSE (defensive; the validator
///   already rejects them at save).
pub fn evaluate(tree: &RuleTree, facts: &Facts) -> bool {
    if tree.grant_on_any_birthday {
        return true;
    }
    if tree.groups.is_empty() {
        return false;
    }
    tree.groups
        .iter()
        .any(|g| !g.conditions.is_empty() && g.conditions.iter().all(|c| evaluate_single(c, facts)))
}

fn evaluate_single(c: &Condition, f: &Facts) -> bool {
    use ConditionTarget::*;
    match c.target {
        // -- booleans --
        HasBirthdaySet => bool_match(c, f.has_birthday),
        HasBirthYear => bool_match(c, f.has_year),
        IsBirthdayToday => bool_match(c, f.is_today),
        IsBirthdayWeek => bool_match(c, f.is_this_week),
        IsBirthdayMonth => bool_match(c, f.is_this_month),

        // -- integers (some nullable → fail closed) --
        DaysUntilBirthday => int_match(c, Some(f.days_until)),
        AgeYears => int_match(c, f.age_years),
        AgeTurningThisYear => int_match(c, f.age_turning),
        BirthMonth => int_match(c, Some(f.birth_month)),
        BirthDay => int_match(c, Some(f.birth_day)),
        BirthYear => int_match(c, f.birth_year),

        // -- strings (chinese / weekday nullable) --
        ZodiacSign => string_match(c, Some(f.zodiac.as_str())),
        ChineseZodiac => string_match(c, f.chinese_zodiac.as_deref()),
        BirthSeason => string_match(c, Some(f.season.as_str())),
        Birthstone => string_match(c, Some(f.birthstone.as_str())),
        BirthWeekday => string_match(c, f.weekday.as_deref()),
    }
}

fn bool_match(c: &Condition, actual: bool) -> bool {
    if !matches!(c.operator, ConditionOperator::Eq) {
        return false;
    }
    c.value.as_bool().map(|v| v == actual).unwrap_or(false)
}

fn int_list(value: &Value) -> Vec<i64> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default()
}

fn int_match(c: &Condition, actual: Option<i64>) -> bool {
    let Some(a) = actual else {
        return false; // missing data ⇒ fail-closed
    };
    let v = c.value.as_i64();
    match c.operator {
        ConditionOperator::Eq => v.map(|n| a == n).unwrap_or(false),
        ConditionOperator::Neq => v.map(|n| a != n).unwrap_or(false),
        ConditionOperator::Gt => v.map(|n| a > n).unwrap_or(false),
        ConditionOperator::Gte => v.map(|n| a >= n).unwrap_or(false),
        ConditionOperator::Lt => v.map(|n| a < n).unwrap_or(false),
        ConditionOperator::Lte => v.map(|n| a <= n).unwrap_or(false),
        ConditionOperator::Between => {
            let lo = v;
            let hi = c.value_end.as_ref().and_then(|x| x.as_i64());
            match (lo, hi) {
                (Some(lo), Some(hi)) => a >= lo && a <= hi,
                _ => false,
            }
        }
        ConditionOperator::In => int_list(&c.value).contains(&a),
        ConditionOperator::NotIn => !int_list(&c.value).contains(&a),
        _ => false,
    }
}

fn string_match(c: &Condition, actual: Option<&str>) -> bool {
    let Some(a) = actual else {
        // For `neq` against a missing value treat as match — admins use this
        // for "anyone whose <fact> is NOT x" where some members have no year.
        return matches!(c.operator, ConditionOperator::Neq);
    };
    let v = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => v.map(|s| a == s).unwrap_or(false),
        ConditionOperator::Neq => v.map(|s| a != s).unwrap_or(false),
        ConditionOperator::Contains => v.map(|s| a.contains(s)).unwrap_or(false),
        ConditionOperator::Regex => {
            let Some(pattern) = v else { return false };
            let Ok(re) = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            re.is_match(a)
        }
        ConditionOperator::In => str_list_contains(&c.value, a),
        ConditionOperator::NotIn => !str_list_contains(&c.value, a),
        _ => false,
    }
}

fn str_list_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == needle))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::ConditionTarget as T;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn c(target: T, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target,
            operator: op,
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<Condition>) -> RuleTree {
        RuleTree {
            grant_on_any_birthday: false,
            groups: vec![ConditionGroup { conditions: conds }],
        }
    }

    fn or_groups(g: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_birthday: false,
            groups: g
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    fn facts() -> Facts {
        Facts {
            has_birthday: true,
            ..Default::default()
        }
    }

    // ---------- Convention 42 ----------

    #[test]
    fn convention_42_no_groups_no_grant_means_nobody() {
        let t = RuleTree::default();
        assert!(!evaluate(&t, &facts()));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let t = RuleTree {
            grant_on_any_birthday: true,
            groups: vec![],
        };
        assert!(evaluate(&t, &facts()));
    }

    #[test]
    fn empty_group_is_false_defensive() {
        let t = RuleTree {
            grant_on_any_birthday: false,
            groups: vec![ConditionGroup { conditions: vec![] }],
        };
        assert!(!evaluate(&t, &facts()));
    }

    // ---------- the classic "birthday today" rule ----------

    #[test]
    fn birthday_today_only_on_the_day() {
        let t = one_group(vec![c(
            T::IsBirthdayToday,
            ConditionOperator::Eq,
            json!(true),
        )]);
        let mut f = facts();
        f.is_today = true;
        assert!(evaluate(&t, &f));
        f.is_today = false;
        assert!(!evaluate(&t, &f));
    }

    // ---------- AND / OR ----------

    #[test]
    fn turning_18_this_year_in_their_birthday_month() {
        // "turns 18 this year AND it's their birthday month"
        let t = one_group(vec![
            c(T::AgeTurningThisYear, ConditionOperator::Eq, json!(18)),
            c(T::IsBirthdayMonth, ConditionOperator::Eq, json!(true)),
        ]);
        let mut f = facts();
        f.age_turning = Some(18);
        f.is_this_month = true;
        assert!(evaluate(&t, &f));
        f.age_turning = Some(19);
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn or_today_or_zodiac() {
        let t = or_groups(vec![
            vec![c(T::IsBirthdayToday, ConditionOperator::Eq, json!(true))],
            vec![c(
                T::ZodiacSign,
                ConditionOperator::In,
                json!(["leo", "virgo"]),
            )],
        ]);
        let mut f = facts();
        f.zodiac = "virgo".into();
        assert!(evaluate(&t, &f));
        f.zodiac = "aries".into();
        assert!(!evaluate(&t, &f));
        f.is_today = true;
        assert!(evaluate(&t, &f));
    }

    // ---------- int In / Between ----------

    #[test]
    fn born_in_specific_months_via_int_in() {
        let t = one_group(vec![c(
            T::BirthMonth,
            ConditionOperator::In,
            json!([6, 7, 8]),
        )]);
        let mut f = facts();
        f.birth_month = 7;
        assert!(evaluate(&t, &f));
        f.birth_month = 1;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn days_until_between() {
        let mut cond = c(T::DaysUntilBirthday, ConditionOperator::Between, json!(0));
        cond.value_end = Some(json!(6));
        let t = one_group(vec![cond]);
        let mut f = facts();
        f.days_until = 3;
        assert!(evaluate(&t, &f));
        f.days_until = 30;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn age_missing_fails_closed() {
        let t = one_group(vec![c(T::AgeYears, ConditionOperator::Gte, json!(18))]);
        let f = facts(); // age_years = None
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn missing_chinese_neq_passes() {
        // No year ⇒ chinese_zodiac None ⇒ "anyone NOT a dragon" still matches.
        let t = one_group(vec![c(
            T::ChineseZodiac,
            ConditionOperator::Neq,
            json!("dragon"),
        )]);
        let f = facts();
        assert!(evaluate(&t, &f));
    }
}
