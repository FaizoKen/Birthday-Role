//! SQL WHERE-clause builder for bulk per-role-link sync.
//!
//! Pushes the same DNF semantics as [services::condition_eval::evaluate]
//! down into Postgres so `sync_for_role_link` filters server-side instead of
//! loading every member's birthday into memory (Convention 6 / 8).
//!
//! The clause references the `bt` alias (the `birthdays` table). Every
//! time-relative fact is resolved against the member's *local* date,
//! `(now() AT TIME ZONE bt.tz)::date`, via the immutable `bday_*` functions
//! from migration 005 — the SQL mirror of [services::birthday]. Static
//! derived facts (zodiac / season / …) compare a denormalised column
//! directly. NULL handling matches the Rust evaluator's fail-closed rules.

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::RuleTree;

/// Member's local "today". `now()` is STABLE within a statement so every row
/// is evaluated against a single consistent instant.
const LOCAL: &str = "((now() AT TIME ZONE bt.tz)::date)";

#[derive(Debug, Clone)]
pub enum Bind {
    Bool(bool),
    Int(i64),
    Text(String),
    IntArray(Vec<i64>),
    TextArray(Vec<String>),
}

/// Returns ("clause", binds). Binds use parameter indices starting at
/// `bind_offset + 1`. Convention 42: `grant_on_any_birthday = false` AND no
/// groups ⇒ "FALSE" (match nobody). `grant_on_any_birthday = true` ⇒ "TRUE".
pub fn build_rule_where(tree: &RuleTree, bind_offset: usize) -> (String, Vec<Bind>) {
    if tree.grant_on_any_birthday {
        return ("TRUE".to_string(), vec![]);
    }
    if tree.groups.is_empty() {
        return ("FALSE".to_string(), vec![]);
    }

    let mut binds: Vec<Bind> = Vec::new();
    let mut group_clauses: Vec<String> = Vec::new();

    for group in &tree.groups {
        if group.conditions.is_empty() {
            group_clauses.push("FALSE".to_string());
            continue;
        }
        let mut cond_clauses: Vec<String> = Vec::new();
        for c in &group.conditions {
            cond_clauses.push(build_condition(c, bind_offset, &mut binds));
        }
        group_clauses.push(format!("({})", cond_clauses.join(" AND ")));
    }

    (format!("({})", group_clauses.join(" OR ")), binds)
}

/// SQL expression for a target. Bools/ints/strings are typed naturally;
/// nullable expressions (age, year, chinese, weekday) stay NULL-able so
/// comparisons fail closed exactly like the Rust evaluator.
fn target_expr(target: ConditionTarget) -> String {
    use ConditionTarget::*;
    match target {
        HasBirthdaySet => "TRUE".to_string(),
        HasBirthYear => "(bt.birth_year IS NOT NULL)".to_string(),
        IsBirthdayToday => format!("bday_is_today(bt.birth_month, bt.birth_day, {LOCAL})"),
        IsBirthdayWeek => {
            format!("(bday_days_until(bt.birth_month, bt.birth_day, {LOCAL}) <= 6)")
        }
        IsBirthdayMonth => format!("(EXTRACT(MONTH FROM {LOCAL})::int = bt.birth_month)"),
        DaysUntilBirthday => format!("bday_days_until(bt.birth_month, bt.birth_day, {LOCAL})"),
        AgeYears => {
            format!("bday_age(bt.birth_year, bt.birth_month, bt.birth_day, {LOCAL})")
        }
        AgeTurningThisYear => {
            format!("bday_age_turning(bt.birth_year, bt.birth_month, bt.birth_day, {LOCAL})")
        }
        BirthMonth => "bt.birth_month".to_string(),
        BirthDay => "bt.birth_day".to_string(),
        BirthYear => "bt.birth_year".to_string(),
        ZodiacSign => "bt.zodiac".to_string(),
        ChineseZodiac => "bt.chinese_zodiac".to_string(),
        BirthSeason => "bt.season".to_string(),
        Birthstone => "bt.birthstone".to_string(),
        BirthWeekday => "bt.birth_weekday".to_string(),
    }
}

fn build_condition(c: &Condition, bind_offset: usize, binds: &mut Vec<Bind>) -> String {
    use ConditionOperator::*;
    let expr = target_expr(c.target);
    let kind = c.target.kind();
    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;

    match c.operator {
        Eq => match kind {
            TargetKind::Bool => {
                let b = c.value.as_bool().unwrap_or(false);
                let i = next(binds);
                binds.push(Bind::Bool(b));
                format!("({expr}) = ${i}")
            }
            TargetKind::Int => {
                let n = c.value.as_i64().unwrap_or(0);
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("({expr}) = ${i}")
            }
            TargetKind::String => {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} = ${i}")
            }
        },
        Neq => {
            if matches!(kind, TargetKind::Int) {
                let n = c.value.as_i64().unwrap_or(0);
                let i = next(binds);
                binds.push(Bind::Int(n));
                // Plain <> so a NULL int (no birth year) is NOT matched —
                // matches the Rust evaluator's fail-closed int behavior.
                format!("({expr}) <> ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                // IS DISTINCT FROM so a NULL string (no chinese/weekday) DOES
                // match `neq` — matches the Rust evaluator's string behavior.
                format!("{expr} IS DISTINCT FROM ${i}")
            }
        }
        Gt | Gte | Lt | Lte => {
            let n = c.value.as_i64().unwrap_or(0);
            let i = next(binds);
            binds.push(Bind::Int(n));
            let op = match c.operator {
                Gt => ">",
                Gte => ">=",
                Lt => "<",
                Lte => "<=",
                _ => unreachable!(),
            };
            format!("({expr}) {op} ${i}")
        }
        Between => {
            let lo = c.value.as_i64().unwrap_or(0);
            let hi = c.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(lo);
            let ia = next(binds);
            binds.push(Bind::Int(lo));
            let ib = next(binds);
            binds.push(Bind::Int(hi));
            format!("(({expr}) >= ${ia} AND ({expr}) <= ${ib})")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("{expr} LIKE ${i}")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(v.to_string()));
            format!("{expr} ~ ${i}")
        }
        In => {
            if matches!(kind, TargetKind::Int) {
                let arr = int_array(c);
                if arr.is_empty() {
                    return "FALSE".to_string();
                }
                let i = next(binds);
                binds.push(Bind::IntArray(arr));
                format!("({expr}) = ANY(${i}::int[])")
            } else {
                let arr = str_array(c);
                if arr.is_empty() {
                    return "FALSE".to_string();
                }
                let i = next(binds);
                binds.push(Bind::TextArray(arr));
                format!("{expr} = ANY(${i}::text[])")
            }
        }
        NotIn => {
            if matches!(kind, TargetKind::Int) {
                let arr = int_array(c);
                if arr.is_empty() {
                    return "TRUE".to_string();
                }
                let i = next(binds);
                binds.push(Bind::IntArray(arr));
                format!("(({expr}) IS NOT NULL AND ({expr}) <> ALL(${i}::int[]))")
            } else {
                let arr = str_array(c);
                if arr.is_empty() {
                    return "TRUE".to_string();
                }
                let i = next(binds);
                binds.push(Bind::TextArray(arr));
                format!("({expr} IS NOT NULL AND {expr} <> ALL(${i}::text[]))")
            }
        }
    }
}

fn int_array(c: &Condition) -> Vec<i64> {
    c.value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default()
}

fn str_array(c: &Condition) -> Vec<String> {
    c.value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::{Condition, ConditionOperator as Op, ConditionTarget as T};
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn cond(t: T, op: Op, v: serde_json::Value) -> Condition {
        Condition {
            target: t,
            operator: op,
            value: v,
            value_end: None,
        }
    }

    fn tree(grant: bool, groups: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_birthday: grant,
            groups: groups
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    #[test]
    fn grant_on_any_is_true() {
        let (sql, binds) = build_rule_where(&tree(true, vec![]), 1);
        assert_eq!(sql, "TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn convention_42_empty_is_false() {
        let (sql, _) = build_rule_where(&RuleTree::default(), 1);
        assert_eq!(sql, "FALSE");
    }

    #[test]
    fn birthday_today_uses_local_function() {
        let t = tree(
            false,
            vec![vec![cond(T::IsBirthdayToday, Op::Eq, json!(true))]],
        );
        let (sql, binds) = build_rule_where(&t, 1);
        assert!(sql.contains("bday_is_today(bt.birth_month, bt.birth_day"));
        assert!(sql.contains("now() AT TIME ZONE bt.tz"));
        assert!(matches!(binds[0], Bind::Bool(true)));
    }

    #[test]
    fn int_in_uses_int_array() {
        let t = tree(
            false,
            vec![vec![cond(T::BirthMonth, Op::In, json!([6, 7, 8]))]],
        );
        // bind_offset = 1 (the caller binds member_ids as $1), so the first
        // rule bind is $2.
        let (sql, binds) = build_rule_where(&t, 1);
        assert!(sql.contains("= ANY($2::int[])"));
        assert!(matches!(&binds[0], Bind::IntArray(v) if v.len() == 3));
    }

    #[test]
    fn string_in_uses_text_array() {
        let t = tree(
            false,
            vec![vec![cond(T::ZodiacSign, Op::In, json!(["leo", "virgo"]))]],
        );
        let (sql, binds) = build_rule_where(&t, 1);
        assert!(sql.contains("bt.zodiac = ANY($2::text[])"));
        assert!(matches!(&binds[0], Bind::TextArray(v) if v.len() == 2));
    }

    #[test]
    fn age_between_two_binds() {
        let mut c = cond(T::AgeYears, Op::Between, json!(18));
        c.value_end = Some(json!(25));
        let (sql, binds) = build_rule_where(&tree(false, vec![vec![c]]), 1);
        assert!(sql.contains(">= $2") && sql.contains("<= $3"));
        assert!(sql.contains("bday_age(bt.birth_year"));
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn or_of_two_groups() {
        let t = tree(
            false,
            vec![
                vec![cond(T::IsBirthdayToday, Op::Eq, json!(true))],
                vec![cond(T::BirthSeason, Op::Eq, json!("summer"))],
            ],
        );
        let (sql, _) = build_rule_where(&t, 1);
        assert!(sql.contains(" OR "));
    }

    #[test]
    fn like_escapes_wildcards() {
        let t = tree(
            false,
            vec![vec![cond(T::ZodiacSign, Op::Contains, json!("100%_x"))]],
        );
        let (_, binds) = build_rule_where(&t, 1);
        match &binds[0] {
            Bind::Text(s) => assert_eq!(s, "%100\\%\\_x%"),
            _ => panic!("expected Text bind"),
        }
    }
}
