//! Parse and validate the rule-tree payload sent by the iframe UI on save.
//!
//! Returns a clean `RuleTree` ready to persist as `role_links.rule_tree`
//! JSONB. Error messages are user-facing (surfaced through the dashboard's
//! `rl:toast`).

use serde::Deserialize;
use serde_json::Value;

use crate::error::AppError;
use crate::models::condition::{Condition, ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::{ConditionGroup, RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};
use crate::services::birthday;

#[derive(Debug, Deserialize)]
pub struct RuleTreeBody {
    #[serde(default)]
    pub grant_on_any_birthday: bool,
    #[serde(default)]
    pub groups: Vec<ConditionGroupInput>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionGroupInput {
    #[serde(default)]
    pub conditions: Vec<ConditionInput>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionInput {
    pub target: String,
    pub operator: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default)]
    pub value_end: Option<Value>,
}

pub struct ParsedRule {
    pub rule_tree: RuleTree,
}

pub fn parse_rule_tree(body: RuleTreeBody) -> Result<ParsedRule, AppError> {
    if !body.grant_on_any_birthday {
        if body.groups.is_empty() {
            return Err(AppError::BadRequest(
                "Pick who should get this role, or choose \"anyone who added a birthday\".".into(),
            ));
        }
        if body.groups.len() > MAX_GROUPS {
            return Err(AppError::BadRequest(format!(
                "At most {MAX_GROUPS} OR-groups per role."
            )));
        }
    }

    let mut groups: Vec<ConditionGroup> = Vec::with_capacity(body.groups.len());
    if !body.grant_on_any_birthday {
        for (gi, raw_group) in body.groups.into_iter().enumerate() {
            let group_num = gi + 1;
            if raw_group.conditions.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Group #{group_num}: add at least one condition (or remove the group)."
                )));
            }
            if raw_group.conditions.len() > MAX_CONDITIONS_PER_GROUP {
                return Err(AppError::BadRequest(format!(
                    "Group #{group_num}: at most {MAX_CONDITIONS_PER_GROUP} conditions per group."
                )));
            }
            let mut conditions: Vec<Condition> = Vec::with_capacity(raw_group.conditions.len());
            for (ci, raw) in raw_group.conditions.into_iter().enumerate() {
                conditions.push(validate_condition(group_num, ci + 1, raw)?);
            }
            groups.push(ConditionGroup { conditions });
        }
    }

    Ok(ParsedRule {
        rule_tree: RuleTree {
            grant_on_any_birthday: body.grant_on_any_birthday,
            groups,
        },
    })
}

fn validate_condition(
    group_num: usize,
    cond_num: usize,
    raw: ConditionInput,
) -> Result<Condition, AppError> {
    let where_ = format!("Group #{group_num}, condition #{cond_num}");

    let target = ConditionTarget::from_key(raw.target.trim()).ok_or_else(|| {
        AppError::BadRequest(format!("{where_}: unknown target '{}'.", raw.target))
    })?;

    let operator = ConditionOperator::from_key(raw.operator.trim()).ok_or_else(|| {
        AppError::BadRequest(format!("{where_}: unknown operator '{}'.", raw.operator))
    })?;

    if !operator.valid_for(target.kind()) {
        return Err(AppError::BadRequest(format!(
            "{where_}: operator '{}' is not valid for '{}'.",
            operator.as_str(),
            target.as_str()
        )));
    }

    let value = normalize_value(&where_, target, operator, raw.value)?;
    let value_end = match (operator, raw.value_end) {
        (ConditionOperator::Between, Some(end)) => {
            Some(normalize_value(&where_, target, operator, end)?)
        }
        (ConditionOperator::Between, None) => {
            return Err(AppError::BadRequest(format!(
                "{where_}: \"between\" needs both a min and a max value."
            )));
        }
        _ => None,
    };

    if matches!(operator, ConditionOperator::Regex) {
        let pattern = value.as_str().unwrap_or("");
        if regex::RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .is_err()
        {
            return Err(AppError::BadRequest(format!(
                "{where_}: regex pattern is invalid."
            )));
        }
    }

    Ok(Condition {
        target,
        operator,
        value,
        value_end,
    })
}

/// The values a string target can hold, and what one of them is called.
/// Every string target is an enum: the stored facts are always one of these,
/// lower-case (`services::birthday`).
fn string_choices(target: ConditionTarget) -> (&'static [&'static str], &'static str) {
    use ConditionTarget::*;
    match target {
        ZodiacSign => (birthday::ZODIAC_SIGNS, "zodiac sign"),
        ChineseZodiac => (birthday::CHINESE_ZODIACS, "Chinese zodiac animal"),
        BirthSeason => (birthday::SEASONS, "season"),
        Birthstone => (birthday::BIRTHSTONES, "birthstone"),
        BirthWeekday => (birthday::WEEKDAYS, "weekday"),
        _ => (&[], "value"),
    }
}

/// One value for an enum target, as it is stored: trimmed and lower-cased
/// ("Leo" is "leo", "fall" is "autumn"), and refused when it is not one of
/// the target's values. Comparisons are exact, so before this a capital or a
/// typo saved a condition that silently matched nobody.
fn enum_value(where_: &str, target: ConditionTarget, raw: &str) -> Result<String, AppError> {
    let mut v = raw.trim().to_lowercase();
    if target == ConditionTarget::BirthSeason && v == "fall" {
        v = "autumn".to_string();
    }
    let (choices, noun) = string_choices(target);
    if choices.is_empty() || choices.contains(&v.as_str()) {
        return Ok(v);
    }
    Err(AppError::BadRequest(format!(
        "{where_}: \"{}\" isn't a {noun}. Use one of: {}.",
        raw.trim(),
        choices.join(", ")
    )))
}

fn normalize_value(
    where_: &str,
    target: ConditionTarget,
    op: ConditionOperator,
    raw: Value,
) -> Result<Value, AppError> {
    use ConditionOperator::{Contains, In, NotIn, Regex};

    let kind = target.kind();
    match (kind, op) {
        (TargetKind::Bool, _) => match &raw {
            Value::Bool(_) => Ok(raw),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(Value::Bool(true)),
                "false" | "0" | "no" => Ok(Value::Bool(false)),
                _ => Err(AppError::BadRequest(format!(
                    "{where_}: boolean value required (got {raw})."
                ))),
            },
            _ => Err(AppError::BadRequest(format!(
                "{where_}: boolean value required (got {raw})."
            ))),
        },
        (TargetKind::Int, In | NotIn) => {
            let items: Vec<Value> = match raw {
                Value::Array(a) => a,
                Value::String(s) => s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
                Value::Number(_) => vec![raw],
                Value::Null => vec![],
                other => vec![other],
            };
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let n = match &it {
                    Value::Number(num) => num.as_i64(),
                    Value::String(s) => s.trim().parse::<i64>().ok(),
                    _ => None,
                };
                match n {
                    Some(n) => out.push(Value::from(n)),
                    None => {
                        return Err(AppError::BadRequest(format!(
                            "{where_}: list must be whole numbers (got {it})."
                        )))
                    }
                }
            }
            if out.is_empty() {
                let what = if target == ConditionTarget::BirthMonth {
                    "pick at least one month"
                } else {
                    "enter at least one number"
                };
                return Err(AppError::BadRequest(format!("{where_}: {what}.")));
            }
            Ok(Value::Array(out))
        }
        (TargetKind::Int, _) => {
            // An empty box is the normal state right after picking a number
            // condition, and the role settings show this message under the
            // rule while it lasts, so say what to do rather than `(got "")`.
            let blank = match &raw {
                Value::Null => true,
                Value::String(s) => s.trim().is_empty(),
                _ => false,
            };
            if blank {
                return Err(AppError::BadRequest(format!("{where_}: enter a number.")));
            }
            let n = match &raw {
                Value::Number(num) => num.as_i64().or_else(|| num.as_f64().map(|f| f as i64)),
                Value::String(s) => s.trim().parse::<i64>().ok(),
                _ => None,
            };
            n.map(Value::from).ok_or_else(|| {
                AppError::BadRequest(format!("{where_}: whole number required (got {raw})."))
            })
        }
        (TargetKind::String, In | NotIn) => {
            let items: Vec<Value> = match raw {
                Value::Array(a) => a
                    .into_iter()
                    .filter(|v| !matches!(v, Value::Null))
                    .filter(|v| !v.as_str().is_some_and(|s| s.trim().is_empty()))
                    .collect(),
                Value::String(s) => s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
                Value::Null => vec![],
                other => vec![other],
            };
            if items.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "{where_}: pick at least one value."
                )));
            }
            let mut out: Vec<Value> = Vec::with_capacity(items.len());
            for it in items {
                let Some(s) = it.as_str() else {
                    return Err(AppError::BadRequest(format!(
                        "{where_}: list values must be text (got {it})."
                    )));
                };
                let v = Value::String(enum_value(where_, target, s)?);
                if !out.contains(&v) {
                    out.push(v);
                }
            }
            Ok(Value::Array(out))
        }
        (TargetKind::String, _) => {
            let s = match raw {
                Value::String(s) => s,
                Value::Number(num) => num.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => String::new(),
            };
            if s.trim().is_empty() {
                return Err(AppError::BadRequest(format!("{where_}: value required.")));
            }
            match op {
                // A pattern is the admin's own; leave it exactly as typed.
                Regex => Ok(Value::String(s)),
                // A fragment of a stored (lower-case) value.
                Contains => Ok(Value::String(s.trim().to_lowercase())),
                _ => Ok(Value::String(enum_value(where_, target, &s)?)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(target: &str, operator: &str, value: Value) -> ConditionInput {
        ConditionInput {
            target: target.into(),
            operator: operator.into(),
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<ConditionInput>) -> RuleTreeBody {
        RuleTreeBody {
            grant_on_any_birthday: false,
            groups: vec![ConditionGroupInput { conditions: conds }],
        }
    }

    #[test]
    fn grant_on_any_no_groups_ok() {
        let body = RuleTreeBody {
            grant_on_any_birthday: true,
            groups: vec![],
        };
        let parsed = parse_rule_tree(body).unwrap();
        assert!(parsed.rule_tree.grant_on_any_birthday);
    }

    #[test]
    fn convention_42_rejects_no_groups_no_grant() {
        let body = RuleTreeBody {
            grant_on_any_birthday: false,
            groups: vec![],
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_unknown_target() {
        let body = one_group(vec![input("not_a_target", "eq", json!(true))]);
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_operator_target_mismatch() {
        let body = one_group(vec![input("is_birthday_today", "gt", json!(0))]);
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn int_in_normalizes_csv() {
        let body = one_group(vec![input("birth_month", "in", json!("6, 7, 8"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value,
            json!([6, 7, 8])
        );
    }

    #[test]
    fn int_in_rejects_non_numbers() {
        let body = one_group(vec![input("birth_month", "in", json!(["june"]))]);
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn string_in_normalizes_csv() {
        let body = one_group(vec![input("zodiac_sign", "in", json!("leo, virgo"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value,
            json!(["leo", "virgo"])
        );
    }

    #[test]
    fn string_values_ignore_case_and_spaces() {
        let body = one_group(vec![
            input("zodiac_sign", "in", json!(["Leo", " VIRGO ", "leo"])),
            input("birth_weekday", "eq", json!("Friday")),
        ]);
        let parsed = parse_rule_tree(body).unwrap();
        let cs = &parsed.rule_tree.groups[0].conditions;
        assert_eq!(cs[0].value, json!(["leo", "virgo"]));
        assert_eq!(cs[1].value, json!("friday"));
    }

    #[test]
    fn string_typo_is_refused_not_saved() {
        let body = one_group(vec![input("zodiac_sign", "in", json!("leo, virgoo"))]);
        let err = match parse_rule_tree(body) {
            Err(AppError::BadRequest(m)) => m,
            _ => panic!("expected a BadRequest"),
        };
        assert!(
            err.starts_with("Group #1, condition #1: \"virgoo\" isn't a zodiac sign."),
            "{err}"
        );
    }

    #[test]
    fn fall_is_autumn() {
        let body = one_group(vec![input("birth_season", "eq", json!("Fall"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value,
            json!("autumn")
        );
    }

    #[test]
    fn regex_is_kept_as_typed() {
        let body = one_group(vec![input("zodiac_sign", "regex", json!("^(Leo|virgo)$"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value,
            json!("^(Leo|virgo)$")
        );
    }

    #[test]
    fn empty_number_asks_for_one() {
        let body = one_group(vec![input("age_years", "gte", json!(""))]);
        let err = match parse_rule_tree(body) {
            Err(AppError::BadRequest(m)) => m,
            _ => panic!("expected a BadRequest"),
        };
        assert_eq!(err, "Group #1, condition #1: enter a number.");
    }

    #[test]
    fn empty_month_list_asks_for_a_month() {
        let body = one_group(vec![input("birth_month", "in", json!([]))]);
        let err = match parse_rule_tree(body) {
            Err(AppError::BadRequest(m)) => m,
            _ => panic!("expected a BadRequest"),
        };
        assert_eq!(err, "Group #1, condition #1: pick at least one month.");
    }

    #[test]
    fn between_requires_value_end() {
        let body = one_group(vec![ConditionInput {
            target: "age_years".into(),
            operator: "between".into(),
            value: json!(18),
            value_end: None,
        }]);
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn age_between_ok() {
        let body = one_group(vec![ConditionInput {
            target: "age_years".into(),
            operator: "between".into(),
            value: json!(18),
            value_end: Some(json!(25)),
        }]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value_end,
            Some(json!(25))
        );
    }

    #[test]
    fn caps_max_groups() {
        let mut groups = Vec::new();
        for _ in 0..(MAX_GROUPS + 1) {
            groups.push(ConditionGroupInput {
                conditions: vec![input("is_birthday_today", "eq", json!(true))],
            });
        }
        let body = RuleTreeBody {
            grant_on_any_birthday: false,
            groups,
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }
}
