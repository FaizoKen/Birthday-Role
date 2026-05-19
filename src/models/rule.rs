//! The rule tree: OR of AND-groups (DNF).
//!
//! Stored verbatim as the JSONB `rule_tree` column on `role_links`. Any
//! boolean rule has a DNF form, so this two-level shape keeps validation,
//! SQL translation, and the iframe rule-builder UI simple while still
//! expressing everything.
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. `grant_on_any_birthday = false` AND `groups.is_empty()` means
//! "match nobody" — both [services::condition_eval::evaluate] and
//! [services::rule_sql::build_rule_where] enforce this BEFORE inspecting
//! groups. `grant_on_any_birthday = true` means "anyone who has saved a
//! birthday" (the plugin's analogue of "any verified member").

use serde::{Deserialize, Serialize};

use crate::models::condition::Condition;

/// Maximum top-level OR-groups. 8 comfortably fits a multi-tier rule
/// ("birthday today" OR "zodiac in {…}" OR "turning 18 this year" …).
pub const MAX_GROUPS: usize = 8;
/// Maximum conditions per AND-group. 12 is generous; real rules rarely
/// exceed 3-4.
pub const MAX_CONDITIONS_PER_GROUP: usize = 12;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleTree {
    #[serde(default)]
    pub grant_on_any_birthday: bool,
    #[serde(default)]
    pub groups: Vec<ConditionGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConditionGroup {
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
