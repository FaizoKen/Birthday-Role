//! Sync engine — per-player (lightweight) and per-role-link (bulk).
//!
//! Dispatch targets for jobs claimed by [`crate::tasks::job_worker`].
//!
//! Convention 38: guild membership comes from the Auth Gateway
//! `/auth/internal/*`, never a local JOIN. Convention 40: gateway HTTP
//! failures bubble up (the worker retries) — we never clear a role on a
//! transient lookup failure. Convention 47: a RoleLinkNotFound deletes the
//! orphan local row instead of retrying forever. A disabled/paused link or a
//! removal RoleLogic holds for confirmation is skipped (not retried): local
//! assignments stay as-is, so the next tick resends the list.
//!
//! Except when the calendar alone explains a held removal. A "birthday today"
//! role empties the day after every birthday in a small server, and RoleLogic
//! holds any write that empties a list, so yesterday's birthday member kept
//! the role until an owner confirmed it in the dashboard. When every member a
//! held write removes is still in the server, still has a birthday saved, and
//! was given the role by this same rule but no longer qualifies for it today,
//! the write is confirmed with RoleLogic's change id (see
//! [`explain_by_calendar`]). Anything else the gate is there for (a member
//! list that came back short, birthdays that went missing, a rule edit, more
//! removals than we will vouch for) is left to the owner as before.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::rule::RuleTree;
use crate::services::birthday::{compute_facts, compute_facts_at, BirthdayInput};
use crate::services::condition_eval;
use crate::services::rule_sql::{self, Bind};
use crate::services::{auth_gateway, jobs};
use crate::AppState;

/// The columns we need to evaluate a member's rule. `birth_month/day` are
/// SMALLINT in the DB; sqlx decodes those as i16.
#[derive(sqlx::FromRow)]
struct BirthdayRow {
    birth_month: i16,
    birth_day: i16,
    birth_year: Option<i32>,
    tz: String,
}

impl From<BirthdayRow> for BirthdayInput {
    fn from(r: BirthdayRow) -> Self {
        BirthdayInput {
            birth_month: r.birth_month as i32,
            birth_day: r.birth_day as i32,
            birth_year: r.birth_year,
            tz: r.tz,
        }
    }
}

const BIRTHDAY_SELECT: &str =
    "SELECT birth_month, birth_day, birth_year, tz FROM birthdays WHERE discord_id = $1";

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;
    if guild_ids.is_empty() {
        return Ok(());
    }

    let role_links = sqlx::query_as::<_, (String, String, String, serde_json::Value)>(
        "SELECT guild_id, role_id, api_token, rule_tree \
         FROM role_links WHERE guild_id = ANY($1)",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;
    if role_links.is_empty() {
        return Ok(());
    }

    // The member's birthday (if they've saved one). Computed once and reused
    // for every role link in every guild they're in.
    let row: Option<BirthdayRow> = sqlx::query_as(BIRTHDAY_SELECT)
        .bind(discord_id)
        .fetch_optional(pool)
        .await?;
    let facts = row.map(|r| compute_facts(&BirthdayInput::from(r)));
    let has_birthday = facts.is_some();

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add(String, String, String),
        Remove(String, String, String),
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, raw_tree) in &role_links {
        let tree: RuleTree = serde_json::from_value(raw_tree.clone()).unwrap_or_default();

        let qualifies = if tree.grant_on_any_birthday {
            has_birthday
        } else if tree.groups.is_empty() {
            false // Convention 42 — unconfigured grants to nobody
        } else {
            match &facts {
                Some(f) => condition_eval::evaluate(&tree, f),
                None => false, // no birthday saved → qualifies for nothing
            }
        };

        let assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, assigned) {
            (true, false) => actions.push(Action::Add(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            (false, true) => actions.push(Action::Remove(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let did = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl = rl_client.clone();
            let did = did.clone();
            async move {
                match action {
                    Action::Add(g, r, tok) => {
                        match rl.add_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::RoleLinkDisabled) => return,
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(g, r, did, limit, "user limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "add_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                    Action::Remove(g, r, tok) => {
                        match rl.remove_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::RoleLinkDisabled) => return,
                            Err(e) => {
                                tracing::error!(g, r, did, "remove_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id=$1 AND role_id=$2 AND discord_id=$3",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk)
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl = &state.rl_client;

    let link = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT api_token, rule_tree FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, raw_tree)) = link else {
        return Ok(());
    };
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    // Convention 42: NOT grant_on_any AND no groups ⇒ unconfigured ⇒ grant
    // to nobody. Clear any stray assignments from a prior misconfiguration.
    if !tree.grant_on_any_birthday && tree.groups.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let member_ids = auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;
    if member_ids.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let (_count, user_limit) = match rl.get_user_info(guild_id, role_id, &api_token).await {
        Ok(v) => v,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(AppError::RoleLinkDisabled) => return Ok(()),
        Err(e) => return Err(e),
    };

    let qualifying: Vec<String> = if tree.grant_on_any_birthday {
        // Anyone in the guild who saved a birthday.
        sqlx::query_scalar(
            "SELECT discord_id FROM birthdays \
             WHERE discord_id = ANY($1::text[]) \
             ORDER BY discord_id LIMIT $2",
        )
        .bind(&member_ids)
        .bind(user_limit as i64)
        .fetch_all(pool)
        .await?
    } else {
        // $1 = member_ids; rule binds from $2; limit last.
        let (rule_where, binds) = rule_sql::build_rule_where(&tree, 1);
        let limit_idx = 1 + binds.len() + 1;
        let query = format!(
            "SELECT bt.discord_id \
             FROM birthdays bt \
             WHERE bt.discord_id = ANY($1::text[]) \
               AND ({rule_where}) \
             ORDER BY bt.discord_id \
             LIMIT ${limit_idx}"
        );
        let mut q = sqlx::query_scalar::<_, String>(&query).bind(&member_ids);
        for b in &binds {
            q = match b {
                Bind::Bool(v) => q.bind(*v),
                Bind::Int(v) => q.bind(*v),
                Bind::Text(v) => q.bind(v.clone()),
                Bind::IntArray(v) => q.bind(v.clone()),
                Bind::TextArray(v) => q.bind(v.clone()),
            };
        }
        q = q.bind(user_limit as i64);
        q.fetch_all(pool).await?
    };

    // Skip the RoleLogic PUT entirely when the computed set already equals
    // what's assigned. Critical cost guard for the tick worker: it re-syncs
    // every role link every cycle, but on a quiet day nobody's birthday
    // flips, the set is unchanged, and this is one cheap local SELECT — no
    // PUT, no Discord role-change storm. Both lists are ordered + de-duped.
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    if current == qualifying {
        return Ok(());
    }

    let result = rl
        .upload_users(guild_id, role_id, &qualifying, &api_token, None)
        .await;
    let result = match result {
        Err(AppError::RoleLinkRemovalHeld {
            previous,
            next,
            change_id: Some(change_id),
        }) => {
            let held = Held {
                previous,
                next,
                current: &current,
                qualifying: &qualifying,
                member_ids: &member_ids,
                tree: &tree,
            };
            match explain_by_calendar(guild_id, role_id, &held, pool).await? {
                Ok(removed) => {
                    tracing::info!(
                        guild_id,
                        role_id,
                        previous,
                        next,
                        removed,
                        "RoleLogic held removals the calendar alone explains; confirming them"
                    );
                    rl.upload_users(guild_id, role_id, &qualifying, &api_token, Some(&change_id))
                        .await
                }
                Err(why) => {
                    tracing::info!(
                        guild_id,
                        role_id,
                        previous,
                        next,
                        "Not confirming the held removal ourselves: {why}"
                    );
                    Err(AppError::RoleLinkRemovalHeld {
                        previous,
                        next,
                        change_id: Some(change_id),
                    })
                }
            }
        }
        other => other,
    };
    if !upload_applied(result, guild_id, role_id, pool).await? {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    if !qualifying.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&qualifying)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn drain_to_empty(
    guild_id: &str,
    role_id: &str,
    api_token: &str,
    state: &AppState,
) -> Result<(), AppError> {
    // Already empty ⇒ nothing to clear. Stops a repeated "grant nobody"
    // re-sync from re-PUTting an empty set every tick.
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE guild_id=$1 AND role_id=$2)",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await?;
    if !any {
        return Ok(());
    }

    // Never confirmed by us: an empty member list or an unconfigured rule is
    // not the calendar moving on.
    let result = state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token, None)
        .await;
    if !upload_applied(result, guild_id, role_id, &state.pool).await? {
        return Ok(());
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

/// Classify a full-list upload result. `Ok(true)` = applied, mirror it into
/// `role_assignments`; `Ok(false)` = skipped this cycle, leave local state
/// alone so the next tick resends; `Err` = transient, let the worker retry.
async fn upload_applied(
    result: Result<usize, AppError>,
    guild_id: &str,
    role_id: &str,
    pool: &sqlx::PgPool,
) -> Result<bool, AppError> {
    match result {
        Ok(_) => Ok(true),
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            Ok(false)
        }
        Err(AppError::RoleLinkDisabled) => Ok(false),
        Err(AppError::RoleLinkRemovalHeld { previous, next, .. }) => {
            // The owner has to confirm in the RoleLogic dashboard (or mark the
            // link as a trusted integration). Our 30-min tick resends within
            // the 1h confirmation window, so no retry/backoff from us.
            tracing::info!(
                guild_id,
                role_id,
                previous,
                next,
                "RoleLogic held a large removal for owner confirmation; will resend next tick"
            );
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Held removals the calendar explains
// ---------------------------------------------------------------------------

/// The most removals one write may carry for us to confirm it ourselves.
/// Covers the daily and weekly roles of any but the largest servers; a
/// month role in a big server rolls over with more, and the owner confirms
/// that one, as before.
const SELF_CONFIRM_MAX: usize = 100;

/// A full-list write RoleLogic is holding, with what this sync computed.
struct Held<'a> {
    /// RoleLogic's stored count, from its 409.
    previous: u64,
    /// The count of the list we sent, from its 409.
    next: u64,
    /// The local mirror: the list RoleLogic last accepted from us.
    current: &'a [String],
    /// The list we sent.
    qualifying: &'a [String],
    /// The server's members, as the Auth Gateway listed them for this sync.
    member_ids: &'a [String],
    tree: &'a RuleTree,
}

/// What we know about one member a held write removes.
struct RemovedMember {
    /// When they were last given the role (the mirror row's time).
    assigned_at: DateTime<Utc>,
    /// Their saved birthday, if they still have one.
    birthday: Option<BirthdayInput>,
}

/// Whether the calendar alone explains every removal in a held write:
/// `Ok(Ok(n))` = all `n` removals are explained, confirm it; `Ok(Err(why))`
/// = leave it to the owner.
async fn explain_by_calendar(
    guild_id: &str,
    role_id: &str,
    held: &Held<'_>,
    pool: &sqlx::PgPool,
) -> Result<Result<usize, String>, AppError> {
    let removed = match removals_to_explain(held) {
        Ok(removed) => removed,
        Err(why) => return Ok(Err(why)),
    };
    type Row = (
        String,
        DateTime<Utc>,
        Option<i16>,
        Option<i16>,
        Option<i32>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT ra.discord_id, ra.assigned_at, b.birth_month, b.birth_day, b.birth_year, b.tz \
         FROM role_assignments ra \
         LEFT JOIN birthdays b ON b.discord_id = ra.discord_id \
         WHERE ra.guild_id = $1 AND ra.role_id = $2 AND ra.discord_id = ANY($3)",
    )
    .bind(guild_id)
    .bind(role_id)
    .bind(&removed)
    .fetch_all(pool)
    .await?;
    let known: HashMap<String, RemovedMember> = rows
        .into_iter()
        .map(|(id, assigned_at, month, day, year, tz)| {
            let birthday = match (month, day, tz) {
                (Some(m), Some(d), Some(tz)) => Some(BirthdayInput {
                    birth_month: m as i32,
                    birth_day: d as i32,
                    birth_year: year,
                    tz,
                }),
                _ => None,
            };
            (
                id,
                RemovedMember {
                    assigned_at,
                    birthday,
                },
            )
        })
        .collect();
    Ok(judge_removals(&removed, &known, held.tree, Utc::now()))
}

/// The members a held write removes, if it is a write we may judge at all:
/// RoleLogic's numbers must match ours, the removals must be few enough, and
/// every removed member must still be on the server's member list.
fn removals_to_explain(held: &Held<'_>) -> Result<Vec<String>, String> {
    if held.previous as usize != held.current.len() {
        return Err(format!(
            "RoleLogic stores {} users for this link, but we last sent {}",
            held.previous,
            held.current.len()
        ));
    }
    if held.next as usize != held.qualifying.len() {
        return Err(format!(
            "RoleLogic counted {} users in a list of {}",
            held.next,
            held.qualifying.len()
        ));
    }
    let keep: HashSet<&str> = held.qualifying.iter().map(String::as_str).collect();
    let removed: Vec<String> = held
        .current
        .iter()
        .filter(|id| !keep.contains(id.as_str()))
        .cloned()
        .collect();
    if removed.is_empty() {
        return Err("the write removes nobody we sent before".into());
    }
    if removed.len() > SELF_CONFIRM_MAX {
        return Err(format!(
            "{} removals is more than the {SELF_CONFIRM_MAX} we confirm ourselves",
            removed.len()
        ));
    }
    // Someone missing from the member list may have left, or the list may have
    // come back incomplete; only the owner can tell those apart.
    let members: HashSet<&str> = held.member_ids.iter().map(String::as_str).collect();
    let missing = removed
        .iter()
        .filter(|id| !members.contains(id.as_str()))
        .count();
    if missing > 0 {
        return Err(format!(
            "{missing} of the {} removed members are not on the server's member list",
            removed.len()
        ));
    }
    Ok(removed)
}

/// Every removed member must still have a saved birthday, and the link's
/// current rule must have given them the role at the time they got it and
/// not give it to them now: then the date moving on is the whole reason.
/// Judging both instants with the current rule also catches a rule edit,
/// which the owner confirms: under an edited rule a member it now removes
/// would not have qualified when they got the role either.
fn judge_removals(
    removed: &[String],
    known: &HashMap<String, RemovedMember>,
    tree: &RuleTree,
    now: DateTime<Utc>,
) -> Result<usize, String> {
    for id in removed {
        let Some(member) = known.get(id) else {
            return Err("a removed member has no assignment on record".into());
        };
        let Some(birthday) = &member.birthday else {
            return Err("a removed member no longer has a birthday saved".into());
        };
        if member.assigned_at > now {
            return Err("a removed member's assignment is dated in the future".into());
        }
        if !condition_eval::evaluate(tree, &compute_facts_at(birthday, member.assigned_at)) {
            return Err(
                "the rule would not have given a removed member the role when they got it \
                 (was the rule edited?)"
                    .into(),
            );
        }
        if condition_eval::evaluate(tree, &compute_facts_at(birthday, now)) {
            return Err("the rule still gives a removed member the role".into());
        }
    }
    Ok(removed.len())
}

/// Fan a resync out to every role link. Called by the tick worker so
/// time-relative rules (birthday today / week / age) flip on schedule even
/// with no member activity. De-duped against already-pending jobs.
pub async fn enqueue_resync_all_role_links(state: &AppState) -> Result<u64, AppError> {
    let links = sqlx::query_as::<_, (String, String)>("SELECT guild_id, role_id FROM role_links")
        .fetch_all(&state.pool)
        .await?;
    let n = links.len() as u64;
    for (guild_id, role_id) in links {
        if let Err(e) = jobs::enqueue_config_sync_unique(&state.pool, &guild_id, &role_id).await {
            tracing::warn!(guild_id, role_id, "tick enqueue config_sync failed: {e}");
        }
    }
    Ok(n)
}

/// Delete a role_link the RoleLogic API reports as gone (Convention 47).
/// CASCADE clears role_assignments. Best-effort: never propagates DB errors.
async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn rule(json: &str) -> RuleTree {
        serde_json::from_str(json).unwrap()
    }

    /// The rule most production links use.
    fn today_rule() -> RuleTree {
        rule(
            r#"{"groups":[{"conditions":[{"value":true,"target":"is_birthday_today","operator":"eq"}]}],"grant_on_any_birthday":false}"#,
        )
    }

    fn week_rule() -> RuleTree {
        rule(
            r#"{"groups":[{"conditions":[{"value":true,"target":"is_birthday_week","operator":"eq"}]}],"grant_on_any_birthday":false}"#,
        )
    }

    fn member(month: i32, day: i32, year: Option<i32>, tz: &str, assigned: &str) -> RemovedMember {
        RemovedMember {
            assigned_at: at(assigned),
            birthday: Some(BirthdayInput {
                birth_month: month,
                birth_day: day,
                birth_year: year,
                tz: tz.to_string(),
            }),
        }
    }

    fn one(id: &str, m: RemovedMember) -> (Vec<String>, HashMap<String, RemovedMember>) {
        (vec![id.to_string()], HashMap::from([(id.to_string(), m)]))
    }

    const NOW: &str = "2026-11-15T12:00:00Z";

    #[test]
    fn yesterdays_birthday_is_explained() {
        let (removed, known) = one("a", member(11, 14, None, "UTC", "2026-11-14T09:00:00Z"));
        assert_eq!(
            judge_removals(&removed, &known, &today_rule(), at(NOW)),
            Ok(1)
        );
    }

    #[test]
    fn the_day_is_judged_in_the_members_timezone() {
        // UTC+14: at 11:00 UTC on 15 Nov it is already 16 Nov there, so a
        // 15 Nov birthday is over although it is still the 15th in UTC.
        let (removed, known) = one(
            "a",
            member(11, 15, None, "Pacific/Kiritimati", "2026-11-14T12:00:00Z"),
        );
        assert_eq!(
            judge_removals(&removed, &known, &today_rule(), at("2026-11-15T11:00:00Z")),
            Ok(1)
        );
    }

    #[test]
    fn a_member_the_rule_still_grants_is_not_explained() {
        let (removed, known) = one("a", member(11, 15, None, "UTC", "2026-11-15T00:10:00Z"));
        assert!(judge_removals(&removed, &known, &today_rule(), at(NOW)).is_err());
    }

    #[test]
    fn the_end_of_a_birthday_week_is_explained() {
        // Birthday 13 Nov: inside "the coming week" from 7 Nov to 13 Nov.
        let (removed, known) = one("a", member(11, 13, None, "UTC", "2026-11-10T08:00:00Z"));
        assert_eq!(
            judge_removals(&removed, &known, &week_rule(), at(NOW)),
            Ok(1)
        );
    }

    #[test]
    fn a_rule_edit_is_left_to_the_owner() {
        // Given the role when they turned 18 under "age 18 or over"; the rule
        // is now "21 or over", which would not have given it to them then.
        let adult21 = rule(
            r#"{"groups":[{"conditions":[{"value":21,"target":"age_years","operator":"gte"}]}],"grant_on_any_birthday":false}"#,
        );
        let (removed, known) = one("a", member(3, 1, Some(2008), "UTC", "2026-03-01T10:00:00Z"));
        let why = judge_removals(&removed, &known, &adult21, at(NOW)).unwrap_err();
        assert!(why.contains("rule edited"), "{why}");
    }

    #[test]
    fn a_member_without_a_birthday_is_left_to_the_owner() {
        let known = HashMap::from([(
            "a".to_string(),
            RemovedMember {
                assigned_at: at("2026-11-14T09:00:00Z"),
                birthday: None,
            },
        )]);
        assert!(judge_removals(&["a".to_string()], &known, &today_rule(), at(NOW)).is_err());
        // Nor one with no assignment on record at all.
        assert!(judge_removals(&["b".to_string()], &known, &today_rule(), at(NOW)).is_err());
    }

    #[test]
    fn grant_on_any_birthday_never_removes_for_the_calendar() {
        let any = rule(r#"{"groups":[],"grant_on_any_birthday":true}"#);
        let (removed, known) = one("a", member(11, 14, None, "UTC", "2026-11-14T09:00:00Z"));
        assert!(judge_removals(&removed, &known, &any, at(NOW)).is_err());
    }

    #[test]
    fn one_unexplained_removal_holds_the_whole_write() {
        let mut known = HashMap::new();
        known.insert(
            "a".to_string(),
            member(11, 14, None, "UTC", "2026-11-14T09:00:00Z"),
        );
        known.insert(
            "b".to_string(),
            member(11, 15, None, "UTC", "2026-11-15T00:10:00Z"),
        );
        let removed = vec!["a".to_string(), "b".to_string()];
        assert!(judge_removals(&removed, &known, &today_rule(), at(NOW)).is_err());
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn held<'a>(
        previous: u64,
        next: u64,
        current: &'a [String],
        qualifying: &'a [String],
        members: &'a [String],
        tree: &'a RuleTree,
    ) -> Held<'a> {
        Held {
            previous,
            next,
            current,
            qualifying,
            member_ids: members,
            tree,
        }
    }

    #[test]
    fn the_removed_members_are_the_ones_dropped_from_our_last_list() {
        let tree = today_rule();
        let current = ids(&["a", "b", "c"]);
        let qualifying = ids(&["c", "d"]);
        let members = ids(&["a", "b", "c", "d", "e"]);
        let h = held(3, 2, &current, &qualifying, &members, &tree);
        assert_eq!(removals_to_explain(&h), Ok(ids(&["a", "b"])));
    }

    #[test]
    fn a_list_rolelogic_counts_differently_is_not_ours_to_judge() {
        let tree = today_rule();
        let current = ids(&["a"]);
        let empty: Vec<String> = vec![];
        let members = ids(&["a"]);
        assert!(removals_to_explain(&held(2, 0, &current, &empty, &members, &tree)).is_err());
        assert!(removals_to_explain(&held(1, 1, &current, &empty, &members, &tree)).is_err());
    }

    #[test]
    fn a_member_missing_from_the_member_list_is_left_to_the_owner() {
        // They may have left, or the gateway's list may have come back short.
        let tree = today_rule();
        let current = ids(&["a", "b"]);
        let empty: Vec<String> = vec![];
        let members = ids(&["b"]);
        let why = removals_to_explain(&held(2, 0, &current, &empty, &members, &tree)).unwrap_err();
        assert!(why.contains("not on the server's member list"), "{why}");
    }

    #[test]
    fn too_many_removals_are_left_to_the_owner() {
        let tree = today_rule();
        let current: Vec<String> = (0..=SELF_CONFIRM_MAX).map(|i| format!("{i:03}")).collect();
        let empty: Vec<String> = vec![];
        let n = current.len() as u64;
        let h = held(n, 0, &current, &empty, &current, &tree);
        assert!(removals_to_explain(&h).is_err());
        let fewer = &current[..SELF_CONFIRM_MAX];
        let h = held(fewer.len() as u64, 0, fewer, &empty, fewer, &tree);
        assert_eq!(
            removals_to_explain(&h).map(|r| r.len()),
            Ok(SELF_CONFIRM_MAX)
        );
    }
}
