//! Sync engine — per-player (lightweight) and per-role-link (bulk).
//!
//! Dispatch targets for jobs claimed by [`crate::tasks::job_worker`].
//!
//! Convention 38: guild membership comes from the Auth Gateway
//! `/auth/internal/*`, never a local JOIN. Convention 40: gateway HTTP
//! failures bubble up (the worker retries) — we never clear a role on a
//! transient lookup failure. Convention 47: a RoleLinkNotFound deletes the
//! orphan local row instead of retrying forever.

use std::collections::HashSet;

use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::rule::RuleTree;
use crate::services::birthday::{compute_facts, BirthdayInput};
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
        Err(_) => (0, 100),
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

    match rl
        .upload_users(guild_id, role_id, &qualifying, &api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
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

    match state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, &state.pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
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
