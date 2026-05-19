//! Public "birthdays" listing — every member of this guild who saved a
//! birthday, with the calendar facts and a countdown to their next one.
//!
//! Gated by `guild_settings.view_permission`:
//!   * 'disabled' — nobody
//!   * 'managers' — Manage-Server only
//!   * 'members'  — any member of the guild
//!
//! Privacy: the year/age is only included when the member opted in
//! (`show_year`). Convention 36: on 401 the page renders an in-page "Login
//! with Discord" prompt — it never auto-redirects.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::{extract_bearer, guild_members, guild_permission, require_guild_admin};
use crate::services::birthday::{compute_facts, BirthdayInput};
use crate::services::csrf;
use crate::AppState;

const USERS_PAGE: &str = include_str!("../../templates/users.html");

pub async fn users_page(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
) -> impl IntoResponse {
    let html = USERS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{GUILD_ID}}", &guild_id);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[derive(sqlx::FromRow)]
struct UserRow {
    discord_id: String,
    discord_name: Option<String>,
    birth_month: i16,
    birth_day: i16,
    birth_year: Option<i32>,
    tz: String,
    show_year: bool,
    zodiac: String,
    chinese_zodiac: Option<String>,
    season: String,
    birthstone: String,
}

pub async fn users_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    if view_permission == "disabled" {
        return Err(AppError::Forbidden(
            "The birthdays page is disabled for this server.".into(),
        ));
    }

    let perm = guild_permission(&state, &jar, &guild_id).await?;
    if !perm.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if view_permission == "managers" && !perm.is_manager {
        return Err(AppError::Forbidden(
            "This list is visible to server managers only.".into(),
        ));
    }

    // "Who is in this guild" comes from the Auth Gateway (BLUEPRINT §16.3),
    // never a local table. One user-cookie call returns the member filter
    // and the guild name.
    let (member_ids, guild_name) = guild_members(&state, &jar, &guild_id).await?;

    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT discord_id, discord_name, birth_month, birth_day, birth_year, tz, \
                show_year, zodiac, chinese_zodiac, season, birthstone \
         FROM birthdays \
         WHERE discord_id = ANY($1) \
         ORDER BY birth_month, birth_day \
         LIMIT 2000",
    )
    .bind(&member_ids)
    .fetch_all(&state.pool)
    .await?;

    let users = rows
        .into_iter()
        .map(|r| {
            let f = compute_facts(&BirthdayInput {
                birth_month: r.birth_month as i32,
                birth_day: r.birth_day as i32,
                birth_year: r.birth_year,
                tz: r.tz.clone(),
            });
            // Privacy: only expose the year/age when the member opted in.
            let (year, age) = if r.show_year {
                (r.birth_year, f.age_years)
            } else {
                (None, None)
            };
            json!({
                "discord_id": r.discord_id,
                "discord_name": r.discord_name,
                "month": r.birth_month,
                "day": r.birth_day,
                "year": year,
                "age": age,
                "zodiac": r.zodiac,
                "chinese_zodiac": r.chinese_zodiac,
                "season": r.season,
                "birthstone": r.birthstone,
                "days_until": f.days_until,
                "is_today": f.is_today,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "guild_id": guild_id,
        "guild_name": guild_name,
        "count": users.len(),
        "users": users,
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/view-permission  (manager-only)
// ---------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ViewPermBody {
    pub view_permission: String,
}

pub async fn set_view_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<ViewPermBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let vp = match body.view_permission.as_str() {
        "disabled" | "managers" | "members" => body.view_permission.as_str(),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}' (expected disabled|managers|members)."
            )))
        }
    };

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) DO UPDATE SET view_permission = EXCLUDED.view_permission, \
                                              updated_at = now()",
    )
    .bind(&guild_id)
    .bind(vp)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "success": true, "view_permission": vp })))
}
