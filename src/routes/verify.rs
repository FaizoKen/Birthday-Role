//! Member-facing flow: sign in with Discord, then save your birthday.
//!
//! Routes:
//!   GET  /verify           — landing page (HTML)
//!   POST /verify/login     — redirect to the Auth Gateway Discord login
//!   GET  /verify/status    — JSON status for the page's JS
//!   POST /verify/save      — store / update the caller's birthday
//!   POST /verify/unlink    — delete the caller's birthday
//!
//! Convention 27/36: login uses a *relative* `return_to=`, and the landing
//! page renders an in-page sign-in prompt — it never auto-redirects.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::read_session;
use crate::services::birthday::{self, compute_facts, BirthdayInput};
use crate::services::{csrf, jobs};
use crate::AppState;

const VERIFY_PAGE: &str = include_str!("../../templates/verify.html");

pub async fn verify_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = VERIFY_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[derive(sqlx::FromRow)]
struct StatusRow {
    birth_month: i16,
    birth_day: i16,
    birth_year: Option<i32>,
    tz: String,
    show_year: bool,
}

pub async fn verify_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Value>, AppError> {
    let discord = read_session(&jar, &state.config.session_secret).ok();

    let row: Option<StatusRow> = match &discord {
        Some((did, _)) => {
            sqlx::query_as(
                "SELECT birth_month, birth_day, birth_year, tz, show_year \
                 FROM birthdays WHERE discord_id = $1",
            )
            .bind(did)
            .fetch_optional(&state.pool)
            .await?
        }
        None => None,
    };

    let birthday = row.map(|r| {
        let input = BirthdayInput {
            birth_month: r.birth_month as i32,
            birth_day: r.birth_day as i32,
            birth_year: r.birth_year,
            tz: r.tz.clone(),
        };
        let f = compute_facts(&input);
        json!({
            "month": r.birth_month,
            "day": r.birth_day,
            "year": r.birth_year,
            "tz": r.tz,
            "show_year": r.show_year,
            "zodiac": f.zodiac,
            "chinese_zodiac": f.chinese_zodiac,
            "season": f.season,
            "birthstone": f.birthstone,
            "weekday": f.weekday,
            "age": f.age_years,
            "days_until": f.days_until,
            "is_today": f.is_today,
        })
    });

    Ok(Json(json!({
        "signed_in_discord": discord.is_some(),
        "discord_username": discord.as_ref().map(|(_, n)| n.clone()),
        "has_birthday": birthday.is_some(),
        "birthday": birthday,
    })))
}

pub async fn verify_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // The Auth Gateway only accepts a path for return_to (Convention 27).
    let path = path_only(&state.config.base_url);
    let return_to = format!("{path}/verify");
    let url = format!(
        "{}/auth/login?return_to={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&return_to)
    );
    Redirect::to(&url)
}

fn path_only(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(slash) = base_url[after_scheme..].find('/') {
            return base_url[after_scheme + slash..]
                .trim_end_matches('/')
                .to_string();
        }
    }
    String::new()
}

#[derive(Deserialize)]
pub struct SaveBody {
    pub month: i32,
    pub day: i32,
    #[serde(default)]
    pub year: Option<i32>,
    #[serde(default)]
    pub tz: Option<String>,
    #[serde(default)]
    pub show_year: bool,
}

pub async fn verify_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<SaveBody>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, discord_name) = read_session(&jar, &state.config.session_secret)?;

    birthday::validate_date(body.month, body.day, body.year).map_err(AppError::BadRequest)?;
    let tz = birthday::normalize_tz(body.tz.as_deref().unwrap_or("UTC"));
    let derived = birthday::compute_derived(body.month, body.day, body.year);

    sqlx::query(
        "INSERT INTO birthdays \
            (discord_id, discord_name, birth_month, birth_day, birth_year, tz, show_year, \
             zodiac, chinese_zodiac, season, birthstone, birth_weekday, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now()) \
         ON CONFLICT (discord_id) DO UPDATE SET \
            discord_name   = EXCLUDED.discord_name, \
            birth_month    = EXCLUDED.birth_month, \
            birth_day      = EXCLUDED.birth_day, \
            birth_year     = EXCLUDED.birth_year, \
            tz             = EXCLUDED.tz, \
            show_year      = EXCLUDED.show_year, \
            zodiac         = EXCLUDED.zodiac, \
            chinese_zodiac = EXCLUDED.chinese_zodiac, \
            season         = EXCLUDED.season, \
            birthstone     = EXCLUDED.birthstone, \
            birth_weekday  = EXCLUDED.birth_weekday, \
            updated_at     = now()",
    )
    .bind(&discord_id)
    .bind(&discord_name)
    .bind(body.month as i16)
    .bind(body.day as i16)
    .bind(body.year)
    .bind(&tz)
    .bind(body.show_year)
    .bind(&derived.zodiac)
    .bind(&derived.chinese_zodiac)
    .bind(&derived.season)
    .bind(&derived.birthstone)
    .bind(&derived.birth_weekday)
    .execute(&state.pool)
    .await?;

    // Re-evaluate every role this member could qualify for now.
    jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(
        discord_id = %discord_id,
        month = body.month,
        day = body.day,
        has_year = body.year.is_some(),
        "Birthday saved"
    );

    Ok(Json(json!({ "success": true })))
}

pub async fn verify_unlink(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    let removed = sqlx::query("DELETE FROM birthdays WHERE discord_id = $1")
        .bind(&discord_id)
        .execute(&state.pool)
        .await?;

    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound("No saved birthday to remove.".into()));
    }

    // With the birthday gone the member qualifies for nothing — player_sync
    // strips the roles via RoleLogic and clears role_assignments.
    jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(discord_id = %discord_id, "Birthday removed");

    Ok(Json(json!({ "success": true })))
}
