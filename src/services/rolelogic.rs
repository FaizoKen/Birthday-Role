use std::time::Duration;

use crate::error::AppError;

/// Hard cap for a single `PUT /users` request (server-side limit).
const PUT_MAX_USERS: usize = 100_000;
/// Per-chunk cap for the chunked upload flow (server-side limit).
const CHUNK_SIZE: usize = 100_000;
/// Per-request timeout for a single chunk POST.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-request timeout for the commit POST.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Body substring RoleLogic returns when our token isn't found server-side.
/// Convention 47: this signals the role link was deleted upstream; the caller
/// must clean up the local row, not retry forever.
const RL_LINK_GONE_ERROR_MSG: &str = "Invalid or revoked token";
/// Body substring RoleLogic returns when the role link exists but its owner
/// toggled it off. NOT a deletion (that is `RL_LINK_GONE_ERROR_MSG`): leave the
/// link + config intact and skip syncing it this cycle instead of erroring and
/// retrying forever. Source: `role-link-token.guard.ts`.
const RL_LINK_DISABLED_ERROR_MSG: &str = "This role link is disabled";
/// Body prefix RoleLogic returns when the link is beyond the guild's
/// integration-slot quota (e.g. after a plan downgrade). Every endpoint rejects
/// it exactly like a disabled link until the owner upgrades or frees a slot, so
/// it maps to the same skip-this-cycle outcome.
const RL_LINK_PAUSED_ERROR_MSG: &str = "This role link is paused";
/// `errors.error` RoleLogic returns (409) when a list write would remove a
/// quarter or more of the link's users (at least 10), or empty it. The write is
/// held until the owner confirms it in the dashboard (or marks the link as a
/// trusted integration); resending the same list afterwards goes through.
const RL_CONFIRM_REQUIRED_ERROR: &str = "confirm_required";

/// Map the link-state rejections every role-link endpoint shares (deleted,
/// disabled, paused) to their typed errors. `None` means the caller should
/// fall through to its own handling.
fn link_state_error(status: reqwest::StatusCode, body: &str) -> Option<AppError> {
    if status != reqwest::StatusCode::FORBIDDEN {
        return None;
    }
    if body.contains(RL_LINK_GONE_ERROR_MSG) {
        return Some(AppError::RoleLinkNotFound);
    }
    if body.contains(RL_LINK_DISABLED_ERROR_MSG) || body.contains(RL_LINK_PAUSED_ERROR_MSG) {
        return Some(AppError::RoleLinkDisabled);
    }
    None
}

/// Detect the 409 shrink hold on `PUT /users` / upload commit.
fn shrink_held_error(status: reqwest::StatusCode, body: &str) -> Option<AppError> {
    if status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let errors = &parsed["errors"];
    if errors["error"].as_str() != Some(RL_CONFIRM_REQUIRED_ERROR) {
        return None;
    }
    Some(AppError::RoleLinkRemovalHeld {
        previous: errors["previous"].as_u64().unwrap_or(0),
        next: errors["next"].as_u64().unwrap_or(0),
    })
}

#[derive(Clone)]
pub struct RoleLogicClient {
    http: reqwest::Client,
    base_url: String,
}

impl RoleLogicClient {
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get user count and limit for a role link.
    pub async fn get_user_info(
        &self,
        guild_id: &str,
        role_id: &str,
        token: &str,
    ) -> Result<(usize, usize), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Some(e) = link_state_error(status, &body) {
                return Err(e);
            }
            return Err(AppError::RoleLogic(format!(
                "Get user info failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        let user_count = body["data"]["user_count"].as_u64().unwrap_or(0) as usize;
        let user_limit = body["data"]["user_limit"].as_u64().unwrap_or(100) as usize;

        Ok((user_count, user_limit))
    }

    pub async fn add_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if let Some(e) = link_state_error(status, &body) {
                return Err(e);
            }

            if (status == reqwest::StatusCode::BAD_REQUEST
                || status == reqwest::StatusCode::FORBIDDEN)
                && body.contains("limit")
            {
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let limit = parsed["data"]["user_limit"].as_u64().unwrap_or(100) as usize;
                return Err(AppError::UserLimitReached { limit });
            }

            return Err(AppError::RoleLogic(format!(
                "Add user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["added"].as_bool().unwrap_or(false))
    }

    pub async fn remove_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Some(e) = link_state_error(status, &body) {
                return Err(e);
            }
            return Err(AppError::RoleLogic(format!(
                "Remove user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["removed"].as_bool().unwrap_or(false))
    }

    /// Replace the full user set in a single atomic `PUT /users` request.
    /// Server rejects anything over `PUT_MAX_USERS`. For larger sets, callers
    /// should use [`upload_users`] which routes to the chunked flow.
    pub async fn replace_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Some(e) = link_state_error(status, &body) {
                return Err(e);
            }
            if let Some(e) = shrink_held_error(status, &body) {
                return Err(e);
            }
            return Err(AppError::RoleLogic(format!(
                "Replace users failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// High-level user-set upload. Picks the right transport for the size:
    /// - `len <= 100_000`: single atomic `PUT /users`.
    /// - `len > 100_000`: chunked flow (init → chunks → commit).
    ///
    /// Returns the deduped `user_count` reported by the server.
    pub async fn upload_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        if user_ids.len() <= PUT_MAX_USERS {
            return self.replace_users(guild_id, role_id, user_ids, token).await;
        }

        let total = user_ids.len();
        tracing::info!(
            guild_id,
            role_id,
            total,
            "Bulk user set exceeds PUT cap; using chunked upload"
        );

        let upload_id = self.start_upload(guild_id, role_id, token).await?;
        let chunk_count = user_ids.chunks(CHUNK_SIZE).count();

        for (i, chunk) in user_ids.chunks(CHUNK_SIZE).enumerate() {
            if let Err(e) = self
                .upload_chunk(guild_id, role_id, &upload_id, chunk, token)
                .await
            {
                tracing::error!(
                    guild_id,
                    role_id,
                    upload_id,
                    chunk_idx = i,
                    chunk_count,
                    "Chunk upload failed; cancelling session: {e}"
                );
                if let Err(cancel_err) = self
                    .cancel_upload(guild_id, role_id, &upload_id, token)
                    .await
                {
                    tracing::warn!(
                        guild_id,
                        role_id,
                        upload_id,
                        "Cancel after chunk failure also failed: {cancel_err}"
                    );
                }
                return Err(e);
            }
        }

        // A failed commit (notably a 409 shrink hold) keeps the staged users
        // server-side. We resend the full list next cycle anyway, so drop it.
        let final_count = match self
            .commit_upload(guild_id, role_id, &upload_id, token)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                if let Err(cancel_err) = self
                    .cancel_upload(guild_id, role_id, &upload_id, token)
                    .await
                {
                    tracing::warn!(
                        guild_id,
                        role_id,
                        upload_id,
                        "Cancel after commit failure also failed: {cancel_err}"
                    );
                }
                return Err(e);
            }
        };
        tracing::info!(
            guild_id,
            role_id,
            upload_id,
            chunks = chunk_count,
            final_count,
            "Chunked upload committed"
        );
        Ok(final_count)
    }

    /// Step 1: open a chunked-upload session. Returns the `upload_id`.
    pub async fn start_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        token: &str,
    ) -> Result<String, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Some(e) = link_state_error(status, &body) {
                return Err(e);
            }
            return Err(AppError::RoleLogic(format!(
                "Start upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        body["data"]["upload_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AppError::RoleLogic("Start upload response missing upload_id".into()))
    }

    /// Step 2: append a chunk (≤ `CHUNK_SIZE` user IDs) to an open session.
    pub async fn upload_chunk(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/chunk",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(CHUNK_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Upload chunk failed: {status} - {body}"
            )));
        }

        Ok(())
    }

    /// Step 3: commit a chunked upload. Server dedupes across chunks and
    /// atomically swaps in the new user set. Returns the final user_count.
    pub async fn commit_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/commit",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(COMMIT_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if let Some(e) =
                link_state_error(status, &body).or_else(|| shrink_held_error(status, &body))
            {
                return Err(e);
            }
            return Err(AppError::RoleLogic(format!(
                "Commit upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// Cancel an open upload session (best-effort cleanup on failure).
    pub async fn cancel_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Cancel upload failed: {status} - {body}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn paused_link_maps_to_disabled() {
        let body = r#"{"errors":"This role link is paused — integration slots quota exceeded. Upgrade for more integration slots or delete other role links."}"#;
        assert!(matches!(
            link_state_error(StatusCode::FORBIDDEN, body),
            Some(AppError::RoleLinkDisabled)
        ));
    }

    #[test]
    fn gone_and_disabled_links_classified() {
        assert!(matches!(
            link_state_error(
                StatusCode::FORBIDDEN,
                r#"{"errors":"Invalid or revoked token"}"#
            ),
            Some(AppError::RoleLinkNotFound)
        ));
        assert!(matches!(
            link_state_error(
                StatusCode::FORBIDDEN,
                r#"{"errors":"This role link is disabled"}"#
            ),
            Some(AppError::RoleLinkDisabled)
        ));
        assert!(link_state_error(StatusCode::BAD_REQUEST, "This role link is paused").is_none());
    }

    #[test]
    fn shrink_hold_detected() {
        let body = r#"{"errors":{"error":"confirm_required","code":"shrink","change_id":"8f0c","previous":1200,"next":300,"removals":900,"message":"..."},"requestId":"x"}"#;
        assert!(matches!(
            shrink_held_error(StatusCode::CONFLICT, body),
            Some(AppError::RoleLinkRemovalHeld {
                previous: 1200,
                next: 300
            })
        ));
        assert!(shrink_held_error(StatusCode::CONFLICT, r#"{"errors":"other"}"#).is_none());
        assert!(shrink_held_error(StatusCode::BAD_REQUEST, body).is_none());
    }
}
