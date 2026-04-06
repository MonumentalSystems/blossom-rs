//! LFS Lock API endpoints (BUD-19).
//!
//! Implements the Git LFS lock protocol over HTTP:
//! - `POST /lfs/{repo_id}/locks` — create lock
//! - `GET /lfs/{repo_id}/locks` — list locks
//! - `POST /lfs/{repo_id}/locks/verify` — verify locks
//! - `POST /lfs/{repo_id}/locks/{id}/unlock` — unlock

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::{error_json, extract_auth_event, verify_auth_event, SharedState};
use crate::access::{Action, Role};
use crate::locks::{LockFilters, LockRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LfsOwner {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LfsLock {
    id: String,
    path: String,
    locked_at: String,
    owner: LfsOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateLockRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct CreateLockResponse {
    lock: LfsLock,
}

#[derive(Debug, Serialize)]
struct LockListResponse {
    locks: Vec<LfsLock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    ours: Vec<LfsLock>,
    theirs: Vec<LfsLock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UnlockRequest {
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Deserialize)]
struct ListQueryParams {
    path: Option<String>,
    id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ConflictResponse {
    lock: LfsLock,
    message: String,
}

fn lock_record_to_lfs(record: &LockRecord) -> LfsLock {
    let locked_at = format_unix_timestamp(record.locked_at);

    LfsLock {
        id: record.id.clone(),
        path: record.path.clone(),
        locked_at,
        owner: LfsOwner {
            name: record.pubkey.clone(),
        },
    }
}

fn format_unix_timestamp(secs: u64) -> String {
    use std::time::UNIX_EPOCH;
    let duration = std::time::Duration::from_secs(secs);
    let datetime = UNIX_EPOCH + duration;
    let secs_since_epoch = datetime
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days_since_epoch = secs_since_epoch / 86400;
    let time_of_day = secs_since_epoch % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_date(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    let mut remaining = days;

    loop {
        let year_len = if is_leap_year(y) { 366 } else { 365 };
        if remaining < year_len {
            break;
        }
        remaining -= year_len;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut m = 0;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        m += 1;
    }

    (y, m + 1, remaining + 1)
}

fn is_leap_year(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn lock_not_configured() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        error_json("lock support not configured"),
    )
}

pub fn locks_router(state: SharedState) -> Router {
    Router::new()
        .route(
            "/lfs/{repo_id}/locks",
            post(handle_create_lock).get(handle_list_locks),
        )
        .route("/lfs/{repo_id}/locks/verify", post(handle_verify_locks))
        .route("/lfs/{repo_id}/locks/{lock_id}/unlock", post(handle_unlock))
        .with_state(state)
}

#[instrument(name = "lfs.locks.create", skip_all, fields(lfs.repo = %repo_id))]
async fn handle_create_lock(
    State(state): State<SharedState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateLockRequest>,
) -> impl IntoResponse {
    let event = match extract_auth_event(&headers) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, error_json(&e.to_string())),
    };
    if let Err(e) = verify_auth_event(&event, Some("lock")) {
        return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
    }
    let pubkey = event.pubkey;

    let mut s = state.lock().await;

    if !s.access.is_allowed(&pubkey, Action::Lock) {
        return (StatusCode::FORBIDDEN, error_json("lock not allowed"));
    }

    let lock_db = match s.lock_db.as_mut() {
        Some(db) => db,
        None => return lock_not_configured(),
    };

    match lock_db.create_lock(&repo_id, &body.path, &pubkey) {
        Ok(record) => {
            let lfs_lock = lock_record_to_lfs(&record);
            (
                StatusCode::CREATED,
                Json(
                    serde_json::to_value(CreateLockResponse { lock: lfs_lock }).unwrap_or_default(),
                ),
            )
        }
        Err(crate::locks::LockError::Conflict(existing_id)) => {
            if let Ok(existing) = lock_db.get_lock(&repo_id, &existing_id) {
                let lfs_lock = lock_record_to_lfs(&existing);
                let resp = ConflictResponse {
                    lock: lfs_lock,
                    message: "path already locked".to_string(),
                };
                (
                    StatusCode::CONFLICT,
                    Json(serde_json::to_value(resp).unwrap_or_default()),
                )
            } else {
                (StatusCode::CONFLICT, error_json("path already locked"))
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

#[instrument(name = "lfs.locks.list", skip_all, fields(lfs.repo = %repo_id))]
async fn handle_list_locks(
    State(state): State<SharedState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<ListQueryParams>,
) -> impl IntoResponse {
    let event = match extract_auth_event(&headers) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, error_json(&e.to_string())),
    };
    if let Err(e) = verify_auth_event(&event, Some("lock")) {
        return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
    }

    let s = state.lock().await;

    let lock_db = match s.lock_db.as_ref() {
        Some(db) => db,
        None => return lock_not_configured(),
    };

    let filters = LockFilters {
        path: params.path,
        id: params.id,
        cursor: params.cursor,
        limit: params.limit,
    };

    match lock_db.list_locks(&repo_id, &filters) {
        Ok((records, next_cursor)) => {
            let locks: Vec<LfsLock> = records.iter().map(lock_record_to_lfs).collect();
            let resp = LockListResponse { locks, next_cursor };
            (
                StatusCode::OK,
                Json(serde_json::to_value(resp).unwrap_or_default()),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

#[instrument(name = "lfs.locks.verify", skip_all, fields(lfs.repo = %repo_id))]
async fn handle_verify_locks(
    State(state): State<SharedState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    let event = match extract_auth_event(&headers) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, error_json(&e.to_string())),
    };
    if let Err(e) = verify_auth_event(&event, Some("lock")) {
        return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
    }
    let pubkey = event.pubkey;

    let s = state.lock().await;

    let lock_db = match s.lock_db.as_ref() {
        Some(db) => db,
        None => return lock_not_configured(),
    };

    let filters = LockFilters {
        cursor: body.cursor,
        limit: body.limit,
        ..Default::default()
    };

    match lock_db.list_locks(&repo_id, &filters) {
        Ok((records, next_cursor)) => {
            let mut ours = Vec::new();
            let mut theirs = Vec::new();

            for record in records {
                let lfs_lock = lock_record_to_lfs(&record);
                if record.pubkey == pubkey {
                    ours.push(lfs_lock);
                } else {
                    theirs.push(lfs_lock);
                }
            }

            let resp = VerifyResponse {
                ours,
                theirs,
                next_cursor,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(resp).unwrap_or_default()),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}

#[instrument(name = "lfs.locks.unlock", skip_all, fields(lfs.repo = %repo_id, lfs.lock_id = %lock_id))]
async fn handle_unlock(
    State(state): State<SharedState>,
    Path((repo_id, lock_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<UnlockRequest>,
) -> impl IntoResponse {
    let event = match extract_auth_event(&headers) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, error_json(&e.to_string())),
    };
    if let Err(e) = verify_auth_event(&event, Some("lock")) {
        return (StatusCode::UNAUTHORIZED, error_json(&e.to_string()));
    }
    let pubkey = event.pubkey;

    let mut s = state.lock().await;

    let is_admin = s.access.role(&pubkey) == Role::Admin;

    let lock_db = match s.lock_db.as_mut() {
        Some(db) => db,
        None => return lock_not_configured(),
    };

    let force = body.force || is_admin;

    match lock_db.delete_lock(&repo_id, &lock_id, force, &pubkey) {
        Ok(record) => {
            let lfs_lock = lock_record_to_lfs(&record);
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(CreateLockResponse { lock: lfs_lock }).unwrap_or_default(),
                ),
            )
        }
        Err(crate::locks::LockError::NotFound) => {
            (StatusCode::NOT_FOUND, error_json("lock not found"))
        }
        Err(crate::locks::LockError::Forbidden(msg)) => (StatusCode::FORBIDDEN, error_json(&msg)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(&e.to_string()),
        ),
    }
}
