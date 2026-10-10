//! Bonny: a private JSON HTTP API over a Turso database.
//!
//! Callers never send SQL. Every statement is generated here from validated identifiers and a
//! small structured operation model, and every value is passed as a bind parameter.
//!
//! The file is organized top to bottom as: configuration, errors, value/identifier policy,
//! database layer (`Db` plus schema introspection), request plans and operations, HTTP
//! handlers and middleware, and `main`. The tests live in `src/tests.rs`.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    path::Path,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Query, Request, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Number, Value as JsonValue, json};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};
use tracing::{error, info, warn};
use turso::{Connection, Value as DbValue, params_from_iter, transaction::TransactionBehavior};

// ---------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------

const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_BATCH_STEPS: usize = 20;
const DEFAULT_MAX_BATCH_ROWS: usize = 5_000;
const DEFAULT_MAX_BATCH_VALUES: usize = 100_000;
const MAX_COLUMNS: usize = 100;
const MAX_INDEX_COLUMNS: usize = 32;
const MAX_IDENT_LEN: usize = 64;
const DEFAULT_QUERY_ROWS: u32 = 100;
const MAX_QUERY_ROWS: u32 = 500;
const MAX_QUERY_OFFSET: u32 = 1_000_000;
/// Cap on bound values in one query's filters (mainly guards huge `in` lists).
const MAX_QUERY_PARAMS: usize = 1_000;
const MIN_API_KEY_LEN: usize = 32;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How many times a batch is re-run after losing a write-write conflict before giving up (409).
const MAX_WRITE_ATTEMPTS: u32 = 10;
const SHUTDOWN_PUSH_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

struct ReplicaConfig {
    url: String,
    auth_token: String,
}

/// Request-size limits, configurable through environment variables (see `Config`).
///
/// The batch limits apply to a whole `POST /v1/batch` request, summed over all its steps, so a
/// multi-table request cannot grow the transaction beyond what a single batch could.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// `MAX_BODY_BYTES`: request body size; larger bodies get 413.
    max_body_bytes: usize,
    /// `MAX_BATCH_STEPS`: entries in `batches`.
    max_batch_steps: usize,
    /// `MAX_BATCH_ROWS`: rows in total across all steps.
    max_batch_rows: usize,
    /// `MAX_BATCH_VALUES`: individual values (rows x columns) in total across all steps.
    max_batch_values: usize,
    /// `MAX_DELETE_ROWS`: most rows one `/v1/delete` request may remove; `None` (the default)
    /// means no limit. A delete that would remove more is rolled back.
    max_delete_rows: Option<usize>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_batch_steps: DEFAULT_MAX_BATCH_STEPS,
            max_batch_rows: DEFAULT_MAX_BATCH_ROWS,
            max_batch_values: DEFAULT_MAX_BATCH_VALUES,
            max_delete_rows: None,
        }
    }
}

/// File-IO engine for the local database (`IO_BACKEND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoMode {
    /// The crate's platform default.
    Default,
    /// Plain blocking syscalls (pread/pwrite/fsync) on the calling thread.
    Syscall,
    /// Linux `io_uring`: requests are submitted to the kernel and completed asynchronously.
    IoUring,
}

impl IoMode {
    fn parse(input: &str) -> Result<Self, String> {
        match input.trim().to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "syscall" => Ok(Self::Syscall),
            "io_uring" => Ok(Self::IoUring),
            other => Err(format!(
                "IO_BACKEND must be one of default, syscall, io_uring (got {other:?})"
            )),
        }
    }

    fn backend(self) -> turso::IoBackend {
        match self {
            Self::Default => turso::IoBackend::Default,
            Self::Syscall => turso::IoBackend::Syscall,
            Self::IoUring => turso::IoBackend::IoUring,
        }
    }
}

struct Config {
    /// `None` disables authentication (only allowed on a loopback address).
    api_key: Option<String>,
    listen_addr: SocketAddr,
    local_path: String,
    io_mode: IoMode,
    /// `Some` selects embedded-replica mode; `None` is local-only.
    replica: Option<ReplicaConfig>,
    /// Background push+pull period in replica mode; `None` disables the worker.
    sync_interval: Option<Duration>,
    request_timeout: Duration,
    max_concurrent_requests: usize,
    limits: Limits,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let non_empty = |key: &str| get(key).filter(|v| !v.trim().is_empty());
        let number = |key: &str, default: u64| -> Result<u64, String> {
            match non_empty(key) {
                None => Ok(default),
                Some(v) => v
                    .trim()
                    .parse()
                    .map_err(|_| format!("{key} must be a non-negative integer")),
            }
        };

        // Unset means "no authentication". A variable that is set but blank is almost certainly
        // a misconfigured secret, so it is an error rather than a silent switch-off.
        let api_key = match get("API_KEY") {
            None => None,
            Some(key) if key.trim().is_empty() => {
                return Err("API_KEY is set but empty; unset it to disable authentication".into());
            }
            Some(key) => {
                if key.len() < MIN_API_KEY_LEN {
                    return Err(format!(
                        "API_KEY must be at least {MIN_API_KEY_LEN} characters"
                    ));
                }
                let first = key.chars().next().unwrap_or_default();
                if key.chars().all(|c| c == first) {
                    return Err("API_KEY is too weak (a single repeated character)".into());
                }
                Some(key)
            }
        };

        let listen_addr: SocketAddr = non_empty("LISTEN_ADDR")
            .unwrap_or_else(|| "127.0.0.1:3000".into())
            .parse()
            .map_err(|_| "LISTEN_ADDR must be a socket address such as 127.0.0.1:3000")?;
        if api_key.is_none() && !listen_addr.ip().is_loopback() {
            return Err(format!(
                "refusing to listen on {listen_addr} without authentication; set API_KEY or bind to a loopback address"
            ));
        }

        let local_path = non_empty("TURSO_LOCAL_PATH").unwrap_or_else(|| "bonny.db".into());

        let io_mode = non_empty("IO_BACKEND")
            .map(|v| IoMode::parse(&v))
            .transpose()?
            .unwrap_or(IoMode::Default);

        let replica = match non_empty("TURSO_DATABASE_URL") {
            None => None,
            Some(url) => Some(ReplicaConfig {
                url,
                auth_token: non_empty("TURSO_AUTH_TOKEN")
                    .ok_or("TURSO_AUTH_TOKEN is required when TURSO_DATABASE_URL is set")?,
            }),
        };

        let sync_secs = number("SYNC_INTERVAL_SECS", 30)?;
        let sync_interval =
            (replica.is_some() && sync_secs > 0).then(|| Duration::from_secs(sync_secs));

        let timeout_secs = number("REQUEST_TIMEOUT_SECS", 30)?;
        if timeout_secs == 0 {
            return Err("REQUEST_TIMEOUT_SECS must be greater than zero".into());
        }
        let max_concurrent_requests = number("MAX_CONCURRENT_REQUESTS", 64)? as usize;
        if max_concurrent_requests == 0 {
            return Err("MAX_CONCURRENT_REQUESTS must be greater than zero".into());
        }

        if replica.is_some() && io_mode != IoMode::Default {
            return Err(
                "IO_BACKEND is only supported in local mode; the replica builder has no IO option"
                    .into(),
            );
        }

        let limit = |key: &str, default: usize| -> Result<usize, String> {
            let value = usize::try_from(number(key, default as u64)?)
                .map_err(|_| format!("{key} is too large"))?;
            if value == 0 {
                return Err(format!("{key} must be greater than zero"));
            }
            Ok(value)
        };
        let defaults = Limits::default();
        let limits = Limits {
            max_body_bytes: limit("MAX_BODY_BYTES", defaults.max_body_bytes)?,
            max_batch_steps: limit("MAX_BATCH_STEPS", defaults.max_batch_steps)?,
            max_batch_rows: limit("MAX_BATCH_ROWS", defaults.max_batch_rows)?,
            max_batch_values: limit("MAX_BATCH_VALUES", defaults.max_batch_values)?,
            // Unset means unlimited; when set it must be a positive number.
            max_delete_rows: match non_empty("MAX_DELETE_ROWS") {
                Some(_) => Some(limit("MAX_DELETE_ROWS", 1)?),
                None => None,
            },
        };

        Ok(Self {
            api_key,
            listen_addr,
            local_path,
            io_mode,
            replica,
            sync_interval,
            request_timeout: Duration::from_secs(timeout_secs),
            max_concurrent_requests,
            limits,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("request body too large")]
    PayloadTooLarge,
    #[error("content-type must be application/json")]
    UnsupportedMediaType,
    #[error("too many concurrent requests")]
    TooManyRequests,
    #[error("{0}")]
    NotImplemented(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("write conflict with a concurrent transaction; nothing was written, retry the request")]
    WriteConflict,
    #[error("{0}")]
    TooManyRows(String),
    #[error("{0}")]
    LossyConversion(String),
    #[error("request timed out")]
    Timeout,
    #[error("database operation failed")]
    Database,
    #[error("internal server error")]
    Internal,
}

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
            Self::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "not_implemented"),
            Self::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::WriteConflict => (StatusCode::CONFLICT, "write_conflict"),
            Self::TooManyRows(_) => (StatusCode::CONFLICT, "too_many_rows"),
            Self::LossyConversion(_) => (StatusCode::CONFLICT, "lossy_conversion"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let mut response = (
            status,
            Json(json!({ "error": self.to_string(), "code": code })),
        )
            .into_response();
        if matches!(self, Self::TooManyRequests) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Maps a driver error to a client-safe error. Details are logged, never returned.
fn db_err(error: turso::Error) -> ApiError {
    if is_write_conflict(&error) {
        return ApiError::WriteConflict;
    }
    match error {
        turso::Error::Constraint(detail) => {
            warn!(%detail, "constraint violation");
            ApiError::Conflict("constraint violation".into())
        }
        turso::Error::Busy(detail) | turso::Error::BusySnapshot(detail) => {
            warn!(%detail, "database busy");
            ApiError::Unavailable("database is busy, retry shortly".into())
        }
        other => {
            error!(error = %other, "database operation failed");
            ApiError::Database
        }
    }
}

/// Whether the error means "another transaction got there first" (MVCC first-committer-wins, or
/// the schema changed under the transaction). The driver reports these through its generic
/// error variants, so the message has to be inspected. The whole transaction is already aborted
/// when this happens, and re-running it on a new connection is safe.
fn is_write_conflict(error: &turso::Error) -> bool {
    match error {
        turso::Error::BusySnapshot(_) => true,
        turso::Error::Error(message) | turso::Error::Busy(message) => {
            let message = message.to_ascii_lowercase();
            message.contains("write-write conflict") || message.contains("schema conflict")
        }
        _ => false,
    }
}

/// JSON body extractor that reports failures through [`ApiError`] so every error is JSON.
struct ApiJson<T>(T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge,
                StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::UnsupportedMediaType,
                _ => ApiError::BadRequest(rejection.body_text()),
            }),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Identifiers and values
// ---------------------------------------------------------------------------------------------

/// A validated SQL identifier. Identifiers cannot be bound parameters, so they are restricted
/// to `[A-Za-z_][A-Za-z0-9_]*` and always emitted double-quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ident(String);

impl Ident {
    fn parse(what: &str, input: &str) -> ApiResult<Self> {
        let mut chars = input.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
            && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
            && input.len() <= MAX_IDENT_LEN;
        if !valid {
            let shown: String = input.chars().take(MAX_IDENT_LEN).collect();
            return Err(ApiError::bad(format!(
                "invalid {what} name {shown:?}: must match [A-Za-z_][A-Za-z0-9_]* and be at most {MAX_IDENT_LEN} characters"
            )));
        }
        let lower = input.to_ascii_lowercase();
        if lower.starts_with("sqlite_")
            || lower.starts_with("turso_")
            || lower.starts_with("__turso")
        {
            return Err(ApiError::bad(format!(
                "invalid {what} name {input:?}: the sqlite_, turso_ and __turso prefixes are reserved"
            )));
        }
        Ok(Self(input.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

/// Parses a list of identifiers, rejecting duplicates (SQLite names are case-insensitive).
fn parse_idents(what: &str, names: &[String], max: usize) -> ApiResult<Vec<Ident>> {
    if names.len() > max {
        return Err(ApiError::bad(format!(
            "at most {max} {what} names are allowed"
        )));
    }
    let mut seen = HashSet::new();
    names
        .iter()
        .map(|name| {
            let ident = Ident::parse(what, name)?;
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(ApiError::bad(format!("duplicate {what} name {name:?}")));
            }
            Ok(ident)
        })
        .collect()
}

fn quoted_list(idents: &[Ident]) -> String {
    idents
        .iter()
        .map(Ident::quoted)
        .collect::<Vec<_>>()
        .join(", ")
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// JSON → SQLite. See the README for the full policy.
fn db_value(value: &JsonValue) -> Result<DbValue, String> {
    match value {
        JsonValue::Null => Ok(DbValue::Null),
        JsonValue::Bool(b) => Ok(DbValue::Integer(i64::from(*b))),
        JsonValue::String(s) => Ok(DbValue::Text(s.clone())),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Ok(DbValue::Integer(i));
            }
            // With `arbitrary_precision` the original literal is preserved, so an integer
            // literal that does not fit i64 can be told apart from a float and rejected
            // instead of silently losing precision.
            let literal = n.to_string();
            if literal.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                return Err("integer is outside the signed 64-bit range".into());
            }
            match n.as_f64() {
                Some(f) if f.is_finite() => Ok(DbValue::Real(f)),
                _ => Err("number is not a finite 64-bit float".into()),
            }
        }
        JsonValue::Object(map) => blob_from_tagged(map),
        JsonValue::Array(_) => {
            Err("arrays are not SQL values; send them as a JSON-encoded string".into())
        }
    }
}

fn blob_from_tagged(map: &Map<String, JsonValue>) -> Result<DbValue, String> {
    const HINT: &str = "objects are not SQL values; use {\"$type\":\"blob\",\"base64\":\"...\"} for blobs or send a JSON-encoded string";
    let is_blob = map.len() == 2 && map.get("$type").and_then(JsonValue::as_str) == Some("blob");
    let Some(encoded) = map
        .get("base64")
        .and_then(JsonValue::as_str)
        .filter(|_| is_blob)
    else {
        return Err(HINT.into());
    };
    BASE64
        .decode(encoded)
        .map(DbValue::Blob)
        .map_err(|_| "blob base64 is invalid".into())
}

/// SQLite → JSON. Blobs become tagged objects; non-finite reals (not representable) become null.
fn json_value(value: DbValue) -> JsonValue {
    match value {
        DbValue::Null => JsonValue::Null,
        DbValue::Integer(i) => JsonValue::Number(Number::from(i)),
        DbValue::Real(f) => Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number),
        DbValue::Text(s) => JsonValue::String(s),
        DbValue::Blob(bytes) => json!({ "$type": "blob", "base64": BASE64.encode(bytes) }),
    }
}

// ---------------------------------------------------------------------------------------------
// Database layer
// ---------------------------------------------------------------------------------------------

enum Backend {
    Local(turso::Database),
    Replica(turso::sync::Database),
}

#[derive(Default, Clone)]
struct SyncState {
    last_push_unix: Option<u64>,
    last_pull_unix: Option<u64>,
    last_error: Option<String>,
    last_error_unix: Option<u64>,
    consecutive_failures: u32,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Owns the database handle plus the in-process coordination the driver does not provide.
///
/// * `mvcc`: local databases run in MVCC mode, where batches use `BEGIN CONCURRENT` and many
///   write transactions proceed in parallel; conflicting ones are detected at commit and retried.
///   Replica databases stay in WAL mode, where SQLite allows one writer at a time.
/// * `write_lock` serializes DDL (schema changes need an exclusive transaction), and in WAL mode
///   also batch writes so they queue instead of racing for the single write lock. In MVCC mode
///   batches never take it. Reads never take it.
/// * `sync_lock` ensures only one push or pull runs at a time.
struct Db {
    backend: Backend,
    mvcc: bool,
    write_lock: tokio::sync::Mutex<()>,
    sync_lock: tokio::sync::Mutex<()>,
    sync_state: Mutex<SyncState>,
}

impl Db {
    fn new(backend: Backend, mvcc: bool) -> Self {
        Self {
            backend,
            mvcc,
            write_lock: tokio::sync::Mutex::new(()),
            sync_lock: tokio::sync::Mutex::new(()),
            sync_state: Mutex::new(SyncState::default()),
        }
    }

    /// Opens (creating if needed) a local database and puts it into MVCC mode. The mode is
    /// stored in the file, so an existing WAL-mode database is converted on first start and
    /// later starts find it already set.
    async fn open_local(path: &str, io_mode: IoMode) -> Result<Self, String> {
        ensure_parent_dir(path)?;
        let db = turso::Builder::new_local(path)
            .with_io(io_mode.backend())
            .build()
            .await
            .map_err(|e| format!("failed to open local database {path}: {e}"))?;
        enable_mvcc(&db)
            .await
            .map_err(|e| format!("failed to enable MVCC mode on {path}: {e}"))?;
        Ok(Self::new(Backend::Local(db), true))
    }

    async fn open_replica(path: &str, replica: &ReplicaConfig) -> Result<Self, String> {
        ensure_parent_dir(path)?;
        let db = turso::sync::Builder::new_remote(path)
            .with_remote_url(&replica.url)
            .with_auth_token(&replica.auth_token)
            .bootstrap_if_empty(true)
            .build()
            .await
            .map_err(|e| format!("failed to open embedded replica {path}: {e}"))?;
        // The sync engine manages the replica's journal; its MVCC support has not been verified,
        // so replicas keep the default mode and serialized writes.
        Ok(Self::new(Backend::Replica(db), false))
    }

    fn is_replica(&self) -> bool {
        matches!(self.backend, Backend::Replica(_))
    }

    fn mode(&self) -> &'static str {
        if self.is_replica() {
            "replica"
        } else {
            "local"
        }
    }

    /// Every request gets its own connection; connections are cheap and not shared.
    async fn connect(&self) -> Result<Connection, turso::Error> {
        let conn = match &self.backend {
            Backend::Local(db) => db.connect()?,
            Backend::Replica(db) => db.connect().await?,
        };
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // SQLite-compatible engines leave foreign keys unenforced until this is switched on, and
        // the setting belongs to the connection, so every new connection has to do it.
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        Ok(conn)
    }

    fn replica(&self) -> ApiResult<&turso::sync::Database> {
        match &self.backend {
            Backend::Replica(db) => Ok(db),
            Backend::Local(_) => Err(ApiError::NotImplemented(
                "sync is only available in embedded-replica mode (set TURSO_DATABASE_URL)".into(),
            )),
        }
    }

    fn record_sync(&self, op: &str, result: &Result<(), turso::Error>) {
        let mut state = self.sync_state.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(()) => {
                let now = unix_now();
                match op {
                    "push" => state.last_push_unix = Some(now),
                    _ => state.last_pull_unix = Some(now),
                }
                state.consecutive_failures = 0;
                state.last_error = None;
            }
            Err(e) => {
                state.consecutive_failures += 1;
                state.last_error = Some(format!("{op}: {e}"));
                state.last_error_unix = Some(unix_now());
            }
        }
    }

    fn sync_snapshot(&self) -> SyncState {
        self.sync_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn push(&self) -> ApiResult<()> {
        let db = self.replica()?;
        let _guard = self.sync_lock.lock().await;
        let result = db.push().await;
        self.record_sync("push", &result);
        result.map_err(db_err)
    }

    /// Returns whether remote changes were applied.
    async fn pull(&self) -> ApiResult<bool> {
        let db = self.replica()?;
        let _guard = self.sync_lock.lock().await;
        let result = db.pull().await;
        self.record_sync("pull", &result.as_ref().map(|_| ()).map_err(clone_err));
        result.map_err(db_err)
    }
}

/// `turso::Error` is not `Clone`; only the message matters for sync bookkeeping.
fn clone_err(error: &turso::Error) -> turso::Error {
    turso::Error::Error(error.to_string())
}

fn ensure_parent_dir(path: &str) -> Result<(), String> {
    match Path::new(path).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create directory {}: {e}", parent.display())),
        _ => Ok(()),
    }
}

async fn journal_mode(conn: &Connection) -> Result<String, turso::Error> {
    let (_, rows) = fetch_all(conn, "PRAGMA journal_mode", vec![]).await?;
    Ok(rows.first().map(|r| text_at(r, 0)).unwrap_or_default())
}

async fn enable_mvcc(db: &turso::Database) -> Result<(), String> {
    let conn = db.connect().map_err(|e| e.to_string())?;
    if journal_mode(&conn).await.map_err(|e| e.to_string())? != "mvcc" {
        conn.pragma_update("journal_mode", "'mvcc'")
            .await
            .map_err(|e| e.to_string())?;
    }
    match journal_mode(&conn)
        .await
        .map_err(|e| e.to_string())?
        .as_str()
    {
        "mvcc" => Ok(()),
        other => Err(format!("journal_mode is {other:?} after enabling MVCC")),
    }
}

/// Runs database work on its own task so that a client disconnect or request timeout cannot
/// cancel it halfway (for example in the middle of a transaction).
async fn spawn_db<T, F>(work: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: Future<Output = ApiResult<T>> + Send + 'static,
{
    match tokio::spawn(work).await {
        Ok(result) => result,
        Err(join_error) => {
            error!(error = %join_error, "database task failed");
            Err(ApiError::Internal)
        }
    }
}

async fn fetch_all(
    conn: &Connection,
    sql: &str,
    params: Vec<DbValue>,
) -> Result<(Vec<String>, Vec<Vec<DbValue>>), turso::Error> {
    let mut rows = conn.query(sql, params_from_iter(params)).await?;
    let names = rows.column_names();
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(
            (0..names.len())
                .map(|i| row.get_value(i))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok((names, out))
}

fn text_at(row: &[DbValue], idx: usize) -> String {
    row.get(idx)
        .and_then(|v| v.as_text().cloned())
        .unwrap_or_default()
}

fn int_at(row: &[DbValue], idx: usize) -> i64 {
    row.get(idx)
        .and_then(|v| v.as_integer().copied())
        .unwrap_or(0)
}

#[derive(Debug)]
struct ColumnInfo {
    name: String,
    decl_type: String,
    not_null: bool,
    /// 1-based position within the primary key, 0 if not part of it.
    pk: i64,
    /// The column's `DEFAULT` expression, if it has one.
    default: Option<String>,
}

#[derive(Debug)]
struct TableInfo {
    columns: Vec<ColumnInfo>,
}

impl TableInfo {
    fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| eq_ci(&c.name, name))
    }

    fn primary_key(&self) -> Vec<String> {
        let mut pk: Vec<&ColumnInfo> = self.columns.iter().filter(|c| c.pk > 0).collect();
        pk.sort_by_key(|c| c.pk);
        pk.into_iter().map(|c| c.name.clone()).collect()
    }
}

/// Returns `None` when the table does not exist.
async fn load_table(conn: &Connection, table: &Ident) -> ApiResult<Option<TableInfo>> {
    let sql = format!("PRAGMA table_info({})", table.quoted());
    let (_, rows) = fetch_all(conn, &sql, vec![]).await.map_err(db_err)?;
    if rows.is_empty() {
        return Ok(None);
    }
    // Columns: cid, name, type, notnull, dflt_value, pk
    let columns = rows
        .iter()
        .map(|row| ColumnInfo {
            name: text_at(row, 1),
            decl_type: text_at(row, 2).to_ascii_uppercase(),
            not_null: int_at(row, 3) != 0,
            pk: int_at(row, 5),
            default: row.get(4).and_then(|v| v.as_text().cloned()),
        })
        .collect();
    Ok(Some(TableInfo { columns }))
}

async fn require_table(conn: &Connection, table: &Ident) -> ApiResult<TableInfo> {
    load_table(conn, table)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("table {:?} does not exist", table.as_str())))
}

fn require_columns(info: &TableInfo, table: &Ident, columns: &[&Ident]) -> ApiResult<()> {
    for column in columns {
        if !info.has_column(column.as_str()) {
            return Err(ApiError::bad(format!(
                "table {:?} has no column {:?}",
                table.as_str(),
                column.as_str()
            )));
        }
    }
    Ok(())
}

/// Returns `(type, table)` of any schema object with this name (names are case-insensitive and
/// shared between tables and indexes).
async fn schema_object(conn: &Connection, name: &str) -> ApiResult<Option<(String, String)>> {
    let (_, rows) = fetch_all(
        conn,
        "SELECT type, tbl_name FROM sqlite_schema WHERE lower(name) = lower(?1)",
        vec![DbValue::Text(name.to_owned())],
    )
    .await
    .map_err(db_err)?;
    Ok(rows.first().map(|r| (text_at(r, 0), text_at(r, 1))))
}

/// A name from the catalog, quoted for use as an identifier (embedded quotes doubled).
fn quote_name(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// One row of `PRAGMA foreign_key_list`: a column of a foreign key. A composite key has one row
/// per column, all sharing the same `id`.
struct ForeignKeyRow {
    id: i64,
    from: String,
    table: String,
    /// Empty when the key was declared without naming the referenced column.
    to: String,
    on_update: String,
    on_delete: String,
}

async fn foreign_key_rows_of(conn: &Connection, table: &str) -> ApiResult<Vec<ForeignKeyRow>> {
    let sql = format!("PRAGMA foreign_key_list({})", quote_name(table));
    let (_, rows) = fetch_all(conn, &sql, vec![]).await.map_err(db_err)?;
    // Columns: id, seq, table, from, to, on_update, on_delete, match
    Ok(rows
        .iter()
        .map(|r| ForeignKeyRow {
            id: int_at(r, 0),
            from: text_at(r, 3),
            table: text_at(r, 2),
            to: text_at(r, 4),
            on_update: text_at(r, 5),
            on_delete: text_at(r, 6),
        })
        .collect())
}

async fn foreign_key_rows(conn: &Connection, table: &Ident) -> ApiResult<Vec<ForeignKeyRow>> {
    foreign_key_rows_of(conn, table.as_str()).await
}

/// A foreign key of another table that points at a column of a given table.
struct Referrer {
    child_table: String,
    child_column: String,
    parent_column: String,
}

/// Every foreign key, in any table, that references `table`.
async fn referencing_keys(conn: &Connection, table: &Ident) -> ApiResult<Vec<Referrer>> {
    let (_, names) = fetch_all(
        conn,
        "SELECT name FROM sqlite_schema WHERE type = 'table'",
        vec![],
    )
    .await
    .map_err(db_err)?;
    let mut referrers = Vec::new();
    for row in &names {
        let child = text_at(row, 0);
        for key in foreign_key_rows_of(conn, &child).await? {
            if eq_ci(&key.table, table.as_str()) {
                referrers.push(Referrer {
                    child_table: child.clone(),
                    child_column: key.from,
                    parent_column: key.to,
                });
            }
        }
    }
    Ok(referrers)
}

/// `(column, referenced table, referenced column)` of every foreign key of a table, lowercased.
async fn load_foreign_keys(
    conn: &Connection,
    table: &Ident,
) -> ApiResult<Vec<(String, String, String)>> {
    Ok(foreign_key_rows(conn, table)
        .await?
        .into_iter()
        .map(|r| {
            (
                r.from.to_ascii_lowercase(),
                r.table.to_ascii_lowercase(),
                r.to.to_ascii_lowercase(),
            )
        })
        .collect())
}

struct IndexInfo {
    name: String,
    unique: bool,
    partial: bool,
    /// `c`: `CREATE INDEX`; `u`: a UNIQUE constraint; `pk`: the primary key.
    origin: String,
}

async fn list_indexes(conn: &Connection, table: &Ident) -> ApiResult<Vec<IndexInfo>> {
    let sql = format!("PRAGMA index_list({})", table.quoted());
    let (_, rows) = fetch_all(conn, &sql, vec![]).await.map_err(db_err)?;
    // Columns: seq, name, unique, origin, partial
    Ok(rows
        .iter()
        .map(|r| IndexInfo {
            name: text_at(r, 1),
            unique: int_at(r, 2) != 0,
            partial: int_at(r, 4) != 0,
            origin: text_at(r, 3),
        })
        .collect())
}

async fn index_columns(conn: &Connection, index_name: &str) -> ApiResult<Vec<String>> {
    // Index names come from the catalog or a validated identifier; escape quotes regardless.
    let sql = format!("PRAGMA index_info(\"{}\")", index_name.replace('"', "\"\""));
    let (_, rows) = fetch_all(conn, &sql, vec![]).await.map_err(db_err)?;
    // Columns: seqno, cid, name
    Ok(rows.iter().map(|r| text_at(r, 2)).collect())
}

/// Column sets (lowercased, sorted) that identify a row uniquely: the primary key and every
/// non-partial unique index. These are the valid `ON CONFLICT` targets.
async fn unique_keys(
    conn: &Connection,
    table: &Ident,
    info: &TableInfo,
) -> ApiResult<Vec<Vec<String>>> {
    let normalize = |cols: Vec<String>| {
        let mut cols: Vec<String> = cols.into_iter().map(|c| c.to_ascii_lowercase()).collect();
        cols.sort();
        cols
    };
    let mut keys = Vec::new();
    let pk = info.primary_key();
    if !pk.is_empty() {
        keys.push(normalize(pk));
    }
    for index in list_indexes(conn, table).await? {
        if index.unique && !index.partial {
            keys.push(normalize(index_columns(conn, &index.name).await?));
        }
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------------------------
// POST /v1/tables
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColumnDef {
    name: String,
    #[serde(rename = "type")]
    data_type: String,
    #[serde(default)]
    nullable: bool,
    /// Makes the column a foreign key: a table name (referencing its `id` column), or
    /// `{"table": "...", "column": "..."}`.
    #[serde(default)]
    references: Option<JsonValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTable {
    name: String,
    columns: Vec<ColumnDef>,
    /// Omitted or `true`: an automatic `id INTEGER PRIMARY KEY` column. `false`: no primary key.
    /// An array of column names: an explicit (possibly composite) key over the given columns.
    #[serde(default)]
    primary_key: Option<JsonValue>,
}

/// The type of the column another table's foreign key points at, and whether that column is
/// unique on its own (a primary key, or covered by a unique index).
async fn parent_column(
    conn: &Connection,
    reference: &ForeignKey,
    what: &str,
) -> ApiResult<(String, bool)> {
    let info = load_table(conn, &reference.table).await?.ok_or_else(|| {
        ApiError::bad(format!(
            "{what}, but table {:?} does not exist; create it first",
            reference.table.as_str()
        ))
    })?;
    let parent = info
        .columns
        .iter()
        .find(|c| eq_ci(&c.name, reference.column.as_str()))
        .ok_or_else(|| {
            let hint = if reference.column_defaulted {
                format!(
                    "; name the referenced column with {{\"table\": {:?}, \"column\": ...}}",
                    reference.table.as_str()
                )
            } else {
                String::new()
            };
            ApiError::bad(format!(
                "{what}, but table {:?} has no column {:?}{hint}",
                reference.table.as_str(),
                reference.column.as_str()
            ))
        })?;
    let wanted = vec![reference.column.as_str().to_ascii_lowercase()];
    let unique = unique_keys(conn, &reference.table, &info)
        .await?
        .contains(&wanted);
    Ok((parent.decl_type.clone(), unique))
}

fn check_reference_types(
    what: &str,
    unique: bool,
    parent_type: &str,
    child_type: &str,
) -> ApiResult<()> {
    if !unique {
        return Err(ApiError::bad(format!(
            "{what}, which is not unique: a foreign key must point at the table's primary key or at a column with a unique index"
        )));
    }
    if parent_type != child_type {
        return Err(ApiError::bad(format!(
            "{what}, but the types differ ({child_type} vs {parent_type}); a foreign key column must have the same type as the column it references"
        )));
    }
    Ok(())
}

/// One of the five column types the API allows, spelled in capitals (input is case-insensitive).
fn parse_sql_type(column: &str, input: &str) -> ApiResult<&'static str> {
    match input.to_ascii_uppercase().as_str() {
        "INTEGER" => Ok("INTEGER"),
        "REAL" => Ok("REAL"),
        "TEXT" => Ok("TEXT"),
        "BLOB" => Ok("BLOB"),
        "NUMERIC" => Ok("NUMERIC"),
        _ => Err(ApiError::bad(format!(
            "unsupported type for column {column:?}: expected INTEGER, REAL, TEXT, BLOB or NUMERIC"
        ))),
    }
}

/// The column a foreign key points at.
#[derive(Debug, Clone)]
struct ForeignKey {
    table: Ident,
    column: Ident,
    /// The column was not named in the request and defaulted to `id`; only used for hints.
    column_defaulted: bool,
}

const DEFAULT_REFERENCED_COLUMN: &str = "id";

/// Parses `references`: `"stocks"` (the `id` column) or `{"table": "stocks", "column": "code"}`.
fn parse_reference(column: &str, value: &JsonValue) -> ApiResult<ForeignKey> {
    let shape = || {
        ApiError::bad(format!(
            "references of column {column:?} must be a table name, or an object like {{\"table\": \"stocks\", \"column\": \"id\"}}"
        ))
    };
    let (table, referenced) = match value {
        JsonValue::String(table) => (table.as_str(), None),
        JsonValue::Object(map) => {
            if let Some(unknown) = map
                .keys()
                .find(|k| !matches!(k.as_str(), "table" | "column"))
            {
                return Err(ApiError::bad(format!(
                    "references of column {column:?} has an unknown field {unknown:?}; allowed fields: table, column"
                )));
            }
            let table = map
                .get("table")
                .and_then(JsonValue::as_str)
                .ok_or_else(shape)?;
            let referenced = match map.get("column") {
                None => None,
                Some(JsonValue::String(name)) => Some(name.as_str()),
                Some(_) => return Err(shape()),
            };
            (table, referenced)
        }
        _ => return Err(shape()),
    };
    Ok(ForeignKey {
        table: Ident::parse("referenced table", table)?,
        column: Ident::parse(
            "referenced column",
            referenced.unwrap_or(DEFAULT_REFERENCED_COLUMN),
        )?,
        column_defaulted: referenced.is_none(),
    })
}

struct PlannedColumn {
    name: Ident,
    sql_type: &'static str,
    nullable: bool,
    references: Option<ForeignKey>,
}

/// How the table's primary key is defined.
#[derive(Debug)]
enum KeyPlan {
    /// An `id INTEGER PRIMARY KEY` column is added in front of the requested columns. SQLite
    /// assigns the id of every inserted row that does not supply one (1, 2, 3, ...).
    ///
    /// `AUTOINCREMENT` is deliberately not used: it makes every insert update one shared counter
    /// row, so concurrent writers conflict with each other under MVCC (measured: 535 conflicts
    /// for 1,600 inserts by 8 writers, against none without it). Its only extra guarantee, never
    /// reusing the id of a deleted row, is irrelevant while Bonny has no delete operation.
    AutoId,
    /// No primary key at all.
    None,
    /// An explicit key over columns of the request.
    Columns(Vec<Ident>),
}

const AUTO_ID_COLUMN: &str = "id";

struct TablePlan {
    name: Ident,
    /// The requested columns (without the automatic `id`).
    columns: Vec<PlannedColumn>,
    key: KeyPlan,
}

fn key_spec_error(detail: &str) -> ApiError {
    ApiError::bad(format!(
        "primary_key {detail}: use an array of column names, false for no primary key, or omit it for an automatic integer id"
    ))
}

/// Interprets the `primary_key` field: `None` (omitted/null) and `true` mean the automatic id.
fn parse_key_spec(value: Option<&JsonValue>) -> ApiResult<Option<Vec<String>>> {
    match value {
        None | Some(JsonValue::Bool(true)) => Ok(Some(Vec::new())),
        Some(JsonValue::Bool(false)) => Ok(None),
        Some(JsonValue::Array(items)) if items.is_empty() => {
            Err(key_spec_error("must not be an empty array"))
        }
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| key_spec_error("must contain only column names (strings)"))
            })
            .collect::<ApiResult<Vec<_>>>()
            .map(Some),
        Some(_) => Err(key_spec_error("has an unsupported value")),
    }
}

impl TablePlan {
    fn from_request(req: CreateTable) -> ApiResult<Self> {
        let name = Ident::parse("table", &req.name)?;
        if req.columns.is_empty() || req.columns.len() > MAX_COLUMNS {
            return Err(ApiError::bad(format!(
                "a table must have between 1 and {MAX_COLUMNS} columns"
            )));
        }
        let column_names: Vec<String> = req.columns.iter().map(|c| c.name.clone()).collect();
        let idents = parse_idents("column", &column_names, MAX_COLUMNS)?;

        let columns = req
            .columns
            .iter()
            .zip(idents)
            .map(|(def, name)| {
                let sql_type = parse_sql_type(&def.name, &def.data_type)?;
                let references = def
                    .references
                    .as_ref()
                    .map(|value| parse_reference(&def.name, value))
                    .transpose()?;
                Ok(PlannedColumn {
                    name,
                    sql_type,
                    nullable: def.nullable,
                    references,
                })
            })
            .collect::<ApiResult<Vec<_>>>()?;

        let key = match parse_key_spec(req.primary_key.as_ref())? {
            None => KeyPlan::None,
            Some(keys) if keys.is_empty() => {
                if columns
                    .iter()
                    .any(|c| eq_ci(c.name.as_str(), AUTO_ID_COLUMN))
                {
                    return Err(ApiError::bad(format!(
                        "column {AUTO_ID_COLUMN:?} clashes with the automatic primary key; remove it, \
                         or set \"primary_key\" explicitly (an array of column names, or false for no primary key)"
                    )));
                }
                KeyPlan::AutoId
            }
            Some(keys) => {
                let key = parse_idents("primary key column", &keys, MAX_COLUMNS)?;
                for column in &key {
                    match columns
                        .iter()
                        .find(|c| eq_ci(c.name.as_str(), column.as_str()))
                    {
                        None => {
                            return Err(ApiError::bad(format!(
                                "primary key references unknown column {:?}",
                                column.as_str()
                            )));
                        }
                        Some(found) if found.nullable => {
                            return Err(ApiError::bad(format!(
                                "primary key column {:?} must not be nullable",
                                column.as_str()
                            )));
                        }
                        Some(_) => {}
                    }
                }
                KeyPlan::Columns(key)
            }
        };
        Ok(Self { name, columns, key })
    }

    fn create_sql(&self) -> String {
        let mut parts = Vec::new();
        if matches!(self.key, KeyPlan::AutoId) {
            parts.push(format!("\"{AUTO_ID_COLUMN}\" INTEGER PRIMARY KEY"));
        }
        parts.extend(self.columns.iter().map(|c| {
            let not_null = if c.nullable { "" } else { " NOT NULL" };
            format!("{} {}{not_null}", c.name.quoted(), c.sql_type)
        }));
        if let KeyPlan::Columns(key) = &self.key {
            parts.push(format!("PRIMARY KEY ({})", quoted_list(key)));
        }
        for column in &self.columns {
            if let Some(reference) = &column.references {
                parts.push(format!(
                    "FOREIGN KEY ({}) REFERENCES {} ({})",
                    column.name.quoted(),
                    reference.table.quoted(),
                    reference.column.quoted()
                ));
            }
        }
        format!("CREATE TABLE {} ({})", self.name.quoted(), parts.join(", "))
    }

    /// The foreign keys as `(column, referenced table, referenced column)`, lowercased and
    /// sorted, for comparing with what an existing table has.
    fn foreign_keys(&self) -> Vec<(String, String, String)> {
        let mut keys: Vec<_> = self
            .columns
            .iter()
            .filter_map(|c| {
                c.references.as_ref().map(|r| {
                    (
                        c.name.as_str().to_ascii_lowercase(),
                        r.table.as_str().to_ascii_lowercase(),
                        r.column.as_str().to_ascii_lowercase(),
                    )
                })
            })
            .collect();
        keys.sort();
        keys
    }

    /// For a foreign key that points at the table being created: the referenced column's type
    /// and whether it is this table's sole primary key (the only unique column it will have).
    fn own_column(&self, name: &Ident) -> Option<(String, bool)> {
        if matches!(self.key, KeyPlan::AutoId) && eq_ci(name.as_str(), AUTO_ID_COLUMN) {
            return Some(("INTEGER".to_owned(), true));
        }
        let column = self
            .columns
            .iter()
            .find(|c| eq_ci(c.name.as_str(), name.as_str()))?;
        let sole_key = matches!(&self.key, KeyPlan::Columns(key)
            if key.len() == 1 && eq_ci(key[0].as_str(), name.as_str()));
        Some((column.sql_type.to_owned(), sole_key))
    }

    /// Checks every foreign key against the live schema before anything is created: the
    /// referenced table must already exist (or be this table), the referenced column must be
    /// unique on its own, and both columns must have the same type. The engine would accept a
    /// reference to a missing table and only fail later, on the first insert.
    ///
    /// `siblings` are all the tables of the same request: a foreign key may point at any of them,
    /// whatever their order, and is then checked against the sibling's definition instead of the
    /// database (which does not have the table yet).
    async fn validate_references(
        &self,
        conn: &Connection,
        siblings: &[TablePlan],
    ) -> ApiResult<()> {
        for column in &self.columns {
            let Some(reference) = &column.references else {
                continue;
            };
            let what = format!(
                "column {:?} references {}.{}",
                column.name.as_str(),
                reference.table.as_str(),
                reference.column.as_str()
            );
            let (parent_type, unique) = if eq_ci(reference.table.as_str(), self.name.as_str()) {
                self.own_column(&reference.column).ok_or_else(|| {
                    ApiError::bad(format!(
                        "{what}, but this table has no column {:?}",
                        reference.column.as_str()
                    ))
                })?
            } else if let Some(sibling) = siblings
                .iter()
                .find(|t| eq_ci(t.name.as_str(), reference.table.as_str()))
            {
                sibling.own_column(&reference.column).ok_or_else(|| {
                    ApiError::bad(format!(
                        "{what}, but table {:?} has no column {:?}",
                        reference.table.as_str(),
                        reference.column.as_str()
                    ))
                })?
            } else {
                parent_column(conn, reference, &what).await?
            };
            check_reference_types(&what, unique, &parent_type, column.sql_type)?;
        }
        Ok(())
    }

    /// Whether an existing table has exactly the requested definition.
    fn matches(&self, existing: &TableInfo) -> bool {
        let key: &[Ident] = match &self.key {
            KeyPlan::Columns(key) => key,
            _ => &[],
        };
        // (name, type, expected NOT NULL or "don't care", position in the primary key or 0)
        let mut expected: Vec<(&str, &str, Option<bool>, i64)> = Vec::new();
        if matches!(self.key, KeyPlan::AutoId) {
            // A rowid alias: NOT NULL is not reported for it, and either spelling behaves alike.
            expected.push((AUTO_ID_COLUMN, "INTEGER", None, 1));
        }
        for column in &self.columns {
            let position = key
                .iter()
                .position(|k| eq_ci(k.as_str(), column.name.as_str()))
                .map_or(0, |p| p as i64 + 1);
            expected.push((
                column.name.as_str(),
                column.sql_type,
                Some(!column.nullable),
                position,
            ));
        }
        expected.len() == existing.columns.len()
            && expected.iter().zip(&existing.columns).all(|(want, have)| {
                eq_ci(want.0, &have.name)
                    && want.1 == have.decl_type
                    && want.2.is_none_or(|not_null| not_null == have.not_null)
                    && want.3 == have.pk
            })
    }
}

/// Creates one table inside the caller's transaction. Returns whether it was created (`false`
/// means an identical table already existed).
///
/// `CREATE TABLE IF NOT EXISTS` is deliberately not used: it would accept an existing table with
/// a different shape. The definition is compared instead and a mismatch is a 409.
async fn ensure_table_in(
    conn: &Connection,
    plan: &TablePlan,
    siblings: &[TablePlan],
) -> Result<bool, Failure> {
    if let Some(existing) = load_table(conn, &plan.name).await? {
        let mut have = load_foreign_keys(conn, &plan.name).await?;
        have.sort();
        return if plan.matches(&existing) && have == plan.foreign_keys() {
            Ok(false)
        } else {
            Err(conflict(format!(
                "table {:?} already exists with a different definition",
                plan.name.as_str()
            )))
        };
    }
    if schema_object(conn, plan.name.as_str()).await?.is_some() {
        return Err(conflict(format!(
            "name {:?} is already used by another schema object",
            plan.name.as_str()
        )));
    }
    plan.validate_references(conn, siblings).await?;
    ddl(conn, &plan.create_sql()).await?;
    Ok(true)
}

/// The tables of one `POST /v1/tables` request.
struct CreateJob {
    plans: Vec<TablePlan>,
    /// Whether the body used `{"tables": [...]}`; only then are errors prefixed with the table.
    envelope: bool,
}

/// The multi-table body. Each element is checked as a [`CreateTable`] on its own, so that an
/// error can say which one it was.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTables {
    tables: Vec<JsonValue>,
}

const MAX_TABLES_PER_REQUEST: usize = 50;

fn annotate_table(error: ApiError, index: usize, name: &str, envelope: bool) -> ApiError {
    if !envelope {
        return error;
    }
    let prefix = format!("tables[{index}] (table {name:?}): ");
    match error {
        ApiError::BadRequest(message) => ApiError::BadRequest(prefix + &message),
        ApiError::NotFound(message) => ApiError::NotFound(prefix + &message),
        ApiError::Conflict(message) => ApiError::Conflict(prefix + &message),
        other => other,
    }
}

/// Parses and validates the whole body before anything touches the database. A body is either one
/// table (`{"name": ..., "columns": ...}`) or `{"tables": [<table>, ...]}`.
fn parse_create_body(body: JsonValue) -> ApiResult<CreateJob> {
    if !body.is_object() {
        return Err(ApiError::bad(
            "the request body must be a JSON object: either one table ({\"name\": ..., \"columns\": ...}) or {\"tables\": [ ... ]}",
        ));
    }
    let invalid = |e: serde_json::Error| ApiError::bad(format!("invalid request body: {e}"));
    let envelope = body.as_object().is_some_and(|o| o.contains_key("tables"));
    let requests: Vec<CreateTable> = if envelope {
        let envelope: CreateTables = serde_json::from_value(body).map_err(invalid)?;
        if envelope.tables.len() > MAX_TABLES_PER_REQUEST {
            return Err(ApiError::bad(format!(
                "a request may create at most {MAX_TABLES_PER_REQUEST} tables (got {})",
                envelope.tables.len()
            )));
        }
        envelope
            .tables
            .into_iter()
            .enumerate()
            .map(|(i, table)| {
                serde_json::from_value(table)
                    .map_err(|e| ApiError::bad(format!("tables[{i}]: {e}")))
            })
            .collect::<ApiResult<_>>()?
    } else {
        vec![serde_json::from_value(body).map_err(invalid)?]
    };

    let mut seen = HashSet::new();
    let mut plans = Vec::with_capacity(requests.len());
    for (i, request) in requests.into_iter().enumerate() {
        let name = request.name.clone();
        let plan =
            TablePlan::from_request(request).map_err(|e| annotate_table(e, i, &name, envelope))?;
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(annotate_table(
                ApiError::bad("the request creates a table with this name more than once"),
                i,
                &name,
                envelope,
            ));
        }
        plans.push(plan);
    }
    Ok(CreateJob { plans, envelope })
}

/// One try, in one transaction: either every table of the request exists afterwards, or none of
/// the new ones does. Returns, per table, whether it was created.
async fn attempt_create_tables(db: &Db, job: &CreateJob) -> Result<Vec<bool>, Failure> {
    let mut conn = db.connect().await.map_err(classify)?;
    let tx = conn.transaction().await.map_err(ddl_failure)?;
    let mut created = Vec::with_capacity(job.plans.len());
    for (i, plan) in job.plans.iter().enumerate() {
        match ensure_table_in(&tx, plan, &job.plans).await {
            Ok(was_created) => created.push(was_created),
            Err(failure) => {
                if let Err(error) = tx.rollback().await {
                    tracing::debug!(%error, "rollback after a failed table creation");
                }
                return Err(match failure {
                    Failure::Api(error) => {
                        Failure::Api(annotate_table(error, i, plan.name.as_str(), job.envelope))
                    }
                    other => other,
                });
            }
        }
    }
    tx.commit().await.map_err(ddl_failure)?;
    Ok(created)
}

async fn create_tables_in(db: &Db, job: CreateJob) -> ApiResult<Vec<(String, bool)>> {
    // Schema changes queue behind each other (and, without MVCC, behind writers).
    let _write = db.write_lock.lock().await;
    let created = with_conflict_retries(|| attempt_create_tables(db, &job)).await?;
    Ok(job
        .plans
        .iter()
        .map(|p| p.name.as_str().to_owned())
        .zip(created)
        .collect())
}

/// Answers `204 No Content` on success: both "created" and "an identical table already existed"
/// leave the database in the requested state, and a body would add nothing. Failures keep the
/// usual JSON error shape.
async fn create_table(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<JsonValue>,
) -> ApiResult<StatusCode> {
    let job = parse_create_body(body)?;
    let db = state.db.clone();
    let results = spawn_db(async move { create_tables_in(&db, job).await }).await?;
    for (table, created) in &results {
        info!(table = table.as_str(), created = *created, "create table");
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// POST /v1/indexes
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateIndex {
    name: String,
    table: String,
    columns: Vec<String>,
    #[serde(default)]
    unique: bool,
}

struct IndexPlan {
    name: Ident,
    table: Ident,
    columns: Vec<Ident>,
    unique: bool,
}

impl IndexPlan {
    fn from_request(req: CreateIndex) -> ApiResult<Self> {
        if req.columns.is_empty() {
            return Err(ApiError::bad(format!(
                "an index must have between 1 and {MAX_INDEX_COLUMNS} columns"
            )));
        }
        Ok(Self {
            name: Ident::parse("index", &req.name)?,
            table: Ident::parse("table", &req.table)?,
            columns: parse_idents("column", &req.columns, MAX_INDEX_COLUMNS)?,
            unique: req.unique,
        })
    }

    fn create_sql(&self) -> String {
        format!(
            "CREATE {}INDEX {} ON {} ({})",
            if self.unique { "UNIQUE " } else { "" },
            self.name.quoted(),
            self.table.quoted(),
            quoted_list(&self.columns)
        )
    }
}

/// Returns `(created, warnings)`. An existing index with the same name is accepted only if it
/// has the same table, uniqueness and column list; otherwise the request is a 409.
async fn ensure_index(db: &Db, plan: &IndexPlan) -> ApiResult<(bool, Vec<String>)> {
    let _write = db.write_lock.lock().await;
    let conn = db.connect().await.map_err(db_err)?;
    let info = require_table(&conn, &plan.table).await?;
    require_columns(&info, &plan.table, &plan.columns.iter().collect::<Vec<_>>())?;

    if let Some((kind, on_table)) = schema_object(&conn, plan.name.as_str()).await? {
        let same_table = eq_ci(&on_table, plan.table.as_str());
        if kind == "index" && same_table {
            let indexes = list_indexes(&conn, &plan.table).await?;
            let existing = indexes.iter().find(|i| eq_ci(&i.name, plan.name.as_str()));
            let existing_columns = index_columns(&conn, plan.name.as_str()).await?;
            let same_columns = existing_columns.len() == plan.columns.len()
                && existing_columns
                    .iter()
                    .zip(&plan.columns)
                    .all(|(a, b)| eq_ci(a, b.as_str()));
            if existing.is_some_and(|i| i.unique == plan.unique && !i.partial) && same_columns {
                return Ok((false, vec![]));
            }
        }
        return Err(ApiError::Conflict(format!(
            "name {:?} is already used by a different schema object or index definition",
            plan.name.as_str()
        )));
    }

    let mut warnings = Vec::new();
    let pk = info.primary_key();
    let wanted: Vec<&str> = plan.columns.iter().map(Ident::as_str).collect();
    let is_prefix = wanted.len() <= pk.len() && wanted.iter().zip(&pk).all(|(a, b)| eq_ci(a, b));
    let redundant = if plan.unique {
        wanted.len() == pk.len() && is_prefix
    } else {
        is_prefix
    };
    if redundant {
        warnings.push(
            "index duplicates the primary key's own index; confirm with a query plan that it is needed".into(),
        );
    }

    conn.execute(&plan.create_sql(), ()).await.map_err(db_err)?;
    Ok((true, warnings))
}

/// Answers `204 No Content` on success (a new index, or an identical one that already existed).
/// Advisory warnings, such as an index that only repeats the primary key's own, go to the
/// server log rather than the response.
async fn create_index(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<CreateIndex>,
) -> ApiResult<StatusCode> {
    let plan = IndexPlan::from_request(req)?;
    let db = state.db.clone();
    let (name, created, warnings) = spawn_db(async move {
        let (created, warnings) = ensure_index(&db, &plan).await?;
        Ok((plan.name, created, warnings))
    })
    .await?;
    info!(index = name.as_str(), created, "create index");
    for warning in &warnings {
        warn!(index = name.as_str(), "{warning}");
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// PATCH /v1/table
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlterTable {
    table: String,
    column: String,
    #[serde(rename = "type")]
    data_type: Option<String>,
    rename: Option<String>,
    /// Only when adding a column. Like `POST /v1/tables`, columns are NOT NULL unless `true`.
    nullable: Option<bool>,
    /// Only when adding a column: a table name, or `{"table": ..., "column": ...}`.
    references: Option<JsonValue>,
    /// Only when adding a column: the value existing rows get.
    default: Option<JsonValue>,
    /// Allow a type conversion that changes some values (see the README).
    #[serde(default)]
    lossy: bool,
}

struct AlterPlan {
    table: Ident,
    column: Ident,
    sql_type: Option<&'static str>,
    rename: Option<Ident>,
    nullable: bool,
    /// Whether the request said anything about `nullable`; it is refused for existing columns.
    nullable_given: bool,
    references: Option<ForeignKey>,
    default: Option<DbValue>,
    lossy: bool,
}

impl AlterPlan {
    fn from_request(req: AlterTable) -> ApiResult<Self> {
        let table = Ident::parse("table", &req.table)?;
        let column = Ident::parse("column", &req.column)?;
        let sql_type = req
            .data_type
            .as_deref()
            .map(|t| parse_sql_type(&req.column, t))
            .transpose()?;
        let rename = req
            .rename
            .as_deref()
            .map(|r| Ident::parse("column", r))
            .transpose()?;
        if sql_type.is_none() && rename.is_none() {
            return Err(ApiError::bad(
                "give a type, a rename, or both: {\"table\": ..., \"column\": ..., \"type\": ..., \"rename\": ...}",
            ));
        }
        if let Some(new_name) = &rename
            && new_name.as_str() != column.as_str()
            && eq_ci(new_name.as_str(), column.as_str())
        {
            return Err(ApiError::bad(
                "rename only changes the letter case of the name, which the database does not support",
            ));
        }
        let references = req
            .references
            .as_ref()
            .map(|value| parse_reference(&req.column, value))
            .transpose()?;
        let default = req
            .default
            .as_ref()
            .map(|value| db_value(value).map_err(|e| ApiError::bad(format!("default: {e}"))))
            .transpose()?;
        Ok(Self {
            table,
            column,
            sql_type,
            rename,
            nullable: req.nullable.unwrap_or(false),
            nullable_given: req.nullable.is_some(),
            references,
            default,
            lossy: req.lossy,
        })
    }
}

#[derive(Debug, Default)]
struct AlterOutcome {
    added: bool,
    retyped: bool,
    renamed: bool,
}

fn refuse(message: impl Into<String>) -> Failure {
    Failure::Api(ApiError::bad(message))
}

fn conflict(message: impl Into<String>) -> Failure {
    Failure::Api(ApiError::Conflict(message.into()))
}

/// Maps an error of a schema-changing statement. The engine's refusals (it names the column or
/// index involved, all of which came from the request) are reported to the client as conflicts.
fn ddl_failure(error: turso::Error) -> Failure {
    if is_write_conflict(&error) || matches!(error, turso::Error::Busy(_)) {
        return Failure::Conflict;
    }
    match error {
        turso::Error::Error(message) if message.starts_with("Parse error") => conflict(format!(
            "the database refused the change: {}; nothing was changed",
            message.trim_start_matches("Parse error: ")
        )),
        turso::Error::Constraint(message) => conflict(format!(
            "the change violates a constraint ({message}); nothing was changed"
        )),
        other => classify(other),
    }
}

async fn ddl(tx: &Connection, sql: &str) -> Result<(), Failure> {
    tx.execute(sql, ()).await.map(|_| ()).map_err(ddl_failure)
}

async fn table_has_rows(tx: &Connection, table: &Ident) -> ApiResult<bool> {
    let sql = format!("SELECT 1 FROM {} LIMIT 1", table.quoted());
    Ok(!fetch_all(tx, &sql, vec![])
        .await
        .map_err(db_err)?
        .1
        .is_empty())
}

async fn row_count(tx: &Connection, table: &str) -> ApiResult<i64> {
    let sql = format!("SELECT count(*) FROM {}", quote_name(table));
    let (_, rows) = fetch_all(tx, &sql, vec![]).await.map_err(db_err)?;
    Ok(rows.first().map_or(0, |r| int_at(r, 0)))
}

/// A table name derived from `base` that nothing uses yet.
async fn free_table_name(tx: &Connection, base: &str) -> ApiResult<String> {
    for n in 0..100 {
        let candidate = if n == 0 {
            base.to_owned()
        } else {
            format!("{base}_{n}")
        };
        if schema_object(tx, &candidate).await?.is_none() {
            return Ok(candidate);
        }
    }
    Err(ApiError::Internal)
}

fn free_column_name(info: &TableInfo, base: &str) -> String {
    (0..100)
        .map(|n| {
            if n == 0 {
                format!("{base}__new")
            } else {
                format!("{base}__new{n}")
            }
        })
        .find(|candidate| !info.has_column(candidate))
        .unwrap_or_else(|| format!("{base}__new_tmp"))
}

/// A `CREATE INDEX` statement of a table, kept so the index can be created again.
struct IndexStatement {
    name: String,
    sql: String,
    columns: Vec<String>,
}

async fn table_index_statements(tx: &Connection, table: &Ident) -> ApiResult<Vec<IndexStatement>> {
    let (_, rows) = fetch_all(
        tx,
        "SELECT name, sql FROM sqlite_schema WHERE type = 'index' AND lower(tbl_name) = lower(?1) AND sql IS NOT NULL ORDER BY name",
        vec![DbValue::Text(table.as_str().to_owned())],
    )
    .await
    .map_err(db_err)?;
    let mut statements = Vec::new();
    for row in &rows {
        let name = text_at(row, 0);
        let columns = index_columns(tx, &name).await?;
        statements.push(IndexStatement {
            name,
            sql: text_at(row, 1),
            columns,
        });
    }
    Ok(statements)
}

/// The SQL predicate that is true for a value which converting to `new` would change, or `None`
/// when every value converts without loss. A value is lossless when converting there and back
/// gives the original back, so `"007"` (leading zeros), `"3.9"` to an integer, and `"abc"`
/// (which would silently become 0) are all caught.
fn lossy_predicate(old: &str, new: &str, c: &str) -> Option<String> {
    match (old, new) {
        ("TEXT", "INTEGER") => Some(format!("CAST(CAST({c} AS INTEGER) AS TEXT) <> {c}")),
        ("TEXT", "REAL") => Some(format!(
            "CAST(CAST({c} AS REAL) AS TEXT) <> {c} AND CAST(CAST(CAST({c} AS REAL) AS INTEGER) AS TEXT) <> {c}"
        )),
        ("INTEGER", "REAL") => Some(format!("CAST(CAST({c} AS REAL) AS INTEGER) <> {c}")),
        ("REAL", "INTEGER") => Some(format!("CAST(CAST({c} AS INTEGER) AS REAL) <> {c}")),
        _ => None, // anything to TEXT
    }
}

fn sample(value: &DbValue) -> String {
    match value {
        DbValue::Text(text) => {
            let shown: String = text.chars().take(30).collect();
            let more = if text.chars().count() > 30 { "..." } else { "" };
            format!("{shown:?}{more}")
        }
        DbValue::Integer(i) => i.to_string(),
        DbValue::Real(r) => r.to_string(),
        other => format!("{other:?}"),
    }
}

/// Refuses the conversion if it would change values, unless the request allowed that.
async fn check_conversion(
    tx: &Connection,
    table: &Ident,
    column: &ColumnInfo,
    new_type: &str,
    lossy: bool,
) -> Result<(), Failure> {
    let c = quote_name(&column.name);
    let Some(predicate) = lossy_predicate(&column.decl_type, new_type, &c) else {
        return Ok(());
    };
    if lossy {
        return Ok(());
    }
    let filter = format!("{c} IS NOT NULL AND ({predicate})");
    let count_sql = format!("SELECT count(*) FROM {} WHERE {filter}", table.quoted());
    let (_, rows) = fetch_all(tx, &count_sql, vec![]).await.map_err(db_err)?;
    let changed = rows.first().map_or(0, |r| int_at(r, 0));
    if changed == 0 {
        return Ok(());
    }
    let sample_sql = format!("SELECT {c} FROM {} WHERE {filter} LIMIT 5", table.quoted());
    let (_, samples) = fetch_all(tx, &sample_sql, vec![]).await.map_err(db_err)?;
    let shown: Vec<String> = samples
        .iter()
        .filter_map(|r| r.first())
        .map(sample)
        .collect();
    Err(Failure::Api(ApiError::LossyConversion(format!(
        "converting column {:?} from {} to {new_type} would change {changed} value(s), for example {}; nothing was changed. Fix the data, or send \"lossy\": true to convert anyway (values are cast: \"abc\" becomes 0, 3.9 becomes 3)",
        column.name,
        column.decl_type,
        shown.join(", ")
    ))))
}

/// What stops a table from being rebuilt faithfully. Bonny only creates tables from columns,
/// a primary key, single-column foreign keys and plain indexes, so any of these means the table
/// came from elsewhere and a rebuild could silently lose something.
async fn rebuild_blockers(
    tx: &Connection,
    table: &Ident,
    info: &TableInfo,
    own_keys: &[ForeignKeyRow],
) -> ApiResult<Vec<String>> {
    let mut blockers = Vec::new();
    let referrers: Vec<String> = referencing_keys(tx, table)
        .await?
        .into_iter()
        .filter(|r| !eq_ci(&r.child_table, table.as_str()))
        .map(|r| format!("{}.{}", r.child_table, r.child_column))
        .collect();
    if !referrers.is_empty() {
        blockers.push(format!(
            "is referenced by foreign keys of other tables ({}), which would have to be dropped and recreated",
            referrers.join(", ")
        ));
    }
    if let Some(column) = info.columns.iter().find(|c| c.default.is_some()) {
        blockers.push(format!("has a default value on column {:?}", column.name));
    }
    let (_, triggers) = fetch_all(
        tx,
        "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND lower(tbl_name) = lower(?1)",
        vec![DbValue::Text(table.as_str().to_owned())],
    )
    .await
    .map_err(db_err)?;
    if !triggers.is_empty() {
        blockers.push("has triggers".to_owned());
    }
    if list_indexes(tx, table)
        .await?
        .iter()
        .any(|i| i.origin == "u")
    {
        blockers.push("has a UNIQUE constraint".to_owned());
    }
    if own_keys
        .iter()
        .any(|k| own_keys.iter().filter(|o| o.id == k.id).count() > 1)
    {
        blockers.push("has a composite foreign key".to_owned());
    }
    if own_keys
        .iter()
        .any(|k| k.on_update != "NO ACTION" || k.on_delete != "NO ACTION")
    {
        blockers.push("has foreign key actions (ON DELETE / ON UPDATE)".to_owned());
    }
    let (_, definition) = fetch_all(
        tx,
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND lower(name) = lower(?1)",
        vec![DbValue::Text(table.as_str().to_owned())],
    )
    .await
    .map_err(db_err)?;
    let sql = definition
        .first()
        .map(|r| text_at(r, 0).to_ascii_uppercase())
        .unwrap_or_default();
    for feature in [
        "CHECK(",
        "CHECK (",
        "WITHOUT ROWID",
        "STRICT",
        "GENERATED",
        "AUTOINCREMENT",
        "COLLATE ",
    ] {
        if sql.contains(feature) {
            blockers.push(format!("uses {}", feature.trim_end_matches(['(', ' '])));
        }
    }
    Ok(blockers)
}

enum Rebuild<'a> {
    Retype {
        column: &'a ColumnInfo,
        new_type: &'static str,
    },
    Add {
        name: &'a Ident,
        sql_type: &'static str,
        reference: Option<&'a ForeignKey>,
        default: Option<DbValue>,
    },
}

/// Replaces the table by a copy with the change applied: create the new definition, copy the
/// rows, drop the old table, rename the copy, create the indexes again. Used when the column is
/// NOT NULL, because the engine cannot add that constraint to a column afterwards. Everything
/// happens in the caller's transaction, so any failure leaves the old table untouched.
async fn rebuild_table(
    tx: &Connection,
    table: &Ident,
    info: &TableInfo,
    change: Rebuild<'_>,
) -> Result<(), Failure> {
    let own_keys = foreign_key_rows(tx, table).await?;
    let blockers = rebuild_blockers(tx, table, info, &own_keys).await?;
    if !blockers.is_empty() {
        return Err(conflict(format!(
            "table {:?} cannot be rebuilt for this change because it {}; nothing was changed",
            table.as_str(),
            blockers.join("; ")
        )));
    }
    let indexes = table_index_statements(tx, table).await?;
    let copy = free_table_name(tx, &format!("{}__rebuild", table.as_str())).await?;

    // The new definition: the same columns and constraints, with the change applied.
    let mut definition = Vec::new();
    for c in &info.columns {
        let sql_type = match &change {
            Rebuild::Retype { column, new_type } if eq_ci(&c.name, &column.name) => *new_type,
            _ => c.decl_type.as_str(),
        };
        let not_null = if c.not_null { " NOT NULL" } else { "" };
        definition.push(format!("{} {sql_type}{not_null}", quote_name(&c.name)));
    }
    if let Rebuild::Add { name, sql_type, .. } = &change {
        definition.push(format!("{} {sql_type} NOT NULL", name.quoted()));
    }
    let key = info.primary_key();
    if !key.is_empty() {
        let quoted: Vec<String> = key.iter().map(|k| quote_name(k)).collect();
        definition.push(format!("PRIMARY KEY ({})", quoted.join(", ")));
    }
    let foreign_key = |from: &str, parent: &str, to: &str| {
        let target = if to.is_empty() {
            String::new()
        } else {
            format!(" ({})", quote_name(to))
        };
        format!(
            "FOREIGN KEY ({}) REFERENCES {}{target}",
            quote_name(from),
            quote_name(parent)
        )
    };
    for k in &own_keys {
        definition.push(foreign_key(&k.from, &k.table, &k.to));
    }
    if let Rebuild::Add {
        name,
        reference: Some(r),
        ..
    } = &change
    {
        definition.push(foreign_key(
            name.as_str(),
            r.table.as_str(),
            r.column.as_str(),
        ));
    }
    ddl(
        tx,
        &format!(
            "CREATE TABLE {} ({})",
            quote_name(&copy),
            definition.join(", ")
        ),
    )
    .await?;

    // Copy the rows.
    let mut targets: Vec<String> = info.columns.iter().map(|c| quote_name(&c.name)).collect();
    let mut values: Vec<String> = info
        .columns
        .iter()
        .map(|c| match &change {
            Rebuild::Retype { column, new_type } if eq_ci(&c.name, &column.name) => {
                format!("CAST({} AS {new_type})", quote_name(&c.name))
            }
            _ => quote_name(&c.name),
        })
        .collect();
    let mut params = Vec::new();
    if let Rebuild::Add { name, default, .. } = change {
        targets.push(name.quoted());
        match default {
            Some(value) => {
                values.push("?1".to_owned());
                params.push(value);
            }
            None => values.push("NULL".to_owned()), // only reached for an empty table
        }
    }
    let insert = format!(
        "INSERT INTO {} ({}) SELECT {} FROM {}",
        quote_name(&copy),
        targets.join(", "),
        values.join(", "),
        table.quoted()
    );
    tx.execute(&insert, params_from_iter(params))
        .await
        .map_err(ddl_failure)?;
    if row_count(tx, &copy).await? != row_count(tx, table.as_str()).await? {
        error!(
            table = table.as_str(),
            "rebuild copied a different number of rows"
        );
        return Err(Failure::Api(ApiError::Internal));
    }

    ddl(tx, &format!("DROP TABLE {}", table.quoted())).await?;
    ddl(
        tx,
        &format!(
            "ALTER TABLE {} RENAME TO {}",
            quote_name(&copy),
            table.quoted()
        ),
    )
    .await?;
    for index in &indexes {
        ddl(tx, &index.sql).await?;
    }
    Ok(())
}

/// Changes the type of a nullable column without touching the rest of the table: add a column of
/// the new type, copy the cast values into it, drop the old column, give the new one its name.
/// The column moves to the end of the table; indexes on it are dropped first and created again.
async fn retype_in_place(
    tx: &Connection,
    table: &Ident,
    info: &TableInfo,
    column: &ColumnInfo,
    new_type: &str,
) -> Result<(), Failure> {
    let indexes = table_index_statements(tx, table).await?;
    let affected: Vec<&IndexStatement> = indexes
        .iter()
        .filter(|i| i.columns.iter().any(|c| eq_ci(c, &column.name)))
        .collect();
    for index in &affected {
        ddl(tx, &format!("DROP INDEX {}", quote_name(&index.name))).await?;
    }
    let old = quote_name(&column.name);
    let temp = quote_name(&free_column_name(info, &column.name));
    let t = table.quoted();
    ddl(tx, &format!("ALTER TABLE {t} ADD COLUMN {temp} {new_type}")).await?;
    ddl(
        tx,
        &format!("UPDATE {t} SET {temp} = CAST({old} AS {new_type})"),
    )
    .await?;
    ddl(tx, &format!("ALTER TABLE {t} DROP COLUMN {old}")).await?;
    ddl(
        tx,
        &format!("ALTER TABLE {t} RENAME COLUMN {temp} TO {old}"),
    )
    .await?;
    for index in affected {
        ddl(tx, &index.sql).await?;
    }
    Ok(())
}

async fn change_column_type(
    tx: &Connection,
    table: &Ident,
    info: &TableInfo,
    column: &ColumnInfo,
    new_type: &'static str,
    lossy: bool,
) -> Result<(), Failure> {
    const CONVERTIBLE: [&str; 3] = ["INTEGER", "REAL", "TEXT"];
    if !CONVERTIBLE.contains(&column.decl_type.as_str()) || !CONVERTIBLE.contains(&new_type) {
        return Err(refuse(format!(
            "cannot convert column {:?} from {} to {new_type}: only INTEGER, REAL and TEXT columns can be converted between each other",
            column.name, column.decl_type
        )));
    }
    if column.pk > 0 {
        return Err(conflict(format!(
            "column {:?} is part of the primary key; its type cannot be changed",
            column.name
        )));
    }
    if let Some(key) = foreign_key_rows(tx, table)
        .await?
        .iter()
        .find(|k| eq_ci(&k.from, &column.name))
    {
        return Err(conflict(format!(
            "column {:?} is a foreign key to {}; its type must match the referenced column",
            column.name, key.table
        )));
    }
    let used_by: Vec<String> = referencing_keys(tx, table)
        .await?
        .into_iter()
        .filter(|r| eq_ci(&r.parent_column, &column.name))
        .map(|r| format!("{}.{}", r.child_table, r.child_column))
        .collect();
    if !used_by.is_empty() {
        return Err(conflict(format!(
            "column {:?} is referenced by the foreign key of {}; its type cannot be changed",
            column.name,
            used_by.join(", ")
        )));
    }
    check_conversion(tx, table, column, new_type, lossy).await?;
    if column.not_null {
        rebuild_table(tx, table, info, Rebuild::Retype { column, new_type }).await
    } else {
        retype_in_place(tx, table, info, column, new_type).await
    }
}

/// A default must fit the column type: the database would otherwise store a mismatching value
/// as it is (a text in an INTEGER column) and the column would hold mixed types.
fn fit_default(sql_type: &str, value: DbValue) -> ApiResult<DbValue> {
    match (sql_type, value) {
        ("INTEGER", v @ DbValue::Integer(_)) => Ok(v),
        ("REAL", DbValue::Integer(i)) => Ok(DbValue::Real(i as f64)),
        ("REAL", v @ DbValue::Real(_)) => Ok(v),
        ("NUMERIC", v @ (DbValue::Integer(_) | DbValue::Real(_))) => Ok(v),
        ("TEXT", v @ DbValue::Text(_)) => Ok(v),
        ("BLOB", v @ DbValue::Blob(_)) => Ok(v),
        (kind, _) => Err(ApiError::bad(format!(
            "default does not fit a {kind} column"
        ))),
    }
}

async fn add_column(tx: &Connection, plan: &AlterPlan, info: &TableInfo) -> Result<(), Failure> {
    let sql_type = plan.sql_type.ok_or_else(|| {
        refuse(format!(
            "column {:?} does not exist; adding it needs a type",
            plan.column.as_str()
        ))
    })?;
    if let Some(reference) = &plan.references {
        if eq_ci(reference.table.as_str(), plan.table.as_str()) {
            return Err(refuse(
                "a column added to a table cannot reference that same table",
            ));
        }
        let what = format!(
            "column {:?} references {}.{}",
            plan.column.as_str(),
            reference.table.as_str(),
            reference.column.as_str()
        );
        let (parent_type, unique) = parent_column(tx, reference, &what).await?;
        check_reference_types(&what, unique, &parent_type, sql_type)?;
    }
    let default = plan
        .default
        .clone()
        .map(|v| fit_default(sql_type, v))
        .transpose()?;
    let t = plan.table.quoted();
    let column = plan.column.quoted();
    if plan.nullable {
        let reference = plan.references.as_ref().map_or_else(String::new, |r| {
            format!(" REFERENCES {} ({})", r.table.quoted(), r.column.quoted())
        });
        ddl(
            tx,
            &format!("ALTER TABLE {t} ADD COLUMN {column} {sql_type}{reference}"),
        )
        .await?;
        if let Some(value) = default {
            tx.execute(
                &format!("UPDATE {t} SET {column} = ?1"),
                params_from_iter([value]),
            )
            .await
            .map_err(ddl_failure)?;
        }
        return Ok(());
    }
    // NOT NULL: the engine cannot add such a column without leaving a permanent DEFAULT, so the
    // table is rebuilt and existing rows get the given value once.
    let has_rows = table_has_rows(tx, &plan.table).await?;
    if has_rows && default.is_none() {
        return Err(refuse(format!(
            "column {:?} would be NOT NULL but the table has rows that need a value: give \"default\" (the value existing rows get) or set \"nullable\": true",
            plan.column.as_str()
        )));
    }
    let change = Rebuild::Add {
        name: &plan.column,
        sql_type,
        reference: plan.references.as_ref(),
        default: if has_rows { default } else { None },
    };
    rebuild_table(tx, &plan.table, info, change).await
}

async fn run_alter(tx: &Connection, plan: &AlterPlan) -> Result<AlterOutcome, Failure> {
    let info = require_table(tx, &plan.table).await?;
    let mut outcome = AlterOutcome::default();
    let named = |name: &str| info.columns.iter().find(|c| eq_ci(&c.name, name));

    let existing = named(plan.column.as_str());
    let (current, renaming) = match (existing, &plan.rename) {
        (Some(column), rename) => (column, rename.as_ref()),
        // Already renamed by an earlier request: do not add the old name again.
        (None, Some(rename)) if named(rename.as_str()).is_some() => (
            named(rename.as_str()).ok_or(Failure::Api(ApiError::Internal))?,
            None,
        ),
        (None, Some(_)) => {
            return Err(refuse(format!(
                "column {:?} does not exist, so it cannot be renamed; to add a column leave out \"rename\"",
                plan.column.as_str()
            )));
        }
        (None, None) => {
            add_column(tx, plan, &info).await?;
            outcome.added = true;
            return Ok(outcome);
        }
    };

    // Repeating the request that added the column must be harmless, so what it says about
    // nullability and the foreign key is accepted when it agrees with the column as it is. The
    // `default` only ever fills existing rows when the column is added, so it is ignored here.
    let is_nullable = !current.not_null && current.pk == 0;
    if plan.nullable_given && plan.nullable != is_nullable {
        return Err(conflict(format!(
            "column {:?} already exists and {} NULL; the nullability of an existing column cannot be changed",
            current.name,
            if is_nullable {
                "accepts"
            } else {
                "does not accept"
            }
        )));
    }
    if let Some(wanted) = &plan.references {
        let same = foreign_key_rows(tx, &plan.table).await?.iter().any(|k| {
            eq_ci(&k.from, &current.name)
                && eq_ci(&k.table, wanted.table.as_str())
                && eq_ci(&k.to, wanted.column.as_str())
        });
        if !same {
            return Err(conflict(format!(
                "column {:?} already exists without a foreign key to {}.{}; foreign keys of existing columns cannot be changed",
                current.name,
                wanted.table.as_str(),
                wanted.column.as_str()
            )));
        }
    }
    let new_name = renaming.filter(|r| !eq_ci(r.as_str(), &current.name));
    if let Some(new_name) = new_name
        && named(new_name.as_str()).is_some()
    {
        return Err(conflict(format!(
            "cannot rename {:?} to {:?}: the table already has a column with that name",
            current.name,
            new_name.as_str()
        )));
    }
    if let Some(new_type) = plan.sql_type.filter(|t| *t != current.decl_type) {
        change_column_type(tx, &plan.table, &info, current, new_type, plan.lossy).await?;
        outcome.retyped = true;
    }
    if let Some(new_name) = new_name {
        let sql = format!(
            "ALTER TABLE {} RENAME COLUMN {} TO {}",
            plan.table.quoted(),
            quote_name(&current.name),
            new_name.quoted()
        );
        ddl(tx, &sql).await?;
        outcome.renamed = true;
    }
    Ok(outcome)
}

async fn attempt_alter(db: &Db, plan: &AlterPlan) -> Result<AlterOutcome, Failure> {
    let mut conn = db.connect().await.map_err(classify)?;
    // A schema change needs the database to itself for a moment; while writers are busy the
    // engine says "busy", which is retried like a lost write conflict.
    let tx = conn.transaction().await.map_err(ddl_failure)?;
    match run_alter(&tx, plan).await {
        Ok(outcome) => {
            tx.commit().await.map_err(ddl_failure)?;
            Ok(outcome)
        }
        Err(failure) => {
            if let Err(error) = tx.rollback().await {
                tracing::debug!(%error, "rollback after a failed schema change");
            }
            Err(failure)
        }
    }
}

async fn run_alter_plan(db: &Db, plan: AlterPlan) -> ApiResult<AlterOutcome> {
    // Schema changes queue behind each other (and, without MVCC, behind writers) like table creation.
    let _write = db.write_lock.lock().await;
    with_conflict_retries(|| attempt_alter(db, &plan)).await
}

/// Adds a column, changes its type and/or renames it, so that the table ends up as described
/// (see the README). Answers `204 No Content`, also when there was nothing to change.
async fn patch_table(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<AlterTable>,
) -> ApiResult<StatusCode> {
    let plan = AlterPlan::from_request(req)?;
    let (table, column) = (plan.table.clone(), plan.column.clone());
    let db = state.db.clone();
    let outcome = spawn_db(async move { run_alter_plan(&db, plan).await }).await?;
    info!(
        table = table.as_str(),
        column = column.as_str(),
        added = outcome.added,
        retyped = outcome.retyped,
        renamed = outcome.renamed,
        "alter table"
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// DELETE /v1/index?name=...
// ---------------------------------------------------------------------------------------------

/// Reads the single `name` query parameter; anything else is a 400, not silently ignored.
fn index_name_param(
    query: Result<Query<std::collections::HashMap<String, String>>, QueryRejection>,
) -> ApiResult<Ident> {
    let Query(params) = query.map_err(|e| ApiError::bad(format!("invalid query string: {e}")))?;
    if let Some(unknown) = params.keys().find(|k| k.as_str() != "name") {
        return Err(ApiError::bad(format!(
            "unknown query parameter {unknown:?}; the only parameter is name"
        )));
    }
    let name = params.get("name").ok_or_else(|| {
        ApiError::bad("the name of the index is required: DELETE /v1/index?name=<index>")
    })?;
    Ident::parse("index", name)
}

/// Drops an index made with `POST /v1/indexes`.
///
/// Refused when the index is what makes a column unique for a foreign key of another table: the
/// engine would let it go and then reject every later insert into the child table.
async fn drop_index_named(db: &Db, name: &Ident) -> ApiResult<()> {
    let _write = db.write_lock.lock().await;
    let conn = db.connect().await.map_err(db_err)?;
    let Some((kind, table)) = schema_object(&conn, name.as_str()).await? else {
        return Err(ApiError::NotFound(format!(
            "index {:?} does not exist",
            name.as_str()
        )));
    };
    if kind != "index" {
        return Err(ApiError::bad(format!(
            "{:?} is a {kind}, not an index",
            name.as_str()
        )));
    }
    let table = Ident::parse("table", &table)?;
    let indexes = list_indexes(&conn, &table).await?;
    let index = indexes
        .iter()
        .find(|i| eq_ci(&i.name, name.as_str()))
        .ok_or_else(|| ApiError::NotFound(format!("index {:?} does not exist", name.as_str())))?;
    if index.unique && !index.partial {
        let columns = index_columns(&conn, &index.name).await?;
        if let [column] = columns.as_slice() {
            let info = require_table(&conn, &table).await?;
            let is_the_key = info.primary_key().len() == 1 && eq_ci(&info.primary_key()[0], column);
            if !is_the_key {
                let users: Vec<String> = referencing_keys(&conn, &table)
                    .await?
                    .into_iter()
                    .filter(|r| eq_ci(&r.parent_column, column))
                    .map(|r| format!("{}.{}", r.child_table, r.child_column))
                    .collect();
                if !users.is_empty() {
                    return Err(ApiError::Conflict(format!(
                        "index {:?} makes {}.{column} unique, which the foreign key of {} requires; nothing was dropped",
                        name.as_str(),
                        table.as_str(),
                        users.join(", ")
                    )));
                }
            }
        }
    }
    conn.execute(&format!("DROP INDEX {}", name.quoted()), ())
        .await
        .map_err(db_err)?;
    Ok(())
}

async fn drop_index(
    State(state): State<Arc<AppState>>,
    query: Result<Query<std::collections::HashMap<String, String>>, QueryRejection>,
) -> ApiResult<StatusCode> {
    let name = index_name_param(query)?;
    let db = state.db.clone();
    let logged = name.clone();
    spawn_db(async move { drop_index_named(&db, &name).await }).await?;
    info!(index = logged.as_str(), "drop index");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// POST /v1/query
// ---------------------------------------------------------------------------------------------

/// One predicate on a column. Several predicates on the same column (and on different columns)
/// are combined with AND.
#[derive(Debug, PartialEq)]
enum Condition {
    /// `=`, `<>`, `>`, `>=`, `<` or `<=` against a non-null value.
    Compare(&'static str, DbValue),
    /// `IN (...)` / `NOT IN (...)`. An empty list matches nothing (`IN`) or everything (`NOT IN`).
    In {
        values: Vec<DbValue>,
        negated: bool,
    },
    /// `LIKE` / `NOT LIKE`. With several patterns, `like` matches any of them (OR) and
    /// `not_like` matches none of them (AND), mirroring `in` / `not_in`.
    Like {
        patterns: Vec<String>,
        negated: bool,
    },
    IsNull {
        negated: bool,
    },
}

impl Condition {
    fn param_count(&self) -> usize {
        match self {
            Self::Compare(..) => 1,
            Self::In { values, .. } => values.len(),
            Self::Like { patterns, .. } => patterns.len(),
            Self::IsNull { .. } => 0,
        }
    }
}

const FILTER_OPERATORS: &str = "eq, ne, gt, gte, lt, lte, in, not_in, like, not_like, is_null";

/// Parses the value of one entry of `filters`:
///
/// * a scalar means equality, `null` means `IS NULL`;
/// * an object is a set of operators (`{"gt": 1, "lt": 10}`), all of which must hold;
/// * an object with a `$type` key is a tagged blob and means equality, as for batch values.
fn parse_filter(column: &str, value: &JsonValue) -> ApiResult<Vec<Condition>> {
    let fail = |detail: String| ApiError::bad(format!("filter {column:?}: {detail}"));
    match value {
        JsonValue::Null => Ok(vec![Condition::IsNull { negated: false }]),
        JsonValue::Object(operators) if !operators.contains_key("$type") => {
            if operators.is_empty() {
                return Err(fail(format!(
                    "an operator object needs at least one operator ({FILTER_OPERATORS})"
                )));
            }
            operators
                .iter()
                .map(|(operator, operand)| parse_operator(operator, operand).map_err(&fail))
                .collect()
        }
        scalar => db_value(scalar)
            .map(|v| vec![Condition::Compare("=", v)])
            .map_err(fail),
    }
}

fn parse_operator(operator: &str, operand: &JsonValue) -> Result<Condition, String> {
    let scalar = |value: &JsonValue| match db_value(value)? {
        DbValue::Null => Err("null is not allowed here; use is_null".to_owned()),
        value => Ok(value),
    };
    let list = |what: &str| -> Result<Vec<DbValue>, String> {
        operand
            .as_array()
            .ok_or_else(|| format!("{what} expects an array"))?
            .iter()
            .map(scalar)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{what}: {e}"))
    };
    let compare = |sql: &'static str| {
        scalar(operand)
            .map(|v| Condition::Compare(sql, v))
            .map_err(|e| format!("{operator}: {e}"))
    };
    let patterns = || -> Result<Vec<String>, String> {
        match operand {
            JsonValue::String(pattern) => Ok(vec![pattern.clone()]),
            JsonValue::Array(items) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("{operator} patterns must be strings"))
                })
                .collect(),
            _ => Err(format!(
                "{operator} expects a string or an array of strings"
            )),
        }
    };
    match operator {
        "eq" => compare("="),
        "ne" => compare("<>"),
        "gt" => compare(">"),
        "gte" => compare(">="),
        "lt" => compare("<"),
        "lte" => compare("<="),
        "in" | "not_in" => Ok(Condition::In {
            values: list(operator)?,
            negated: operator == "not_in",
        }),
        "like" | "not_like" => Ok(Condition::Like {
            patterns: patterns()?,
            negated: operator == "not_like",
        }),
        "is_null" => match operand {
            JsonValue::Bool(is_null) => Ok(Condition::IsNull { negated: !is_null }),
            _ => Err("is_null expects true or false".to_owned()),
        },
        other => Err(format!(
            "unknown operator {other:?}; supported operators: {FILTER_OPERATORS}"
        )),
    }
}

/// The parsed `filters` object shared by `/v1/query` and `/v1/delete`: per column, the conditions
/// that must all hold. Different columns, and several conditions on one column, are ANDed.
struct FilterPlan {
    entries: Vec<(ColRef, Vec<Condition>)>,
}

/// A column, possibly qualified with the table it belongs to (`table.column`). Only queries with
/// joins use qualified references; everywhere else `table` is `None`.
#[derive(Debug, Clone)]
struct ColRef {
    table: Option<Ident>,
    column: Ident,
}

impl ColRef {
    fn quoted(&self) -> String {
        match &self.table {
            Some(table) => format!("{}.{}", table.quoted(), self.column.quoted()),
            None => self.column.quoted(),
        }
    }

    fn describe(&self) -> String {
        match &self.table {
            Some(table) => format!("{}.{}", table.as_str(), self.column.as_str()),
            None => self.column.as_str().to_owned(),
        }
    }
}

/// Splits `table.column` (or just `column`) and validates both parts as identifiers.
fn parse_column_ref(what: &str, text: &str) -> ApiResult<ColRef> {
    match text.split_once('.') {
        Some((table, column)) => Ok(ColRef {
            table: Some(Ident::parse("table", table)?),
            column: Ident::parse(what, column)?,
        }),
        None => Ok(ColRef {
            table: None,
            column: Ident::parse(what, text)?,
        }),
    }
}

impl FilterPlan {
    fn parse(filters: &Map<String, JsonValue>) -> ApiResult<Self> {
        let names: Vec<String> = filters.keys().cloned().collect();
        let idents = parse_idents("filter column", &names, MAX_COLUMNS)?;
        let refs = idents
            .into_iter()
            .map(|column| ColRef {
                table: None,
                column,
            })
            .collect();
        Self::from_refs(refs, filters)
    }

    /// Like [`FilterPlan::parse`], but keys may be `table.column` (for queries with joins).
    fn parse_qualified(filters: &Map<String, JsonValue>) -> ApiResult<Self> {
        if filters.len() > MAX_COLUMNS {
            return Err(ApiError::bad(format!(
                "at most {MAX_COLUMNS} filter columns are allowed"
            )));
        }
        let mut seen = HashSet::new();
        let mut refs = Vec::new();
        for key in filters.keys() {
            let column = parse_column_ref("filter column", key)?;
            if !seen.insert(key.to_ascii_lowercase()) {
                return Err(ApiError::bad(format!("duplicate filter column {key:?}")));
            }
            refs.push(column);
        }
        Self::from_refs(refs, filters)
    }

    fn from_refs(refs: Vec<ColRef>, filters: &Map<String, JsonValue>) -> ApiResult<Self> {
        let entries = refs
            .into_iter()
            .zip(filters.values())
            .map(|(column, value)| {
                let conditions = parse_filter(&column.describe(), value)?;
                Ok((column, conditions))
            })
            .collect::<ApiResult<Vec<_>>>()?;
        let params: usize = entries
            .iter()
            .flat_map(|(_, conditions)| conditions)
            .map(Condition::param_count)
            .sum();
        if params > MAX_QUERY_PARAMS {
            return Err(ApiError::bad(format!(
                "filters use {params} values; at most {MAX_QUERY_PARAMS} are allowed"
            )));
        }
        Ok(Self { entries })
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every column the filters refer to, for checking them against the live schema.
    fn columns(&self) -> impl Iterator<Item = &Ident> {
        self.entries.iter().map(|(column, _)| &column.column)
    }

    /// The SQL conditions (to be joined with `AND`). Values are appended to `params` and
    /// referenced by numbered placeholders, so `params` may already hold earlier values.
    fn clauses(&self, params: &mut Vec<DbValue>) -> Vec<String> {
        let mut bind = |value: DbValue| {
            params.push(value);
            format!("?{}", params.len())
        };
        let mut clauses = Vec::new();
        for (column, conditions) in &self.entries {
            let column = column.quoted();
            for condition in conditions {
                match condition {
                    Condition::Compare(op, value) => {
                        clauses.push(format!("{column} {op} {}", bind(value.clone())));
                    }
                    Condition::In { values, negated } => {
                        if values.is_empty() {
                            // `x IN ()` is always false; `x NOT IN ()` is always true.
                            if !negated {
                                clauses.push("0".to_owned());
                            }
                            continue;
                        }
                        let placeholders: Vec<String> =
                            values.iter().map(|v| bind(v.clone())).collect();
                        let not = if *negated { "NOT " } else { "" };
                        clauses.push(format!("{column} {not}IN ({})", placeholders.join(", ")));
                    }
                    Condition::Like { patterns, negated } => {
                        if patterns.is_empty() {
                            if !negated {
                                clauses.push("0".to_owned());
                            }
                            continue;
                        }
                        let (keyword, joiner) = if *negated {
                            ("NOT LIKE", " AND ")
                        } else {
                            ("LIKE", " OR ")
                        };
                        let parts: Vec<String> = patterns
                            .iter()
                            .map(|p| {
                                format!("{column} {keyword} {}", bind(DbValue::Text(p.clone())))
                            })
                            .collect();
                        clauses.push(if parts.len() == 1 {
                            parts.into_iter().next().unwrap_or_default()
                        } else {
                            format!("({})", parts.join(joiner))
                        });
                    }
                    Condition::IsNull { negated } => {
                        let not = if *negated { "NOT " } else { "" };
                        clauses.push(format!("{column} IS {not}NULL"));
                    }
                }
            }
        }
        clauses
    }
}

/// One column of the result: where it comes from, and the name it has in the answer.
#[derive(Debug, Clone)]
struct SelectItem {
    table: Option<Ident>,
    column: Ident,
    alias: Option<Ident>,
}

impl SelectItem {
    fn output_name(&self) -> &str {
        self.alias.as_ref().unwrap_or(&self.column).as_str()
    }
}

/// Parses `columns`, which may be
///
/// * a list of names: `["a", "b"]`, each optionally qualified (`"stocks.symbol"`),
/// * an object per table: `{"fact_values": ["value"], "stocks": ["symbol"]}`, where an entry can
///   be `{"column": "id", "as": "stock_id"}` to name the result column,
/// * or a list containing such objects, as in `[{"fact_values": ["value"], "stocks": ["symbol"]}]`.
fn parse_select(value: &JsonValue) -> ApiResult<Vec<SelectItem>> {
    fn mapping(map: &Map<String, JsonValue>, items: &mut Vec<SelectItem>) -> ApiResult<()> {
        for (table, columns) in map {
            let table = Ident::parse("table", table)?;
            let JsonValue::Array(columns) = columns else {
                return Err(ApiError::bad(format!(
                    "columns of table {:?} must be a list",
                    table.as_str()
                )));
            };
            for entry in columns {
                let (column, alias) = match entry {
                    JsonValue::String(name) => (Ident::parse("column", name)?, None),
                    JsonValue::Object(object) => {
                        if let Some(unknown) = object
                            .keys()
                            .find(|k| !matches!(k.as_str(), "column" | "as"))
                        {
                            return Err(ApiError::bad(format!(
                                "unknown field {unknown:?} in a column of {:?}; allowed: column, as",
                                table.as_str()
                            )));
                        }
                        let name = object
                            .get("column")
                            .and_then(JsonValue::as_str)
                            .ok_or_else(|| {
                                ApiError::bad(format!(
                                    "a column of {:?} written as an object needs a \"column\" name",
                                    table.as_str()
                                ))
                            })?;
                        let alias = match object.get("as") {
                            None => None,
                            Some(JsonValue::String(alias)) => {
                                Some(Ident::parse("column alias", alias)?)
                            }
                            Some(_) => return Err(ApiError::bad("\"as\" must be a name")),
                        };
                        (Ident::parse("column", name)?, alias)
                    }
                    _ => {
                        return Err(ApiError::bad(format!(
                            "columns of table {:?} must be names, or objects like {{\"column\": \"id\", \"as\": \"stock_id\"}}",
                            table.as_str()
                        )));
                    }
                };
                items.push(SelectItem {
                    table: Some(table.clone()),
                    column,
                    alias,
                });
            }
        }
        Ok(())
    }

    let mut items = Vec::new();
    match value {
        JsonValue::Null => {}
        JsonValue::Object(map) => mapping(map, &mut items)?,
        JsonValue::Array(entries) => {
            for entry in entries {
                match entry {
                    JsonValue::String(text) => {
                        let reference = parse_column_ref("column", text)?;
                        items.push(SelectItem {
                            table: reference.table,
                            column: reference.column,
                            alias: None,
                        });
                    }
                    JsonValue::Object(map) => mapping(map, &mut items)?,
                    _ => {
                        return Err(ApiError::bad(
                            "columns must be a list of names, an object per table, or a list of those",
                        ));
                    }
                }
            }
        }
        _ => {
            return Err(ApiError::bad(
                "columns must be a list of names, or an object with a list of columns per table",
            ));
        }
    }
    if items.len() > MAX_COLUMNS {
        return Err(ApiError::bad(format!(
            "at most {MAX_COLUMNS} columns can be selected"
        )));
    }
    Ok(items)
}

/// The column names of a query without joins: only the base table, and no renaming.
fn plain_columns(table: &Ident, value: &JsonValue) -> ApiResult<Vec<Ident>> {
    let items = parse_select(value)?;
    let mut names = Vec::with_capacity(items.len());
    for item in &items {
        if let Some(owner) = &item.table
            && !eq_ci(owner.as_str(), table.as_str())
        {
            return Err(ApiError::bad(format!(
                "column {:?} belongs to table {:?}, which is not part of this query (add it with \"join\")",
                item.column.as_str(),
                owner.as_str()
            )));
        }
        if item.alias.is_some() {
            return Err(ApiError::bad(
                "\"as\" is only available in queries with \"join\"",
            ));
        }
        names.push(item.column.as_str().to_owned());
    }
    parse_idents("column", &names, MAX_COLUMNS)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectRequest {
    table: String,
    /// Plain query: a list of column names. With `join`, columns per table:
    /// `{"table": ["column", {"column": "x", "as": "y"}]}`.
    #[serde(default)]
    columns: JsonValue,
    /// Other tables to join to `table`: `{"stocks": "symbol_id"}` (see the README).
    #[serde(default)]
    join: Option<Map<String, JsonValue>>,
    /// `{column: value | null | {operator: operand, ...}}`, all combined with AND.
    #[serde(default)]
    filters: Map<String, JsonValue>,
    /// `[{column: "asc" | "desc"}, ...]`: one single-column object per sort key, in priority order.
    #[serde(default)]
    sort: Vec<Map<String, JsonValue>>,
    limit: Option<u32>,
    offset: Option<u32>,
}

struct QueryPlan {
    table: Ident,
    columns: Vec<Ident>,
    filters: FilterPlan,
    /// `(column, descending)` in priority order.
    sort: Vec<(Ident, bool)>,
    limit: u32,
    offset: u32,
}

impl QueryPlan {
    fn from_request(req: SelectRequest) -> ApiResult<Self> {
        let table = Ident::parse("table", &req.table)?;
        let columns = plain_columns(&table, &req.columns)?;

        let filters = FilterPlan::parse(&req.filters)?;

        let mut sort_names = Vec::new();
        let mut directions = Vec::new();
        for (i, entry) in req.sort.iter().enumerate() {
            let mut pairs = entry.iter();
            let (Some((column, direction)), None) = (pairs.next(), pairs.next()) else {
                return Err(ApiError::bad(format!(
                    "sort[{i}] must be an object with exactly one column, like {{\"period\": \"asc\"}}"
                )));
            };
            sort_names.push(column.clone());
            directions.push(direction);
        }
        let sort = parse_idents("sort column", &sort_names, MAX_COLUMNS)?
            .into_iter()
            .zip(directions)
            .map(|(ident, direction)| {
                let descending = match direction.as_str().map(str::to_ascii_lowercase).as_deref() {
                    Some("asc") => false,
                    Some("desc") => true,
                    _ => {
                        return Err(ApiError::bad(format!(
                            "sort {:?}: direction must be \"asc\" or \"desc\"",
                            ident.as_str()
                        )));
                    }
                };
                Ok((ident, descending))
            })
            .collect::<ApiResult<Vec<_>>>()?;

        let limit = req.limit.unwrap_or(DEFAULT_QUERY_ROWS);
        if limit == 0 || limit > MAX_QUERY_ROWS {
            return Err(ApiError::bad(format!(
                "limit must be between 1 and {MAX_QUERY_ROWS}"
            )));
        }
        let offset = req.offset.unwrap_or(0);
        if offset > MAX_QUERY_OFFSET {
            return Err(ApiError::bad(format!(
                "offset must be at most {MAX_QUERY_OFFSET}"
            )));
        }
        if offset > 0 && sort.is_empty() {
            return Err(ApiError::bad(
                "offset requires sort so that pages are deterministic",
            ));
        }
        Ok(Self {
            table,
            columns,
            filters,
            sort,
            limit,
            offset,
        })
    }

    fn sql(&self) -> (String, Vec<DbValue>) {
        let selected = if self.columns.is_empty() {
            "*".to_owned()
        } else {
            quoted_list(&self.columns)
        };
        let mut sql = format!("SELECT {selected} FROM {}", self.table.quoted());
        let mut params: Vec<DbValue> = Vec::new();
        let clauses = self.filters.clauses(&mut params);
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        if !self.sort.is_empty() {
            let terms: Vec<String> = self
                .sort
                .iter()
                .map(|(column, descending)| {
                    format!(
                        "{} {}",
                        column.quoted(),
                        if *descending { "DESC" } else { "ASC" }
                    )
                })
                .collect();
            sql.push_str(&format!(" ORDER BY {}", terms.join(", ")));
        }
        sql.push_str(&format!(" LIMIT {}", self.limit));
        if self.offset > 0 {
            sql.push_str(&format!(" OFFSET {}", self.offset));
        }
        (sql, params)
    }
}

async fn run_query(db: &Db, plan: QueryPlan) -> ApiResult<JsonValue> {
    let conn = db.connect().await.map_err(db_err)?;
    let info = require_table(&conn, &plan.table).await?;
    let mut referenced: Vec<&Ident> = plan.columns.iter().collect();
    referenced.extend(plan.filters.columns());
    referenced.extend(plan.sort.iter().map(|(c, _)| c));
    require_columns(&info, &plan.table, &referenced)?;

    let (sql, params) = plan.sql();
    let (names, rows) = fetch_all(&conn, &sql, params).await.map_err(db_err)?;
    Ok(rows_json(&names, rows))
}

/// `{"rows": [{column: value, ...}, ...], "row_count": n}`.
fn rows_json(names: &[String], rows: Vec<Vec<DbValue>>) -> JsonValue {
    let row_count = rows.len();
    let rows: Vec<JsonValue> = rows
        .into_iter()
        .map(|row| {
            let object: Map<String, JsonValue> = names
                .iter()
                .cloned()
                .zip(row.into_iter().map(json_value))
                .collect();
            JsonValue::Object(object)
        })
        .collect();
    json!({ "rows": rows, "row_count": row_count })
}

// ---- queries with joins ----

const MAX_JOINS: usize = 5;

/// One entry of `join`: `{"stocks": "symbol_id"}` or
/// `{"stocks": {"column": "symbol_id", "to": "code", "type": "left"}}`.
struct JoinSpec {
    table: Ident,
    /// The column of the base table that holds the key.
    column: Ident,
    /// The column of the joined table it must equal; `None` means "work it out" (see
    /// [`default_join_key`]).
    to: Option<Ident>,
    left: bool,
}

fn parse_joins(base: &Ident, joins: &Map<String, JsonValue>) -> ApiResult<Vec<JoinSpec>> {
    if joins.is_empty() || joins.len() > MAX_JOINS {
        return Err(ApiError::bad(format!(
            "join must name between 1 and {MAX_JOINS} tables"
        )));
    }
    let mut seen = HashSet::new();
    let mut specs = Vec::new();
    for (name, spec) in joins {
        let table = Ident::parse("joined table", name)?;
        if eq_ci(table.as_str(), base.as_str()) {
            return Err(ApiError::bad(format!(
                "table {:?} cannot be joined to itself",
                table.as_str()
            )));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(ApiError::bad(format!("table {name:?} is joined twice")));
        }
        let shape = || {
            ApiError::bad(format!(
                "join {name:?} must be the name of a column of {:?}, or an object like {{\"column\": \"symbol_id\", \"to\": \"id\", \"type\": \"left\"}}",
                base.as_str()
            ))
        };
        let (column, to, left) = match spec {
            JsonValue::String(column) => (Ident::parse("join column", column)?, None, false),
            JsonValue::Object(object) => {
                if let Some(unknown) = object
                    .keys()
                    .find(|k| !matches!(k.as_str(), "column" | "to" | "type"))
                {
                    return Err(ApiError::bad(format!(
                        "unknown field {unknown:?} in join {name:?}; allowed: column, to, type"
                    )));
                }
                let column = object
                    .get("column")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(shape)?;
                let to = match object.get("to") {
                    None => None,
                    Some(JsonValue::String(to)) => Some(Ident::parse("join column", to)?),
                    Some(_) => return Err(shape()),
                };
                let left = match object
                    .get("type")
                    .map(|t| t.as_str().map(str::to_ascii_lowercase))
                {
                    None => false,
                    Some(Some(kind)) if kind == "inner" => false,
                    Some(Some(kind)) if kind == "left" => true,
                    Some(_) => {
                        return Err(ApiError::bad(format!(
                            "type of join {name:?} must be \"inner\" or \"left\""
                        )));
                    }
                };
                (Ident::parse("join column", column)?, to, left)
            }
            _ => return Err(shape()),
        };
        specs.push(JoinSpec {
            table,
            column,
            to,
            left,
        });
    }
    Ok(specs)
}

struct JoinPlan {
    base: Ident,
    joins: Vec<JoinSpec>,
    select: Vec<SelectItem>,
    filters: FilterPlan,
    sort: Vec<(ColRef, bool)>,
    limit: u32,
    offset: u32,
}

impl JoinPlan {
    fn from_request(req: SelectRequest) -> ApiResult<Self> {
        let base = Ident::parse("table", &req.table)?;
        let joins = parse_joins(&base, req.join.as_ref().ok_or(ApiError::Internal)?)?;

        let select = parse_select(&req.columns)?;
        if select.is_empty() {
            return Err(ApiError::bad(
                "columns is required in a query with join: list the columns of each table, like {\"orders\": [\"id\"], \"stocks\": [\"symbol\"]}",
            ));
        }
        let mut names = HashSet::new();
        for item in &select {
            if !names.insert(item.output_name().to_ascii_lowercase()) {
                return Err(ApiError::bad(format!(
                    "the result would have two columns named {:?}; rename one of them with {{\"column\": ..., \"as\": ...}}",
                    item.output_name()
                )));
            }
        }

        let filters = FilterPlan::parse_qualified(&req.filters)?;

        let mut sort = Vec::new();
        let mut seen = HashSet::new();
        for (i, entry) in req.sort.iter().enumerate() {
            let mut pairs = entry.iter();
            let (Some((key, direction)), None) = (pairs.next(), pairs.next()) else {
                return Err(ApiError::bad(format!(
                    "sort[{i}] must be an object with exactly one column, like {{\"period\": \"asc\"}}"
                )));
            };
            if !seen.insert(key.to_ascii_lowercase()) {
                return Err(ApiError::bad(format!("sort column {key:?} appears twice")));
            }
            let descending = match direction.as_str().map(str::to_ascii_lowercase).as_deref() {
                Some("asc") => false,
                Some("desc") => true,
                _ => {
                    return Err(ApiError::bad(format!(
                        "sort {key:?}: direction must be \"asc\" or \"desc\""
                    )));
                }
            };
            sort.push((parse_column_ref("sort column", key)?, descending));
        }

        let limit = req.limit.unwrap_or(DEFAULT_QUERY_ROWS);
        if limit == 0 || limit > MAX_QUERY_ROWS {
            return Err(ApiError::bad(format!(
                "limit must be between 1 and {MAX_QUERY_ROWS}"
            )));
        }
        let offset = req.offset.unwrap_or(0);
        if offset > MAX_QUERY_OFFSET {
            return Err(ApiError::bad(format!(
                "offset must be at most {MAX_QUERY_OFFSET}"
            )));
        }
        if offset > 0 && sort.is_empty() {
            return Err(ApiError::bad(
                "offset requires sort so that pages are deterministic",
            ));
        }
        Ok(Self {
            base,
            joins,
            select,
            filters,
            sort,
            limit,
            offset,
        })
    }
}

/// Finds which table of the query a column belongs to. A qualified name (`stocks.symbol`) names
/// its table; an unqualified one must exist in exactly one table of the query.
fn locate(
    tables: &[(Ident, TableInfo)],
    table: Option<&Ident>,
    column: &Ident,
) -> ApiResult<usize> {
    if let Some(table) = table {
        let index = tables
            .iter()
            .position(|(name, _)| eq_ci(name.as_str(), table.as_str()))
            .ok_or_else(|| {
                ApiError::bad(format!(
                    "table {:?} is not part of the query; it uses {}",
                    table.as_str(),
                    tables
                        .iter()
                        .map(|(n, _)| format!("{:?}", n.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        if !tables[index].1.has_column(column.as_str()) {
            return Err(ApiError::bad(format!(
                "table {:?} has no column {:?}",
                tables[index].0.as_str(),
                column.as_str()
            )));
        }
        return Ok(index);
    }
    let owners: Vec<usize> = tables
        .iter()
        .enumerate()
        .filter(|(_, (_, info))| info.has_column(column.as_str()))
        .map(|(i, _)| i)
        .collect();
    match owners.as_slice() {
        [] => Err(ApiError::bad(format!(
            "no table of the query has a column {:?}",
            column.as_str()
        ))),
        [only] => Ok(*only),
        several => Err(ApiError::bad(format!(
            "column {:?} exists in several tables of the query ({}); write it as table.column",
            column.as_str(),
            several
                .iter()
                .map(|i| tables[*i].0.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The column of the joined table that `base.<column>` is compared with when the request does not
/// say: the one a declared foreign key points at, otherwise the joined table's `id`.
async fn default_join_key(
    conn: &Connection,
    base: &Ident,
    join: &JoinSpec,
    joined: &TableInfo,
) -> ApiResult<String> {
    let keys = foreign_key_rows(conn, base).await?;
    if let Some(key) = keys
        .iter()
        .find(|k| eq_ci(&k.from, join.column.as_str()) && eq_ci(&k.table, join.table.as_str()))
    {
        if !key.to.is_empty() {
            return Ok(key.to.clone());
        }
        if let Some(primary) = joined.primary_key().first() {
            return Ok(primary.clone());
        }
    }
    if let Some(column) = joined.columns.iter().find(|c| eq_ci(&c.name, "id")) {
        return Ok(column.name.clone());
    }
    Err(ApiError::bad(format!(
        "{}.{} has no foreign key to {}, and {} has no column \"id\"; say which column to join on: {{\"{}\": {{\"column\": \"{}\", \"to\": \"<column of {}>\"}}}}",
        base.as_str(),
        join.column.as_str(),
        join.table.as_str(),
        join.table.as_str(),
        join.table.as_str(),
        join.column.as_str(),
        join.table.as_str()
    )))
}

async fn run_join_query(db: &Db, mut plan: JoinPlan) -> ApiResult<JsonValue> {
    let conn = db.connect().await.map_err(db_err)?;
    let mut tables: Vec<(Ident, TableInfo)> = Vec::new();
    for name in std::iter::once(&plan.base).chain(plan.joins.iter().map(|j| &j.table)) {
        tables.push((name.clone(), require_table(&conn, name).await?));
    }

    // FROM ... JOIN ... ON: the base column must equal the joined table's key.
    let base = &tables[0].0;
    let mut from = base.quoted();
    for (i, join) in plan.joins.iter().enumerate() {
        let joined = &tables[i + 1];
        if !tables[0].1.has_column(join.column.as_str()) {
            return Err(ApiError::bad(format!(
                "join column {:?} is not a column of {:?}",
                join.column.as_str(),
                base.as_str()
            )));
        }
        let to = match &join.to {
            Some(to) if joined.1.has_column(to.as_str()) => to.quoted(),
            Some(to) => {
                return Err(ApiError::bad(format!(
                    "table {:?} has no column {:?} to join on",
                    joined.0.as_str(),
                    to.as_str()
                )));
            }
            None => quote_name(&default_join_key(&conn, base, join, &joined.1).await?),
        };
        from.push_str(&format!(
            " {}JOIN {} ON {}.{} = {}.{}",
            if join.left { "LEFT " } else { "" },
            joined.0.quoted(),
            base.quoted(),
            join.column.quoted(),
            joined.0.quoted(),
            to
        ));
    }

    let mut select = Vec::new();
    for item in &plan.select {
        let index = locate(&tables, item.table.as_ref(), &item.column)?;
        select.push(format!(
            "{}.{} AS {}",
            tables[index].0.quoted(),
            item.column.quoted(),
            quote_name(item.output_name())
        ));
    }
    for (reference, _) in &mut plan.filters.entries {
        let index = locate(&tables, reference.table.as_ref(), &reference.column)?;
        reference.table = Some(tables[index].0.clone());
    }
    for (reference, _) in &mut plan.sort {
        let index = locate(&tables, reference.table.as_ref(), &reference.column)?;
        reference.table = Some(tables[index].0.clone());
    }

    let mut sql = format!("SELECT {} FROM {from}", select.join(", "));
    let mut params = Vec::new();
    let clauses = plan.filters.clauses(&mut params);
    if !clauses.is_empty() {
        sql.push_str(&format!(" WHERE {}", clauses.join(" AND ")));
    }
    if !plan.sort.is_empty() {
        let terms: Vec<String> = plan
            .sort
            .iter()
            .map(|(column, descending)| {
                format!(
                    "{} {}",
                    column.quoted(),
                    if *descending { "DESC" } else { "ASC" }
                )
            })
            .collect();
        sql.push_str(&format!(" ORDER BY {}", terms.join(", ")));
    }
    sql.push_str(&format!(" LIMIT {}", plan.limit));
    if plan.offset > 0 {
        sql.push_str(&format!(" OFFSET {}", plan.offset));
    }
    let (names, rows) = fetch_all(&conn, &sql, params).await.map_err(db_err)?;
    Ok(rows_json(&names, rows))
}

async fn query(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<SelectRequest>,
) -> ApiResult<Json<JsonValue>> {
    let db = state.db.clone();
    let body = if req.join.is_some() {
        let plan = JoinPlan::from_request(req)?;
        spawn_db(async move { run_join_query(&db, plan).await }).await?
    } else {
        let plan = QueryPlan::from_request(req)?;
        spawn_db(async move { run_query(&db, plan).await }).await?
    };
    Ok(Json(body))
}

// ---------------------------------------------------------------------------------------------
// POST /v1/batch
// ---------------------------------------------------------------------------------------------

/// Conflict handling for a batch insert.
///
/// * `"abort"` (default): plain `INSERT`; any constraint violation fails and rolls back the batch.
/// * `"nothing"` (alias `"ignore"`): `INSERT OR IGNORE`; conflicting rows are skipped.
/// * `"replace_all"`: upsert that overwrites every non-key column from the incoming row.
/// * `{"replace": [cols]}`: upsert that overwrites only the listed columns.
///
/// The replace modes use `ON CONFLICT ... DO UPDATE`, which updates the existing row in place.
/// `INSERT OR REPLACE` is intentionally not offered: it deletes the old row and inserts a new
/// one, which resets any column not supplied in the batch to its default.
#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum OnConflict {
    #[default]
    Abort,
    #[serde(alias = "ignore")]
    Nothing,
    ReplaceAll,
    Replace(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    table: String,
    columns: Vec<String>,
    rows: Vec<Vec<JsonValue>>,
    #[serde(default)]
    on_conflict: OnConflict,
    /// Columns of the primary key or unique index to upsert against. Defaults to the primary key.
    conflict_target: Option<Vec<String>>,
}

enum ConflictPlan {
    Abort,
    Nothing,
    Upsert {
        target: Option<Vec<Ident>>,
        update: Option<Vec<Ident>>,
    },
}

struct BatchPlan {
    table: Ident,
    columns: Vec<Ident>,
    rows: Vec<Vec<DbValue>>,
    conflict: ConflictPlan,
}

impl BatchPlan {
    fn from_request(req: BatchRequest) -> ApiResult<Self> {
        let table = Ident::parse("table", &req.table)?;
        if req.columns.is_empty() {
            return Err(ApiError::bad("columns must not be empty"));
        }
        let columns = parse_idents("column", &req.columns, MAX_COLUMNS)?;
        let rows = req
            .rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                if row.len() != columns.len() {
                    return Err(ApiError::bad(format!(
                        "row {i} has {} values but {} columns were given",
                        row.len(),
                        columns.len()
                    )));
                }
                row.iter()
                    .zip(&columns)
                    .map(|(value, column)| {
                        db_value(value).map_err(|e| {
                            ApiError::bad(format!("row {i}, column {:?}: {e}", column.as_str()))
                        })
                    })
                    .collect()
            })
            .collect::<ApiResult<Vec<_>>>()?;

        let target = req
            .conflict_target
            .as_deref()
            .map(|t| parse_idents("conflict target column", t, MAX_INDEX_COLUMNS))
            .transpose()?;
        if target.as_ref().is_some_and(Vec::is_empty) {
            return Err(ApiError::bad("conflict_target must not be empty"));
        }

        let conflict = match req.on_conflict {
            OnConflict::Abort | OnConflict::Nothing if target.is_some() => {
                return Err(ApiError::bad(
                    "conflict_target is only valid with replace or replace_all",
                ));
            }
            OnConflict::Abort => ConflictPlan::Abort,
            OnConflict::Nothing => ConflictPlan::Nothing,
            OnConflict::ReplaceAll => ConflictPlan::Upsert {
                target,
                update: None,
            },
            OnConflict::Replace(cols) => {
                if cols.is_empty() {
                    return Err(ApiError::bad("replace must list at least one column"));
                }
                let update = parse_idents("replace column", &cols, MAX_COLUMNS)?;
                if let Some(missing) = update
                    .iter()
                    .find(|u| !columns.iter().any(|c| eq_ci(c.as_str(), u.as_str())))
                {
                    return Err(ApiError::bad(format!(
                        "replace column {:?} is not among the batch columns",
                        missing.as_str()
                    )));
                }
                ConflictPlan::Upsert {
                    target,
                    update: Some(update),
                }
            }
        };
        Ok(Self {
            table,
            columns,
            rows,
            conflict,
        })
    }
}

/// The statement text for a batch. `target`/`update` are only used for upserts; an empty
/// `update` list degrades to `DO NOTHING`.
fn insert_sql(plan: &BatchPlan, target: &[Ident], update: &[Ident]) -> String {
    let placeholders = (1..=plan.columns.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let verb = match plan.conflict {
        ConflictPlan::Nothing => "INSERT OR IGNORE",
        _ => "INSERT",
    };
    let mut sql = format!(
        "{verb} INTO {} ({}) VALUES ({placeholders})",
        plan.table.quoted(),
        quoted_list(&plan.columns)
    );
    if matches!(plan.conflict, ConflictPlan::Upsert { .. }) {
        sql.push_str(&format!(" ON CONFLICT ({})", quoted_list(target)));
        if update.is_empty() {
            sql.push_str(" DO NOTHING");
        } else {
            let sets = update
                .iter()
                .map(|c| format!("{} = excluded.{}", c.quoted(), c.quoted()))
                .collect::<Vec<_>>()
                .join(", ");
            sql.push_str(&format!(" DO UPDATE SET {sets}"));
        }
    }
    sql
}

/// Resolves the conflict target and update columns for an upsert against the live schema.
async fn resolve_upsert(
    conn: &Connection,
    plan: &BatchPlan,
    info: &TableInfo,
    target: &Option<Vec<Ident>>,
    update: &Option<Vec<Ident>>,
) -> ApiResult<(Vec<Ident>, Vec<Ident>)> {
    let target = match target {
        Some(t) => t.clone(),
        None => {
            let pk = info.primary_key();
            if pk.is_empty() {
                return Err(ApiError::bad(
                    "table has no primary key; provide conflict_target",
                ));
            }
            pk.iter()
                .map(|c| Ident::parse("primary key column", c))
                .collect::<ApiResult<Vec<_>>>()?
        }
    };
    require_columns(info, &plan.table, &target.iter().collect::<Vec<_>>())?;

    let mut wanted: Vec<String> = target
        .iter()
        .map(|c| c.as_str().to_ascii_lowercase())
        .collect();
    wanted.sort();
    if !unique_keys(conn, &plan.table, info)
        .await?
        .contains(&wanted)
    {
        return Err(ApiError::bad(
            "conflict_target must match the table's primary key or a unique index",
        ));
    }
    for key in &target {
        if !plan.columns.iter().any(|c| eq_ci(c.as_str(), key.as_str())) {
            return Err(ApiError::bad(format!(
                "conflict target column {:?} must be included in the batch columns",
                key.as_str()
            )));
        }
    }

    let in_target = |c: &Ident| target.iter().any(|t| eq_ci(t.as_str(), c.as_str()));
    let update = match update {
        Some(cols) => {
            if let Some(bad) = cols.iter().find(|c| in_target(c)) {
                return Err(ApiError::bad(format!(
                    "replace column {:?} is part of the conflict target",
                    bad.as_str()
                )));
            }
            cols.clone()
        }
        None => plan
            .columns
            .iter()
            .filter(|c| !in_target(c))
            .cloned()
            .collect(),
    };
    Ok((target, update))
}

async fn insert_rows(
    tx: &Connection,
    sql: &str,
    rows: &[Vec<DbValue>],
) -> Result<u64, (Option<usize>, turso::Error)> {
    let mut stmt = tx.prepare(sql).await.map_err(|e| (None, e))?;
    let mut affected = 0;
    for (i, row) in rows.iter().enumerate() {
        affected += stmt
            .execute(params_from_iter(row.iter().cloned()))
            .await
            .map_err(|e| (Some(i), e))?;
    }
    Ok(affected)
}

/// Outcome of one attempt that did not succeed.
enum Failure {
    /// Lost a write-write conflict; nothing was committed and the request can be re-run.
    Conflict,
    /// A final error to report to the client.
    Api(ApiError),
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

fn classify(error: turso::Error) -> Failure {
    if is_write_conflict(&error) {
        Failure::Conflict
    } else {
        Failure::Api(db_err(error))
    }
}

/// A parsed `POST /v1/batch` body: the steps to run, in order, in one transaction.
struct BatchJob {
    steps: Vec<BatchPlan>,
    /// Whether the body used the `{"batches": [...]}` envelope. Only then are error messages
    /// prefixed with the step they belong to.
    envelope: bool,
}

/// The multi-step body. Each element is validated as a [`BatchRequest`] on its own so that an
/// error can say which one it was.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchEnvelope {
    batches: Vec<JsonValue>,
}

/// Prefixes an error with the step it came from (envelope form only).
fn annotate(error: ApiError, step: usize, table: &str, envelope: bool) -> ApiError {
    if !envelope {
        return error;
    }
    let prefix = format!("batches[{step}] (table {table:?}): ");
    match error {
        ApiError::BadRequest(message) => ApiError::BadRequest(prefix + &message),
        ApiError::NotFound(message) => ApiError::NotFound(prefix + &message),
        ApiError::Conflict(message) => ApiError::Conflict(prefix + &message),
        other => other,
    }
}

/// Parses and validates the whole body up front: shape, limits, identifiers, values and conflict
/// options of every step. Nothing touches the database until this succeeds.
///
/// Two shapes are accepted: a single batch object (`{"table": ..., "rows": ...}`) or the envelope
/// `{"batches": [ <batch object>, ... ]}`.
fn parse_batch_body(body: JsonValue, limits: &Limits) -> ApiResult<BatchJob> {
    if !body.is_object() {
        return Err(ApiError::bad(
            "the request body must be a JSON object: either one batch ({\"table\": ..., \"rows\": ...}) or {\"batches\": [ ... ]}",
        ));
    }
    let invalid = |e: serde_json::Error| ApiError::bad(format!("invalid request body: {e}"));
    let envelope = body
        .as_object()
        .is_some_and(|object| object.contains_key("batches"));

    let requests: Vec<BatchRequest> = if envelope {
        let envelope: BatchEnvelope = serde_json::from_value(body).map_err(invalid)?;
        if envelope.batches.len() > limits.max_batch_steps {
            return Err(ApiError::bad(format!(
                "a request may contain at most {} batches (got {})",
                limits.max_batch_steps,
                envelope.batches.len()
            )));
        }
        envelope
            .batches
            .into_iter()
            .enumerate()
            .map(|(i, step)| {
                serde_json::from_value(step)
                    .map_err(|e| ApiError::bad(format!("batches[{i}]: {e}")))
            })
            .collect::<ApiResult<_>>()?
    } else {
        vec![serde_json::from_value(body).map_err(invalid)?]
    };

    let rows: usize = requests.iter().map(|r| r.rows.len()).sum();
    if rows > limits.max_batch_rows {
        return Err(ApiError::bad(format!(
            "a request may contain at most {} rows in total (got {rows})",
            limits.max_batch_rows
        )));
    }
    let values: usize = requests
        .iter()
        .map(|r| r.rows.len().saturating_mul(r.columns.len()))
        .sum();
    if values > limits.max_batch_values {
        return Err(ApiError::bad(format!(
            "a request may contain at most {} values in total (got {values})",
            limits.max_batch_values
        )));
    }

    let steps = requests
        .into_iter()
        .enumerate()
        .map(|(i, request)| {
            let table = request.table.clone();
            BatchPlan::from_request(request).map_err(|e| annotate(e, i, &table, envelope))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(BatchJob { steps, envelope })
}

/// Turns a failure of step `step` into the error the client sees.
fn insert_failure(
    source: turso::Error,
    row: Option<usize>,
    step: usize,
    job: &BatchJob,
) -> Failure {
    let table = job.steps[step].table.as_str();
    if is_write_conflict(&source) {
        return Failure::Conflict;
    }
    match (source, row) {
        (turso::Error::Constraint(detail), Some(row)) => {
            warn!(%detail, step, table, row, "constraint violation in batch");
            let scope = if job.envelope { "request" } else { "batch" };
            let what = if is_foreign_key_violation(&detail) {
                "foreign key violation (a referenced row does not exist)"
            } else {
                "constraint violation"
            };
            Failure::Api(annotate(
                ApiError::Conflict(format!(
                    "{what} at row {row}; the whole {scope} was rolled back"
                )),
                step,
                table,
                job.envelope,
            ))
        }
        (other, _) => Failure::Api(annotate(db_err(other), step, table, job.envelope)),
    }
}

/// Whether a constraint error came from a foreign key (the engine words it "FOREIGN KEY constraint failed").
fn is_foreign_key_violation(detail: &str) -> bool {
    detail.to_ascii_uppercase().contains("FOREIGN KEY")
}

/// One complete try: fresh connection, fresh snapshot of the schema, one transaction for all
/// steps. Returns the rows affected by each step.
///
/// A new connection per attempt matters: after a conflict the engine has already aborted the
/// transaction, and the old connection cannot be reused cleanly.
async fn attempt_batches(db: &Db, job: &BatchJob) -> Result<Vec<u64>, Failure> {
    let mut conn = db.connect().await.map_err(classify)?;

    // Resolve every step against the current schema before the transaction opens, so that a
    // mistake in a later step costs nothing. Steps without rows are skipped entirely.
    let mut schemas: HashMap<String, TableInfo> = HashMap::new();
    let mut statements: Vec<Option<String>> = Vec::with_capacity(job.steps.len());
    for (i, plan) in job.steps.iter().enumerate() {
        if plan.rows.is_empty() {
            statements.push(None);
            continue;
        }
        let fail = |e: ApiError| Failure::Api(annotate(e, i, plan.table.as_str(), job.envelope));
        let key = plan.table.as_str().to_ascii_lowercase();
        if !schemas.contains_key(&key) {
            let info = require_table(&conn, &plan.table).await.map_err(fail)?;
            schemas.insert(key.clone(), info);
        }
        let info = &schemas[&key];
        require_columns(info, &plan.table, &plan.columns.iter().collect::<Vec<_>>())
            .map_err(fail)?;
        let sql = match &plan.conflict {
            ConflictPlan::Upsert { target, update } => {
                let (target, update) = resolve_upsert(&conn, plan, info, target, update)
                    .await
                    .map_err(fail)?;
                insert_sql(plan, &target, &update)
            }
            _ => insert_sql(plan, &[], &[]),
        };
        statements.push(Some(sql));
    }

    let behavior = if db.mvcc {
        TransactionBehavior::Concurrent
    } else {
        TransactionBehavior::Immediate
    };
    let tx = conn
        .transaction_with_behavior(behavior)
        .await
        .map_err(classify)?;
    let mut affected = vec![0_u64; job.steps.len()];
    for (i, (plan, sql)) in job.steps.iter().zip(&statements).enumerate() {
        let Some(sql) = sql else { continue };
        match insert_rows(&tx, sql, &plan.rows).await {
            Ok(count) => affected[i] = count,
            Err((row, source)) => {
                // After a conflict the transaction is already gone and rollback reports an
                // error; that is expected and harmless.
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::debug!(error = %rollback_error, "rollback after failed batch");
                }
                return Err(insert_failure(source, row, i, job));
            }
        }
    }
    tx.commit().await.map_err(classify)?;
    Ok(affected)
}

/// `{"rows": {"submitted", "affected"}, "batches": {"<table>": {"submitted", "affected"}}}`.
///
/// `batches` is keyed by table; if several steps write the same table their counts are added up.
fn batch_response(job: &BatchJob, affected: &[u64]) -> JsonValue {
    let mut tables: Vec<(String, u64, u64)> = Vec::new();
    for (plan, &affected) in job.steps.iter().zip(affected) {
        let submitted = plan.rows.len() as u64;
        match tables
            .iter_mut()
            .find(|(name, ..)| eq_ci(name, plan.table.as_str()))
        {
            Some(entry) => {
                entry.1 += submitted;
                entry.2 += affected;
            }
            None => tables.push((plan.table.as_str().to_owned(), submitted, affected)),
        }
    }
    let submitted: u64 = tables.iter().map(|t| t.1).sum();
    let affected: u64 = tables.iter().map(|t| t.2).sum();
    let batches: Map<String, JsonValue> = tables
        .into_iter()
        .map(|(name, submitted, affected)| {
            (
                name,
                json!({ "submitted": submitted, "affected": affected }),
            )
        })
        .collect();
    json!({ "rows": { "submitted": submitted, "affected": affected }, "batches": batches })
}

/// Pause before re-running a conflicted request: half fixed, half random ("equal jitter"),
/// growing with the attempt number up to 64 ms. The random part keeps transactions that just
/// conflicted from colliding again in lockstep; the fixed part guarantees a minimum wait.
fn conflict_backoff(attempt: u32) -> Duration {
    let ceiling_ms = 1_u64 << attempt.clamp(1, 6);
    let half = ceiling_ms / 2;
    let jitter = u64::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()),
    );
    Duration::from_millis(half + jitter % (half + 1))
}

/// Runs `attempt` until it succeeds or fails for good. After losing a write-write conflict the
/// whole attempt (new connection, new snapshot, new transaction) is run again, a few times with
/// a short randomized pause; if it keeps losing the caller gets `WriteConflict`.
async fn with_conflict_retries<T, F, Fut>(mut attempt: F) -> ApiResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Failure>>,
{
    for n in 1..=MAX_WRITE_ATTEMPTS {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(Failure::Api(error)) => return Err(error),
            Err(Failure::Conflict) => {
                tracing::debug!(attempt = n, "lost a write-write conflict; retrying");
                tokio::time::sleep(conflict_backoff(n)).await;
            }
        }
    }
    warn!(
        attempts = MAX_WRITE_ATTEMPTS,
        "gave up after repeated write conflicts"
    );
    Err(ApiError::WriteConflict)
}

async fn run_batches(db: &Db, job: BatchJob) -> ApiResult<JsonValue> {
    // A request without any rows is a valid no-op; do not open a transaction.
    if job.steps.iter().all(|step| step.rows.is_empty()) {
        return Ok(batch_response(&job, &vec![0; job.steps.len()]));
    }

    // Under MVCC writers run in parallel. Without it SQLite has a single write lock, so queue.
    let _serial = if db.mvcc {
        None
    } else {
        Some(db.write_lock.lock().await)
    };

    let affected = with_conflict_retries(|| attempt_batches(db, &job)).await?;
    Ok(batch_response(&job, &affected))
}

async fn batch(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<JsonValue>,
) -> ApiResult<Json<JsonValue>> {
    let job = parse_batch_body(body, &state.limits)?;
    let db = state.db.clone();
    let response = spawn_db(async move { run_batches(&db, job).await }).await?;
    info!(
        rows = %response["rows"]["submitted"],
        tables = response["batches"].as_object().map_or(0, Map::len),
        "batch committed"
    );
    Ok(Json(response))
}

// ---------------------------------------------------------------------------------------------
// POST /v1/delete
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRequest {
    table: String,
    /// Same grammar as `/v1/query`. Required, unless `all` is true.
    #[serde(default)]
    filters: Map<String, JsonValue>,
    /// Must be set to delete every row; it cannot be combined with `filters`.
    #[serde(default)]
    all: bool,
    /// Safety guard: if more rows than this would be deleted, nothing is deleted (409).
    max_rows: Option<u64>,
}

/// The most rows a delete may remove, and where that number comes from (for the error message).
struct RowLimit {
    max: u64,
    source: &'static str,
}

struct DeletePlan {
    table: Ident,
    filters: FilterPlan,
    limit: Option<RowLimit>,
}

impl DeletePlan {
    /// `server_cap` is the `MAX_DELETE_ROWS` setting; the request's `max_rows` can only lower it.
    fn from_request(req: DeleteRequest, server_cap: Option<usize>) -> ApiResult<Self> {
        let table = Ident::parse("table", &req.table)?;
        let filters = FilterPlan::parse(&req.filters)?;
        match (filters.is_empty(), req.all) {
            (true, false) => {
                return Err(ApiError::bad(
                    "filters are required; to delete every row set \"all\": true",
                ));
            }
            (false, true) => {
                return Err(ApiError::bad(
                    "\"all\": true cannot be combined with filters",
                ));
            }
            _ => {}
        }
        if req.max_rows == Some(0) {
            return Err(ApiError::bad("max_rows must be at least 1"));
        }
        let from_request = req.max_rows.map(|max| RowLimit {
            max,
            source: "max_rows",
        });
        let from_server = server_cap.map(|cap| RowLimit {
            max: cap as u64,
            source: "MAX_DELETE_ROWS",
        });
        let limit = match (from_request, from_server) {
            (Some(a), Some(b)) => Some(if b.max < a.max { b } else { a }),
            (a, b) => a.or(b),
        };
        Ok(Self {
            table,
            filters,
            limit,
        })
    }

    fn sql(&self) -> (String, Vec<DbValue>) {
        let mut sql = format!("DELETE FROM {}", self.table.quoted());
        let mut params = Vec::new();
        let clauses = self.filters.clauses(&mut params);
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        (sql, params)
    }
}

/// One complete try: check the table and columns, delete inside a transaction, and roll the
/// whole thing back if it removed more rows than allowed. Returns the number of rows deleted.
async fn attempt_delete(db: &Db, plan: &DeletePlan) -> Result<u64, Failure> {
    let mut conn = db.connect().await.map_err(classify)?;
    let info = require_table(&conn, &plan.table).await?;
    require_columns(
        &info,
        &plan.table,
        &plan.filters.columns().collect::<Vec<_>>(),
    )?;

    let (sql, params) = plan.sql();
    let behavior = if db.mvcc {
        TransactionBehavior::Concurrent
    } else {
        TransactionBehavior::Immediate
    };
    let tx = conn
        .transaction_with_behavior(behavior)
        .await
        .map_err(classify)?;
    let deleted = match tx.execute(&sql, params_from_iter(params)).await {
        Ok(count) => count,
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::debug!(error = %rollback_error, "rollback after failed delete");
            }
            if let turso::Error::Constraint(detail) = &error
                && is_foreign_key_violation(detail)
            {
                warn!(%detail, "delete blocked by a foreign key");
                return Err(Failure::Api(ApiError::Conflict(
                    "some of the rows to delete are still referenced by rows in other tables (foreign key); nothing was deleted".into(),
                )));
            }
            return Err(classify(error));
        }
    };
    if let Some(limit) = &plan.limit
        && deleted > limit.max
    {
        if let Err(rollback_error) = tx.rollback().await {
            error!(error = %rollback_error, "rollback failed");
        }
        return Err(Failure::Api(ApiError::TooManyRows(format!(
            "the delete would remove {deleted} rows, more than the {} limit of {}; nothing was deleted",
            limit.source, limit.max
        ))));
    }
    tx.commit().await.map_err(classify)?;
    Ok(deleted)
}

async fn run_delete(db: &Db, plan: DeletePlan) -> ApiResult<u64> {
    let _serial = if db.mvcc {
        None
    } else {
        Some(db.write_lock.lock().await)
    };
    with_conflict_retries(|| attempt_delete(db, &plan)).await
}

async fn delete_rows(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<DeleteRequest>,
) -> ApiResult<Json<JsonValue>> {
    let plan = DeletePlan::from_request(req, state.limits.max_delete_rows)?;
    let table = plan.table.clone();
    let db = state.db.clone();
    let deleted = spawn_db(async move { run_delete(&db, plan).await }).await?;
    info!(table = table.as_str(), deleted, "delete");
    Ok(Json(json!({ "rows": { "deleted": deleted } })))
}

// ---------------------------------------------------------------------------------------------
// GET /v1/schema
// ---------------------------------------------------------------------------------------------

/// Describes every table the API can address: its columns, primary key, foreign keys and indexes,
/// in the vocabulary of `POST /v1/tables` and `POST /v1/indexes`.
///
/// Tables Bonny cannot address are left out: the engine's own bookkeeping tables, anything with a
/// reserved prefix, and names outside the identifier rules. Of the indexes only those made with
/// `CREATE INDEX` are listed; the automatic ones for the primary key and for UNIQUE constraints
/// are implied by `primary_key`. Composite foreign keys (which Bonny cannot create) are not shown.
async fn build_schema(conn: &Connection) -> ApiResult<JsonValue> {
    let (_, names) = fetch_all(
        conn,
        "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
        vec![],
    )
    .await
    .map_err(db_err)?;

    let mut tables = Vec::new();
    for row in &names {
        let Ok(name) = Ident::parse("table", &text_at(row, 0)) else {
            continue;
        };
        let Some(info) = load_table(conn, &name).await? else {
            continue;
        };
        let primary_key = info.primary_key();

        // Foreign keys with a single column become `references` on that column.
        let key_rows = foreign_key_rows(conn, &name).await?;
        let single_column_keys: Vec<&ForeignKeyRow> = key_rows
            .iter()
            .filter(|r| key_rows.iter().filter(|o| o.id == r.id).count() == 1)
            .collect();

        let columns: Vec<JsonValue> = info
            .columns
            .iter()
            .map(|c| {
                let mut column = Map::new();
                column.insert("name".into(), json!(c.name));
                column.insert("type".into(), json!(c.decl_type));
                // Key columns can never be NULL (an INTEGER key is a rowid alias).
                column.insert("nullable".into(), json!(!c.not_null && c.pk == 0));
                // A lone INTEGER key is filled in by the database when an insert leaves it out.
                column.insert(
                    "auto_id".into(),
                    json!(primary_key.len() == 1 && c.pk == 1 && c.decl_type == "INTEGER"),
                );
                if let Some(fk) = single_column_keys.iter().find(|k| eq_ci(&k.from, &c.name)) {
                    let target = if fk.to.is_empty() {
                        JsonValue::Null
                    } else {
                        json!(fk.to)
                    };
                    column.insert(
                        "references".into(),
                        json!({ "table": fk.table, "column": target }),
                    );
                }
                JsonValue::Object(column)
            })
            .collect();

        let mut indexes = list_indexes(conn, &name).await?;
        indexes.retain(|i| i.origin == "c");
        indexes.sort_by(|a, b| a.name.cmp(&b.name));
        let mut index_list = Vec::new();
        for index in indexes {
            let columns: Vec<JsonValue> = index_columns(conn, &index.name)
                .await?
                .into_iter()
                // An expression index has no column name for that position.
                .map(|c| {
                    if c.is_empty() {
                        JsonValue::Null
                    } else {
                        json!(c)
                    }
                })
                .collect();
            let mut entry = Map::new();
            entry.insert("name".into(), json!(index.name));
            entry.insert("unique".into(), json!(index.unique));
            entry.insert("columns".into(), JsonValue::Array(columns));
            if index.partial {
                entry.insert("partial".into(), json!(true));
            }
            index_list.push(JsonValue::Object(entry));
        }

        tables.push(json!({
            "name": name.as_str(),
            "primary_key": primary_key,
            "columns": columns,
            "indexes": index_list,
        }));
    }
    Ok(json!({ "tables": tables }))
}

async fn load_schema(db: &Db) -> ApiResult<JsonValue> {
    let mut conn = db.connect().await.map_err(db_err)?;
    // One transaction, so the whole listing comes from a single consistent snapshot even if
    // tables or indexes are being created at the same time.
    let tx = conn.transaction().await.map_err(db_err)?;
    let schema = build_schema(&tx).await;
    if let Err(error) = tx.rollback().await {
        tracing::debug!(%error, "closing the read transaction of a schema listing");
    }
    schema
}

async fn schema(State(state): State<Arc<AppState>>) -> ApiResult<Json<JsonValue>> {
    let db = state.db.clone();
    Ok(Json(spawn_db(async move { load_schema(&db).await }).await?))
}

// ---------------------------------------------------------------------------------------------
// Sync endpoints
// ---------------------------------------------------------------------------------------------

async fn sync_push(State(state): State<Arc<AppState>>) -> ApiResult<Json<JsonValue>> {
    let db = state.db.clone();
    spawn_db(async move { db.push().await }).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn sync_pull(State(state): State<Arc<AppState>>) -> ApiResult<Json<JsonValue>> {
    let db = state.db.clone();
    let changed = spawn_db(async move { db.pull().await }).await?;
    Ok(Json(json!({ "ok": true, "changed": changed })))
}

async fn sync_status(State(state): State<Arc<AppState>>) -> ApiResult<Json<JsonValue>> {
    let replica = state.db.replica()?;
    let sync = state.db.sync_snapshot();
    let stats = replica.stats().await.map_err(db_err)?;
    Ok(Json(json!({
        "ok": sync.last_error.is_none(),
        "last_push_unix": sync.last_push_unix,
        "last_pull_unix": sync.last_pull_unix,
        "last_error": sync.last_error,
        "last_error_unix": sync.last_error_unix,
        "consecutive_failures": sync.consecutive_failures,
        "pending_local_changes": stats.cdc_operations,
        "revision": stats.revision,
        "network_sent_bytes": stats.network_sent_bytes,
        "network_received_bytes": stats.network_received_bytes,
    })))
}

/// Background push-then-pull loop. Local commits are not durable remotely until pushed, so in
/// replica mode this runs unless `SYNC_INTERVAL_SECS=0`. Failures are recorded for
/// `GET /v1/sync/status` and retried on the next tick.
async fn sync_worker(db: Arc<Db>, interval: Duration, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let db = db.clone();
                // Run on its own task so shutdown never interrupts a sync midway.
                let outcome = tokio::spawn(async move {
                    db.push().await?;
                    db.pull().await.map(|_| ())
                }).await;
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(error = %e, "background sync failed"),
                    Err(e) => error!(error = %e, "background sync task panicked"),
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Router, middleware and probes
// ---------------------------------------------------------------------------------------------

struct AppState {
    db: Arc<Db>,
    /// `None` means authentication is disabled and the middleware is not installed.
    api_key: Option<String>,
    limiter: Arc<Semaphore>,
    request_timeout: Duration,
    limits: Limits,
}

/// Compares in time that depends only on the longer input, not on where they first differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    std::hint::black_box(diff) == 0
}

/// Accepts the key as `x-api-key: <key>` or `authorization: Bearer <key>`.
async fn require_api_key(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });
    match (provided, state.api_key.as_deref()) {
        (Some(key), Some(expected)) if constant_time_eq(key.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => ApiError::Unauthorized.into_response(),
    }
}

/// Sheds load with 429 once too many authenticated requests are in flight.
async fn limit_concurrency(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    match state.limiter.clone().try_acquire_owned() {
        Ok(_permit) => next.run(req).await,
        Err(_) => ApiError::TooManyRequests.into_response(),
    }
}

/// Note that database work keeps running after a timeout (see [`spawn_db`]): a 504 means the
/// outcome is unknown, not that the operation failed.
async fn enforce_timeout(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(state.request_timeout, next.run(req)).await {
        Ok(response) => response,
        Err(_) => ApiError::Timeout.into_response(),
    }
}

/// Logs method, path and status only. Headers (and therefore credentials) are never logged.
async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = std::time::Instant::now();
    let response = next.run(req).await;
    info!(%method, %path, status = response.status().as_u16(), elapsed_ms = started.elapsed().as_millis() as u64, "request");
    response
}

async fn health() -> Json<JsonValue> {
    Json(json!({ "ok": true }))
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let check = async {
        let conn = state.db.connect().await?;
        fetch_all(&conn, "SELECT 1", vec![]).await?;
        journal_mode(&conn).await
    };
    let result = tokio::time::timeout(READY_TIMEOUT, check).await;
    let sync = state.db.sync_snapshot();
    match result {
        Ok(Ok(journal_mode)) => Json(json!({
            "ok": true,
            "mode": state.db.mode(),
            "journal_mode": journal_mode,
            "sync_consecutive_failures": sync.consecutive_failures,
        }))
        .into_response(),
        Ok(Err(e)) => {
            error!(error = %e, "readiness check failed");
            ApiError::Unavailable("database unavailable".into()).into_response()
        }
        Err(_) => ApiError::Unavailable("database check timed out".into()).into_response(),
    }
}

fn app(state: Arc<AppState>) -> Router {
    let mut v1 = Router::new()
        .route("/tables", post(create_table))
        .route("/table", patch(patch_table))
        .route("/indexes", post(create_index))
        .route("/index", delete(drop_index))
        .route("/query", post(query))
        .route("/batch", post(batch))
        .route("/delete", post(delete_rows))
        .route("/schema", get(schema));

    // Features without configuration are not exposed at all: the sync routes exist only when a
    // remote database is configured (otherwise they are plain 404s).
    if state.db.is_replica() {
        v1 = v1
            .route("/sync/push", post(sync_push))
            .route("/sync/pull", post(sync_pull))
            .route("/sync/status", get(sync_status));
    }

    // Layers added later wrap earlier ones: auth runs first, then load shedding, then timeout.
    v1 = v1
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_timeout,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_concurrency,
        ));
    if state.api_key.is_some() {
        v1 = v1.route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));
    }

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .nest("/v1", v1)
        .fallback(|| async { ApiError::NotFound("no such route".into()) })
        .layer(DefaultBodyLimit::max(state.limits.max_body_bytes))
        .layer(middleware::from_fn(log_requests))
        .with_state(state)
}

// ---------------------------------------------------------------------------------------------
// Startup and shutdown
// ---------------------------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

async fn run() -> Result<(), String> {
    let config = Config::from_env()?;

    let db = Arc::new(match &config.replica {
        Some(replica) => Db::open_replica(&config.local_path, replica).await?,
        None => Db::open_local(&config.local_path, config.io_mode).await?,
    });

    if config.api_key.is_none() {
        warn!(
            "authentication is DISABLED (API_KEY is not set); acceptable for local development only"
        );
    }

    let state = Arc::new(AppState {
        db: db.clone(),
        api_key: config.api_key,
        limiter: Arc::new(Semaphore::new(config.max_concurrent_requests)),
        request_timeout: config.request_timeout,
        limits: config.limits,
    });

    let (stop_tx, stop_rx) = watch::channel(false);
    let worker = config
        .sync_interval
        .map(|interval| tokio::spawn(sync_worker(db.clone(), interval, stop_rx)));

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", config.listen_addr))?;
    info!(address = %config.listen_addr, mode = db.mode(), path = %config.local_path, io = ?config.io_mode, "listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))?;

    let _ = stop_tx.send(true);
    if let Some(worker) = worker {
        let _ = worker.await;
    }
    if db.is_replica() {
        // Best effort: do not leave committed local writes unpushed on a clean shutdown.
        match tokio::time::timeout(SHUTDOWN_PUSH_TIMEOUT, db.push()).await {
            Ok(Ok(())) => info!("final push complete"),
            Ok(Err(e)) => warn!(error = %e, "final push failed"),
            Err(_) => warn!("final push timed out"),
        }
    }
    info!("stopped");
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
