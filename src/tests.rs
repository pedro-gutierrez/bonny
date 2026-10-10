//! Tests for Bonny. Declared from `main.rs` as `#[cfg(test)] mod tests;`, so they can reach the
//! private items of the binary through `use super::*`.
//!
//! Layout: unit tests for identifiers, values, config and request planning come first, then
//! HTTP-level integration tests that drive the real router against a temporary on-disk database,
//! then the optional replica test that needs a real remote.

use super::*;
use axum::{body::Body, http::Method};
use tower::ServiceExt;

const KEY: &str = "test-api-key-0123456789-abcdefghijkl";

// ----- unit: identifiers -----

#[test]
fn identifiers_accept_plain_names() {
    for ok in [
        "a",
        "_x",
        "financial_metrics",
        "T1",
        &"a".repeat(MAX_IDENT_LEN),
    ] {
        assert!(Ident::parse("t", ok).is_ok(), "{ok}");
    }
    assert_eq!(Ident::parse("t", "abc").unwrap().quoted(), "\"abc\"");
}

#[test]
fn identifiers_reject_injection_and_reserved_names() {
    for bad in [
        "",
        "1abc",
        "a b",
        "a-b",
        "a\"b",
        "a;DROP TABLE x",
        "x\"; DROP TABLE y; --",
        "é",
        "sqlite_master",
        "SQLITE_schema",
        "turso_cdc",
        "__turso_internal_mvcc_meta",
        &"a".repeat(MAX_IDENT_LEN + 1),
    ] {
        assert!(Ident::parse("t", bad).is_err(), "{bad:?}");
    }
}

#[test]
fn identifier_lists_reject_duplicates_case_insensitively() {
    let names = vec!["a".to_string(), "A".to_string()];
    assert!(parse_idents("column", &names, 10).is_err());
    let too_many: Vec<String> = (0..5).map(|i| format!("c{i}")).collect();
    assert!(parse_idents("column", &too_many, 4).is_err());
}

// ----- unit: values -----

fn conv(json: &str) -> Result<DbValue, String> {
    db_value(&serde_json::from_str(json).unwrap())
}

#[test]
fn json_to_db_values() {
    assert_eq!(conv("null"), Ok(DbValue::Null));
    assert_eq!(conv("true"), Ok(DbValue::Integer(1)));
    assert_eq!(conv("false"), Ok(DbValue::Integer(0)));
    assert_eq!(conv("42"), Ok(DbValue::Integer(42)));
    assert_eq!(conv("-9223372036854775808"), Ok(DbValue::Integer(i64::MIN)));
    assert_eq!(conv("9223372036854775807"), Ok(DbValue::Integer(i64::MAX)));
    assert_eq!(conv("90753.0"), Ok(DbValue::Real(90753.0)));
    assert_eq!(conv("1e3"), Ok(DbValue::Real(1000.0)));
    assert_eq!(conv("\"hi\""), Ok(DbValue::Text("hi".into())));
}

#[test]
fn json_to_db_rejects_unrepresentable_values() {
    assert!(conv("9223372036854775808").is_err(), "u64 above i64::MAX");
    assert!(conv("18446744073709551616").is_err(), "above u64::MAX");
    assert!(conv("-9223372036854775809").is_err(), "below i64::MIN");
    assert!(conv("1e999").is_err(), "non-finite float");
    assert!(conv("[1,2]").is_err());
    assert!(conv("{\"a\":1}").is_err());
    assert!(conv("{\"$type\":\"blob\"}").is_err());
    assert!(conv("{\"$type\":\"blob\",\"base64\":\"!!\"}").is_err());
    assert!(conv("{\"$type\":\"blob\",\"base64\":\"AA==\",\"x\":1}").is_err());
}

#[test]
fn blobs_round_trip_as_tagged_objects() {
    let value = conv("{\"$type\":\"blob\",\"base64\":\"AAEC\"}").unwrap();
    assert_eq!(value, DbValue::Blob(vec![0, 1, 2]));
    assert_eq!(
        json_value(value),
        json!({"$type": "blob", "base64": "AAEC"})
    );
}

#[test]
fn db_to_json_values() {
    assert_eq!(json_value(DbValue::Null), JsonValue::Null);
    assert_eq!(json_value(DbValue::Integer(7)), json!(7));
    assert_eq!(json_value(DbValue::Real(1.5)), json!(1.5));
    assert_eq!(json_value(DbValue::Real(f64::INFINITY)), JsonValue::Null);
    assert_eq!(json_value(DbValue::Text("x".into())), json!("x"));
    assert_eq!(
        serde_json::to_string(&json_value(DbValue::Real(90753.0))).unwrap(),
        "90753.0"
    );
}

// ----- unit: auth and config -----

#[test]
fn constant_time_eq_behaves_like_eq() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(!constant_time_eq(b"secret", b"secreT"));
    assert!(!constant_time_eq(b"secret", b"secre"));
    assert!(!constant_time_eq(b"secre", b"secret"));
    assert!(!constant_time_eq(b"abc", b"abc\0"));
    assert!(constant_time_eq(b"", b""));
}

fn config(vars: &[(&str, &str)]) -> Result<Config, String> {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Config::from_lookup(|key| vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()))
}

#[test]
fn config_needs_no_variables_for_local_development() {
    let c = config(&[]).unwrap();
    assert!(c.api_key.is_none());
    assert!(c.replica.is_none());
    assert!(c.sync_interval.is_none());
    assert_eq!(c.local_path, "bonny.db");
    assert_eq!(c.listen_addr.to_string(), "127.0.0.1:3000");
    assert_eq!(c.io_mode, IoMode::Default);
}

#[test]
fn config_refuses_no_auth_on_a_public_address() {
    for addr in ["0.0.0.0:3000", "192.168.1.5:3000", "[::]:3000"] {
        assert!(config(&[("LISTEN_ADDR", addr)]).is_err(), "{addr}");
        assert!(
            config(&[("LISTEN_ADDR", addr), ("API_KEY", KEY)]).is_ok(),
            "{addr}"
        );
    }
    assert!(config(&[("LISTEN_ADDR", "127.0.0.1:8080")]).is_ok());
    assert!(config(&[("LISTEN_ADDR", "[::1]:8080")]).is_ok());
}

#[test]
fn config_requires_a_strong_api_key_when_one_is_given() {
    // Set-but-blank is a misconfiguration, not "disabled".
    assert!(config(&[("API_KEY", "")]).is_err());
    assert!(config(&[("API_KEY", "   ")]).is_err());
    assert!(config(&[("API_KEY", "short")]).is_err());
    assert!(config(&[("API_KEY", &"a".repeat(64))]).is_err());
    assert!(config(&[("API_KEY", KEY)]).is_ok());
}

#[test]
fn config_io_backend() {
    let base = [("API_KEY", KEY)];
    assert_eq!(config(&base).unwrap().io_mode, IoMode::Default);
    let with = |v: &'static str| config(&[("API_KEY", KEY), ("IO_BACKEND", v)]);
    assert_eq!(with("io_uring").unwrap().io_mode, IoMode::IoUring);
    assert_eq!(with(" SysCall ").unwrap().io_mode, IoMode::Syscall);
    assert_eq!(with("default").unwrap().io_mode, IoMode::Default);
    // `memory` would silently lose data, so it is not selectable.
    assert!(with("memory").is_err());
    assert!(with("nope").is_err());
    // Not supported by the replica builder: fail instead of silently ignoring.
    let replica = |io: &'static str| {
        config(&[
            ("API_KEY", KEY),
            ("TURSO_DATABASE_URL", "libsql://x"),
            ("TURSO_AUTH_TOKEN", "t"),
            ("IO_BACKEND", io),
        ])
    };
    assert!(replica("io_uring").is_err());
    assert!(replica("default").is_ok());
}

#[tokio::test]
async fn syscall_backend_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    let db = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::Syscall)
            .await
            .unwrap(),
    );
    let router = app(state_for(db));
    let (status, _) = call(
        &router,
        Method::POST,
        "/v1/tables",
        Some(KEY),
        Some(json!({"name": "t", "columns": [{"name": "a", "type": "INTEGER"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// Needs a Linux kernel (>= 5.1) that allows io_uring; Docker's default seccomp profile and
/// some hardened kernels block it, in which case this test fails by design.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn io_uring_backend_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uring.db");
    let db = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::IoUring)
            .await
            .unwrap(),
    );
    let router = app(state_for(db));
    let (status, body) = call(&router, Method::POST, "/v1/tables", Some(KEY), Some(json!({"name": "t", "columns": [{"name": "a", "type": "INTEGER"}], "primary_key": ["a"]}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let rows: Vec<JsonValue> = (0..200).map(|i| json!([i])).collect();
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/batch",
        Some(KEY),
        Some(json!({"table": "t", "columns": ["a"], "rows": rows})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Off Linux the request must fail loudly at open, never fall back silently.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn io_uring_backend_errors_off_linux() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uring.db");
    let err = Db::open_local(path.to_str().unwrap(), IoMode::IoUring)
        .await
        .err()
        .expect("io_uring must be rejected off Linux");
    assert!(err.contains("io_uring"), "{err}");
}

#[test]
fn config_modes_and_defaults() {
    let local = config(&[("API_KEY", KEY)]).unwrap();
    assert!(local.replica.is_none());
    assert!(local.sync_interval.is_none());
    assert_eq!(local.listen_addr.to_string(), "127.0.0.1:3000");

    // URL without token is an error, never a silent fallback to local mode.
    assert!(config(&[("API_KEY", KEY), ("TURSO_DATABASE_URL", "libsql://x")]).is_err());

    let replica = config(&[
        ("API_KEY", KEY),
        ("TURSO_DATABASE_URL", "libsql://x"),
        ("TURSO_AUTH_TOKEN", "t"),
    ])
    .unwrap();
    assert!(replica.replica.is_some());
    assert_eq!(replica.sync_interval, Some(Duration::from_secs(30)));

    let no_worker = config(&[
        ("API_KEY", KEY),
        ("TURSO_DATABASE_URL", "libsql://x"),
        ("TURSO_AUTH_TOKEN", "t"),
        ("SYNC_INTERVAL_SECS", "0"),
    ])
    .unwrap();
    assert!(no_worker.sync_interval.is_none());

    assert!(config(&[("API_KEY", KEY), ("LISTEN_ADDR", "nope")]).is_err());
    assert!(config(&[("API_KEY", KEY), ("REQUEST_TIMEOUT_SECS", "abc")]).is_err());
}

// ----- unit: request planning -----

fn table_request(v: JsonValue) -> ApiResult<TablePlan> {
    TablePlan::from_request(serde_json::from_value(v).unwrap())
}

#[test]
fn table_plan_generates_sql() {
    let plan = table_request(metrics_table()).unwrap();
    assert_eq!(
        plan.create_sql(),
        "CREATE TABLE \"financial_metrics\" (\"ticker\" TEXT NOT NULL, \"metric\" TEXT NOT NULL, \"period\" TEXT NOT NULL, \"value\" REAL, PRIMARY KEY (\"ticker\", \"metric\", \"period\"))"
    );
}

#[test]
fn table_plan_validation() {
    let col = |n: &str, t: &str| json!({"name": n, "type": t});
    assert!(table_request(json!({"name": "t", "columns": []})).is_err());
    assert!(table_request(json!({"name": "t", "columns": [col("a", "VARCHAR")]})).is_err());
    assert!(
        table_request(json!({"name": "t", "columns": [col("a", "TEXT"), col("A", "TEXT")]}))
            .is_err()
    );
    assert!(
        table_request(json!({"name": "t", "columns": [col("a", "TEXT")], "primary_key": ["b"]}))
            .is_err()
    );
    assert!(
        table_request(
            json!({"name": "t", "columns": [col("a", "TEXT")], "primary_key": ["a", "a"]})
        )
        .is_err()
    );
    assert!(
        table_request(json!({"name": "t", "columns": [{"name": "a", "type": "TEXT", "nullable": true}], "primary_key": ["a"]}))
            .is_err()
    );
    assert!(table_request(json!({"name": "t", "columns": [col("a", "text")]})).is_ok());
}

fn batch_request(v: JsonValue) -> ApiResult<BatchPlan> {
    BatchPlan::from_request(serde_json::from_value(v).unwrap())
}

#[test]
fn batch_plan_validation() {
    let ok = json!({"table": "t", "columns": ["a", "b"], "rows": [[1, 2]]});
    assert!(batch_request(ok).is_ok());
    assert!(batch_request(json!({"table": "t", "columns": [], "rows": []})).is_err());
    assert!(batch_request(json!({"table": "t", "columns": ["a", "a"], "rows": []})).is_err());
    assert!(batch_request(json!({"table": "t", "columns": ["a", "b"], "rows": [[1]]})).is_err());
    assert!(batch_request(json!({"table": "t", "columns": ["a"], "rows": [[[1]]]})).is_err());
    // conflict_target only makes sense for upserts; replace needs columns from the batch.
    assert!(
        batch_request(
            json!({"table": "t", "columns": ["a"], "rows": [], "conflict_target": ["a"]})
        )
        .is_err()
    );
    assert!(
        batch_request(
            json!({"table": "t", "columns": ["a"], "rows": [], "on_conflict": {"replace": []}})
        )
        .is_err()
    );
    assert!(
        batch_request(
            json!({"table": "t", "columns": ["a"], "rows": [], "on_conflict": {"replace": ["z"]}})
        )
        .is_err()
    );
    assert!(
        batch_request(json!({"table": "t", "columns": ["a"], "rows": [], "on_conflict": "ignore"}))
            .is_ok()
    );
    assert!(
        batch_request(
            json!({"table": "t", "columns": ["a"], "rows": [], "on_conflict": "nothing"})
        )
        .is_ok()
    );
}

#[test]
fn query_plan_sql_and_validation() {
    let plan = QueryPlan::from_request(
        serde_json::from_value(json!({
            "table": "t",
            "columns": ["a"],
            "filters": {"x": 1, "y": null, "z": "s"},
            "sort": [{"a": "desc"}],
            "limit": 10,
            "offset": 5
        }))
        .unwrap(),
    )
    .unwrap();
    let (sql, params) = plan.sql();
    assert_eq!(
        sql,
        "SELECT \"a\" FROM \"t\" WHERE \"x\" = ?1 AND \"y\" IS NULL AND \"z\" = ?2 ORDER BY \"a\" DESC LIMIT 10 OFFSET 5"
    );
    assert_eq!(params, vec![DbValue::Integer(1), DbValue::Text("s".into())]);

    let bad = |v: JsonValue| QueryPlan::from_request(serde_json::from_value(v).unwrap()).is_err();
    assert!(bad(json!({"table": "t", "limit": 0})));
    assert!(bad(json!({"table": "t", "limit": MAX_QUERY_ROWS + 1})));
    assert!(bad(json!({"table": "t", "offset": 1})), "offset needs sort");
    assert!(bad(json!({"table": "t", "filters": {"a": [1]}})));
    assert!(bad(json!({"table": "t", "filters": {"a b": 1}})));
    assert!(bad(json!({"table": "t", "columns": ["a", "a"]})));
}

// ----- integration: HTTP against a temporary on-disk database -----

struct TestApp {
    router: Router,
    db: Arc<Db>,
    dir: tempfile::TempDir,
}

fn state_for(db: Arc<Db>) -> Arc<AppState> {
    Arc::new(AppState {
        db,
        api_key: Some(KEY.to_string()),
        limiter: Arc::new(Semaphore::new(64)),
        request_timeout: Duration::from_secs(30),
        limits: Limits::default(),
    })
}

impl TestApp {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Arc::new(
            Db::open_local(path.to_str().unwrap(), IoMode::Default)
                .await
                .unwrap(),
        );
        Self {
            router: app(state_for(db.clone())),
            db,
            dir,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<JsonValue>,
    ) -> (StatusCode, JsonValue) {
        call(&self.router, method, path, key, body).await
    }

    async fn post(&self, path: &str, body: JsonValue) -> (StatusCode, JsonValue) {
        self.call(Method::POST, path, Some(KEY), Some(body)).await
    }

    async fn create_metrics(&self) {
        let (status, body) = self.post("/v1/tables", metrics_table()).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    async fn insert(&self, rows: JsonValue) -> (StatusCode, JsonValue) {
        self.post(
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows}),
        )
        .await
    }

    async fn all_rows(&self) -> Vec<JsonValue> {
        let (status, body) = self
            .post(
                "/v1/query",
                json!({"table": "financial_metrics", "sort": [{"period": "asc"}], "limit": MAX_QUERY_ROWS}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rows"].as_array().unwrap().clone()
    }
}

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    key: Option<&str>,
    body: Option<JsonValue>,
) -> (StatusCode, JsonValue) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        builder = builder.header("x-api-key", key);
    }
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    raw(router, request).await
}

async fn raw(router: &Router, request: Request<Body>) -> (StatusCode, JsonValue) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    // An empty body (e.g. 204 No Content) is reported as `null`.
    let json = if bytes.is_empty() {
        JsonValue::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("non-JSON body: {bytes:?}"))
    };
    (status, json)
}

fn metrics_table() -> JsonValue {
    json!({
        "name": "financial_metrics",
        "columns": [
            {"name": "ticker", "type": "TEXT"},
            {"name": "metric", "type": "TEXT"},
            {"name": "period", "type": "TEXT"},
            {"name": "value", "type": "REAL", "nullable": true}
        ],
        "primary_key": ["ticker", "metric", "period"]
    })
}

#[tokio::test]
async fn health_and_ready_need_no_key() {
    let t = TestApp::new().await;
    let (status, body) = t.call(Method::GET, "/health", None, None).await;
    assert_eq!((status, body), (StatusCode::OK, json!({"ok": true})));
    let (status, body) = t.call(Method::GET, "/ready", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mode"], "local");
    assert_eq!(
        body["journal_mode"], "mvcc",
        "local databases run in MVCC mode"
    );
}

#[tokio::test]
async fn api_requires_a_valid_key() {
    let t = TestApp::new().await;
    let (status, body) = t
        .call(Method::POST, "/v1/query", None, Some(json!({"table": "t"})))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "unauthorized");
    let (status, _) = t
        .call(Method::POST, "/v1/query", Some("wrong"), Some(json!({})))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "auth must run before body parsing"
    );
    let (status, _) = t
        .call(Method::POST, "/v1/query", Some(&KEY[..KEY.len() - 1]), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bearer scheme is accepted too.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/query")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"table": "missing"}).to_string()))
        .unwrap();
    let (status, _) = raw(&t.router, request).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "authenticated, then table lookup"
    );
}

#[tokio::test]
async fn unknown_routes_return_json_404() {
    let t = TestApp::new().await;
    let (status, body) = t.call(Method::GET, "/nope", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn create_table_answers_204_and_is_idempotent() {
    let t = TestApp::new().await;
    let (status, body) = t.post("/v1/tables", metrics_table()).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));
    t.insert(json!([["A", "m", "p1", 1.0]])).await;

    // Repeating an identical request is accepted, answers the same, and must not recreate
    // (and thereby empty) the table.
    let (status, body) = t.post("/v1/tables", metrics_table()).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));
    assert_eq!(t.all_rows().await.len(), 1);

    let mut different = metrics_table();
    different["columns"][3]["type"] = json!("TEXT");
    let (status, body) = t.post("/v1/tables", different).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let mut other_key = metrics_table();
    other_key["primary_key"] = json!(["ticker", "metric"]);
    let (status, _) = t.post("/v1/tables", other_key).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let mut not_null = metrics_table();
    not_null["columns"][3]["nullable"] = json!(false);
    let (status, _) = t.post("/v1/tables", not_null).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_table_rejects_bad_input() {
    let t = TestApp::new().await;
    let (status, _) = t
        .post(
            "/v1/tables",
            json!({"name": "x\"; DROP TABLE y; --", "columns": [{"name": "a", "type": "TEXT"}]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = t
        .post(
            "/v1/tables",
            json!({"name": "x", "columns": [{"name": "a", "type": "TEXT; DROP"}]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ----- primary key modes -----

fn key_table(primary_key: Option<JsonValue>) -> ApiResult<TablePlan> {
    let mut request = json!({"name": "t", "columns": [{"name": "a", "type": "TEXT"}]});
    if let Some(value) = primary_key {
        request["primary_key"] = value;
    }
    table_request(request)
}

#[test]
fn primary_key_modes_generate_sql() {
    // Omitted, null and true all mean: add an automatic integer id (not AUTOINCREMENT, which
    // would make concurrent inserts fight over one counter row).
    let auto = "CREATE TABLE \"t\" (\"id\" INTEGER PRIMARY KEY, \"a\" TEXT NOT NULL)";
    assert_eq!(key_table(None).unwrap().create_sql(), auto);
    assert_eq!(key_table(Some(json!(null))).unwrap().create_sql(), auto);
    assert_eq!(key_table(Some(json!(true))).unwrap().create_sql(), auto);
    assert!(!auto.contains("AUTOINCREMENT"));
    // false: no primary key at all, and no id column.
    assert_eq!(
        key_table(Some(json!(false))).unwrap().create_sql(),
        "CREATE TABLE \"t\" (\"a\" TEXT NOT NULL)"
    );
    // An explicit array is used as given and adds no id.
    assert_eq!(
        key_table(Some(json!(["a"]))).unwrap().create_sql(),
        "CREATE TABLE \"t\" (\"a\" TEXT NOT NULL, PRIMARY KEY (\"a\"))"
    );
}

#[test]
fn primary_key_validation() {
    for invalid in [
        json!([]),
        json!([1]),
        json!(["a", 5]),
        json!("id"),
        json!("a"),
        json!(1),
        json!(0),
        json!({}),
        json!({"columns": ["a"]}),
        json!(["nope"]),
        json!(["a", "a"]),
        json!(["a", "A"]),
    ] {
        assert!(key_table(Some(invalid.clone())).is_err(), "{invalid}");
    }
    // The messages explain the three valid spellings.
    for bad in [json!([]), json!("id"), json!({})] {
        let msg = key_table(Some(bad)).err().unwrap().to_string();
        assert!(
            msg.contains("primary_key") && msg.contains("false") && msg.contains("omit"),
            "{msg}"
        );
    }
    // A nullable column cannot be a key column.
    let nullable = table_request(
        json!({"name": "t", "columns": [{"name": "a", "type": "TEXT", "nullable": true}], "primary_key": ["a"]}),
    );
    assert!(nullable.is_err());
}

#[test]
fn a_user_column_named_id_clashes_only_with_the_automatic_key() {
    let with_id = |key: Option<JsonValue>, name: &str| {
        let mut request = json!({"name": "t", "columns": [{"name": name, "type": "INTEGER"}, {"name": "a", "type": "TEXT"}]});
        if let Some(key) = key {
            request["primary_key"] = key;
        }
        table_request(request)
    };
    for name in ["id", "ID", "Id"] {
        let msg = with_id(None, name).err().expect("clash").to_string();
        assert!(
            msg.contains("\"id\"") && msg.contains("primary_key") && msg.contains("false"),
            "{msg}"
        );
        assert!(with_id(Some(json!(true)), name).is_err());
        // Not a clash when the key is explicit or absent.
        assert!(with_id(Some(json!(false)), name).is_ok());
        assert!(with_id(Some(json!([name])), name).is_ok());
    }
    assert!(
        with_id(None, "identifier").is_ok(),
        "only the exact name id is reserved"
    );
}

impl TestApp {
    async fn create_table_ok(&self, body: JsonValue) {
        let (status, response) = self.post("/v1/tables", body).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    }

    async fn rows_of(&self, table: &str) -> Vec<JsonValue> {
        let (status, body) = self
            .post(
                "/v1/query",
                json!({"table": table, "limit": MAX_QUERY_ROWS}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rows"].as_array().unwrap().clone()
    }
}

fn notes_table() -> JsonValue {
    json!({"name": "notes", "columns": [{"name": "text", "type": "TEXT"}, {"name": "done", "type": "INTEGER", "nullable": true}]})
}

#[tokio::test]
async fn omitting_primary_key_creates_an_auto_assigned_integer_id() {
    let t = TestApp::new().await;
    t.create_table_ok(notes_table()).await;

    // Rows are inserted without an id; the database assigns 1, 2, 3.
    let (status, body) = t
        .post("/v1/batch", json!({"table": "notes", "columns": ["text", "done"], "rows": [["first", 0], ["second", null], ["third", 1]]}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"], json!({"submitted": 3, "affected": 3}));
    let rows = t.rows_of("notes").await;
    assert_eq!(
        rows,
        [
            json!({"id": 1, "text": "first", "done": 0}),
            json!({"id": 2, "text": "second", "done": null}),
            json!({"id": 3, "text": "third", "done": 1})
        ]
    );
    // The id comes first in `*`, is an integer, and is selectable, filterable and sortable.
    let keys: Vec<&String> = rows[0].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "text", "done"]);
    let (_, body) = t
        .post("/v1/query", json!({"table": "notes", "columns": ["id", "text"], "filters": {"id": {"gt": 1}}, "sort": [{"id": "desc"}]}))
        .await;
    assert_eq!(
        body["rows"],
        json!([{"id": 3, "text": "third"}, {"id": 2, "text": "second"}])
    );

    // An explicit id is allowed, and later automatic ids continue after the highest one.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"table": "notes", "columns": ["id", "text"], "rows": [[100, "explicit"]]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    t.post(
        "/v1/batch",
        json!({"table": "notes", "columns": ["text"], "rows": [["after"]]}),
    )
    .await;
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "notes", "columns": ["id"], "filters": {"text": "after"}}),
        )
        .await;
    assert_eq!(body["rows"], json!([{"id": 101}]));

    // The id is a real primary key: duplicates are rejected, and it is the upsert target.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"table": "notes", "columns": ["id", "text"], "rows": [[1, "dup"]]}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = t
        .post("/v1/batch", json!({"table": "notes", "columns": ["id", "text"], "rows": [[1, "updated"]], "on_conflict": {"replace": ["text"]}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "notes", "columns": ["text"], "filters": {"id": 1}}),
        )
        .await;
    assert_eq!(body["rows"], json!([{"text": "updated"}]));
    // An upsert needs the key in the batch; without an id there is nothing to conflict on.
    let (status, body) = t
        .post("/v1/batch", json!({"table": "notes", "columns": ["text"], "rows": [["x"]], "on_conflict": "replace_all"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("\"id\""), "{body}");
}

#[tokio::test]
async fn primary_key_true_is_the_same_as_omitting_it() {
    let t = TestApp::new().await;
    let mut explicit = notes_table();
    explicit["primary_key"] = json!(true);
    t.create_table_ok(explicit).await;
    // ...and is accepted as an identical definition of the table created by omitting it.
    t.create_table_ok(notes_table()).await;
    t.post(
        "/v1/batch",
        json!({"table": "notes", "columns": ["text"], "rows": [["a"]]}),
    )
    .await;
    assert_eq!(t.rows_of("notes").await[0]["id"], 1);
}

#[tokio::test]
async fn primary_key_false_creates_a_table_without_any_key() {
    let t = TestApp::new().await;
    let mut body = json!({"name": "events", "columns": [{"name": "name", "type": "TEXT"}, {"name": "at", "type": "TEXT", "nullable": true}]});
    body["primary_key"] = json!(false);
    t.create_table_ok(body).await;

    // No id column, and nothing stops duplicate rows.
    let row = json!({"table": "events", "columns": ["name", "at"], "rows": [["login", "t1"], ["login", "t1"]]});
    let (status, response) = t.post("/v1/batch", row.clone()).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["rows"], json!({"submitted": 2, "affected": 2}));
    t.post("/v1/batch", row).await;
    let rows = t.rows_of("events").await;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0], json!({"name": "login", "at": "t1"}));
    assert!(rows[0].get("id").is_none());
    // The table's `id` is not special here: it does not exist.
    let (status, _) = t
        .post("/v1/query", json!({"table": "events", "columns": ["id"]}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Upserts have no key to default to; `nothing` still works, and a unique index can be the target.
    let (status, body) = t
        .post("/v1/batch", json!({"table": "events", "columns": ["name"], "rows": [["x"]], "on_conflict": "replace_all"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("no primary key"),
        "{body}"
    );
    let (status, _) = t
        .post("/v1/batch", json!({"table": "events", "columns": ["name", "at"], "rows": [["a", "1"]], "on_conflict": "nothing"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = t
        .post("/v1/indexes", json!({"name": "u_events_name_at", "table": "events", "columns": ["name", "at"], "unique": false}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn each_key_mode_is_idempotent_and_distinct_from_the_others() {
    let t = TestApp::new().await;
    let table = |name: &str, key: Option<JsonValue>| {
        let mut body = json!({"name": name, "columns": [{"name": "a", "type": "TEXT"}]});
        if let Some(key) = key {
            body["primary_key"] = key;
        }
        body
    };
    let modes: [(&str, Option<JsonValue>); 3] = [
        ("m_auto", None),
        ("m_none", Some(json!(false))),
        ("m_explicit", Some(json!(["a"]))),
    ];
    for (name, key) in &modes {
        t.create_table_ok(table(name, key.clone())).await;
        t.create_table_ok(table(name, key.clone())).await; // identical again: accepted
    }
    // Asking for a different kind of key on an existing table is a conflict.
    for (name, _) in &modes {
        for (other_name, other_key) in &modes {
            if name != other_name {
                let (status, body) = t.post("/v1/tables", table(name, other_key.clone())).await;
                assert_eq!(
                    status,
                    StatusCode::CONFLICT,
                    "{name} requested as {other_key:?}: {body}"
                );
            }
        }
    }
    // A user-defined `id` clashes with the automatic key (400), not with the other modes.
    let id_column = |key: Option<JsonValue>| {
        let mut body = json!({"name": "has_id", "columns": [{"name": "id", "type": "INTEGER"}, {"name": "a", "type": "TEXT"}]});
        if let Some(key) = key {
            body["primary_key"] = key;
        }
        body
    };
    let (status, body) = t.post("/v1/tables", id_column(None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("automatic primary key"),
        "{body}"
    );
    t.create_table_ok(id_column(Some(json!(["id"])))).await;
    // A user-defined INTEGER key named id is a rowid alias too: omitting it still assigns ids.
    t.post(
        "/v1/batch",
        json!({"table": "has_id", "columns": ["a"], "rows": [["x"], ["y"]]}),
    )
    .await;
    assert_eq!(
        t.rows_of("has_id")
            .await
            .iter()
            .map(|r| r["id"].clone())
            .collect::<Vec<_>>(),
        [json!(1), json!(2)]
    );

    // The old default (no key unless given) is now spelled `false`; invalid values are 400s.
    for bad in [json!([]), json!("id"), json!(1)] {
        let (status, _) = t
            .post("/v1/tables", table("bad_key", Some(bad.clone())))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn auto_ids_work_inside_multi_table_batches() {
    let t = TestApp::new().await;
    t.create_table_ok(notes_table()).await;
    t.create_metrics().await;
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                {"table": "notes", "columns": ["text"], "rows": [["a"], ["b"]]},
                metrics_step(json!([["A", "m", "p1", 1.0]]))
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["batches"]["notes"],
        json!({"submitted": 2, "affected": 2})
    );
    assert_eq!(t.rows_of("notes").await.len(), 2);
    // A failing later step rolls the generated ids back with everything else.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                {"table": "notes", "columns": ["text"], "rows": [["rolled back"]]},
                metrics_step(json!([["A", "m", "p1", 2.0]]))
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(t.rows_of("notes").await.len(), 2);
}

/// Concurrent inserts that do not supply an id must not conflict with each other: that is why
/// the id is a plain INTEGER PRIMARY KEY and not AUTOINCREMENT.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_without_an_id_get_distinct_ids_and_never_conflict() {
    let t = TestApp::new().await;
    t.create_table_ok(notes_table()).await;
    let mut tasks = Vec::new();
    for writer in 0..12 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..3 {
                let rows: Vec<JsonValue> = (0..20)
                    .map(|i| json!([format!("w{writer}r{round}n{i}")]))
                    .collect();
                let (status, body) = call(
                    &router,
                    Method::POST,
                    "/v1/batch",
                    Some(KEY),
                    Some(json!({"table": "notes", "columns": ["text"], "rows": rows})),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "writer {writer}: {body}");
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut ids = std::collections::HashSet::new();
    for offset in [0, 500] {
        let (_, body) = t
            .post("/v1/query", json!({"table": "notes", "columns": ["id"], "sort": [{"id": "asc"}], "limit": 500, "offset": offset}))
            .await;
        for row in body["rows"].as_array().unwrap() {
            assert!(
                ids.insert(row["id"].as_i64().unwrap()),
                "duplicate id {row}"
            );
        }
    }
    assert_eq!(ids.len(), 12 * 3 * 20);
    assert_eq!(
        (ids.iter().min().copied(), ids.iter().max().copied()),
        (Some(1), Some(720)),
        "ids are dense"
    );
}

#[tokio::test]
async fn create_index_validates_and_is_idempotent() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let index = |name: &str, cols: JsonValue, unique: bool| json!({"name": name, "table": "financial_metrics", "columns": cols, "unique": unique});

    let (status, body) = t
        .post("/v1/indexes", index("idx_period", json!(["period"]), false))
        .await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));

    // An identical request is accepted and answers the same way.
    let (status, body) = t
        .post("/v1/indexes", index("idx_period", json!(["period"]), false))
        .await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));

    // Same name, different definition.
    let (status, _) = t
        .post("/v1/indexes", index("idx_period", json!(["metric"]), false))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = t
        .post("/v1/indexes", index("idx_period", json!(["period"]), true))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Name already used by a table.
    let (status, _) = t
        .post(
            "/v1/indexes",
            index("financial_metrics", json!(["period"]), false),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = t
        .post("/v1/indexes", index("i2", json!(["nope"]), false))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = t
        .post(
            "/v1/indexes",
            json!({"name": "i3", "table": "missing", "columns": ["a"]}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = t.post("/v1/indexes", index("i4", json!([]), false)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The brief's own example duplicates the primary key: still created (204, empty body).
    let (status, body) = t
        .post(
            "/v1/indexes",
            index(
                "idx_metrics_ticker_metric_period",
                json!(["ticker", "metric", "period"]),
                false,
            ),
        )
        .await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));
}

/// The redundant-index advice is no longer part of the HTTP response, but is still produced (and
/// logged) by the operation itself.
#[tokio::test]
async fn redundant_primary_key_index_produces_a_warning() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let plan = |name: &str, columns: &[&str], unique: bool| {
        IndexPlan::from_request(
            serde_json::from_value(json!({"name": name, "table": "financial_metrics", "columns": columns, "unique": unique})).unwrap(),
        )
        .unwrap()
    };
    let (created, warnings) = ensure_index(
        &t.db,
        &plan("idx_full_pk", &["ticker", "metric", "period"], false),
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    // A prefix of the key is redundant too; an unrelated column is not.
    let (_, warnings) = ensure_index(&t.db, &plan("idx_ticker", &["ticker"], false))
        .await
        .unwrap();
    assert_eq!(warnings.len(), 1);
    let (_, warnings) = ensure_index(&t.db, &plan("idx_value", &["value"], false))
        .await
        .unwrap();
    assert!(warnings.is_empty());
    // Re-asking for an index that already exists is not "created" and warns about nothing.
    let (created, warnings) = ensure_index(&t.db, &plan("idx_value", &["value"], false))
        .await
        .unwrap();
    assert!(!created && warnings.is_empty());
}

#[tokio::test]
async fn unique_index_creation_fails_cleanly_on_duplicate_data() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["A", "m", "p1", 1.0], ["B", "m", "p1", 1.0]]))
        .await;
    let (status, _) = t
        .post("/v1/indexes", json!({"name": "u_value", "table": "financial_metrics", "columns": ["value"], "unique": true}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn batch_then_query_round_trip() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let (status, body) = t
        .insert(json!([
            ["AAPL", "revenue", "2024-Q1", 90753.0],
            ["AAPL", "revenue", "2024-Q2", 85777.0],
            ["AAPL", "revenue", "2024-Q3", 94930.0],
            ["MSFT", "revenue", "2024-Q1", null]
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"]["affected"], 4);

    let (status, body) = t
        .post(
            "/v1/query",
            json!({
                "table": "financial_metrics",
                "columns": ["period", "value"],
                "filters": {"ticker": "AAPL", "metric": "revenue"},
                "sort": [{"period": "asc"}],
                "limit": 100
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["row_count"], 3);
    assert_eq!(
        body["rows"],
        json!([
            {"period": "2024-Q1", "value": 90753.0},
            {"period": "2024-Q2", "value": 85777.0},
            {"period": "2024-Q3", "value": 94930.0}
        ])
    );
    // Documented key order: rows, then row_count; and rows keep requested column order.
    let text = body.to_string();
    assert!(text.find("\"rows\"").unwrap() < text.find("\"row_count\"").unwrap());

    let (_, body) = t
        .post("/v1/query", json!({"table": "financial_metrics", "columns": ["period"], "filters": {"ticker": "AAPL"}, "sort": [{"period": "desc"}], "limit": 1}))
        .await;
    assert_eq!(body["rows"], json!([{"period": "2024-Q3"}]));

    // A null filter means IS NULL.
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {"value": null}}),
        )
        .await;
    assert_eq!(body["row_count"], 1);
    assert_eq!(body["rows"][0]["ticker"], "MSFT");

    // `*` keeps declared column order.
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {"ticker": "MSFT"}}),
        )
        .await;
    let keys: Vec<&String> = body["rows"][0].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["ticker", "metric", "period", "value"]);

    // Pagination.
    let (_, page1) = t.post("/v1/query", json!({"table": "financial_metrics", "columns": ["ticker", "period"], "sort": [{"period": "asc"}], "limit": 2})).await;
    let (_, page2) = t.post("/v1/query", json!({"table": "financial_metrics", "columns": ["ticker", "period"], "sort": [{"period": "asc"}], "limit": 2, "offset": 2})).await;
    assert_eq!(page1["row_count"], 2);
    assert_eq!(page2["row_count"], 2);
    assert_ne!(page1["rows"], page2["rows"]);
}

#[tokio::test]
async fn values_are_bound_not_interpolated() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let nasty = "x'); DROP TABLE financial_metrics; --";
    let (status, _) = t.insert(json!([[nasty, "m", "p", 1]])).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {"ticker": nasty}}),
        )
        .await;
    assert_eq!(body["row_count"], 1);
    assert_eq!(body["rows"][0]["ticker"], nasty);
    // Integers stored in a REAL column come back as reals.
    assert_eq!(body["rows"][0]["value"], 1.0);
}

#[tokio::test]
async fn blobs_round_trip_through_the_api() {
    let t = TestApp::new().await;
    let (status, _) = t
        .post("/v1/tables", json!({"name": "files", "columns": [{"name": "id", "type": "INTEGER"}, {"name": "data", "type": "BLOB"}], "primary_key": ["id"]}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let blob = json!({"$type": "blob", "base64": "AAECAw=="});
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"table": "files", "columns": ["id", "data"], "rows": [[1, blob]]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "files", "filters": {"data": blob}}),
        )
        .await;
    assert_eq!(body["rows"][0]["data"], blob);
}

#[tokio::test]
async fn batch_failure_rolls_back_every_row() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["SEED", "m", "p", 1.0]])).await;

    // Valid row, valid row, then a duplicate primary key.
    let (status, body) = t
        .insert(json!([
            ["A", "m", "p1", 1.0],
            ["A", "m", "p2", 2.0],
            ["A", "m", "p1", 3.0]
        ]))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "conflict");
    assert!(body["error"].as_str().unwrap().contains("row 2"), "{body}");
    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 1, "only the seed row may remain: {rows:?}");

    // NOT NULL violation after valid rows rolls back too.
    let (status, _) = t
        .insert(json!([["B", "m", "p1", 1.0], [null, "m", "p2", 2.0]]))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(t.all_rows().await.len(), 1);

    // The connection/lock is healthy afterwards.
    let (status, _) = t.insert(json!([["C", "m", "p1", 1.0]])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(t.all_rows().await.len(), 2);
}

#[tokio::test]
async fn batch_validation_failures_write_nothing() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    // A bad value late in the batch is caught before any write.
    let (status, body) = t
        .insert(json!([["A", "m", "p1", 1.0], ["A", "m", "p2", [1]]]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("row 1"));
    let (status, _) = t
        .insert(json!([["A", "m", "p1", 9223372036854775808u64]]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(t.all_rows().await.is_empty());

    let (status, _) = t.post("/v1/batch", json!({"table": "financial_metrics", "columns": ["ticker", "nope"], "rows": [["a", "b"]]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"table": "missing", "columns": ["a"], "rows": [[1]]}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn empty_batch_is_a_no_op() {
    let t = TestApp::new().await;
    // Does not even need the table to exist, since nothing is executed.
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": ["ticker"], "rows": []}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rows"]["affected"], 0);
}

#[tokio::test]
async fn on_conflict_modes() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let post = |on_conflict: JsonValue, target: Option<JsonValue>, rows: JsonValue| {
        let mut body = json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows, "on_conflict": on_conflict});
        if let Some(target) = target {
            body["conflict_target"] = target;
        }
        t.post("/v1/batch", body)
    };
    let value_of = |rows: &[JsonValue], period: &str| {
        rows.iter().find(|r| r["period"] == period).unwrap()["value"].clone()
    };

    t.insert(json!([["A", "m", "p1", 1.0], ["A", "m", "p2", 2.0]]))
        .await;

    // abort (explicit) fails on conflict.
    let (status, _) = post(json!("abort"), None, json!([["A", "m", "p1", 9.0]])).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // nothing: conflicting row skipped, new row inserted, affected counts real changes.
    let (status, body) = post(
        json!("nothing"),
        None,
        json!([["A", "m", "p1", 9.0], ["A", "m", "p3", 3.0]]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (&body["rows"]["affected"], &body["rows"]["submitted"]),
        (&json!(1), &json!(2))
    );
    let rows = t.all_rows().await;
    assert_eq!((rows.len(), value_of(&rows, "p1")), (3, json!(1.0)));

    // replace: explicit column list and explicit target.
    let (status, body) = post(
        json!({"replace": ["value"]}),
        Some(json!(["ticker", "metric", "period"])),
        json!([["A", "m", "p1", 10.0], ["A", "m", "p4", 4.0]]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = t.all_rows().await;
    assert_eq!((rows.len(), value_of(&rows, "p1")), (4, json!(10.0)));

    // replace_all with the target defaulting to the primary key.
    let (status, body) = post(json!("replace_all"), None, json!([["A", "m", "p2", 20.0]])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(value_of(&t.all_rows().await, "p2"), json!(20.0));

    // Target must be a real key; replace cannot touch target columns.
    let (status, _) = post(
        json!({"replace": ["value"]}),
        Some(json!(["ticker"])),
        json!([["A", "m", "p1", 1.0]]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        json!({"replace": ["ticker"]}),
        None,
        json!([["A", "m", "p1", 1.0]]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        json!("replace_all"),
        Some(json!(["value"])),
        json!([["A", "m", "p1", 1.0]]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upsert_can_target_a_unique_index_and_replace_all_with_only_keys_does_nothing() {
    let t = TestApp::new().await;
    let (status, _) = t
        .post("/v1/tables", json!({"name": "u", "columns": [{"name": "id", "type": "INTEGER"}, {"name": "email", "type": "TEXT"}, {"name": "name", "type": "TEXT", "nullable": true}], "primary_key": ["id"]}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = t
        .post(
            "/v1/indexes",
            json!({"name": "u_email", "table": "u", "columns": ["email"], "unique": true}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let upsert = |rows: JsonValue| {
        t.post("/v1/batch", json!({"table": "u", "columns": ["email", "name"], "rows": rows, "on_conflict": "replace_all", "conflict_target": ["email"]}))
    };
    assert_eq!(upsert(json!([["a@x", "one"]])).await.0, StatusCode::OK);
    assert_eq!(upsert(json!([["a@x", "two"]])).await.0, StatusCode::OK);
    let (_, body) = t.post("/v1/query", json!({"table": "u"})).await;
    assert_eq!(
        (body["row_count"].clone(), body["rows"][0]["name"].clone()),
        (json!(1), json!("two"))
    );

    // Only the key column in the batch: nothing to update, so conflicts are skipped.
    let (status, body) = t
        .post("/v1/batch", json!({"table": "u", "columns": ["email"], "rows": [["a@x"]], "on_conflict": "replace_all", "conflict_target": ["email"]}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn query_errors() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let q = |body: JsonValue| t.post("/v1/query", body);
    assert_eq!(
        q(json!({"table": "missing"})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        q(json!({"table": "financial_metrics", "columns": ["nope"]}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        q(json!({"table": "financial_metrics", "filters": {"nope": 1}}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        q(json!({"table": "financial_metrics", "sort": [{"nope": "asc"}]}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        q(json!({"table": "financial_metrics", "limit": MAX_QUERY_ROWS + 1}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        q(json!({"table": "sqlite_schema"})).await.0,
        StatusCode::BAD_REQUEST
    );
    // Unknown fields are rejected so typos do not silently drop a filter.
    let (status, body) = q(json!({"table": "financial_metrics", "filter": {"ticker": "A"}})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("filter"));
}

// ----- query filters and sort -----

fn query_plan(v: JsonValue) -> ApiResult<QueryPlan> {
    QueryPlan::from_request(serde_json::from_value(v).map_err(|e| ApiError::bad(e.to_string()))?)
}

fn where_clause(filters: JsonValue) -> (String, Vec<DbValue>) {
    let (sql, params) = query_plan(json!({"table": "t", "columns": ["a"], "filters": filters}))
        .unwrap()
        .sql();
    let sql = sql
        .strip_prefix("SELECT \"a\" FROM \"t\"")
        .unwrap()
        .to_owned();
    (
        sql.strip_suffix(&format!(" LIMIT {DEFAULT_QUERY_ROWS}"))
            .unwrap()
            .to_owned(),
        params,
    )
}

#[test]
fn filter_operators_generate_sql() {
    let int = DbValue::Integer;
    let text = |s: &str| DbValue::Text(s.into());
    let cases: Vec<(JsonValue, &str, Vec<DbValue>)> = vec![
        (json!({"a": 1}), " WHERE \"a\" = ?1", vec![int(1)]),
        (json!({"a": null}), " WHERE \"a\" IS NULL", vec![]),
        (
            json!({"a": {"eq": "x"}}),
            " WHERE \"a\" = ?1",
            vec![text("x")],
        ),
        (json!({"a": {"ne": 1}}), " WHERE \"a\" <> ?1", vec![int(1)]),
        (json!({"a": {"gt": 1}}), " WHERE \"a\" > ?1", vec![int(1)]),
        (json!({"a": {"gte": 1}}), " WHERE \"a\" >= ?1", vec![int(1)]),
        (json!({"a": {"lt": 1}}), " WHERE \"a\" < ?1", vec![int(1)]),
        (json!({"a": {"lte": 1}}), " WHERE \"a\" <= ?1", vec![int(1)]),
        (
            json!({"a": {"in": ["x", 2]}}),
            " WHERE \"a\" IN (?1, ?2)",
            vec![text("x"), int(2)],
        ),
        (
            json!({"a": {"not_in": [1]}}),
            " WHERE \"a\" NOT IN (?1)",
            vec![int(1)],
        ),
        (
            json!({"a": {"like": "f%"}}),
            " WHERE \"a\" LIKE ?1",
            vec![text("f%")],
        ),
        (
            json!({"a": {"like": ["foo"]}}),
            " WHERE \"a\" LIKE ?1",
            vec![text("foo")],
        ),
        (
            json!({"a": {"like": ["f%", "b%"]}}),
            " WHERE (\"a\" LIKE ?1 OR \"a\" LIKE ?2)",
            vec![text("f%"), text("b%")],
        ),
        (
            json!({"a": {"not_like": ["f%", "b%"]}}),
            " WHERE (\"a\" NOT LIKE ?1 AND \"a\" NOT LIKE ?2)",
            vec![text("f%"), text("b%")],
        ),
        (
            json!({"a": {"is_null": true}}),
            " WHERE \"a\" IS NULL",
            vec![],
        ),
        (
            json!({"a": {"is_null": false}}),
            " WHERE \"a\" IS NOT NULL",
            vec![],
        ),
        // Several operators on one column, and several columns, are all ANDed.
        (
            json!({"a": {"gt": 1, "lt": 9}}),
            " WHERE \"a\" > ?1 AND \"a\" < ?2",
            vec![int(1), int(9)],
        ),
        (
            json!({"a": {"gte": 1, "ne": 5}, "b": "x", "c": {"in": [1, 2]}}),
            " WHERE \"a\" >= ?1 AND \"a\" <> ?2 AND \"b\" = ?3 AND \"c\" IN (?4, ?5)",
            vec![int(1), int(5), text("x"), int(1), int(2)],
        ),
        // Empty lists keep SQL meaning: IN () matches nothing, NOT IN () everything.
        (json!({"a": {"in": []}}), " WHERE 0", vec![]),
        (json!({"a": {"not_in": []}}), "", vec![]),
        (json!({"a": {"like": []}}), " WHERE 0", vec![]),
        (json!({"a": {"not_like": []}}), "", vec![]),
        // Tagged blob objects are values, not operator maps.
        (
            json!({"a": {"$type": "blob", "base64": "AAE="}}),
            " WHERE \"a\" = ?1",
            vec![DbValue::Blob(vec![0, 1])],
        ),
        (
            json!({"a": {"in": [{"$type": "blob", "base64": "AAE="}]}}),
            " WHERE \"a\" IN (?1)",
            vec![DbValue::Blob(vec![0, 1])],
        ),
    ];
    for (filters, expected_sql, expected_params) in cases {
        let (sql, params) = where_clause(filters.clone());
        assert_eq!(
            (sql.as_str(), &params),
            (expected_sql, &expected_params),
            "{filters}"
        );
    }
}

#[test]
fn filter_validation() {
    let bad = |filters: JsonValue| {
        query_plan(json!({"table": "t", "filters": filters}))
            .err()
            .map(|e| e.to_string())
    };
    for invalid in [
        json!({"a": {}}),
        json!({"a": {"between": [1, 2]}}),
        json!({"a": {"gt": null}}),
        json!({"a": {"gt": [1]}}),
        json!({"a": {"eq": {"x": 1}}}),
        json!({"a": {"in": "x"}}),
        json!({"a": {"in": [null]}}),
        json!({"a": {"in": [[1]]}}),
        json!({"a": {"not_in": 5}}),
        json!({"a": {"like": 5}}),
        json!({"a": {"like": [1]}}),
        json!({"a": {"like": null}}),
        json!({"a": {"is_null": "yes"}}),
        json!({"a": {"is_null": 1}}),
        json!({"a": [1, 2]}),
        json!({"a": {"gt": 1, "bogus": 2}}),
        json!({"a": 1, "A": 2}),
    ] {
        assert!(
            bad(invalid.clone()).is_some(),
            "should be rejected: {invalid}"
        );
    }
    // The message names the column and the problem.
    let message = bad(json!({"metric": {"between": [1, 2]}})).unwrap();
    assert!(
        message.contains("metric") && message.contains("between") && message.contains("is_null"),
        "{message}"
    );
    // Huge IN lists are capped.
    let many: Vec<usize> = (0..=MAX_QUERY_PARAMS).collect();
    assert!(bad(json!({"a": {"in": many}})).is_some());
    let ok: Vec<usize> = (0..MAX_QUERY_PARAMS).collect();
    assert!(bad(json!({"a": {"in": ok}})).is_none());
}

#[test]
fn sort_generates_ordered_terms_and_validates() {
    let sql = |sort: JsonValue| {
        query_plan(json!({"table": "t", "columns": ["a"], "sort": sort, "limit": 5}))
            .map(|p| p.sql().0)
    };
    assert_eq!(sql(json!([])).unwrap(), "SELECT \"a\" FROM \"t\" LIMIT 5");
    assert_eq!(
        sql(json!([{"period": "asc"}, {"id": "desc"}])).unwrap(),
        "SELECT \"a\" FROM \"t\" ORDER BY \"period\" ASC, \"id\" DESC LIMIT 5"
    );
    // Array order is priority order; direction is case-insensitive.
    assert_eq!(
        sql(json!([{"id": "DESC"}, {"period": "Asc"}])).unwrap(),
        "SELECT \"a\" FROM \"t\" ORDER BY \"id\" DESC, \"period\" ASC LIMIT 5"
    );
    for invalid in [
        // The previous object notation is no longer accepted.
        json!({"period": "asc", "ticker": "desc"}),
        json!({}),
        // Each entry must be an object with exactly one column.
        json!([{}]),
        json!([{"a": "asc", "b": "desc"}]),
        json!(["a"]),
        json!([["a", "asc"]]),
        json!([{"a": "asc"}, {}]),
        // Directions and names are validated.
        json!([{"a": "up"}]),
        json!([{"a": true}]),
        json!([{"a": null}]),
        json!([{"a": 1}]),
        json!([{"a b": "asc"}]),
        // The same column twice (names are case-insensitive).
        json!([{"a": "asc"}, {"A": "desc"}]),
    ] {
        assert!(sql(invalid.clone()).is_err(), "{invalid}");
    }
    // `offset` needs a sort, and the old `order_by` spelling is gone.
    assert!(query_plan(json!({"table": "t", "offset": 1})).is_err());
    assert!(query_plan(json!({"table": "t", "offset": 1, "sort": [{"a": "asc"}]})).is_ok());
    assert!(query_plan(json!({"table": "t", "order_by": {"column": "a"}})).is_err());
}

/// Seven rows with two NULL values, used by the HTTP filter tests.
async fn filter_fixture() -> TestApp {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let (status, body) = t
        .insert(json!([
            ["AAPL", "revenue", "2024-Q1", 10.0],
            ["AAPL", "revenue", "2024-Q2", 20.0],
            ["AAPL", "profit", "2024-Q1", 5.0],
            ["MSFT", "revenue", "2024-Q1", 30.0],
            ["MSFT", "eps", "2024-Q1", null],
            ["GOOG", "revenue", "2024-Q1", 15.0],
            ["GOOG", "profit", "2024-Q2", null]
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    t
}

/// Runs a query and returns `ticker|metric|period` for each row, in result order.
async fn keys(t: &TestApp, extra: JsonValue) -> Vec<String> {
    let mut body = json!({
        "table": "financial_metrics",
        "columns": ["ticker", "metric", "period"],
        "sort": [{"ticker": "asc"}, {"metric": "asc"}, {"period": "asc"}]
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (status, response) = t.post("/v1/query", body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    response["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{}|{}|{}",
                r["ticker"].as_str().unwrap(),
                r["metric"].as_str().unwrap(),
                r["period"].as_str().unwrap()
            )
        })
        .collect()
}

#[tokio::test]
async fn in_and_not_in_filters() {
    let t = filter_fixture().await;
    let f = |filters: JsonValue| keys(&t, json!({ "filters": filters }));
    assert_eq!(
        f(json!({"metric": {"in": ["profit", "eps"]}})).await,
        [
            "AAPL|profit|2024-Q1",
            "GOOG|profit|2024-Q2",
            "MSFT|eps|2024-Q1"
        ]
    );
    assert_eq!(
        f(json!({"metric": {"not_in": ["revenue"]}})).await,
        [
            "AAPL|profit|2024-Q1",
            "GOOG|profit|2024-Q2",
            "MSFT|eps|2024-Q1"
        ]
    );
    assert_eq!(
        f(json!({"value": {"in": [5, 15.0]}})).await,
        ["AAPL|profit|2024-Q1", "GOOG|revenue|2024-Q1"]
    );
    assert_eq!(f(json!({"metric": {"in": []}})).await, Vec::<String>::new());
    assert_eq!(f(json!({"metric": {"not_in": []}})).await.len(), 7);
}

#[tokio::test]
async fn like_filters() {
    let t = filter_fixture().await;
    let f = |filters: JsonValue| keys(&t, json!({ "filters": filters }));
    assert_eq!(
        f(json!({"ticker": {"like": "%OO%"}})).await,
        ["GOOG|profit|2024-Q2", "GOOG|revenue|2024-Q1"]
    );
    // The array form from the spec: one pattern.
    assert_eq!(f(json!({"ticker": {"like": ["GOOG"]}})).await.len(), 2);
    // Several patterns: like = any, not_like = none.
    assert_eq!(
        f(json!({"ticker": {"like": ["AA%", "MS%"]}})).await.len(),
        5
    );
    assert_eq!(
        f(json!({"ticker": {"not_like": ["AA%", "MS%"]}}))
            .await
            .len(),
        2
    );
    assert_eq!(
        f(json!({"metric": {"like": "r_venue"}})).await.len(),
        4,
        "_ matches one character"
    );
    assert_eq!(f(json!({"period": {"like": "%-Q2"}})).await.len(), 2);
    // Patterns are bound values, never SQL.
    assert_eq!(
        f(json!({"ticker": {"like": "x' OR '1'='1"}})).await.len(),
        0
    );
}

#[tokio::test]
async fn comparison_and_null_filters() {
    let t = filter_fixture().await;
    let f = |filters: JsonValue| keys(&t, json!({ "filters": filters }));
    assert_eq!(
        f(json!({"value": {"gt": 15}})).await,
        ["AAPL|revenue|2024-Q2", "MSFT|revenue|2024-Q1"]
    );
    assert_eq!(f(json!({"value": {"gte": 15}})).await.len(), 3);
    assert_eq!(
        f(json!({"value": {"lt": 10}})).await,
        ["AAPL|profit|2024-Q1"]
    );
    assert_eq!(f(json!({"value": {"lte": 10}})).await.len(), 2);
    assert_eq!(
        f(json!({"value": {"eq": 5}})).await,
        ["AAPL|profit|2024-Q1"]
    );
    // Text comparison works too: periods after 2024-Q1.
    assert_eq!(
        f(json!({"period": {"gt": "2024-Q1"}})).await,
        ["AAPL|revenue|2024-Q2", "GOOG|profit|2024-Q2"]
    );

    // Several operators in one object are ANDed: a range.
    assert_eq!(
        f(json!({"value": {"gt": 5, "lt": 30}})).await,
        [
            "AAPL|revenue|2024-Q1",
            "AAPL|revenue|2024-Q2",
            "GOOG|revenue|2024-Q1"
        ]
    );
    assert_eq!(
        f(json!({"value": {"gt": 5, "lt": 5}})).await,
        Vec::<String>::new()
    );

    // NULL handling: the three spellings of IS NULL, and IS NOT NULL.
    let nulls = ["GOOG|profit|2024-Q2", "MSFT|eps|2024-Q1"];
    assert_eq!(f(json!({"value": null})).await, nulls);
    assert_eq!(f(json!({"value": {"is_null": true}})).await, nulls);
    assert_eq!(f(json!({"value": {"is_null": false}})).await.len(), 5);
    // SQL semantics: comparisons never match NULL, so `ne` leaves the two NULL rows out.
    assert_eq!(f(json!({"value": {"ne": 10}})).await.len(), 4);

    // Different columns combine with AND as well.
    assert_eq!(
        f(json!({"ticker": {"in": ["AAPL", "GOOG"]}, "metric": "revenue", "value": {"gte": 15}}))
            .await,
        ["AAPL|revenue|2024-Q2", "GOOG|revenue|2024-Q1"]
    );
}

#[tokio::test]
async fn blob_values_still_work_as_filters() {
    let t = TestApp::new().await;
    t.post("/v1/tables", json!({"name": "files", "columns": [{"name": "id", "type": "INTEGER"}, {"name": "data", "type": "BLOB"}], "primary_key": ["id"]})).await;
    let (a, b) = (
        json!({"$type": "blob", "base64": "AAEC"}),
        json!({"$type": "blob", "base64": "AwQF"}),
    );
    t.post(
        "/v1/batch",
        json!({"table": "files", "columns": ["id", "data"], "rows": [[1, a], [2, b]]}),
    )
    .await;
    let q = |filters: JsonValue| {
        let t = &t;
        async move {
            t.post(
                "/v1/query",
                json!({"table": "files", "columns": ["id"], "filters": filters}),
            )
            .await
            .1["rows"]
                .clone()
        }
    };
    assert_eq!(q(json!({"data": a})).await, json!([{"id": 1}]));
    assert_eq!(
        q(json!({"data": {"in": [a, b]}, "id": {"gt": 1}})).await,
        json!([{"id": 2}])
    );
}

#[tokio::test]
async fn sort_orders_by_several_columns() {
    let t = filter_fixture().await;
    let order = |sort: JsonValue| keys(&t, json!({ "sort": sort }));
    assert_eq!(
        order(json!([{"ticker": "desc"}, {"metric": "asc"}, {"period": "asc"}])).await,
        [
            "MSFT|eps|2024-Q1",
            "MSFT|revenue|2024-Q1",
            "GOOG|profit|2024-Q2",
            "GOOG|revenue|2024-Q1",
            "AAPL|profit|2024-Q1",
            "AAPL|revenue|2024-Q1",
            "AAPL|revenue|2024-Q2"
        ]
    );
    // The order of the array is the priority: period first, then ticker.
    assert_eq!(
        order(json!([{"period": "desc"}, {"ticker": "asc"}, {"metric": "asc"}])).await[..3],
        [
            "AAPL|revenue|2024-Q2",
            "GOOG|profit|2024-Q2",
            "AAPL|profit|2024-Q1"
        ]
    );
    // Sort composes with filters and paging.
    let (_, page) = t
        .post(
            "/v1/query",
            json!({"table": "financial_metrics", "columns": ["ticker", "period"],
                   "filters": {"metric": "revenue"}, "sort": [{"ticker": "asc"}, {"period": "desc"}], "limit": 2, "offset": 1}),
        )
        .await;
    assert_eq!(
        page["rows"],
        json!([{"ticker": "AAPL", "period": "2024-Q1"}, {"ticker": "GOOG", "period": "2024-Q1"}])
    );
}

#[tokio::test]
async fn filter_and_sort_errors_over_http() {
    let t = filter_fixture().await;
    let q = |body: JsonValue| t.post("/v1/query", body);
    let table = "financial_metrics";

    // The old spelling is rejected with a message that points at the new one.
    let (status, body) = q(json!({"table": table, "order_by": {"column": "period"}})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().unwrap();
    assert!(
        message.contains("order_by") && message.contains("sort"),
        "{message}"
    );

    // The previous object notation gets a 400, not a silently different ordering.
    for old_style in [
        json!({"table": table, "sort": {"period": "asc"}}),
        json!({"table": table, "sort": [{"period": "asc", "ticker": "desc"}]}),
        json!({"table": table, "sort": [{}]}),
    ] {
        assert_eq!(
            q(old_style.clone()).await.0,
            StatusCode::BAD_REQUEST,
            "{old_style}"
        );
    }

    let (status, body) =
        q(json!({"table": table, "filters": {"value": {"between": [1, 2]}}})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("between"));

    for body in [
        json!({"table": table, "filters": {"nope": {"gt": 1}}}),
        json!({"table": table, "sort": [{"nope": "asc"}]}),
        json!({"table": table, "sort": [{"period": "sideways"}]}),
        json!({"table": table, "filters": {"value": {"in": "x"}}}),
        json!({"table": table, "filters": {"value": {}}}),
    ] {
        assert_eq!(q(body.clone()).await.0, StatusCode::BAD_REQUEST, "{body}");
    }
}

// ----- multi-table batches: parsing, limits and response -----

fn job_with(body: JsonValue, limits: Limits) -> ApiResult<BatchJob> {
    parse_batch_body(body, &limits)
}

fn job(body: JsonValue) -> ApiResult<BatchJob> {
    job_with(body, Limits::default())
}

fn step(table: &str, rows: JsonValue) -> JsonValue {
    json!({"table": table, "columns": ["a", "b"], "rows": rows})
}

fn message(error: ApiResult<BatchJob>) -> String {
    error.err().expect("expected an error").to_string()
}

#[test]
fn batch_body_accepts_a_single_batch_or_an_envelope() {
    let single = job(step("t", json!([[1, 2]]))).unwrap();
    assert!(!single.envelope);
    assert_eq!(single.steps.len(), 1);

    let many =
        job(json!({"batches": [step("a", json!([[1, 2]])), step("b", json!([[3, 4]]))]})).unwrap();
    assert!(many.envelope);
    assert_eq!(many.steps.len(), 2);

    // An empty list is a valid no-op.
    assert_eq!(job(json!({"batches": []})).unwrap().steps.len(), 0);
}

#[test]
fn batch_body_rejects_malformed_shapes() {
    let ok = step("t", json!([[1, 2]]));
    for invalid in [
        // A bare array is not the envelope.
        json!([ok.clone()]),
        // The envelope cannot be mixed with a top-level batch or anything else.
        json!({"batches": [ok.clone()], "table": "t"}),
        json!({"batches": [ok.clone()], "rows": []}),
        json!({"batches": "nope"}),
        json!({"batches": {"table": "t"}}),
        json!({"batches": [1]}),
        json!({"batches": [ok.clone(), "x"]}),
        json!("text"),
        json!(5),
        json!(null),
    ] {
        assert!(job(invalid.clone()).is_err(), "{invalid}");
    }
    // Non-objects get an explanation of the two accepted shapes.
    let msg = message(job(json!([ok])));
    assert!(
        msg.contains("must be a JSON object") && msg.contains("batches"),
        "{msg}"
    );
}

#[test]
fn batch_body_errors_name_the_step_only_in_the_envelope() {
    let good = step("a", json!([[1, 2]]));
    // Bad value in the second step.
    let bad_value = step("b", json!([[1, 2], [3, [9]]]));
    let msg = message(job(json!({"batches": [good.clone(), bad_value.clone()]})));
    assert!(
        msg.contains("batches[1]") && msg.contains("\"b\"") && msg.contains("row 1"),
        "{msg}"
    );
    // The single form keeps the plain message.
    let msg = message(job(bad_value));
    assert!(!msg.contains("batches["), "{msg}");

    // Unknown field, bad identifier and bad conflict options inside a step.
    let msg = message(job(
        json!({"batches": [good.clone(), {"table": "b", "columns": ["a"], "rows": [], "oops": 1}]}),
    ));
    assert!(msg.contains("batches[1]") && msg.contains("oops"), "{msg}");
    let msg = message(job(json!({"batches": [step("bad name", json!([]))]})));
    assert!(msg.contains("batches[0]"), "{msg}");
    let msg = message(job(
        json!({"batches": [good, {"table": "b", "columns": ["a"], "rows": [], "conflict_target": ["a"]}]}),
    ));
    assert!(
        msg.contains("batches[1]") && msg.contains("conflict_target"),
        "{msg}"
    );
}

#[test]
fn batch_limits_apply_to_the_whole_request() {
    let limits = Limits {
        max_batch_steps: 3,
        max_batch_rows: 5,
        max_batch_values: 100,
        ..Limits::default()
    };
    let rows = |n: usize| JsonValue::Array((0..n).map(|i| json!([i, i])).collect());
    let steps = |counts: &[usize]| json!({"batches": counts.iter().map(|&n| step("t", rows(n))).collect::<Vec<_>>()});

    // Steps.
    assert!(job_with(steps(&[1, 1, 1]), limits).is_ok());
    let msg = message(job_with(steps(&[0, 0, 0, 0]), limits));
    assert!(msg.contains("at most 3 batches"), "{msg}");

    // Rows are summed across steps: each step is small, the total is too big.
    assert!(job_with(steps(&[3, 2]), limits).is_ok());
    let msg = message(job_with(steps(&[3, 3]), limits));
    assert!(
        msg.contains("5 rows in total") && msg.contains("got 6"),
        "{msg}"
    );
    // The single-object form is limited by the same numbers.
    assert!(job_with(step("t", rows(5)), limits).is_ok());
    assert!(job_with(step("t", rows(6)), limits).is_err());

    // Values are rows x columns, summed across steps.
    let limits = Limits {
        max_batch_values: 8,
        ..Limits::default()
    };
    assert!(job_with(steps(&[2, 2]), limits).is_ok(), "4 + 4 values");
    let msg = message(job_with(steps(&[2, 3]), limits));
    assert!(
        msg.contains("8 values in total") && msg.contains("got 10"),
        "{msg}"
    );
}

#[test]
fn default_limits_match_the_documented_values() {
    let limits = Limits::default();
    assert_eq!(
        (
            limits.max_body_bytes,
            limits.max_batch_steps,
            limits.max_batch_rows,
            limits.max_batch_values
        ),
        (8 * 1024 * 1024, 20, 5_000, 100_000)
    );
    // 5,000 rows and 100,000 values: 5,000 rows of up to 20 columns fit; the row cap binds first
    // for narrow tables and the value cap for wide ones.
    let rows = |n: usize, columns: usize| {
        JsonValue::Array(
            (0..n)
                .map(|i| JsonValue::Array(vec![json!(i); columns]))
                .collect(),
        )
    };
    let one_column = |n: usize| json!({"table": "t", "columns": ["a"], "rows": rows(n, 1)});
    assert!(job(one_column(5_000)).is_ok());
    let msg = message(job(one_column(5_001)));
    assert!(msg.contains("5000 rows in total"), "{msg}");
    let wide = |n: usize, columns: usize| {
        let names: Vec<String> = (0..columns).map(|i| format!("c{i:02}")).collect();
        json!({"table": "t", "columns": names, "rows": rows(n, columns)})
    };
    assert!(
        job(wide(5_000, 20)).is_ok(),
        "5k rows x 20 columns = 100k values"
    );
    let msg = message(job(wide(5_000, 21)));
    assert!(
        msg.contains("100000 values in total") && msg.contains("got 105000"),
        "{msg}"
    );
    let msg = message(job(wide(5_001, 2)));
    assert!(msg.contains("5000 rows in total"), "{msg}");
    assert!(
        job(json!({"batches": (0..20).map(|_| step("t", json!([]))).collect::<Vec<_>>()})).is_ok()
    );
    assert!(
        job(json!({"batches": (0..21).map(|_| step("t", json!([]))).collect::<Vec<_>>()})).is_err()
    );
}

#[test]
fn config_limits_from_the_environment() {
    let c = config(&[]).unwrap();
    assert_eq!(c.limits, Limits::default());

    let c = config(&[
        ("MAX_BODY_BYTES", "1000000"),
        ("MAX_BATCH_STEPS", "5"),
        ("MAX_BATCH_ROWS", "50"),
        ("MAX_BATCH_VALUES", "400"),
    ])
    .unwrap();
    assert_eq!(
        c.limits,
        Limits {
            max_body_bytes: 1_000_000,
            max_batch_steps: 5,
            max_batch_rows: 50,
            max_batch_values: 400,
            max_delete_rows: None
        }
    );
    // Each one can be set on its own.
    assert_eq!(
        config(&[("MAX_BATCH_ROWS", "7")])
            .unwrap()
            .limits
            .max_batch_rows,
        7
    );
    assert_eq!(
        config(&[("MAX_BATCH_ROWS", "7")])
            .unwrap()
            .limits
            .max_batch_steps,
        20
    );

    for (key, value) in [
        ("MAX_BODY_BYTES", "0"),
        ("MAX_BATCH_STEPS", "0"),
        ("MAX_BATCH_ROWS", "0"),
        ("MAX_BATCH_VALUES", "0"),
        ("MAX_BATCH_ROWS", "-1"),
        ("MAX_BATCH_ROWS", "lots"),
        ("MAX_BATCH_STEPS", "1.5"),
    ] {
        let err = config(&[(key, value)])
            .err()
            .unwrap_or_else(|| panic!("{key}={value} accepted"));
        assert!(err.contains(key), "{err}");
    }
}

#[test]
fn batch_response_merges_steps_that_write_the_same_table() {
    let j = job(json!({"batches": [
        step("a", json!([[1, 1], [2, 2]])),
        step("b", json!([[3, 3]])),
        step("A", json!([[4, 4], [5, 5], [6, 6]])),
        step("c", json!([]))
    ]}))
    .unwrap();
    let response = batch_response(&j, &[2, 1, 1, 0]);
    assert_eq!(
        response,
        json!({
            "rows": {"submitted": 6, "affected": 4},
            "batches": {
                "a": {"submitted": 5, "affected": 3},
                "b": {"submitted": 1, "affected": 1},
                "c": {"submitted": 0, "affected": 0}
            }
        })
    );
    // Table order follows the request, and there is no "ok" field.
    let text = response["batches"].to_string();
    assert!(text.find("\"a\"").unwrap() < text.find("\"b\"").unwrap());
    assert!(response.get("ok").is_none());
}

// ----- multi-table batches over HTTP -----

impl TestApp {
    async fn create_companies(&self) {
        let (status, body) = self
            .post(
                "/v1/tables",
                json!({"name": "companies",
                       "columns": [{"name": "ticker", "type": "TEXT"}, {"name": "name", "type": "TEXT", "nullable": true}],
                       "primary_key": ["ticker"]}),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    async fn companies(&self) -> Vec<JsonValue> {
        let (status, body) = self
            .post(
                "/v1/query",
                json!({"table": "companies", "sort": [{"ticker": "asc"}]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rows"].as_array().unwrap().clone()
    }

    async fn two_tables(&self) {
        self.create_metrics().await;
        self.create_companies().await;
    }
}

fn metrics_step(rows: JsonValue) -> JsonValue {
    json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows})
}

fn companies_step(rows: JsonValue) -> JsonValue {
    json!({"table": "companies", "columns": ["ticker", "name"], "rows": rows})
}

#[tokio::test]
async fn single_batch_response_uses_the_rows_and_batches_notation() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let (status, body) = t
        .insert(json!([["A", "m", "p1", 1.0], ["A", "m", "p2", 2.0]]))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"rows": {"submitted": 2, "affected": 2},
               "batches": {"financial_metrics": {"submitted": 2, "affected": 2}}})
    );
}

#[tokio::test]
async fn multi_table_batch_writes_every_table_in_one_request() {
    let t = TestApp::new().await;
    t.two_tables().await;
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                companies_step(json!([["AAPL", "Apple"], ["MSFT", "Microsoft"]])),
                metrics_step(json!([["AAPL", "revenue", "2024-Q1", 1.0], ["MSFT", "revenue", "2024-Q1", 2.0], ["MSFT", "revenue", "2024-Q2", 3.0]]))
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"rows": {"submitted": 5, "affected": 5},
               "batches": {"companies": {"submitted": 2, "affected": 2},
                           "financial_metrics": {"submitted": 3, "affected": 3}}})
    );
    assert_eq!(t.companies().await.len(), 2);
    assert_eq!(t.all_rows().await.len(), 3);
}

#[tokio::test]
async fn multi_table_batch_reports_skipped_rows_per_table() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.post(
        "/v1/batch",
        json!({"batches": [companies_step(json!([["AAPL", "Apple"]]))]}),
    )
    .await;
    let mut skip = companies_step(json!([["AAPL", "Changed"], ["MSFT", "Microsoft"]]));
    skip["on_conflict"] = json!("nothing");
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [skip, metrics_step(json!([["AAPL", "revenue", "2024-Q1", 1.0]]))]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["batches"]["companies"],
        json!({"submitted": 2, "affected": 1})
    );
    assert_eq!(body["rows"], json!({"submitted": 3, "affected": 2}));
    assert_eq!(
        t.companies().await[0]["name"],
        "Apple",
        "existing row untouched"
    );
}

#[tokio::test]
async fn each_step_has_its_own_conflict_handling() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.post("/v1/batch", json!({"batches": [companies_step(json!([["AAPL", "Apple"]])), metrics_step(json!([["AAPL", "revenue", "2024-Q1", 1.0]]))]})).await;
    let mut upsert_companies = companies_step(json!([["AAPL", "Apple Inc."]]));
    upsert_companies["on_conflict"] = json!({"replace": ["name"]});
    let mut upsert_metrics = metrics_step(json!([
        ["AAPL", "revenue", "2024-Q1", 9.0],
        ["AAPL", "revenue", "2024-Q2", 8.0]
    ]));
    upsert_metrics["on_conflict"] = json!("replace_all");
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [upsert_companies, upsert_metrics]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(t.companies().await[0]["name"], "Apple Inc.");
    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["value"], 9.0);
}

#[tokio::test]
async fn a_failure_in_a_later_step_rolls_back_earlier_tables() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.insert(json!([["SEED", "m", "p1", 1.0]])).await;

    // Step 0 is valid; step 1 repeats a primary key inside the metrics table at row 2.
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                companies_step(json!([["AAPL", "Apple"], ["MSFT", "Microsoft"]])),
                metrics_step(json!([["AAPL", "revenue", "p1", 1.0], ["AAPL", "revenue", "p2", 2.0], ["AAPL", "revenue", "p1", 3.0]]))
            ]}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("conflict")),
        "{body}"
    );
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("batches[1]") && msg.contains("financial_metrics") && msg.contains("row 2"),
        "{msg}"
    );
    assert!(msg.contains("rolled back"), "{msg}");
    assert!(
        t.companies().await.is_empty(),
        "step 0 must have been rolled back"
    );
    assert_eq!(t.all_rows().await.len(), 1, "only the seed row remains");

    // Failure in the FIRST step leaves later tables untouched too.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                companies_step(json!([["X", "x"], ["X", "again"]])),
                metrics_step(json!([["X", "m", "p1", 1.0]]))
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(t.all_rows().await.len(), 1);

    // A later step violating NOT NULL, after an upsert step, also rolls everything back.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"batches": [
                companies_step(json!([["OK", "fine"]])),
                metrics_step(json!([[null, "m", "p9", 1.0]]))
            ]}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(t.companies().await.is_empty());

    // Everything still works afterwards.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"batches": [companies_step(json!([["OK", "fine"]]))]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn multi_table_validation_happens_before_anything_is_written() {
    let t = TestApp::new().await;
    t.two_tables().await;
    let good = companies_step(json!([["AAPL", "Apple"]]));
    let cases = [
        // (second step, expected status)
        (
            json!({"table": "financial_metrics", "columns": ["ticker", "nope"], "rows": [["a", "b"]]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"table": "missing_table", "columns": ["a"], "rows": [[1]]}),
            StatusCode::NOT_FOUND,
        ),
        (
            metrics_step(json!([["A", "m", "p1", [1, 2]]])),
            StatusCode::BAD_REQUEST,
        ),
        (
            metrics_step(json!([["A", "m", "p1"]])),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": [["A", "m", "p", 1.0]], "on_conflict": "replace_all", "conflict_target": ["value"]}),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (second, expected) in cases {
        let (status, body) = t
            .post(
                "/v1/batch",
                json!({"batches": [good.clone(), second.clone()]}),
            )
            .await;
        assert_eq!(status, expected, "{second}: {body}");
        let msg = body["error"].as_str().unwrap();
        assert!(msg.contains("batches[1]"), "{msg}");
        assert!(
            t.companies().await.is_empty(),
            "step 0 must not be written when step 1 is invalid: {second}"
        );
    }
}

#[tokio::test]
async fn empty_envelopes_and_empty_steps_are_no_ops() {
    let t = TestApp::new().await;
    let (status, body) = t.post("/v1/batch", json!({"batches": []})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"rows": {"submitted": 0, "affected": 0}, "batches": {}})
    );

    t.two_tables().await;
    let (status, body) = t
        .post("/v1/batch", json!({"batches": [companies_step(json!([])), metrics_step(json!([["A", "m", "p1", 1.0]]))]}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["batches"]["companies"],
        json!({"submitted": 0, "affected": 0})
    );
    assert_eq!(body["rows"]["affected"], 1);
}

#[tokio::test]
async fn limits_are_configurable_and_enforced_over_http() {
    let t = TestApp::new().await;
    t.two_tables().await;
    let limits = Limits {
        max_body_bytes: 2_000,
        max_batch_steps: 2,
        max_batch_rows: 3,
        max_batch_values: 100,
        ..Limits::default()
    };
    let router = app(Arc::new(AppState {
        db: t.db.clone(),
        api_key: Some(KEY.to_string()),
        limiter: Arc::new(Semaphore::new(64)),
        request_timeout: Duration::from_secs(30),
        limits,
    }));
    let post = |body: JsonValue| {
        let router = router.clone();
        async move { call(&router, Method::POST, "/v1/batch", Some(KEY), Some(body)).await }
    };

    let (status, _) = post(json!({"batches": [companies_step(json!([["A", "a"]])), companies_step(json!([["B", "b"]]))]})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(json!({"batches": [companies_step(json!([])), companies_step(json!([])), companies_step(json!([]))]})).await;
    assert_eq!(
        (
            status,
            body["error"]
                .as_str()
                .unwrap()
                .contains("at most 2 batches")
        ),
        (StatusCode::BAD_REQUEST, true),
        "{body}"
    );
    let (status, body) = post(json!({"batches": [companies_step(json!([["C", "c"], ["D", "d"]])), companies_step(json!([["E", "e"], ["F", "f"]]))]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("3 rows in total"));
    assert_eq!(
        t.companies().await.len(),
        2,
        "rejected request wrote nothing"
    );

    // The body-size limit is configurable as well.
    let (status, body) = post(companies_step(json!([["G", "x".repeat(3_000)]]))).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::PAYLOAD_TOO_LARGE, &json!("payload_too_large"))
    );
}

/// A competing transaction touches a row used by the second step. The whole request, both
/// tables, is aborted and re-run, and then lands completely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_table_batch_retries_as_a_whole_after_a_conflict() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.post(
        "/v1/batch",
        json!({"batches": [companies_step(json!([["A", "old"]]))]}),
    )
    .await;

    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute("UPDATE companies SET name = 'held' WHERE ticker = 'A'", ())
        .await
        .unwrap();

    let mut upsert = companies_step(json!([["A", "new"]]));
    upsert["on_conflict"] = json!("replace_all");
    let api = t.post(
        "/v1/batch",
        json!({"batches": [metrics_step(json!([["A", "m", "p1", 1.0]])), upsert]}),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        tx.commit().await.unwrap();
    };
    let ((status, body), ()) = tokio::join!(api, release);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(t.all_rows().await.len(), 1);
    assert_eq!(t.companies().await[0]["name"], "new");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exhausted_retries_leave_no_trace_in_any_table() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.post(
        "/v1/batch",
        json!({"batches": [companies_step(json!([["A", "old"]]))]}),
    )
    .await;

    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute("UPDATE companies SET name = 'held' WHERE ticker = 'A'", ())
        .await
        .unwrap();

    let mut upsert = companies_step(json!([["A", "new"]]));
    upsert["on_conflict"] = json!("replace_all");
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [metrics_step(json!([["A", "m", "p1", 1.0]])), upsert]}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("write_conflict")),
        "{body}"
    );
    tx.commit().await.unwrap();
    assert!(
        t.all_rows().await.is_empty(),
        "the metrics step must have been rolled back"
    );
    assert_eq!(t.companies().await[0]["name"], "held");
}

/// Writers each rewrite the same key in two tables at once. Every request is one transaction,
/// so the two tables must always agree on which writer won.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_multi_table_writers_stay_consistent_across_tables() {
    let t = TestApp::new().await;
    t.two_tables().await;
    t.post("/v1/batch", json!({"batches": [companies_step(json!([["A", "seed"]])), metrics_step(json!([["A", "m", "p1", -1.0], ["A", "m", "p2", -1.0]]))]})).await;

    let mut tasks = Vec::new();
    for writer in 0..12 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            let mut companies = companies_step(json!([["A", format!("writer-{writer}")]]));
            companies["on_conflict"] = json!("replace_all");
            let mut metrics = metrics_step(json!([
                ["A", "m", "p1", f64::from(writer)],
                ["A", "m", "p2", f64::from(writer)]
            ]));
            metrics["on_conflict"] = json!("replace_all");
            let (status, body) = call(
                &router,
                Method::POST,
                "/v1/batch",
                Some(KEY),
                Some(json!({"batches": [companies, metrics]})),
            )
            .await;
            (writer, status, body)
        }));
    }
    let mut committed = Vec::new();
    for task in tasks {
        let (writer, status, body) = task.await.unwrap();
        match status {
            StatusCode::OK => committed.push(writer),
            StatusCode::CONFLICT => assert_eq!(body["code"], "write_conflict", "{body}"),
            other => panic!("writer {writer}: unexpected {other}: {body}"),
        }
    }
    assert!(!committed.is_empty());

    let metric_values: Vec<f64> = t
        .all_rows()
        .await
        .iter()
        .map(|r| r["value"].as_f64().unwrap())
        .collect();
    let company = t.companies().await[0]["name"].as_str().unwrap().to_owned();
    assert_eq!(
        metric_values[0], metric_values[1],
        "mixed writers in one table: {metric_values:?}"
    );
    assert_eq!(
        company,
        format!("writer-{}", metric_values[0]),
        "tables disagree"
    );
    assert!(committed.contains(&(metric_values[0] as i32)));
}

/// 5,000 rows x 20 columns (100,000 values) must go through with the default limits, body-size
/// limit included, as one atomic transaction.
#[tokio::test]
async fn five_thousand_rows_of_twenty_columns_fit_the_defaults() {
    let t = TestApp::new().await;
    let columns: Vec<JsonValue> = (0..20)
        .map(|i| match i {
            0 => json!({"name": "id", "type": "INTEGER"}),
            i if i % 2 == 1 => json!({"name": format!("t{i:02}"), "type": "TEXT"}),
            i => json!({"name": format!("r{i:02}"), "type": "REAL"}),
        })
        .collect();
    let (status, body) = t
        .post(
            "/v1/tables",
            json!({"name": "wide", "columns": columns, "primary_key": ["id"]}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let names: Vec<String> = columns
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_owned())
        .collect();
    let rows: Vec<JsonValue> = (0..5_000)
        .map(|n| {
            let mut row = vec![json!(n)];
            for i in 1..20 {
                row.push(if i % 2 == 1 {
                    json!(format!("ticker-{n}"))
                } else {
                    json!(f64::from(n) * 1.5 + f64::from(i))
                });
            }
            JsonValue::Array(row)
        })
        .collect();
    let request = json!({"table": "wide", "columns": names, "rows": rows});
    let bytes = request.to_string().len();
    assert!(bytes < Limits::default().max_body_bytes, "{bytes} bytes");

    let (status, body) = t.post("/v1/batch", request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"], json!({"submitted": 5000, "affected": 5000}));

    let (_, body) = t
        .post("/v1/query", json!({"table": "wide", "columns": ["id", "t01", "r02"], "filters": {"id": {"in": [0, 2500, 4999]}}, "sort": [{"id": "asc"}]}))
        .await;
    assert_eq!(
        body["rows"],
        json!([{"id": 0, "t01": "ticker-0", "r02": 2.0}, {"id": 2500, "t01": "ticker-2500", "r02": 3752.0}, {"id": 4999, "t01": "ticker-4999", "r02": 7500.5}])
    );
    let (_, body) = t.post("/v1/query", json!({"table": "wide", "columns": ["id"], "filters": {"id": {"gte": 4500}}, "limit": 500})).await;
    assert_eq!(body["row_count"], 500);
}

// ----- delete -----

fn delete_plan(body: JsonValue, server_cap: Option<usize>) -> ApiResult<DeletePlan> {
    let request: DeleteRequest =
        serde_json::from_value(body).map_err(|e| ApiError::bad(e.to_string()))?;
    DeletePlan::from_request(request, server_cap)
}

#[test]
fn delete_request_validation() {
    let ok = |body: JsonValue| assert!(delete_plan(body.clone(), None).is_ok(), "{body}");
    ok(json!({"table": "t", "filters": {"a": 1}}));
    ok(json!({"table": "t", "filters": {"a": {"in": [1, 2]}}, "max_rows": 5}));
    ok(json!({"table": "t", "all": true}));
    ok(json!({"table": "t", "all": true, "filters": {}}));

    let bad = |body: JsonValue| {
        delete_plan(body.clone(), None)
            .err()
            .unwrap_or_else(|| panic!("accepted: {body}"))
            .to_string()
    };
    // Nothing selects the rows: refuse rather than delete everything by accident.
    for body in [
        json!({"table": "t"}),
        json!({"table": "t", "filters": {}}),
        json!({"table": "t", "all": false}),
        json!({"table": "t", "all": false, "filters": {}}),
    ] {
        let msg = bad(body);
        assert!(
            msg.contains("filters are required") && msg.contains("\"all\": true"),
            "{msg}"
        );
    }
    assert!(
        bad(json!({"table": "t", "all": true, "filters": {"a": 1}})).contains("cannot be combined")
    );
    assert!(
        bad(json!({"table": "t", "all": true, "filters": {"a": null}}))
            .contains("cannot be combined")
    );
    assert!(bad(json!({"table": "t", "filters": {"a": 1}, "max_rows": 0})).contains("max_rows"));
    // A negative or fractional number is not a valid row count (the HTTP error also names the field).
    for invalid in [json!(-1), json!(1.5), json!("5")] {
        assert!(
            delete_plan(
                json!({"table": "t", "filters": {"a": 1}, "max_rows": invalid}),
                None
            )
            .is_err()
        );
    }
    // Only what was agreed: no sort, limit, return, dry_run...
    for extra in [
        "sort", "limit", "offset", "order_by", "return", "dry_run", "columns",
    ] {
        let msg = bad(json!({"table": "t", "filters": {"a": 1}, extra: 1}));
        assert!(msg.contains(extra), "{msg}");
    }
    // Same filter validation as queries.
    assert!(bad(json!({"table": "t", "filters": {"a": {"between": [1, 2]}}})).contains("between"));
    assert!(bad(json!({"table": "bad name", "filters": {"a": 1}})).contains("table"));
    assert!(bad(json!({"table": "t", "filters": {"a b": 1}})).contains("filter column"));
    let many: Vec<usize> = (0..=MAX_QUERY_PARAMS).collect();
    assert!(bad(json!({"table": "t", "filters": {"a": {"in": many}}})).contains("values"));
}

#[test]
fn delete_sql_is_generated_from_the_shared_filters() {
    let sql = |body: JsonValue| delete_plan(body, None).unwrap().sql();
    assert_eq!(
        sql(json!({"table": "t", "all": true})),
        ("DELETE FROM \"t\"".to_owned(), vec![])
    );
    let (text, params) = sql(
        json!({"table": "t", "filters": {"a": 1, "b": {"in": ["x", "y"]}, "c": null, "d": {"like": ["p%", "q%"], "gt": 2}}}),
    );
    assert_eq!(
        text,
        "DELETE FROM \"t\" WHERE \"a\" = ?1 AND \"b\" IN (?2, ?3) AND \"c\" IS NULL AND (\"d\" LIKE ?4 OR \"d\" LIKE ?5) AND \"d\" > ?6"
    );
    assert_eq!(params.len(), 6);
    assert_eq!(
        sql(json!({"table": "t", "filters": {"a": {"in": []}}})).0,
        "DELETE FROM \"t\" WHERE 0"
    );
}

#[test]
fn delete_limit_is_the_smaller_of_the_request_and_the_server_setting() {
    let limit = |max_rows: Option<u64>, cap: Option<usize>| {
        let mut body = json!({"table": "t", "filters": {"a": 1}});
        if let Some(m) = max_rows {
            body["max_rows"] = json!(m);
        }
        delete_plan(body, cap)
            .unwrap()
            .limit
            .map(|l| (l.max, l.source))
    };
    assert_eq!(limit(None, None), None, "unlimited by default");
    assert_eq!(limit(Some(5), None), Some((5, "max_rows")));
    assert_eq!(limit(None, Some(10)), Some((10, "MAX_DELETE_ROWS")));
    assert_eq!(limit(Some(5), Some(10)), Some((5, "max_rows")));
    assert_eq!(
        limit(Some(50), Some(10)),
        Some((10, "MAX_DELETE_ROWS")),
        "a request cannot raise the cap"
    );
}

#[test]
fn max_delete_rows_setting() {
    assert_eq!(config(&[]).unwrap().limits.max_delete_rows, None);
    assert_eq!(
        config(&[("MAX_DELETE_ROWS", "250")])
            .unwrap()
            .limits
            .max_delete_rows,
        Some(250)
    );
    // Blank counts as unset, like the other variables; invalid values stop startup.
    assert_eq!(
        config(&[("MAX_DELETE_ROWS", " ")])
            .unwrap()
            .limits
            .max_delete_rows,
        None
    );
    for bad in ["0", "-3", "many", "1.5"] {
        let err = config(&[("MAX_DELETE_ROWS", bad)])
            .err()
            .unwrap_or_else(|| panic!("{bad} accepted"));
        assert!(err.contains("MAX_DELETE_ROWS"), "{err}");
    }
}

impl TestApp {
    async fn delete(&self, body: JsonValue) -> (StatusCode, JsonValue) {
        self.post("/v1/delete", body).await
    }

    async fn metric_rows(&self) -> usize {
        self.all_rows().await.len()
    }
}

#[tokio::test]
async fn delete_removes_exactly_the_matching_rows() {
    // (filters, rows deleted) over the seven-row fixture; the same filters must then match nothing.
    let cases: Vec<(JsonValue, u64)> = vec![
        (json!({"ticker": "AAPL"}), 3),
        (json!({"ticker": "AAPL", "metric": "revenue"}), 2),
        (json!({"metric": {"in": ["profit", "eps"]}}), 3),
        (json!({"metric": {"not_in": ["revenue"]}}), 3),
        (
            json!({"ticker": {"like": ["AA%", "MS%"]}, "period": {"not_like": "%-Q1"}}),
            1,
        ),
        (json!({"ticker": {"like": "%oo%"}}), 2),
        (json!({"value": {"gt": 5, "lt": 30}}), 3),
        (json!({"value": {"gte": 5, "lte": 10}}), 2),
        (json!({"value": {"eq": 15}}), 1),
        (json!({"value": null}), 2),
        (json!({"value": {"is_null": true}}), 2),
        (json!({"value": {"is_null": false}}), 5),
        (json!({"value": {"ne": 10}}), 4),
        (json!({"period": {"gt": "2024-Q1"}}), 2),
        (json!({"metric": {"in": []}}), 0),
        (json!({"metric": {"not_in": []}}), 7),
        (json!({"ticker": "NOBODY"}), 0),
    ];
    for (filters, expected) in cases {
        let t = filter_fixture().await;
        let (status, body) = t
            .delete(json!({"table": "financial_metrics", "filters": filters}))
            .await;
        assert_eq!(status, StatusCode::OK, "{filters}: {body}");
        assert_eq!(body, json!({"rows": {"deleted": expected}}), "{filters}");
        assert_eq!(t.metric_rows().await as u64, 7 - expected, "{filters}");
        // Nothing the filters select is left.
        let (_, left) = t
            .post(
                "/v1/query",
                json!({"table": "financial_metrics", "filters": filters}),
            )
            .await;
        assert_eq!(left["row_count"], 0, "{filters}");
    }
}

#[tokio::test]
async fn deleting_leaves_other_rows_untouched() {
    let t = filter_fixture().await;
    let before = keys(&t, json!({})).await;
    let (_, body) = t
        .delete(json!({"table": "financial_metrics", "filters": {"ticker": "GOOG"}}))
        .await;
    assert_eq!(body["rows"]["deleted"], 2);
    let expected: Vec<String> = before
        .into_iter()
        .filter(|k| !k.starts_with("GOOG"))
        .collect();
    assert_eq!(keys(&t, json!({})).await, expected);
    // A repeat is a successful no-op.
    let (status, body) = t
        .delete(json!({"table": "financial_metrics", "filters": {"ticker": "GOOG"}}))
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 0}}))
    );
}

#[tokio::test]
async fn delete_reports_missing_tables_and_columns_without_deleting() {
    let t = filter_fixture().await;
    let (status, body) = t
        .delete(json!({"table": "missing", "filters": {"a": 1}}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found")),
        "{body}"
    );
    // An unknown column, even one spelled so that an unchecked statement would read it as a
    // string literal (and delete every row), is a 400.
    for filters in [
        json!({"nope": "nope"}),
        json!({"nope": {"in": ["nope"]}}),
        json!({"ticker": "AAPL", "nope": null}),
    ] {
        let (status, body) = t
            .delete(json!({"table": "financial_metrics", "filters": filters}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{filters}: {body}");
        assert!(body["error"].as_str().unwrap().contains("nope"));
    }
    for body in [
        json!({"table": "bad table", "filters": {"a": 1}}),
        json!({"table": "financial_metrics", "filters": {"ticker": {"between": [1, 2]}}}),
        json!({"table": "financial_metrics", "filters": {"ticker": 1}, "sort": [{"ticker": "asc"}]}),
        json!({"table": "financial_metrics", "filters": {"ticker": 1}, "limit": 1}),
    ] {
        assert_eq!(
            t.delete(body.clone()).await.0,
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    assert_eq!(
        t.metric_rows().await,
        7,
        "nothing was deleted by any of the rejected requests"
    );
}

#[tokio::test]
async fn deleting_every_row_needs_all_true() {
    let t = filter_fixture().await;
    for body in [
        json!({"table": "financial_metrics"}),
        json!({"table": "financial_metrics", "filters": {}}),
        json!({"table": "financial_metrics", "all": false}),
        json!({"table": "financial_metrics", "all": true, "filters": {"ticker": "AAPL"}}),
    ] {
        let (status, response) = t.delete(body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
    }
    assert_eq!(t.metric_rows().await, 7);

    let (status, body) = t
        .delete(json!({"table": "financial_metrics", "all": true}))
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 7}}))
    );
    assert_eq!(t.metric_rows().await, 0);
    // The table itself remains and is usable; deleting from an empty table deletes nothing.
    let (status, _) = t.insert(json!([["A", "m", "p1", 1.0]])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        t.delete(json!({"table": "financial_metrics", "all": true}))
            .await
            .1["rows"]["deleted"],
        1
    );
    assert_eq!(
        t.delete(json!({"table": "financial_metrics", "all": true}))
            .await
            .1["rows"]["deleted"],
        0
    );
}

#[tokio::test]
async fn max_rows_guard_rolls_the_delete_back() {
    let t = filter_fixture().await;
    let delete = |max_rows: u64| {
        t.delete(json!({"table": "financial_metrics", "filters": {"ticker": "AAPL"}, "max_rows": max_rows}))
    };
    // Three rows match; a limit of two refuses, and nothing is deleted.
    let (status, body) = delete(2).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("too_many_rows")),
        "{body}"
    );
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("3 rows")
            && msg.contains("max_rows")
            && msg.contains("limit of 2")
            && msg.contains("nothing was deleted"),
        "{msg}"
    );
    assert_eq!(t.metric_rows().await, 7);
    // Exactly as many as the limit is fine.
    let (status, body) = delete(3).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 3}}))
    );
    assert_eq!(t.metric_rows().await, 4);
    // `all` obeys it as well.
    let (status, body) = t
        .delete(json!({"table": "financial_metrics", "all": true, "max_rows": 3}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("too_many_rows")),
        "{body}"
    );
    assert_eq!(t.metric_rows().await, 4);
}

#[tokio::test]
async fn server_wide_delete_cap_is_optional_and_cannot_be_raised_by_a_request() {
    let t = filter_fixture().await;
    let capped = |cap: Option<usize>| {
        app(Arc::new(AppState {
            db: t.db.clone(),
            api_key: Some(KEY.to_string()),
            limiter: Arc::new(Semaphore::new(64)),
            request_timeout: Duration::from_secs(30),
            limits: Limits {
                max_delete_rows: cap,
                ..Limits::default()
            },
        }))
    };
    let router = capped(Some(2));
    let delete = |body: JsonValue| {
        let router = router.clone();
        async move { call(&router, Method::POST, "/v1/delete", Some(KEY), Some(body)).await }
    };
    let (status, body) = delete(json!({"table": "financial_metrics", "all": true})).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("too_many_rows")),
        "{body}"
    );
    assert!(
        body["error"].as_str().unwrap().contains("MAX_DELETE_ROWS"),
        "{body}"
    );
    // A larger max_rows in the request does not lift the server's cap.
    let (status, _) =
        delete(json!({"table": "financial_metrics", "all": true, "max_rows": 1000})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(t.metric_rows().await, 7);
    // Within the cap it works.
    let (status, body) =
        delete(json!({"table": "financial_metrics", "filters": {"ticker": "GOOG"}})).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 2}}))
    );

    // By default there is no cap at all: thousands of rows go in one request.
    let bulk = TestApp::new().await;
    bulk.create_metrics().await;
    for chunk in 0..2 {
        let rows: Vec<JsonValue> = (0..3000)
            .map(|i| json!(["BULK", "m", format!("p{chunk}-{i:04}"), 1.0]))
            .collect();
        assert_eq!(bulk.insert(JsonValue::Array(rows)).await.0, StatusCode::OK);
    }
    let (status, body) = bulk
        .delete(json!({"table": "financial_metrics", "filters": {"ticker": "BULK"}}))
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 6000}}))
    );
    assert_eq!(bulk.metric_rows().await, 0);
}

#[tokio::test]
async fn delete_works_without_a_key_and_with_an_auto_id() {
    let t = TestApp::new().await;
    // Auto id: delete by id, by range and by another column.
    t.create_table_ok(notes_table()).await;
    let rows: Vec<JsonValue> = (1..=6)
        .map(|i| json!([format!("note {i}"), i % 2]))
        .collect();
    t.post(
        "/v1/batch",
        json!({"table": "notes", "columns": ["text", "done"], "rows": rows}),
    )
    .await;
    assert_eq!(
        t.delete(json!({"table": "notes", "filters": {"id": 1}}))
            .await
            .1["rows"]["deleted"],
        1
    );
    assert_eq!(
        t.delete(json!({"table": "notes", "filters": {"id": {"in": [2, 3, 99]}}}))
            .await
            .1["rows"]["deleted"],
        2
    );
    assert_eq!(
        t.delete(json!({"table": "notes", "filters": {"done": 1}}))
            .await
            .1["rows"]["deleted"],
        1,
        "only id 5 is left with done = 1"
    );
    let ids: Vec<_> = t
        .rows_of("notes")
        .await
        .iter()
        .map(|r| r["id"].clone())
        .collect();
    assert_eq!(ids, [json!(4), json!(6)]);

    // No primary key: duplicates are all removed by one delete.
    t.create_table_ok(json!({"name": "events", "columns": [{"name": "name", "type": "TEXT"}], "primary_key": false})).await;
    t.post(
        "/v1/batch",
        json!({"table": "events", "columns": ["name"], "rows": [["a"], ["a"], ["b"], ["a"]]}),
    )
    .await;
    assert_eq!(
        t.delete(json!({"table": "events", "filters": {"name": "a"}}))
            .await
            .1["rows"]["deleted"],
        3
    );
    assert_eq!(t.rows_of("events").await, [json!({"name": "b"})]);
}

#[tokio::test]
async fn delete_filters_accept_blobs() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "files", "columns": [{"name": "data", "type": "BLOB"}]}))
        .await;
    let (a, b, c) = (
        json!({"$type": "blob", "base64": "AAEC"}),
        json!({"$type": "blob", "base64": "AwQF"}),
        json!({"$type": "blob", "base64": "BgcI"}),
    );
    t.post(
        "/v1/batch",
        json!({"table": "files", "columns": ["data"], "rows": [[a], [b], [c]]}),
    )
    .await;
    assert_eq!(
        t.delete(json!({"table": "files", "filters": {"data": a}}))
            .await
            .1["rows"]["deleted"],
        1
    );
    assert_eq!(
        t.delete(json!({"table": "files", "filters": {"data": {"in": [b, c]}}}))
            .await
            .1["rows"]["deleted"],
        2
    );
    assert!(t.rows_of("files").await.is_empty());
}

#[tokio::test]
async fn delete_requires_the_api_key_when_one_is_set() {
    let t = TestApp::new().await;
    let body = json!({"table": "t", "all": true});
    let (status, _) = t
        .call(Method::POST, "/v1/delete", None, Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = t
        .call(Method::POST, "/v1/delete", Some("wrong"), Some(body))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A competing transaction has an uncommitted change to a row the delete wants: the delete loses
/// the conflict and is re-run, and lands once the competing transaction is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_is_retried_after_losing_a_write_conflict() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["A", "m", "p1", 1.0], ["B", "m", "p1", 2.0]]))
        .await;

    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute(
        "UPDATE financial_metrics SET value = 100 WHERE ticker = 'A'",
        (),
    )
    .await
    .unwrap();

    let api = t.delete(json!({"table": "financial_metrics", "filters": {"ticker": "A"}}));
    let release = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        tx.commit().await.unwrap();
    };
    let ((status, body), ()) = tokio::join!(api, release);
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 1}}))
    );
    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ticker"], "B");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_reports_write_conflict_when_retries_are_exhausted() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["A", "m", "p1", 1.0], ["B", "m", "p1", 2.0]]))
        .await;
    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute(
        "UPDATE financial_metrics SET value = 100 WHERE ticker = 'A'",
        (),
    )
    .await
    .unwrap();

    let (status, body) = t
        .delete(json!({"table": "financial_metrics", "all": true}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("write_conflict")),
        "{body}"
    );
    tx.commit().await.unwrap();
    // Nothing was deleted, not even the row nobody else touched.
    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 2, "{rows:?}");
}

/// Writers keep inserting rows while deleters keep removing them. Whatever the interleaving,
/// every row is deleted exactly once or still there: nothing lost, nothing counted twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_and_deletes_account_for_every_row() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let mut tasks = Vec::new();
    for writer in 0..4 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..15 {
                let rows: Vec<JsonValue> = (0..5).map(|i| json!(["X", "m", format!("w{writer}r{round:02}n{i}"), 1.0])).collect();
                let (status, body) = call(&router, Method::POST, "/v1/batch", Some(KEY), Some(json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows}))).await;
                assert_eq!(status, StatusCode::OK, "{body}");
            }
            0_u64
        }));
    }
    for _ in 0..3 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            let mut deleted = 0;
            for _ in 0..25 {
                let (status, body) = call(
                    &router,
                    Method::POST,
                    "/v1/delete",
                    Some(KEY),
                    Some(json!({"table": "financial_metrics", "filters": {"ticker": "X"}})),
                )
                .await;
                match status {
                    StatusCode::OK => deleted += body["rows"]["deleted"].as_u64().unwrap(),
                    // Losing repeatedly to another deleter is allowed; it deleted nothing.
                    StatusCode::CONFLICT => assert_eq!(body["code"], "write_conflict", "{body}"),
                    other => panic!("unexpected {other}: {body}"),
                }
            }
            deleted
        }));
    }
    let mut deleted = 0;
    for task in tasks {
        deleted += task.await.unwrap();
    }
    let remaining = t.metric_rows().await as u64;
    assert_eq!(
        deleted + remaining,
        4 * 15 * 5,
        "deleted {deleted} + remaining {remaining}"
    );
    // A final sweep removes whatever is left.
    let (_, body) = t
        .delete(json!({"table": "financial_metrics", "filters": {"ticker": "X"}}))
        .await;
    assert_eq!(body["rows"]["deleted"].as_u64().unwrap(), remaining);
    assert_eq!(t.metric_rows().await, 0);
}

// ----- foreign keys -----

fn reference(value: JsonValue) -> ApiResult<ForeignKey> {
    parse_reference("symbol_id", &value)
}

#[test]
fn references_accepts_a_table_name_or_a_table_and_column() {
    // A plain table name references its `id` column.
    let fk = reference(json!("stocks")).unwrap();
    assert_eq!(
        (fk.table.as_str(), fk.column.as_str(), fk.column_defaulted),
        ("stocks", "id", true)
    );
    // The object form defaults the column to `id` as well, or names one.
    let fk = reference(json!({"table": "stocks"})).unwrap();
    assert_eq!(
        (fk.table.as_str(), fk.column.as_str(), fk.column_defaulted),
        ("stocks", "id", true)
    );
    let fk = reference(json!({"table": "stocks", "column": "other"})).unwrap();
    assert_eq!(
        (fk.table.as_str(), fk.column.as_str(), fk.column_defaulted),
        ("stocks", "other", false)
    );
}

#[test]
fn references_rejects_everything_else() {
    for invalid in [
        json!(5),
        json!(true),
        json!(["stocks"]),
        json!({}),
        json!({"column": "id"}),
        json!({"table": 1}),
        json!({"table": "stocks", "column": 1}),
        json!({"table": "stocks", "column": null}),
        // Only table and column exist; actions such as cascade are not supported.
        json!({"table": "stocks", "on_delete": "cascade"}),
        json!({"table": "stocks", "columns": ["id"]}),
        // Identifiers get the same validation as everywhere else.
        json!(""),
        json!("bad name"),
        json!("sqlite_master"),
        json!("stocks; DROP TABLE x"),
        json!({"table": "stocks", "column": "bad name"}),
    ] {
        assert!(reference(invalid.clone()).is_err(), "{invalid}");
    }
    let msg = reference(json!(5)).err().unwrap().to_string();
    assert!(
        msg.contains("symbol_id") && msg.contains("\"table\"") && msg.contains("\"column\""),
        "{msg}"
    );
    let msg = reference(json!({"table": "stocks", "on_delete": "cascade"}))
        .err()
        .unwrap()
        .to_string();
    assert!(
        msg.contains("on_delete") && msg.contains("table, column"),
        "{msg}"
    );
}

fn fk_table(columns: JsonValue, key: Option<JsonValue>) -> ApiResult<TablePlan> {
    let mut request = json!({"name": "fact_values", "columns": columns});
    if let Some(key) = key {
        request["primary_key"] = key;
    }
    table_request(request)
}

#[test]
fn foreign_keys_generate_table_constraints() {
    // The example from the feature request: no primary key, one foreign key to stocks.id.
    let plan = fk_table(
        json!([{"name": "symbol_id", "type": "integer", "references": "stocks"}]),
        Some(json!(false)),
    )
    .unwrap();
    assert_eq!(
        plan.create_sql(),
        "CREATE TABLE \"fact_values\" (\"symbol_id\" INTEGER NOT NULL, FOREIGN KEY (\"symbol_id\") REFERENCES \"stocks\" (\"id\"))"
    );
    // Another referenced column, a nullable key column, an automatic id and several foreign keys.
    let plan = fk_table(
        json!([
            {"name": "symbol_id", "type": "INTEGER", "references": {"table": "stocks", "column": "other"}},
            {"name": "owner", "type": "TEXT", "nullable": true, "references": {"table": "people"}},
            {"name": "value", "type": "REAL", "nullable": true}
        ]),
        None,
    )
    .unwrap();
    assert_eq!(
        plan.create_sql(),
        "CREATE TABLE \"fact_values\" (\"id\" INTEGER PRIMARY KEY, \"symbol_id\" INTEGER NOT NULL, \"owner\" TEXT, \"value\" REAL, FOREIGN KEY (\"symbol_id\") REFERENCES \"stocks\" (\"other\"), FOREIGN KEY (\"owner\") REFERENCES \"people\" (\"id\"))"
    );
    assert_eq!(
        plan.foreign_keys(),
        [
            ("owner".to_owned(), "people".to_owned(), "id".to_owned()),
            (
                "symbol_id".to_owned(),
                "stocks".to_owned(),
                "other".to_owned()
            )
        ]
    );
    // Combined with an explicit primary key, the constraints follow it.
    let plan = fk_table(
        json!([{"name": "a", "type": "INTEGER", "references": "p"}, {"name": "b", "type": "TEXT"}]),
        Some(json!(["a", "b"])),
    )
    .unwrap();
    assert!(
        plan.create_sql().ends_with(
            "PRIMARY KEY (\"a\", \"b\"), FOREIGN KEY (\"a\") REFERENCES \"p\" (\"id\"))"
        ),
        "{}",
        plan.create_sql()
    );
    // `references: null` means no reference, like leaving it out.
    let plan = fk_table(
        json!([{"name": "a", "type": "INTEGER", "references": null}]),
        Some(json!(false)),
    )
    .unwrap();
    assert!(!plan.create_sql().contains("FOREIGN KEY"));
    // A bad reference fails the whole table request.
    assert!(
        fk_table(
            json!([{"name": "a", "type": "INTEGER", "references": 5}]),
            None
        )
        .is_err()
    );
}

impl TestApp {
    /// `stocks`: an automatic id plus a `code` that is unique. Rows: 1 = AAPL, 2 = MSFT.
    async fn create_stocks(&self) {
        self.create_table_ok(json!({"name": "stocks", "columns": [{"name": "code", "type": "TEXT"}, {"name": "other", "type": "TEXT", "nullable": true}]})).await;
        self.create_table_ok_index("u_stocks_code", "stocks", "code")
            .await;
        let (status, body) = self
            .post(
                "/v1/batch",
                json!({"table": "stocks", "columns": ["code"], "rows": [["AAPL"], ["MSFT"]]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn create_table_ok_index(&self, name: &str, table: &str, column: &str) {
        let (status, body) = self
            .post(
                "/v1/indexes",
                json!({"name": name, "table": table, "columns": [column], "unique": true}),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    async fn insert_into(
        &self,
        table: &str,
        columns: JsonValue,
        rows: JsonValue,
    ) -> (StatusCode, JsonValue) {
        self.post(
            "/v1/batch",
            json!({"table": table, "columns": columns, "rows": rows}),
        )
        .await
    }
}

fn fact_values(references: JsonValue) -> JsonValue {
    json!({"name": "fact_values", "primary_key": false,
           "columns": [{"name": "symbol_id", "type": "integer", "references": references},
                       {"name": "value", "type": "REAL", "nullable": true}]})
}

#[tokio::test]
async fn foreign_keys_accept_valid_rows_and_reject_orphans() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    // The request exactly as in the feature description (plus a value column).
    t.create_table_ok(fact_values(json!("stocks"))).await;

    let (status, body) = t
        .insert_into(
            "fact_values",
            json!(["symbol_id", "value"]),
            json!([[1, 10.0], [2, 20.0], [1, 11.0]]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"], json!({"submitted": 3, "affected": 3}));

    // A row whose parent does not exist is rejected, and the batch rolls back, valid rows included.
    let (status, body) = t
        .insert_into(
            "fact_values",
            json!(["symbol_id", "value"]),
            json!([[1, 1.0], [99, 2.0], [2, 3.0]]),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("conflict")),
        "{body}"
    );
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("foreign key") && msg.contains("row 1") && msg.contains("rolled back"),
        "{msg}"
    );
    assert_eq!(
        t.rows_of("fact_values").await.len(),
        3,
        "nothing from the rejected batch was written"
    );

    // Other constraint errors keep their own wording.
    let (_, body) = t
        .insert_into("fact_values", json!(["value"]), json!([[1.0]]))
        .await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .starts_with("constraint violation at row 0"),
        "{body}"
    );
}

#[tokio::test]
async fn a_nullable_foreign_key_column_may_be_null() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(json!({"name": "notes", "columns": [{"name": "text", "type": "TEXT"}, {"name": "stock_id", "type": "INTEGER", "nullable": true, "references": "stocks"}]})).await;
    let (status, body) = t
        .insert_into(
            "notes",
            json!(["text", "stock_id"]),
            json!([["about AAPL", 1], ["general", null]]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = t
        .insert_into(
            "notes",
            json!(["text", "stock_id"]),
            json!([["dangling", 42]]),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // A NOT NULL foreign key (the default) refuses NULL, as any NOT NULL column does.
    t.create_table_ok(fact_values(json!("stocks"))).await;
    let (status, _) = t
        .insert_into("fact_values", json!(["symbol_id"]), json!([[null]]))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_referenced_parent_row_cannot_be_deleted() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(fact_values(json!("stocks"))).await;
    t.insert_into(
        "fact_values",
        json!(["symbol_id", "value"]),
        json!([[1, 10.0], [1, 11.0]]),
    )
    .await;

    // Stock 1 still has facts: the delete is refused and nothing is removed.
    let (status, body) = t
        .delete(json!({"table": "stocks", "filters": {"id": 1}}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("conflict")),
        "{body}"
    );
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("still referenced")
            && msg.contains("foreign key")
            && msg.contains("nothing was deleted"),
        "{msg}"
    );
    assert_eq!(t.rows_of("stocks").await.len(), 2);
    // So is deleting every row of the parent while any child exists, even for unreferenced rows.
    let (status, _) = t.delete(json!({"table": "stocks", "all": true})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(t.rows_of("stocks").await.len(), 2);

    // A parent nobody references can go; so can the others once their children are deleted.
    let (status, body) = t
        .delete(json!({"table": "stocks", "filters": {"id": 2}}))
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"rows": {"deleted": 1}}))
    );
    assert_eq!(
        t.delete(json!({"table": "fact_values", "filters": {"symbol_id": 1}}))
            .await
            .1["rows"]["deleted"],
        2
    );
    assert_eq!(
        t.delete(json!({"table": "stocks", "filters": {"id": 1}}))
            .await
            .1["rows"]["deleted"],
        1
    );
}

#[tokio::test]
async fn a_foreign_key_can_reference_another_unique_column() {
    let t = TestApp::new().await;
    t.create_stocks().await; // code is unique, other is not
    let child = |column: &str| json!({"name": "by_code", "columns": [{"name": "code", "type": "TEXT", "references": {"table": "stocks", "column": column}}]});
    // `other` has no unique index: refused.
    let (status, body) = t.post("/v1/tables", json!({"name": "bad", "columns": [{"name": "o", "type": "TEXT", "nullable": true, "references": {"table": "stocks", "column": "other"}}]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("not unique"),
        "{body}"
    );
    // `code` does: accepted, and then enforced.
    t.create_table_ok(child("code")).await;
    let (status, body) = t
        .insert_into("by_code", json!(["code"]), json!([["AAPL"], ["MSFT"]]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = t
        .insert_into("by_code", json!(["code"]), json!([["NOPE"]]))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = t
        .delete(json!({"table": "stocks", "filters": {"code": "AAPL"}}))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "AAPL is referenced through its code"
    );
}

#[tokio::test]
async fn invalid_references_are_rejected_and_create_nothing() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    // A parent whose key is `code` and which has no `id` column at all.
    t.create_table_ok(json!({"name": "keyed", "columns": [{"name": "code", "type": "TEXT"}], "primary_key": ["code"]})).await;

    let child = |references: JsonValue, sql_type: &str| json!({"name": "child", "columns": [{"name": "ref", "type": sql_type, "references": references}], "primary_key": false});
    let cases: Vec<(JsonValue, &str, &str)> = vec![
        (
            child(json!("missing"), "INTEGER"),
            "does not exist",
            "create it first",
        ),
        (
            child(json!({"table": "stocks", "column": "nope"}), "INTEGER"),
            "has no column \"nope\"",
            "stocks",
        ),
        // The default column `id` does not exist in `keyed`: the message says how to name another.
        (
            child(json!("keyed"), "INTEGER"),
            "has no column \"id\"",
            "\"column\"",
        ),
        (
            child(json!("stocks"), "TEXT"),
            "types differ",
            "TEXT vs INTEGER",
        ),
        (
            child(json!({"table": "stocks", "column": "code"}), "INTEGER"),
            "types differ",
            "INTEGER vs TEXT",
        ),
        (
            child(json!({"table": "stocks", "column": "other"}), "TEXT"),
            "not unique",
            "unique index",
        ),
    ];
    for (body, first, second) in cases {
        let (status, response) = t.post("/v1/tables", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        let msg = response["error"].as_str().unwrap();
        assert!(msg.contains(first) && msg.contains(second), "{msg}");
        let (status, _) = t.post("/v1/query", json!({"table": "child"})).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a rejected request must not create the table: {body}"
        );
    }
    // The shape of `references` itself.
    for bad in [
        json!(5),
        json!(true),
        json!([]),
        json!({}),
        json!({"table": "stocks", "on_delete": "cascade"}),
        json!(""),
    ] {
        let (status, _) = t.post("/v1/tables", child(bad.clone(), "INTEGER")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn a_table_can_reference_itself() {
    let t = TestApp::new().await;
    // An automatic id makes `id` the default target; the parent column may be NULL for roots.
    t.create_table_ok(json!({"name": "tree", "columns": [{"name": "name", "type": "TEXT"}, {"name": "parent_id", "type": "INTEGER", "nullable": true, "references": "tree"}]})).await;
    let (status, body) = t
        .insert_into(
            "tree",
            json!(["name", "parent_id"]),
            json!([["root", null]]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        t.insert_into(
            "tree",
            json!(["name", "parent_id"]),
            json!([["child", 1], ["grandchild", 2]])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        t.insert_into(
            "tree",
            json!(["name", "parent_id"]),
            json!([["orphan", 99]])
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // The root has children, so it cannot be deleted; leaves can, from the bottom up.
    assert_eq!(
        t.delete(json!({"table": "tree", "filters": {"name": "root"}}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.delete(json!({"table": "tree", "filters": {"name": "grandchild"}}))
            .await
            .1["rows"]["deleted"],
        1
    );
    assert_eq!(
        t.delete(json!({"table": "tree", "filters": {"name": "child"}}))
            .await
            .1["rows"]["deleted"],
        1
    );
    assert_eq!(
        t.delete(json!({"table": "tree", "filters": {"name": "root"}}))
            .await
            .1["rows"]["deleted"],
        1
    );

    // The referenced column of a self-reference must be the table's own single-column key.
    let own = |references: JsonValue, key: JsonValue| json!({"name": "loop", "primary_key": key, "columns": [{"name": "code", "type": "TEXT"}, {"name": "up", "type": "TEXT", "nullable": true, "references": references}]});
    for (references, key) in [
        (json!({"table": "loop", "column": "code"}), json!(false)), // no key at all
        (json!({"table": "loop", "column": "nope"}), json!(["code"])), // unknown column
        (json!("loop"), json!(["code"])), // default `id` is not a column here
    ] {
        let (status, body) = t
            .post("/v1/tables", own(references.clone(), key.clone()))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{references} with key {key}: {body}"
        );
    }
    t.create_table_ok(own(
        json!({"table": "loop", "column": "code"}),
        json!(["code"]),
    ))
    .await;
}

#[tokio::test]
async fn creating_a_table_with_foreign_keys_is_idempotent() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(json!({"name": "other_parent", "columns": [{"name": "x", "type": "TEXT"}]}))
        .await;
    t.create_table_ok(fact_values(json!("stocks"))).await;
    // The same table again, spelled either way, is accepted.
    t.create_table_ok(fact_values(json!("stocks"))).await;
    t.create_table_ok(fact_values(json!({"table": "stocks"})))
        .await;
    t.create_table_ok(fact_values(json!({"table": "stocks", "column": "id"})))
        .await;
    // A different foreign key, or none, or an extra one, is a different table.
    for different in [
        fact_values(json!({"table": "stocks", "column": "code"})),
        fact_values(json!("other_parent")),
    ] {
        let (status, body) = t.post("/v1/tables", different.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{different}: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("different definition")
        );
    }
    let without = json!({"name": "fact_values", "primary_key": false, "columns": [{"name": "symbol_id", "type": "integer"}, {"name": "value", "type": "REAL", "nullable": true}]});
    assert_eq!(t.post("/v1/tables", without).await.0, StatusCode::CONFLICT);
    // And the other way round: a table created without a reference does not match one with it.
    t.create_table_ok(json!({"name": "plain", "primary_key": false, "columns": [{"name": "symbol_id", "type": "INTEGER"}]})).await;
    let with = json!({"name": "plain", "primary_key": false, "columns": [{"name": "symbol_id", "type": "INTEGER", "references": "stocks"}]});
    assert_eq!(t.post("/v1/tables", with).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn foreign_keys_are_enforced_on_every_connection() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(fact_values(json!("stocks"))).await;
    // Engines of this family leave foreign keys off per connection; Bonny must turn them on.
    for _ in 0..3 {
        let conn = t.db.connect().await.unwrap();
        let (_, rows) = fetch_all(&conn, "PRAGMA foreign_keys", vec![])
            .await
            .unwrap();
        assert_eq!(rows[0][0], DbValue::Integer(1));
        let orphan = conn
            .execute("INSERT INTO fact_values (symbol_id) VALUES (12345)", ())
            .await;
        assert!(
            matches!(orphan, Err(turso::Error::Constraint(_))),
            "{orphan:?}"
        );
    }
}

#[tokio::test]
async fn multi_table_batches_must_insert_parents_before_children() {
    let t = TestApp::new().await;
    t.two_tables().await; // companies(ticker pk) and financial_metrics
    t.create_table_ok(json!({
        "name": "holdings",
        "columns": [{"name": "ticker", "type": "TEXT", "references": {"table": "companies", "column": "ticker"}}, {"name": "shares", "type": "INTEGER"}],
        "primary_key": false
    })).await;
    let parent = companies_step(json!([["NEWCO", "New Co"]]));
    let child =
        json!({"table": "holdings", "columns": ["ticker", "shares"], "rows": [["NEWCO", 10]]});

    // Parent first, then child, in one transaction: fine.
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"batches": [parent.clone(), child.clone()]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The other order is checked immediately and fails; the failure names the step and rolls back everything.
    t.delete(json!({"table": "holdings", "all": true})).await;
    t.delete(json!({"table": "companies", "all": true})).await;
    let (status, body) = t
        .post("/v1/batch", json!({"batches": [child, parent]}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("batches[0]") && msg.contains("holdings") && msg.contains("foreign key"),
        "{msg}"
    );
    assert!(t.companies().await.is_empty());
}

#[tokio::test]
async fn composite_primary_keys_and_foreign_keys_combine() {
    let t = TestApp::new().await;
    t.create_companies().await;
    t.post(
        "/v1/batch",
        json!({"batches": [companies_step(json!([["AAPL", "Apple"]]))]}),
    )
    .await;
    // The financial_metrics table of the examples, with its ticker pointing at companies.
    let mut table = metrics_table();
    table["columns"][0]["references"] = json!({"table": "companies", "column": "ticker"});
    t.create_table_ok(table.clone()).await;
    t.create_table_ok(table).await; // idempotent
    assert_eq!(
        t.insert(json!([["AAPL", "revenue", "2024-Q1", 1.0]]))
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = t.insert(json!([["TSLA", "revenue", "2024-Q1", 1.0]])).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains("foreign key"));
    // Upserts and conflicts on the composite key still work next to the foreign key.
    let (status, body) = t
        .post("/v1/batch", json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": [["AAPL", "revenue", "2024-Q1", 9.0]], "on_conflict": {"replace": ["value"]}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(t.all_rows().await[0]["value"], 9.0);
    // The company cannot be removed while it has metrics.
    assert_eq!(
        t.delete(json!({"table": "companies", "filters": {"ticker": "AAPL"}}))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

// ----- schema listing -----

impl TestApp {
    async fn schema(&self) -> JsonValue {
        let (status, body) = self.call(Method::GET, "/v1/schema", Some(KEY), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// The listed table with this name.
    async fn schema_of(&self, table: &str) -> JsonValue {
        let schema = self.schema().await;
        schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == table)
            .unwrap_or_else(|| panic!("{table} is not in the schema: {schema}"))
            .clone()
    }

    fn raw_table(&self) -> &Arc<Db> {
        &self.db
    }
}

fn names(schema: &JsonValue) -> Vec<String> {
    schema["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn an_empty_database_has_an_empty_schema() {
    // Not even the engine's own bookkeeping tables (MVCC keeps one) are listed.
    let t = TestApp::new().await;
    assert_eq!(t.schema().await, json!({"tables": []}));
    let conn = t.raw_table().connect().await.unwrap();
    let (_, rows) = fetch_all(
        &conn,
        "SELECT name FROM sqlite_schema WHERE type = 'table'",
        vec![],
    )
    .await
    .unwrap();
    assert!(
        !rows.is_empty(),
        "the engine has tables of its own, which the listing must hide"
    );
}

#[tokio::test]
async fn schema_describes_columns_primary_keys_and_auto_ids() {
    let t = TestApp::new().await;
    t.create_table_ok(notes_table()).await; // automatic id
    t.create_metrics().await; // composite key
    t.create_table_ok(json!({"name": "events", "columns": [{"name": "name", "type": "TEXT"}, {"name": "at", "type": "TEXT", "nullable": true}], "primary_key": false})).await;
    t.create_table_ok(json!({"name": "codes", "columns": [{"name": "code", "type": "TEXT"}], "primary_key": ["code"]})).await;
    t.create_table_ok(json!({"name": "ints", "columns": [{"name": "n", "type": "integer"}], "primary_key": ["n"]})).await;

    let schema = t.schema().await;
    // Tables are sorted by name.
    assert_eq!(
        names(&schema),
        ["codes", "events", "financial_metrics", "ints", "notes"]
    );

    assert_eq!(
        t.schema_of("notes").await,
        json!({
            "name": "notes",
            "primary_key": ["id"],
            "columns": [
                {"name": "id", "type": "INTEGER", "nullable": false, "auto_id": true},
                {"name": "text", "type": "TEXT", "nullable": false, "auto_id": false},
                {"name": "done", "type": "INTEGER", "nullable": true, "auto_id": false}
            ],
            "indexes": []
        })
    );
    // A composite key lists its columns in key order, and none of them is an auto id.
    assert_eq!(
        t.schema_of("financial_metrics").await,
        json!({
            "name": "financial_metrics",
            "primary_key": ["ticker", "metric", "period"],
            "columns": [
                {"name": "ticker", "type": "TEXT", "nullable": false, "auto_id": false},
                {"name": "metric", "type": "TEXT", "nullable": false, "auto_id": false},
                {"name": "period", "type": "TEXT", "nullable": false, "auto_id": false},
                {"name": "value", "type": "REAL", "nullable": true, "auto_id": false}
            ],
            "indexes": []
        })
    );
    // No primary key: an empty list, and every column is just what was asked for.
    let events = t.schema_of("events").await;
    assert_eq!(events["primary_key"], json!([]));
    assert_eq!(
        events["columns"][0],
        json!({"name": "name", "type": "TEXT", "nullable": false, "auto_id": false})
    );
    assert_eq!(events["columns"][1]["nullable"], true);
    // A text key is not an auto id; a single INTEGER key is (it is filled in when left out).
    assert_eq!(t.schema_of("codes").await["columns"][0]["auto_id"], false);
    assert_eq!(t.schema_of("ints").await["columns"][0]["auto_id"], true);
    // Types come back in capitals however they were requested.
    assert_eq!(t.schema_of("ints").await["columns"][0]["type"], "INTEGER");
}

#[tokio::test]
async fn schema_lists_foreign_keys_as_references() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(fact_values(json!("stocks"))).await;
    t.create_table_ok(json!({"name": "by_code", "primary_key": false, "columns": [{"name": "code", "type": "TEXT", "references": {"table": "stocks", "column": "code"}}, {"name": "note", "type": "TEXT", "nullable": true}]})).await;

    let fact = t.schema_of("fact_values").await;
    // The default column shows up as the real column it resolved to, in the form of the request.
    assert_eq!(
        fact["columns"][0],
        json!({"name": "symbol_id", "type": "INTEGER", "nullable": false, "auto_id": false, "references": {"table": "stocks", "column": "id"}})
    );
    assert!(
        fact["columns"][1].get("references").is_none(),
        "columns without a foreign key have no references"
    );
    let by_code = t.schema_of("by_code").await;
    assert_eq!(
        by_code["columns"][0]["references"],
        json!({"table": "stocks", "column": "code"})
    );
    assert!(by_code["columns"][1].get("references").is_none());
    assert!(
        t.schema_of("stocks").await["columns"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("references").is_none())
    );
}

#[tokio::test]
async fn schema_lists_the_indexes_made_with_the_api() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let index = |name: &str, columns: JsonValue, unique: bool| json!({"name": name, "table": "financial_metrics", "columns": columns, "unique": unique});
    for body in [
        index("idx_z_value", json!(["value"]), false),
        index("idx_a_metric_period", json!(["metric", "period"]), false),
        index("idx_m_value_ticker", json!(["value", "ticker"]), true),
    ] {
        let (status, response) = t.post("/v1/indexes", body).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    }
    let table = t.schema_of("financial_metrics").await;
    // Sorted by name, columns in index order, and the primary key's own index is not listed.
    assert_eq!(
        table["indexes"],
        json!([
            {"name": "idx_a_metric_period", "unique": false, "columns": ["metric", "period"]},
            {"name": "idx_m_value_ticker", "unique": true, "columns": ["value", "ticker"]},
            {"name": "idx_z_value", "unique": false, "columns": ["value"]}
        ])
    );
    assert_eq!(table["primary_key"], json!(["ticker", "metric", "period"]));
}

#[tokio::test]
async fn the_schema_follows_changes_immediately() {
    let t = TestApp::new().await;
    assert_eq!(names(&t.schema().await), Vec::<String>::new());
    t.create_table_ok(notes_table()).await;
    assert_eq!(names(&t.schema().await), ["notes"]);
    assert_eq!(t.schema_of("notes").await["indexes"], json!([]));
    t.create_table_ok_index("u_notes_text", "notes", "text")
        .await;
    assert_eq!(
        t.schema_of("notes").await["indexes"],
        json!([{"name": "u_notes_text", "unique": true, "columns": ["text"]}])
    );
    t.create_companies().await;
    assert_eq!(names(&t.schema().await), ["companies", "notes"]);
}

#[tokio::test]
async fn schema_leaves_out_what_the_api_cannot_address() {
    let t = TestApp::new().await;
    t.create_table_ok(notes_table()).await;
    let conn = t.raw_table().connect().await.unwrap();
    for sql in [
        "CREATE VIEW \"a_view\" AS SELECT 1 AS one",
        "CREATE TABLE \"has space\" (\"a\" INTEGER)",
        "CREATE TABLE \"with_unique\" (\"a\" TEXT UNIQUE, \"b\" TEXT)",
        "CREATE TABLE \"parent2\" (\"x\" INTEGER, \"y\" INTEGER, PRIMARY KEY (\"x\", \"y\"))",
        "CREATE TABLE \"composite_child\" (\"p\" INTEGER, \"q\" INTEGER, FOREIGN KEY (\"p\", \"q\") REFERENCES \"parent2\" (\"x\", \"y\"))",
    ] {
        conn.execute(sql, ())
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
    let schema = t.schema().await;
    // Views and names the API cannot use are not tables of the API.
    assert_eq!(
        names(&schema),
        ["composite_child", "notes", "parent2", "with_unique"]
    );
    // The automatic index of a UNIQUE constraint is not listed as an index.
    assert_eq!(t.schema_of("with_unique").await["indexes"], json!([]));
    // A composite foreign key cannot be expressed as `references`, so none is claimed.
    assert!(
        t.schema_of("composite_child").await["columns"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("references").is_none())
    );
    // Partial indexes are flagged, where the engine has them.
    match conn
        .execute(
            "CREATE INDEX \"part_idx\" ON \"with_unique\" (\"b\") WHERE \"b\" IS NOT NULL",
            (),
        )
        .await
    {
        Ok(_) => assert_eq!(
            t.schema_of("with_unique").await["indexes"],
            json!([{"name": "part_idx", "unique": false, "columns": ["b"], "partial": true}])
        ),
        Err(error) => eprintln!("partial index not supported by this engine ({error}); skipped"),
    }
}

#[tokio::test]
async fn schema_needs_the_api_key_and_allows_only_get() {
    let t = TestApp::new().await;
    let (status, body) = t.call(Method::GET, "/v1/schema", None, None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("unauthorized"))
    );
    let (status, _) = t.call(Method::GET, "/v1/schema", Some("wrong"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Other methods do not exist on this route.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/schema")
        .header("x-api-key", KEY)
        .body(Body::empty())
        .unwrap();
    let response = t.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn schema_without_an_api_key_setting_is_open_like_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("open.db");
    let db = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::Default)
            .await
            .unwrap(),
    );
    let router = app(Arc::new(AppState {
        db,
        api_key: None,
        limiter: Arc::new(Semaphore::new(64)),
        request_timeout: Duration::from_secs(30),
        limits: Limits::default(),
    }));
    let (status, body) = call(&router, Method::GET, "/v1/schema", None, None).await;
    assert_eq!((status, body), (StatusCode::OK, json!({"tables": []})));
}

/// Tables appear while the schema is being read. Every answer must be a complete, consistent
/// snapshot: never an error, never a table without its columns, and never fewer tables than the
/// answer before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reading_the_schema_while_tables_are_created_gives_consistent_snapshots() {
    let t = TestApp::new().await;
    let creator = {
        let router = t.router.clone();
        tokio::spawn(async move {
            for i in 0..15 {
                let body = json!({"name": format!("t{i:02}"), "columns": [{"name": "a", "type": "TEXT"}, {"name": "b", "type": "REAL", "nullable": true}]});
                let (status, response) =
                    call(&router, Method::POST, "/v1/tables", Some(KEY), Some(body)).await;
                assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
                let body = json!({"name": format!("i{i:02}"), "table": format!("t{i:02}"), "columns": ["a"]});
                let (status, response) =
                    call(&router, Method::POST, "/v1/indexes", Some(KEY), Some(body)).await;
                assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
            }
        })
    };
    let reader = {
        let router = t.router.clone();
        tokio::spawn(async move {
            let mut last = 0;
            for _ in 0..60 {
                let (status, schema) =
                    call(&router, Method::GET, "/v1/schema", Some(KEY), None).await;
                assert_eq!(status, StatusCode::OK, "{schema}");
                let tables = schema["tables"].as_array().unwrap();
                assert!(
                    tables.len() >= last,
                    "the schema shrank from {last} to {}",
                    tables.len()
                );
                last = tables.len();
                for table in tables {
                    // id + a + b, and an index only ever follows its table.
                    assert_eq!(table["columns"].as_array().unwrap().len(), 3, "{table}");
                    assert!(table["indexes"].as_array().unwrap().len() <= 1, "{table}");
                }
            }
        })
    };
    creator.await.unwrap();
    reader.await.unwrap();
    let schema = t.schema().await;
    assert_eq!(names(&schema).len(), 15);
    assert!(
        schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["indexes"].as_array().unwrap().len() == 1)
    );
}

// ----- PATCH /v1/table and DELETE /v1/index -----

impl TestApp {
    async fn patch(&self, body: JsonValue) -> (StatusCode, JsonValue) {
        self.call(Method::PATCH, "/v1/table", Some(KEY), Some(body))
            .await
    }

    async fn patch_ok(&self, body: JsonValue) {
        let (status, response) = self.patch(body.clone()).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}: {response}");
    }

    async fn drop_index(&self, query: &str) -> (StatusCode, JsonValue) {
        self.call(
            Method::DELETE,
            &format!("/v1/index{query}"),
            Some(KEY),
            None,
        )
        .await
    }

    async fn column_names(&self, table: &str) -> Vec<String> {
        self.schema_of(table).await["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn column(&self, table: &str, column: &str) -> JsonValue {
        self.schema_of(table).await["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == column)
            .cloned()
            .unwrap_or_else(|| panic!("no column {column} in {table}"))
    }

    /// `readings`: an automatic id, a NOT NULL text `amount`, and nullable text `qty` and `note`.
    async fn create_readings(&self) {
        self.create_table_ok(json!({"name": "readings", "columns": [
            {"name": "amount", "type": "TEXT"},
            {"name": "qty", "type": "TEXT", "nullable": true},
            {"name": "note", "type": "TEXT", "nullable": true}]}))
            .await;
        let (status, body) = self
            .insert_into(
                "readings",
                json!(["amount", "qty", "note"]),
                json!([["10", "1", "a"], ["20", "2", "b"], ["30", null, "c"]]),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn column_values(&self, table: &str, column: &str) -> Vec<JsonValue> {
        let (_, body) = self
            .post(
                "/v1/query",
                json!({"table": table, "columns": [column], "sort": [{"id": "asc"}]}),
            )
            .await;
        body["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[column].clone())
            .collect()
    }
}

#[test]
fn alter_requests_are_validated() {
    let plan = |body: JsonValue| {
        serde_json::from_value::<AlterTable>(body)
            .map_err(|e| ApiError::bad(e.to_string()))
            .and_then(AlterPlan::from_request)
    };
    assert!(plan(json!({"table": "t", "column": "c", "type": "integer"})).is_ok());
    assert!(plan(json!({"table": "t", "column": "c", "rename": "d"})).is_ok());
    assert!(plan(json!({"table": "t", "column": "c", "type": "TEXT", "rename": "d", "nullable": true, "references": "p", "default": "x", "lossy": true})).is_ok());
    for invalid in [
        json!({"table": "t", "column": "c"}),
        json!({"table": "t", "column": "c", "type": "varchar"}),
        json!({"table": "t", "column": "c", "type": 5}),
        json!({"table": "t", "column": "c", "rename": "C2 x"}),
        json!({"table": "t", "column": "c", "rename": "C"}),
        json!({"table": "bad name", "column": "c", "type": "TEXT"}),
        json!({"table": "t", "column": "sqlite_x", "type": "TEXT"}),
        json!({"table": "t", "column": "c", "type": "TEXT", "lossy": "yes"}),
        json!({"table": "t", "column": "c", "type": "TEXT", "nullable": "no"}),
        json!({"table": "t", "column": "c", "type": "TEXT", "references": 5}),
        json!({"table": "t", "column": "c", "type": "TEXT", "default": [1]}),
        json!({"table": "t", "column": "c", "type": "TEXT", "default": {"a": 1}}),
        json!({"table": "t", "column": "c", "type": "TEXT", "drop": true}),
        json!({"column": "c", "type": "TEXT"}),
        json!({"table": "t", "type": "TEXT"}),
    ] {
        assert!(plan(invalid.clone()).is_err(), "{invalid}");
    }
    // A name that only differs by case from the column's own is a no-op in disguise: refused clearly.
    let msg = plan(json!({"table": "t", "column": "c", "rename": "C"}))
        .err()
        .unwrap()
        .to_string();
    assert!(msg.contains("letter case"), "{msg}");
}

#[test]
fn lossy_predicates_catch_what_a_cast_would_change() {
    assert!(
        lossy_predicate("TEXT", "INTEGER", "c")
            .unwrap()
            .contains("CAST(CAST(c AS INTEGER) AS TEXT)")
    );
    assert!(lossy_predicate("TEXT", "REAL", "c").is_some());
    assert!(lossy_predicate("INTEGER", "REAL", "c").is_some());
    assert!(lossy_predicate("REAL", "INTEGER", "c").is_some());
    // Everything can be shown as text without loss.
    assert!(lossy_predicate("INTEGER", "TEXT", "c").is_none());
    assert!(lossy_predicate("REAL", "TEXT", "c").is_none());
}

#[tokio::test]
async fn patch_adds_a_nullable_column() {
    let t = TestApp::new().await;
    t.create_readings().await;
    t.patch_ok(
        json!({"table": "readings", "column": "extra", "type": "integer", "nullable": true}),
    )
    .await;
    assert_eq!(
        t.column_names("readings").await,
        ["id", "amount", "qty", "note", "extra"]
    );
    assert_eq!(
        t.column("readings", "extra").await,
        json!({"name": "extra", "type": "INTEGER", "nullable": true, "auto_id": false})
    );
    assert_eq!(
        t.column_values("readings", "extra").await,
        [json!(null), json!(null), json!(null)]
    );
    // It is a normal column from now on.
    assert_eq!(
        t.insert_into("readings", json!(["amount", "extra"]), json!([["40", 7]]))
            .await
            .0,
        StatusCode::OK
    );
    // Asking again, now that it exists with that type, changes nothing.
    t.patch_ok(json!({"table": "readings", "column": "extra", "type": "INTEGER"}))
        .await;
    assert_eq!(t.column_names("readings").await.len(), 5);
}

#[tokio::test]
async fn patch_adds_a_column_with_a_value_for_existing_rows() {
    let t = TestApp::new().await;
    t.create_readings().await;
    t.patch_ok(json!({"table": "readings", "column": "unit", "type": "TEXT", "nullable": true, "default": "kg"})).await;
    assert_eq!(
        t.column_values("readings", "unit").await,
        [json!("kg"), json!("kg"), json!("kg")]
    );
    // The value was used once; the column has no default, so a new row without it gets NULL.
    t.insert_into("readings", json!(["amount"]), json!([["40"]]))
        .await;
    assert_eq!(
        t.column_values("readings", "unit").await.last().unwrap(),
        &json!(null)
    );
    // The default has to fit the type.
    for bad in [json!(5), json!(1.5), json!(true)] {
        let (status, _) = t.patch(json!({"table": "readings", "column": "u2", "type": "TEXT", "nullable": true, "default": bad})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = t.patch(json!({"table": "readings", "column": "u3", "type": "INTEGER", "nullable": true, "default": "x"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        t.column_names("readings").await.len(),
        5,
        "rejected requests added nothing"
    );
}

#[tokio::test]
async fn patch_adds_a_not_null_column_by_rebuilding_the_table() {
    let t = TestApp::new().await;
    t.create_readings().await;
    t.create_table_ok_index("u_note", "readings", "note").await;
    let before = t.rows_of("readings").await;

    // Rows exist, so NOT NULL needs a value for them.
    let (status, body) = t
        .patch(json!({"table": "readings", "column": "unit", "type": "TEXT"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("default")
            && body["error"].as_str().unwrap().contains("nullable"),
        "{body}"
    );
    assert_eq!(t.column_names("readings").await.len(), 4);

    t.patch_ok(json!({"table": "readings", "column": "unit", "type": "TEXT", "default": "kg"}))
        .await;
    assert_eq!(t.column("readings", "unit").await["nullable"], false);
    assert_eq!(
        t.column_values("readings", "unit").await,
        [json!("kg"), json!("kg"), json!("kg")]
    );
    // The rest of the table is as it was: ids, values, the index and the NOT NULL columns.
    let after = t.rows_of("readings").await;
    for (old, new) in before.iter().zip(&after) {
        for key in ["id", "amount", "qty", "note"] {
            assert_eq!(old[key], new[key]);
        }
    }
    assert_eq!(
        t.schema_of("readings").await["indexes"],
        json!([{"name": "u_note", "unique": true, "columns": ["note"]}])
    );
    assert_eq!(t.schema_of("readings").await["primary_key"], json!(["id"]));
    assert_eq!(t.column("readings", "id").await["auto_id"], true);
    assert_eq!(t.column("readings", "amount").await["nullable"], false);
    // NOT NULL is enforced, and the value was not left behind as a default.
    assert_eq!(
        t.insert_into("readings", json!(["amount"]), json!([["50"]]))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.insert_into("readings", json!(["amount", "unit"]), json!([["50", "g"]]))
            .await
            .0,
        StatusCode::OK
    );
    // The unique index still works, and ids keep counting.
    assert_eq!(
        t.insert_into(
            "readings",
            json!(["amount", "note", "unit"]),
            json!([["60", "a", "g"]])
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // No table was left over from the rebuild.
    assert_eq!(names(&t.schema().await), ["readings"]);
}

#[tokio::test]
async fn patch_adds_a_not_null_column_to_an_empty_table_without_a_value() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "empty", "columns": [{"name": "a", "type": "TEXT"}]}))
        .await;
    t.patch_ok(json!({"table": "empty", "column": "b", "type": "INTEGER"}))
        .await;
    assert_eq!(t.column_names("empty").await, ["id", "a", "b"]);
    assert_eq!(t.column("empty", "b").await["nullable"], false);
    assert_eq!(
        t.insert_into("empty", json!(["a", "b"]), json!([["x", 1]]))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn patch_adds_foreign_key_columns() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_table_ok(
        json!({"name": "facts", "primary_key": false, "columns": [{"name": "v", "type": "REAL"}]}),
    )
    .await;
    // Nullable column with a reference: added in place and enforced.
    t.patch_ok(json!({"table": "facts", "column": "stock_id", "type": "integer", "nullable": true, "references": "stocks"})).await;
    assert_eq!(
        t.column("facts", "stock_id").await["references"],
        json!({"table": "stocks", "column": "id"})
    );
    assert_eq!(
        t.insert_into("facts", json!(["v", "stock_id"]), json!([[1.0, 1]]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        t.insert_into("facts", json!(["v", "stock_id"]), json!([[1.0, 99]]))
            .await
            .0,
        StatusCode::CONFLICT
    );
    // NOT NULL with a reference (rebuild); existing rows get a value that must satisfy the key.
    let (status, _) = t.patch(json!({"table": "facts", "column": "owner", "type": "INTEGER", "references": "stocks", "default": 99})).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the default 99 points at no stock"
    );
    assert_eq!(
        t.column_names("facts").await,
        ["v", "stock_id"],
        "and nothing was changed"
    );
    t.patch_ok(json!({"table": "facts", "column": "owner", "type": "INTEGER", "references": {"table": "stocks", "column": "id"}, "default": 2})).await;
    assert_eq!(
        t.column("facts", "owner").await["references"],
        json!({"table": "stocks", "column": "id"})
    );
    assert_eq!(
        t.column("facts", "stock_id").await["references"],
        json!({"table": "stocks", "column": "id"}),
        "existing keys survive the rebuild"
    );
    assert_eq!(
        t.insert_into(
            "facts",
            json!(["v", "stock_id", "owner"]),
            json!([[2.0, 1, 99]])
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // The reference is checked like when a table is created.
    for (references, type_) in [
        (json!("missing"), "INTEGER"),
        (json!({"table": "stocks", "column": "name"}), "TEXT"),
        (json!("stocks"), "TEXT"),
        (json!("facts"), "INTEGER"),
    ] {
        let (status, body) = t.patch(json!({"table": "facts", "column": "bad", "type": type_, "nullable": true, "references": references})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{references}: {body}");
    }
    assert!(!t.column_names("facts").await.contains(&"bad".to_owned()));
}

#[tokio::test]
async fn patch_changes_the_type_of_a_nullable_column_in_place() {
    let t = TestApp::new().await;
    t.create_readings().await;
    t.create_table_ok_index("u_qty", "readings", "qty").await;
    t.patch_ok(json!({"table": "readings", "column": "qty", "type": "integer"}))
        .await;
    assert_eq!(t.column("readings", "qty").await["type"], "INTEGER");
    assert_eq!(t.column("readings", "qty").await["nullable"], true);
    // Real numbers now, NULLs kept; the other columns and the ids did not change.
    assert_eq!(
        t.column_values("readings", "qty").await,
        [json!(1), json!(2), json!(null)]
    );
    assert_eq!(
        t.column_values("readings", "amount").await,
        [json!("10"), json!("20"), json!("30")]
    );
    assert_eq!(
        t.column_values("readings", "id").await,
        [json!(1), json!(2), json!(3)]
    );
    // This path moves the column to the end, and the index on it follows.
    assert_eq!(
        t.column_names("readings").await,
        ["id", "amount", "note", "qty"]
    );
    assert_eq!(
        t.schema_of("readings").await["indexes"],
        json!([{"name": "u_qty", "unique": true, "columns": ["qty"]}])
    );
    // Numeric comparisons work now.
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "readings", "columns": ["id"], "filters": {"qty": {"gt": 1}}}),
        )
        .await;
    assert_eq!(body["rows"], json!([{"id": 2}]));
    // Repeating the request is a no-op.
    t.patch_ok(json!({"table": "readings", "column": "qty", "type": "INTEGER"}))
        .await;
}

#[tokio::test]
async fn patch_changes_the_type_of_a_not_null_column_keeping_everything_else() {
    let t = TestApp::new().await;
    t.create_stocks().await;
    t.create_readings().await;
    t.create_table_ok_index("u_amount", "readings", "amount")
        .await;
    let before = t.column_names("readings").await;
    t.patch_ok(json!({"table": "readings", "column": "amount", "type": "INTEGER"}))
        .await;
    // Rebuilt: same order, still NOT NULL, new type, values converted, same ids, index back.
    assert_eq!(t.column_names("readings").await, before);
    assert_eq!(
        t.column("readings", "amount").await,
        json!({"name": "amount", "type": "INTEGER", "nullable": false, "auto_id": false})
    );
    assert_eq!(
        t.column_values("readings", "amount").await,
        [json!(10), json!(20), json!(30)]
    );
    assert_eq!(
        t.column_values("readings", "id").await,
        [json!(1), json!(2), json!(3)]
    );
    assert_eq!(
        t.schema_of("readings").await["indexes"],
        json!([{"name": "u_amount", "unique": true, "columns": ["amount"]}])
    );
    assert_eq!(
        t.insert_into("readings", json!(["amount"]), json!([[null]]))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.insert_into("readings", json!(["amount"]), json!([[40]]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        names(&t.schema().await),
        ["readings", "stocks"],
        "no leftover table"
    );
}

#[tokio::test]
async fn patch_refuses_a_conversion_that_would_change_values() {
    let t = TestApp::new().await;
    t.create_table_ok(
        json!({"name": "messy", "columns": [{"name": "v", "type": "TEXT", "nullable": true}]}),
    )
    .await;
    t.insert_into(
        "messy",
        json!(["v"]),
        json!([["42"], ["007"], ["3.9"], ["abc"], [""], [null]]),
    )
    .await;

    let (status, body) = t
        .patch(json!({"table": "messy", "column": "v", "type": "INTEGER"}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("lossy_conversion")),
        "{body}"
    );
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("4 value(s)")
            && msg.contains("\"007\"")
            && msg.contains("\"abc\"")
            && msg.contains("lossy"),
        "{msg}"
    );
    assert!(
        !msg.contains("\"42\""),
        "values that convert fine are not listed: {msg}"
    );
    // Nothing changed.
    assert_eq!(t.column("messy", "v").await["type"], "TEXT");
    assert_eq!(t.column_values("messy", "v").await.len(), 6);

    // With the explicit opt-in the values are cast.
    t.patch_ok(json!({"table": "messy", "column": "v", "type": "INTEGER", "lossy": true}))
        .await;
    assert_eq!(
        t.column_values("messy", "v").await,
        [
            json!(42),
            json!(7),
            json!(3),
            json!(0),
            json!(0),
            json!(null)
        ]
    );
}

#[tokio::test]
async fn conversions_between_integer_real_and_text() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "nums", "columns": [{"name": "i", "type": "INTEGER", "nullable": true}, {"name": "r", "type": "REAL", "nullable": true}, {"name": "s", "type": "TEXT", "nullable": true}]})).await;
    t.insert_into(
        "nums",
        json!(["i", "r", "s"]),
        json!([[5, 2.5, "1.5"], [7, 4.0, "2"], [null, null, null]]),
    )
    .await;
    let attempt = |column: &str, type_: &str, lossy: bool| {
        let mut body = json!({"table": "nums", "column": column, "type": type_});
        if lossy {
            body["lossy"] = json!(true);
        }
        t.patch(body)
    };
    // Anything to TEXT never loses anything.
    assert_eq!(attempt("i", "TEXT", false).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        t.column_values("nums", "i").await,
        [json!("5"), json!("7"), json!(null)]
    );
    assert_eq!(attempt("r", "TEXT", false).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        t.column_values("nums", "r").await,
        [json!("2.5"), json!("4.0"), json!(null)]
    );
    // Text that is a number converts to REAL; whole numbers and decimals alike.
    assert_eq!(attempt("s", "REAL", false).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        t.column_values("nums", "s").await,
        [json!(1.5), json!(2.0), json!(null)]
    );
    // Back to INTEGER: 2.0 is fine, 1.5 is not.
    let (status, body) = attempt("s", "INTEGER", false).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("lossy_conversion"))
    );
    assert!(
        body["error"].as_str().unwrap().contains("1 value(s)")
            && body["error"].as_str().unwrap().contains("1.5")
    );
    assert_eq!(
        attempt("s", "INTEGER", true).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.column_values("nums", "s").await,
        [json!(1), json!(2), json!(null)]
    );
    // The text copies of the numbers convert back exactly.
    assert_eq!(
        attempt("i", "INTEGER", false).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(attempt("i", "REAL", false).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn patch_refuses_conversions_it_does_not_support() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "odd", "columns": [{"name": "b", "type": "BLOB", "nullable": true}, {"name": "n", "type": "NUMERIC", "nullable": true}, {"name": "t", "type": "TEXT", "nullable": true}]})).await;
    for (column, to) in [
        ("b", "TEXT"),
        ("t", "BLOB"),
        ("n", "INTEGER"),
        ("t", "NUMERIC"),
    ] {
        let (status, body) = t
            .patch(json!({"table": "odd", "column": column, "type": to}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{column} to {to}: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("INTEGER, REAL and TEXT"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn patch_refuses_to_retype_key_columns_and_keeps_referenced_tables_usable() {
    let t = TestApp::new().await;
    t.create_stocks().await; // id (pk), code (unique, NOT NULL), other (nullable)
    t.create_table_ok(fact_values(json!("stocks"))).await;
    t.create_table_ok(json!({"name": "by_code", "primary_key": false, "columns": [{"name": "code", "type": "TEXT", "references": {"table": "stocks", "column": "code"}}]})).await;

    let refused = |body: JsonValue, expect: &'static str| {
        let t = &t;
        async move {
            let (status, response) = t.patch(body.clone()).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}: {response}");
            let msg = response["error"].as_str().unwrap().to_owned();
            assert!(msg.contains(expect), "{msg}");
        }
    };
    refused(
        json!({"table": "stocks", "column": "id", "type": "TEXT"}),
        "primary key",
    )
    .await;
    refused(
        json!({"table": "fact_values", "column": "symbol_id", "type": "TEXT"}),
        "foreign key",
    )
    .await;
    refused(
        json!({"table": "stocks", "column": "code", "type": "INTEGER", "lossy": true}),
        "referenced by the foreign key of by_code.code",
    )
    .await;

    // A NOT NULL column of a table that others reference needs a rebuild, which is refused...
    t.create_table_ok(json!({"name": "parent", "columns": [{"name": "label", "type": "TEXT"}, {"name": "extra", "type": "TEXT", "nullable": true}]})).await;
    t.create_table_ok(json!({"name": "child", "primary_key": false, "columns": [{"name": "parent_id", "type": "INTEGER", "references": "parent"}]})).await;
    t.insert_into("parent", json!(["label", "extra"]), json!([["7", "1"]]))
        .await;
    t.insert_into("child", json!(["parent_id"]), json!([[1]]))
        .await;
    refused(
        json!({"table": "parent", "column": "label", "type": "INTEGER"}),
        "referenced by foreign keys",
    )
    .await;
    assert_eq!(t.column("parent", "label").await["type"], "TEXT");
    // ...while a nullable column of that same table is changed in place, keeping the foreign key alive.
    t.patch_ok(json!({"table": "parent", "column": "extra", "type": "INTEGER"}))
        .await;
    assert_eq!(t.column("parent", "extra").await["type"], "INTEGER");
    assert_eq!(
        t.insert_into("child", json!(["parent_id"]), json!([[99]]))
            .await
            .0,
        StatusCode::CONFLICT,
        "still enforced"
    );
    assert_eq!(
        t.insert_into("child", json!(["parent_id"]), json!([[1]]))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn patch_refuses_to_rebuild_tables_it_cannot_reproduce() {
    let t = TestApp::new().await;
    let conn = t.db.connect().await.unwrap();
    for sql in [
        "CREATE TABLE \"with_default\" (\"a\" TEXT NOT NULL, \"b\" TEXT DEFAULT 'x')",
        "CREATE TABLE \"with_unique\" (\"a\" TEXT NOT NULL, \"b\" TEXT UNIQUE)",
    ] {
        conn.execute(sql, ())
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
    for (table, expect) in [("with_default", "default value"), ("with_unique", "UNIQUE")] {
        let (status, body) = t
            .patch(json!({"table": table, "column": "a", "type": "INTEGER"}))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{table}: {body}");
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("cannot be rebuilt")
                && msg.contains(expect)
                && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert_eq!(t.column(table, "a").await["type"], "TEXT");
    }
    // Adding a NOT NULL column needs the same rebuild, with the same answer; a nullable one does not.
    let (status, _) = t
        .patch(json!({"table": "with_unique", "column": "c", "type": "TEXT"}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    t.patch_ok(json!({"table": "with_unique", "column": "c", "type": "TEXT", "nullable": true}))
        .await;
}

#[tokio::test]
async fn a_failing_change_leaves_the_table_exactly_as_it_was() {
    let t = TestApp::new().await;
    // Two tables that fail the same way, one per code path: "code" nullable (changed in place)
    // and NOT NULL (rebuilt). "1" and "01" both become 1, so the unique index cannot come back.
    for (table, nullable) in [("in_place", true), ("rebuilt", false)] {
        t.create_table_ok(json!({"name": table, "columns": [{"name": "code", "type": "TEXT", "nullable": nullable}, {"name": "other", "type": "TEXT", "nullable": true}]})).await;
        t.create_table_ok_index(&format!("u_{table}_code"), table, "code")
            .await;
        t.create_table_ok_index(&format!("u_{table}_other"), table, "other")
            .await;
        t.insert_into(
            table,
            json!(["code", "other"]),
            json!([["1", "x"], ["01", "y"], ["2", "z"]]),
        )
        .await;
        let before = (t.schema_of(table).await, t.rows_of(table).await);

        let (status, body) = t
            .patch(json!({"table": table, "column": "code", "type": "INTEGER", "lossy": true}))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{table}: {body}");
        assert_eq!(
            (t.schema_of(table).await, t.rows_of(table).await),
            before,
            "{table}: a failed change must undo everything"
        );
    }
    assert_eq!(
        names(&t.schema().await),
        ["in_place", "rebuilt"],
        "no leftover table from the failed rebuild"
    );
}

#[tokio::test]
async fn patch_renames_a_column_and_everything_that_refers_to_it() {
    let t = TestApp::new().await;
    t.create_stocks().await; // id, code (unique index), other
    t.create_table_ok(fact_values(json!("stocks"))).await;
    t.create_table_ok(json!({"name": "by_code", "primary_key": false, "columns": [{"name": "code", "type": "TEXT", "references": {"table": "stocks", "column": "code"}}]})).await;
    t.insert_into(
        "fact_values",
        json!(["symbol_id", "value"]),
        json!([[1, 1.5]]),
    )
    .await;
    t.insert_into("by_code", json!(["code"]), json!([["AAPL"]]))
        .await;
    t.create_table_ok_index("u_other", "stocks", "other").await;

    // An ordinary column keeps its place, its data and its index.
    t.patch_ok(json!({"table": "stocks", "column": "other", "rename": "remark"}))
        .await;
    assert_eq!(t.column_names("stocks").await, ["id", "code", "remark"]);
    assert_eq!(
        t.schema_of("stocks").await["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == "u_other")
            .unwrap()["columns"],
        json!(["remark"])
    );
    assert_eq!(
        t.post(
            "/v1/query",
            json!({"table": "stocks", "columns": ["other"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "the old name is gone"
    );
    assert_eq!(
        t.column_values("stocks", "code").await,
        [json!("AAPL"), json!("MSFT")]
    );

    // The referenced primary key: the child's foreign key follows and is still enforced.
    t.patch_ok(json!({"table": "stocks", "column": "id", "rename": "stock_id"}))
        .await;
    assert_eq!(t.column("stocks", "stock_id").await["auto_id"], true);
    assert_eq!(
        t.column("fact_values", "symbol_id").await["references"],
        json!({"table": "stocks", "column": "stock_id"})
    );
    assert_eq!(
        t.insert_into(
            "fact_values",
            json!(["symbol_id", "value"]),
            json!([[99, 1.0]])
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.insert_into(
            "fact_values",
            json!(["symbol_id", "value"]),
            json!([[2, 1.0]])
        )
        .await
        .0,
        StatusCode::OK
    );
    // A referenced unique column, and a foreign key column of a child.
    t.patch_ok(json!({"table": "stocks", "column": "code", "rename": "ticker"}))
        .await;
    assert_eq!(
        t.column("by_code", "code").await["references"],
        json!({"table": "stocks", "column": "ticker"})
    );
    t.patch_ok(json!({"table": "fact_values", "column": "symbol_id", "rename": "stock"}))
        .await;
    assert_eq!(
        t.column("fact_values", "stock").await["references"],
        json!({"table": "stocks", "column": "stock_id"})
    );
    assert_eq!(
        t.insert_into("fact_values", json!(["stock", "value"]), json!([[99, 1.0]]))
            .await
            .0,
        StatusCode::CONFLICT
    );
    // Upserts and deletes use the new names.
    let (status, body) = t
        .delete(json!({"table": "stocks", "filters": {"ticker": "MSFT"}}))
        .await;
    assert_eq!(
        (status, body["rows"]["deleted"].clone()),
        (StatusCode::CONFLICT, json!(null)),
        "MSFT is referenced by fact_values: {body}"
    );
}

#[tokio::test]
async fn patch_is_idempotent_and_never_adds_a_column_when_repeating_a_rename() {
    let t = TestApp::new().await;
    t.create_readings().await;
    t.patch_ok(json!({"table": "readings", "column": "amount", "rename": "amount2"}))
        .await;
    let columns = t.column_names("readings").await;
    assert_eq!(columns, ["id", "amount2", "qty", "note"]);
    // The same request again: the column is already called amount2, so there is nothing to do.
    // In particular a fresh, empty column named "amount" must not appear.
    t.patch_ok(json!({"table": "readings", "column": "amount", "rename": "amount2"}))
        .await;
    t.patch_ok(
        json!({"table": "readings", "column": "amount", "rename": "amount2", "type": "TEXT"}),
    )
    .await;
    assert_eq!(t.column_names("readings").await, columns);

    // Retyping and renaming in one request, and repeating it.
    let both =
        json!({"table": "readings", "column": "qty", "type": "integer", "rename": "quantity"});
    t.patch_ok(both.clone()).await;
    assert_eq!(t.column("readings", "quantity").await["type"], "INTEGER");
    let after = t.column_names("readings").await;
    assert!(
        after.contains(&"quantity".to_owned()) && !after.contains(&"qty".to_owned()),
        "{after:?}"
    );
    t.patch_ok(both).await;
    assert_eq!(t.column_names("readings").await, after);
    assert_eq!(
        t.column_values("readings", "quantity").await,
        [json!(1), json!(2), json!(null)]
    );

    // Naming the current name again is not a rename; adding the same column twice is fine too.
    t.patch_ok(json!({"table": "readings", "column": "note", "rename": "note"}))
        .await;
    t.patch_ok(json!({"table": "readings", "column": "fresh", "type": "REAL", "nullable": true}))
        .await;
    t.patch_ok(json!({"table": "readings", "column": "fresh", "type": "REAL", "nullable": true}))
        .await;
    assert_eq!(
        t.column_names("readings")
            .await
            .iter()
            .filter(|c| *c == "fresh")
            .count(),
        1
    );
}

#[tokio::test]
async fn patch_reports_mistakes() {
    let t = TestApp::new().await;
    t.create_readings().await;
    let expect = |body: JsonValue, status: StatusCode, text: &'static str| {
        let t = &t;
        async move {
            let (got, response) = t.patch(body.clone()).await;
            assert_eq!(got, status, "{body}: {response}");
            assert!(
                response["error"].as_str().unwrap().contains(text),
                "{body}: {response}"
            );
        }
    };
    expect(
        json!({"table": "nope", "column": "a", "type": "TEXT"}),
        StatusCode::NOT_FOUND,
        "does not exist",
    )
    .await;
    // Renaming a column that is not there, when the new name is not there either.
    expect(
        json!({"table": "readings", "column": "ghost", "rename": "spirit"}),
        StatusCode::BAD_REQUEST,
        "leave out \"rename\"",
    )
    .await;
    expect(
        json!({"table": "readings", "column": "ghost"}),
        StatusCode::BAD_REQUEST,
        "give a type",
    )
    .await;
    expect(
        json!({"table": "readings", "column": "amount", "rename": "note"}),
        StatusCode::CONFLICT,
        "already has a column",
    )
    .await;
    // What the request says about an existing column has to agree with it: `note` is nullable and
    // has no foreign key.
    expect(
        json!({"table": "readings", "column": "note", "type": "TEXT", "nullable": false}),
        StatusCode::CONFLICT,
        "accepts NULL",
    )
    .await;
    expect(
        json!({"table": "readings", "column": "amount", "type": "TEXT", "nullable": true}),
        StatusCode::CONFLICT,
        "does not accept NULL",
    )
    .await;
    expect(
        json!({"table": "readings", "column": "note", "type": "TEXT", "references": "readings"}),
        StatusCode::CONFLICT,
        "foreign keys of existing columns cannot be changed",
    )
    .await;
    // Agreeing values, and a default (which only matters when a column is added), are accepted.
    for extra in [
        json!({"nullable": true}),
        json!({"default": "x"}),
        json!({"nullable": true, "default": "x"}),
    ] {
        let mut body = json!({"table": "readings", "column": "note", "type": "TEXT"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        t.patch_ok(body).await;
    }
    expect(
        json!({"table": "readings", "column": "note", "rename": "Note"}),
        StatusCode::BAD_REQUEST,
        "letter case",
    )
    .await;
    assert_eq!(
        t.column_names("readings").await,
        ["id", "amount", "qty", "note"],
        "none of that changed anything"
    );
}

#[tokio::test]
async fn patch_requires_the_api_key_and_the_patch_method() {
    let t = TestApp::new().await;
    let body = json!({"table": "t", "column": "c", "type": "TEXT"});
    let (status, _) = t
        .call(Method::PATCH, "/v1/table", None, Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for method in [Method::GET, Method::POST, Method::PUT] {
        let request = Request::builder()
            .method(method)
            .uri("/v1/table")
            .header("x-api-key", KEY)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(
            t.router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}

/// Writers keep inserting while a column changes type. Their transactions that were in flight
/// during the change are retried, so nothing is lost and every value ends up an integer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_a_type_while_writers_insert_loses_nothing() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "live", "columns": [{"name": "w", "type": "INTEGER"}, {"name": "n", "type": "TEXT", "nullable": true}]})).await;
    let mut tasks = Vec::new();
    for writer in 0..4 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..20 {
                let rows: Vec<JsonValue> = (0..5)
                    .map(|i| json!([writer, writer * 1000 + round * 10 + i]))
                    .collect();
                let (status, body) = call(
                    &router,
                    Method::POST,
                    "/v1/batch",
                    Some(KEY),
                    Some(json!({"table": "live", "columns": ["w", "n"], "rows": rows})),
                )
                .await;
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "writer {writer} round {round}: {body}"
                );
            }
        }));
    }
    let changer = {
        let router = t.router.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let (status, body) = call(
                &router,
                Method::PATCH,
                "/v1/table",
                Some(KEY),
                Some(json!({"table": "live", "column": "n", "type": "INTEGER"})),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        })
    };
    for task in tasks {
        task.await.unwrap();
    }
    changer.await.unwrap();
    assert_eq!(t.column("live", "n").await["type"], "INTEGER");
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "live", "columns": ["n"], "limit": 500}),
        )
        .await;
    let values = body["rows"].as_array().unwrap();
    assert_eq!(
        values.len(),
        4 * 20 * 5,
        "every inserted row is there exactly once"
    );
    assert!(
        values.iter().all(|r| r["n"].is_i64()),
        "rows from before and after the change are all integers"
    );
}

// ----- DELETE /v1/index -----

#[tokio::test]
async fn an_index_can_be_dropped_and_created_again() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let create = || {
        t.post(
            "/v1/indexes",
            json!({"name": "idx_value", "table": "financial_metrics", "columns": ["value"]}),
        )
    };
    assert_eq!(create().await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        t.schema_of("financial_metrics").await["indexes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let (status, body) = t.drop_index("?name=idx_value").await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));
    assert_eq!(t.schema_of("financial_metrics").await["indexes"], json!([]));
    // Queries and writes carry on; the name is free again.
    assert_eq!(
        t.insert(json!([["A", "m", "p", 1.0]])).await.0,
        StatusCode::OK
    );
    assert_eq!(create().await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        t.schema_of("financial_metrics").await["indexes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn dropping_an_index_reports_mistakes() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let expect = |query: &'static str, status: StatusCode, text: &'static str| {
        let t = &t;
        async move {
            let (got, body) = t.drop_index(query).await;
            assert_eq!(got, status, "{query}: {body}");
            assert!(
                body["error"].as_str().unwrap().contains(text),
                "{query}: {body}"
            );
        }
    };
    expect("?name=nope", StatusCode::NOT_FOUND, "does not exist").await;
    expect(
        "?name=financial_metrics",
        StatusCode::BAD_REQUEST,
        "is a table, not an index",
    )
    .await;
    expect("", StatusCode::BAD_REQUEST, "name of the index is required").await;
    expect("?name=", StatusCode::BAD_REQUEST, "invalid index name").await;
    expect(
        "?name=bad%20name",
        StatusCode::BAD_REQUEST,
        "invalid index name",
    )
    .await;
    expect(
        "?name=sqlite_autoindex_financial_metrics_1",
        StatusCode::BAD_REQUEST,
        "reserved",
    )
    .await;
    expect(
        "?name=a&table=b",
        StatusCode::BAD_REQUEST,
        "unknown query parameter",
    )
    .await;
    // Nothing was dropped by any of that: the primary key's own index still enforces uniqueness.
    t.insert(json!([["A", "m", "p", 1.0]])).await;
    assert_eq!(
        t.insert(json!([["A", "m", "p", 2.0]])).await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn an_index_that_makes_a_column_unique_for_a_foreign_key_cannot_be_dropped() {
    let t = TestApp::new().await;
    t.create_stocks().await; // unique index u_stocks_code on stocks.code
    t.create_table_ok(json!({"name": "by_code", "primary_key": false, "columns": [{"name": "code", "type": "TEXT", "references": {"table": "stocks", "column": "code"}}]})).await;
    let (status, body) = t.drop_index("?name=u_stocks_code").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("by_code.code")
            && msg.contains("foreign key")
            && msg.contains("nothing was dropped"),
        "{msg}"
    );
    // Still there, and the child table still works.
    assert!(
        t.schema_of("stocks").await["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["name"] == "u_stocks_code")
    );
    assert_eq!(
        t.insert_into("by_code", json!(["code"]), json!([["AAPL"]]))
            .await
            .0,
        StatusCode::OK
    );

    // An index nobody depends on goes; so does a unique index on the primary key column itself.
    t.create_table_ok_index("u_other", "stocks", "other").await;
    assert_eq!(
        t.drop_index("?name=u_other").await.0,
        StatusCode::NO_CONTENT
    );
    t.create_table_ok_index("u_id", "stocks", "id").await;
    t.create_table_ok(json!({"name": "by_id", "primary_key": false, "columns": [{"name": "sid", "type": "INTEGER", "references": "stocks"}]})).await;
    assert_eq!(
        t.drop_index("?name=u_id").await.0,
        StatusCode::NO_CONTENT,
        "the primary key keeps id unique"
    );
    assert_eq!(
        t.insert_into("by_id", json!(["sid"]), json!([[1]])).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn dropping_an_index_needs_the_api_key_and_the_delete_method() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.post(
        "/v1/indexes",
        json!({"name": "idx_value", "table": "financial_metrics", "columns": ["value"]}),
    )
    .await;
    let (status, _) = t
        .call(Method::DELETE, "/v1/index?name=idx_value", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for method in [Method::GET, Method::POST] {
        let request = Request::builder()
            .method(method)
            .uri("/v1/index?name=idx_value")
            .header("x-api-key", KEY)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            t.router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    assert_eq!(
        t.schema_of("financial_metrics").await["indexes"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "still there"
    );
}

// ----- joins -----

#[test]
fn columns_can_be_a_list_an_object_per_table_or_a_list_of_those() {
    let items = |v: JsonValue| {
        parse_select(&v).map(|items| {
            items
                .iter()
                .map(|i| {
                    format!(
                        "{}.{}{}",
                        i.table.as_ref().map_or("", |t| t.as_str()),
                        i.column.as_str(),
                        i.alias
                            .as_ref()
                            .map_or(String::new(), |a| format!(" as {}", a.as_str()))
                    )
                })
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(items(json!(null)).unwrap(), Vec::<String>::new());
    assert_eq!(items(json!(["a", "b"])).unwrap(), [".a", ".b"]);
    assert_eq!(items(json!(["t.a", "b"])).unwrap(), ["t.a", ".b"]);
    // An object per table, and the list-wrapped form of the feature request.
    let expected = ["x.a", "x.b", "y.c"];
    assert_eq!(
        items(json!({"x": ["a", "b"], "y": ["c"]})).unwrap(),
        expected
    );
    assert_eq!(
        items(json!([{"x": ["a", "b"], "y": ["c"]}])).unwrap(),
        expected
    );
    assert_eq!(
        items(json!([{"x": ["a"]}, {"x": ["b"], "y": ["c"]}])).unwrap(),
        expected
    );
    // Result columns can be renamed.
    assert_eq!(
        items(json!({"x": [{"column": "id", "as": "x_id"}, "b"]})).unwrap(),
        ["x.id as x_id", "x.b"]
    );
    for invalid in [
        json!("a"),
        json!(5),
        json!([5]),
        json!([["a"]]),
        json!({"x": "a"}),
        json!({"x": [5]}),
        json!({"x": [{"as": "y"}]}),
        json!({"x": [{"column": "a", "as": 5}]}),
        json!({"x": [{"column": "a", "type": "TEXT"}]}),
        json!({"bad name": ["a"]}),
        json!({"x": ["bad name"]}),
        json!({"x": [{"column": "a", "as": "bad name"}]}),
        json!(["a.b.c"]),
    ] {
        assert!(items(invalid.clone()).is_err(), "{invalid}");
    }
    let many: Vec<String> = (0..=MAX_COLUMNS).map(|i| format!("c{i}")).collect();
    assert!(items(json!(many)).is_err());
}

#[test]
fn join_requests_are_validated() {
    let plan = |v: JsonValue| {
        serde_json::from_value::<SelectRequest>(v)
            .map_err(|e| ApiError::bad(e.to_string()))
            .and_then(JoinPlan::from_request)
    };
    let ok = json!({"table": "a", "join": {"b": "x"}, "columns": {"a": ["id"], "b": ["name"]}});
    assert!(plan(ok.clone()).is_ok());
    let with = |key: &str, value: JsonValue| {
        let mut body = ok.clone();
        body[key] = value;
        body
    };
    for invalid in [
        with("join", json!({})),
        with("join", json!({"a": "x"})),
        with("join", json!({"A": "x"})),
        with("join", json!({"b": 5})),
        with("join", json!({"b": {}})),
        with("join", json!({"b": {"column": "x", "type": "outer"}})),
        with("join", json!({"b": {"column": "x", "on": "y"}})),
        with("join", json!({"b": {"column": "x", "to": 5}})),
        with("join", json!({"bad name": "x"})),
        with("join", json!({"b": "bad name"})),
        with("join", json!({"b": "x", "B": "y"})),
        with(
            "join",
            (0..=MAX_JOINS)
                .map(|i| (format!("t{i}"), json!("x")))
                .collect::<Map<String, JsonValue>>()
                .into(),
        ),
        // Joined queries need their columns spelled out, without name clashes.
        with("columns", json!([])),
        with("columns", json!({"a": ["id"], "b": ["id"]})),
        with(
            "columns",
            json!({"a": [{"column": "id", "as": "n"}], "b": [{"column": "name", "as": "N"}]}),
        ),
        with("filters", json!({"a.x.y": 1})),
        with("filters", json!({"x": 1, "X": 2})),
        with("sort", json!([{"a.id": "up"}])),
        with("sort", json!([{"a.id": "asc"}, {"A.ID": "desc"}])),
        with("sort", json!([{"a.id": "asc", "b.name": "asc"}])),
        with("offset", json!(5)),
        with("limit", json!(MAX_QUERY_ROWS + 1)),
    ] {
        assert!(plan(invalid.clone()).is_err(), "{invalid}");
    }
    assert!(
        plan(with(
            "join",
            json!({"b": {"column": "x", "to": "y", "type": "LEFT"}})
        ))
        .is_ok()
    );
    assert!(
        plan(with(
            "filters",
            json!({"b.name": {"in": ["a"]}, "id": null})
        ))
        .is_ok()
    );
    let msg = plan(with("columns", json!({"a": ["id"], "b": ["id"]})))
        .err()
        .unwrap()
        .to_string();
    assert!(
        msg.contains("two columns named \"id\"") && msg.contains("\"as\""),
        "{msg}"
    );
}

struct JoinFixture {
    t: TestApp,
}

impl JoinFixture {
    /// The tables of the feature request: `fact_values` has foreign keys to `stocks` and `facts`.
    async fn new() -> Self {
        let t = TestApp::new().await;
        t.create_table_ok(json!({"name": "stocks", "columns": [{"name": "symbol", "type": "TEXT"}, {"name": "name", "type": "TEXT", "nullable": true}]})).await;
        t.create_table_ok_index("u_symbol", "stocks", "symbol")
            .await;
        t.create_table_ok(json!({"name": "facts", "columns": [{"name": "name", "type": "TEXT"}]}))
            .await;
        t.create_table_ok(json!({"name": "fact_values", "columns": [
            {"name": "symbol_id", "type": "INTEGER", "references": "stocks"},
            {"name": "fact_id", "type": "INTEGER", "references": "facts"},
            {"name": "value", "type": "REAL"},
            {"name": "ordinal", "type": "INTEGER"},
            {"name": "frequency", "type": "INTEGER"}]}))
            .await;
        for (table, columns, rows) in [
            (
                "stocks",
                json!(["symbol", "name"]),
                json!([
                    ["AAPL", "Apple"],
                    ["MSFT", "Microsoft"],
                    ["GOOG", "Alphabet"]
                ]),
            ),
            (
                "facts",
                json!(["name"]),
                json!([["eps"], ["revenue"], ["margin"]]),
            ),
            // symbol_id, fact_id, value, ordinal, frequency
            (
                "fact_values",
                json!(["symbol_id", "fact_id", "value", "ordinal", "frequency"]),
                json!([
                    [1, 1, 1.5, 3, 1],
                    [1, 1, 1.2, 2, 1],
                    [1, 1, 9.9, 1, 4],
                    [1, 2, 100.0, 1, 1],
                    [2, 1, 2.5, 1, 1],
                    [2, 2, 200.0, 1, 1]
                ]),
            ),
        ] {
            let (status, body) = t.insert_into(table, columns, rows).await;
            assert_eq!(status, StatusCode::OK, "{table}: {body}");
        }
        Self { t }
    }

    async fn query(&self, body: JsonValue) -> (StatusCode, JsonValue) {
        self.t.post("/v1/query", body).await
    }

    async fn rows(&self, body: JsonValue) -> Vec<JsonValue> {
        let (status, response) = self.query(body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{body}: {response}");
        response["rows"].as_array().unwrap().clone()
    }

    async fn error(&self, body: JsonValue, status: StatusCode) -> String {
        let (got, response) = self.query(body.clone()).await;
        assert_eq!(got, status, "{body}: {response}");
        response["error"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn the_query_from_the_feature_request_works_as_written() {
    let f = JoinFixture::new().await;
    // Exactly the request shape of the feature description: a list holding one object of columns.
    let (status, body) = f
        .query(json!({
            "table": "fact_values",
            "join": {"stocks": "symbol_id", "facts": "fact_id"},
            "columns": [{"fact_values": ["value", "ordinal"], "stocks": ["symbol"], "facts": ["name"]}],
            "filters": {"facts.name": "eps", "stocks.symbol": "AAPL", "frequency": 1},
            "sort": [{"ordinal": "asc"}]
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"rows": [
            {"value": 1.2, "ordinal": 2, "symbol": "AAPL", "name": "eps"},
            {"value": 1.5, "ordinal": 3, "symbol": "AAPL", "name": "eps"}
        ], "row_count": 2})
    );
    // Keys come back in the order the columns were asked for.
    let text = body["rows"][0].to_string();
    assert!(
        text.find("value").unwrap() < text.find("ordinal").unwrap()
            && text.find("ordinal").unwrap() < text.find("symbol").unwrap()
            && text.find("symbol").unwrap() < text.find("name").unwrap()
    );
}

#[tokio::test]
async fn columns_may_be_given_in_any_of_the_three_shapes() {
    let f = JoinFixture::new().await;
    let base = |columns: JsonValue| {
        json!({
            "table": "fact_values", "join": {"stocks": "symbol_id", "facts": "fact_id"}, "columns": columns,
            "filters": {"facts.name": "eps", "stocks.symbol": "AAPL", "frequency": 1}, "sort": [{"ordinal": "asc"}]
        })
    };
    let expected = f
        .rows(base(
            json!({"fact_values": ["value"], "stocks": ["symbol"], "facts": ["name"]}),
        ))
        .await;
    assert_eq!(expected.len(), 2);
    assert_eq!(
        f.rows(base(
            json!([{"fact_values": ["value"], "stocks": ["symbol"], "facts": ["name"]}])
        ))
        .await,
        expected
    );
    assert_eq!(
        f.rows(base(json!([
            "fact_values.value",
            "stocks.symbol",
            "facts.name"
        ])))
        .await,
        expected
    );
    // Unqualified names are fine where only one table has the column.
    assert_eq!(
        f.rows(base(json!(["value", "symbol", "facts.name"]))).await,
        expected
    );
}

#[tokio::test]
async fn result_columns_that_would_clash_can_be_renamed() {
    let f = JoinFixture::new().await;
    let request = |columns: JsonValue| {
        json!({
            "table": "fact_values", "join": {"stocks": "symbol_id"}, "columns": columns,
            "filters": {"fact_values.ordinal": 3}, "sort": [{"fact_values.id": "asc"}]
        })
    };
    // `id` and `name`-like columns exist in several tables: without a new name that is an error.
    let msg = f
        .error(
            request(json!({"fact_values": ["id"], "stocks": ["id"]})),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert!(
        msg.contains("two columns named \"id\"") && msg.contains("\"as\""),
        "{msg}"
    );
    let rows = f.rows(request(json!({"fact_values": [{"column": "id", "as": "fact_value_id"}], "stocks": [{"column": "id", "as": "stock_id"}, {"column": "symbol", "as": "ticker"}]}))).await;
    assert_eq!(
        rows,
        [json!({"fact_value_id": 1, "stock_id": 1, "ticker": "AAPL"})]
    );
}

#[tokio::test]
async fn unqualified_names_must_belong_to_exactly_one_table() {
    let f = JoinFixture::new().await;
    let request = |filters: JsonValue, sort: JsonValue| {
        json!({
            "table": "fact_values", "join": {"stocks": "symbol_id", "facts": "fact_id"},
            "columns": {"fact_values": ["value"]}, "filters": filters, "sort": sort
        })
    };
    // `name` is a column of both stocks and facts.
    let msg = f
        .error(
            request(json!({"name": "eps"}), json!([])),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert!(
        msg.contains("exists in several tables")
            && msg.contains("stocks, facts")
            && msg.contains("table.column"),
        "{msg}"
    );
    let msg = f
        .error(
            request(json!({}), json!([{"id": "asc"}])),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert!(msg.contains("several tables"), "{msg}");
    // Qualified, the same query is fine; unique names resolve on their own (symbol, value).
    assert_eq!(
        f.rows(request(
            json!({"facts.name": "eps", "symbol": "MSFT"}),
            json!([{"value": "asc"}])
        ))
        .await,
        [json!({"value": 2.5})]
    );
    // Unknown columns and tables are named, never silently read as a string.
    for (filters, text) in [
        (
            json!({"nope": 1}),
            "no table of the query has a column \"nope\"",
        ),
        (
            json!({"stocks.nope": 1}),
            "table \"stocks\" has no column \"nope\"",
        ),
        (
            json!({"other.x": 1}),
            "table \"other\" is not part of the query",
        ),
    ] {
        let msg = f
            .error(request(filters.clone(), json!([])), StatusCode::BAD_REQUEST)
            .await;
        assert!(msg.contains(text), "{filters}: {msg}");
    }
}

#[tokio::test]
async fn joins_follow_foreign_keys_by_default_and_can_name_the_columns() {
    let f = JoinFixture::new().await;
    // No foreign key, but the joined table has an `id`: it is compared with that.
    f.t.create_table_ok(json!({"name": "plain_ref", "primary_key": false, "columns": [{"name": "stock", "type": "INTEGER"}, {"name": "tag", "type": "TEXT"}]})).await;
    f.t.insert_into(
        "plain_ref",
        json!(["stock", "tag"]),
        json!([[2, "x"], [1, "y"]]),
    )
    .await;
    let rows = f.rows(json!({"table": "plain_ref", "join": {"stocks": "stock"}, "columns": {"plain_ref": ["tag"], "stocks": ["symbol"]}, "sort": [{"tag": "asc"}]})).await;
    assert_eq!(
        rows,
        [
            json!({"tag": "x", "symbol": "MSFT"}),
            json!({"tag": "y", "symbol": "AAPL"})
        ]
    );

    // No foreign key and no `id` to fall back on: the message says how to spell it out.
    f.t.create_table_ok(json!({"name": "codes", "columns": [{"name": "code", "type": "TEXT"}], "primary_key": ["code"]})).await;
    let msg = f
        .error(
            json!({"table": "plain_ref", "join": {"codes": "tag"}, "columns": {"codes": ["code"]}}),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert!(
        msg.contains("no foreign key") && msg.contains("\"to\""),
        "{msg}"
    );
    f.t.insert_into("codes", json!(["code"]), json!([["x"]]))
        .await;
    let rows = f.rows(json!({"table": "plain_ref", "join": {"codes": {"column": "tag", "to": "code"}}, "columns": {"plain_ref": ["stock"], "codes": ["code"]}})).await;
    assert_eq!(rows, [json!({"stock": 2, "code": "x"})]);

    // A foreign key to a column other than the primary key is followed to that column.
    f.t.create_table_ok(json!({"name": "by_symbol", "primary_key": false, "columns": [{"name": "sym", "type": "TEXT", "references": {"table": "stocks", "column": "symbol"}}, {"name": "note", "type": "TEXT"}]})).await;
    f.t.insert_into(
        "by_symbol",
        json!(["sym", "note"]),
        json!([["AAPL", "n1"], ["GOOG", "n2"]]),
    )
    .await;
    let rows = f.rows(json!({"table": "by_symbol", "join": {"stocks": "sym"}, "columns": {"by_symbol": ["note"], "stocks": ["name"]}, "sort": [{"note": "asc"}]})).await;
    assert_eq!(
        rows,
        [
            json!({"note": "n1", "name": "Apple"}),
            json!({"note": "n2", "name": "Alphabet"})
        ]
    );
}

#[tokio::test]
async fn a_join_can_run_from_the_parent_to_its_children() {
    let f = JoinFixture::new().await;
    // stocks -> fact_values: one stock, several rows. The key columns are named explicitly.
    let rows = f
        .rows(json!({
            "table": "stocks",
            "join": {"fact_values": {"column": "id", "to": "symbol_id"}},
            "columns": {"stocks": ["symbol"], "fact_values": ["value"]},
            "filters": {"fact_values.frequency": 1, "symbol": "AAPL"},
            "sort": [{"value": "asc"}]
        }))
        .await;
    assert_eq!(
        rows.iter().map(|r| r["value"].clone()).collect::<Vec<_>>(),
        [json!(1.2), json!(1.5), json!(100.0)]
    );
    assert!(rows.iter().all(|r| r["symbol"] == "AAPL"));
}

#[tokio::test]
async fn left_joins_keep_rows_without_a_match() {
    let f = JoinFixture::new().await;
    let request = |kind: JsonValue| {
        json!({
            "table": "stocks",
            "join": {"fact_values": {"column": "id", "to": "symbol_id", "type": kind}},
            "columns": {"stocks": ["symbol"], "fact_values": ["value"]},
            "filters": {"fact_values.ordinal": {"in": [1, 2, 3]}, "symbol": {"in": ["GOOG", "MSFT"]}},
            "sort": [{"symbol": "asc"}]
        })
    };
    // GOOG has no values at all: an inner join drops it, a left join keeps it with NULLs.
    let inner = f.rows(request(json!("inner"))).await;
    assert!(inner.iter().all(|r| r["symbol"] == "MSFT"));
    // A filter on the joined table removes the unmatched row again, as in SQL; without one it stays.
    let mut kept = request(json!("left"));
    kept["filters"] = json!({"symbol": "GOOG"});
    assert_eq!(
        f.rows(kept).await,
        [json!({"symbol": "GOOG", "value": null})]
    );
    // Rows that are missing on the joined side can be asked for with is_null.
    let mut missing = request(json!("LEFT"));
    missing["filters"] = json!({"fact_values.value": {"is_null": true}});
    assert_eq!(
        f.rows(missing).await,
        [json!({"symbol": "GOOG", "value": null})]
    );
}

#[tokio::test]
async fn joined_queries_filter_sort_and_page_across_tables() {
    let f = JoinFixture::new().await;
    let request = |extra: JsonValue| {
        let mut body = json!({
            "table": "fact_values", "join": {"stocks": "symbol_id", "facts": "fact_id"},
            "columns": {"fact_values": ["value"], "stocks": ["symbol"], "facts": ["name"]},
            "sort": [{"stocks.symbol": "asc"}, {"facts.name": "desc"}, {"value": "asc"}]
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let all = f.rows(request(json!({}))).await;
    assert_eq!(all.len(), 6);
    let order: Vec<String> = all
        .iter()
        .map(|r| {
            format!(
                "{}/{}/{}",
                r["symbol"].as_str().unwrap(),
                r["name"].as_str().unwrap(),
                r["value"]
            )
        })
        .collect();
    assert_eq!(
        order,
        [
            "AAPL/revenue/100.0",
            "AAPL/eps/1.2",
            "AAPL/eps/1.5",
            "AAPL/eps/9.9",
            "MSFT/revenue/200.0",
            "MSFT/eps/2.5"
        ]
    );
    // Paging uses the same sort.
    assert_eq!(
        f.rows(request(json!({"limit": 2, "offset": 1}))).await,
        all[1..3]
    );
    // Operators work on joined columns, and across tables at once.
    let rows = f.rows(request(json!({"filters": {"symbol": {"like": ["AA%", "MS%"]}, "facts.name": {"not_in": ["revenue"]}, "value": {"gt": 2, "lt": 5}}}))).await;
    assert_eq!(
        rows,
        [json!({"value": 2.5, "symbol": "MSFT", "name": "eps"})]
    );
    let rows = f
        .rows(request(json!({"filters": {"stocks.name": null}})))
        .await;
    assert!(rows.is_empty());
    // offset still needs a sort.
    let mut unsorted = request(json!({"offset": 1}));
    unsorted["sort"] = json!([]);
    f.error(unsorted, StatusCode::BAD_REQUEST).await;
}

#[tokio::test]
async fn join_errors_name_the_problem() {
    let f = JoinFixture::new().await;
    let request = |join: JsonValue, columns: JsonValue| json!({"table": "fact_values", "join": join, "columns": columns});
    for (body, status, text) in [
        (
            request(json!({"nope": "symbol_id"}), json!({"nope": ["x"]})),
            StatusCode::NOT_FOUND,
            "table \"nope\" does not exist",
        ),
        (
            json!({"table": "nope", "join": {"stocks": "x"}, "columns": {"stocks": ["symbol"]}}),
            StatusCode::NOT_FOUND,
            "table \"nope\" does not exist",
        ),
        (
            request(json!({"stocks": "ghost"}), json!({"stocks": ["symbol"]})),
            StatusCode::BAD_REQUEST,
            "join column \"ghost\" is not a column of \"fact_values\"",
        ),
        (
            request(
                json!({"stocks": {"column": "symbol_id", "to": "ghost"}}),
                json!({"stocks": ["symbol"]}),
            ),
            StatusCode::BAD_REQUEST,
            "has no column \"ghost\" to join on",
        ),
        (
            request(json!({"stocks": "symbol_id"}), json!({"stocks": ["ghost"]})),
            StatusCode::BAD_REQUEST,
            "has no column \"ghost\"",
        ),
        (
            request(json!({"stocks": "symbol_id"}), json!({"facts": ["name"]})),
            StatusCode::BAD_REQUEST,
            "table \"facts\" is not part of the query",
        ),
        (
            request(json!({"stocks": "symbol_id"}), json!({})),
            StatusCode::BAD_REQUEST,
            "columns is required",
        ),
        (
            request(json!({"fact_values": "id"}), json!({"fact_values": ["id"]})),
            StatusCode::BAD_REQUEST,
            "cannot be joined to itself",
        ),
        // Without a join, columns of other tables are not available, nor is renaming.
        (
            json!({"table": "stocks", "columns": {"facts": ["name"]}}),
            StatusCode::BAD_REQUEST,
            "not part of this query",
        ),
        (
            json!({"table": "stocks", "columns": [{"stocks": [{"column": "symbol", "as": "s"}]}]}),
            StatusCode::BAD_REQUEST,
            "only available in queries with",
        ),
        (
            json!({"table": "stocks", "filters": {"stocks.symbol": "AAPL"}}),
            StatusCode::BAD_REQUEST,
            "invalid filter column",
        ),
        // Names are validated like everywhere else.
        (
            request(
                json!({"stocks": "symbol_id"}),
                json!({"stocks": ["symbol\" FROM stocks; --"]}),
            ),
            StatusCode::BAD_REQUEST,
            "invalid",
        ),
        (
            request(
                json!({"stocks\"; DROP TABLE stocks; --": "symbol_id"}),
                json!({"stocks": ["symbol"]}),
            ),
            StatusCode::BAD_REQUEST,
            "invalid",
        ),
    ] {
        let msg = f.error(body.clone(), status).await;
        assert!(msg.contains(text), "{body}: {msg}");
    }
    // Nothing above hurt the data.
    assert_eq!(f.t.rows_of("stocks").await.len(), 3);
}

#[tokio::test]
async fn queries_without_a_join_are_unchanged() {
    let f = JoinFixture::new().await;
    let rows = f.rows(json!({"table": "stocks", "columns": ["symbol"], "filters": {"name": {"like": "A%"}}, "sort": [{"symbol": "asc"}]})).await;
    assert_eq!(rows, [json!({"symbol": "AAPL"}), json!({"symbol": "GOOG"})]);
    // The base table may be named in the list-of-objects form of `columns` too.
    let rows = f.rows(json!({"table": "stocks", "columns": [{"stocks": ["symbol"]}], "filters": {"symbol": "MSFT"}})).await;
    assert_eq!(rows, [json!({"symbol": "MSFT"})]);
    // `*` still means every column of the one table.
    let rows = f
        .rows(json!({"table": "facts", "filters": {"name": "eps"}}))
        .await;
    assert_eq!(rows, [json!({"id": 1, "name": "eps"})]);
}

// ----- several tables in one request -----

/// The request from the feature description.
fn stocks_metrics_facts() -> JsonValue {
    json!({"tables": [
        {"name": "stocks", "columns": [{"name": "symbol", "type": "text"}]},
        {"name": "metrics", "columns": [{"name": "name", "type": "text"}]},
        {"name": "facts", "primary_key": false, "columns": [
            {"name": "stock_id", "type": "integer", "references": "stocks"},
            {"name": "metric_id", "type": "integer", "references": "metrics"},
            {"name": "frequency", "type": "integer"},
            {"name": "period", "type": "integer"},
            {"name": "value", "type": "real"}]}
    ]})
}

#[test]
fn create_bodies_are_one_table_or_a_list_of_tables() {
    let one = json!({"name": "t", "columns": [{"name": "a", "type": "TEXT"}]});
    let job = parse_create_body(one.clone()).unwrap();
    assert!(!job.envelope);
    assert_eq!(job.plans.len(), 1);
    let job = parse_create_body(stocks_metrics_facts()).unwrap();
    assert!(job.envelope);
    assert_eq!(
        job.plans
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["stocks", "metrics", "facts"]
    );
    // An empty list is a valid no-op.
    assert_eq!(
        parse_create_body(json!({"tables": []}))
            .unwrap()
            .plans
            .len(),
        0
    );

    for invalid in [
        json!([one.clone()]),
        json!("t"),
        json!(5),
        json!({"tables": "t"}),
        json!({"tables": {"name": "t"}}),
        json!({"tables": [5]}),
        json!({"tables": [one.clone()], "name": "x"}),
        json!({"tables": [one.clone()], "columns": []}),
        // Each table is validated like a single one.
        json!({"tables": [{"name": "t"}]}),
        json!({"tables": [{"name": "bad name", "columns": [{"name": "a", "type": "TEXT"}]}]}),
        json!({"tables": [one.clone(), {"name": "u", "columns": [{"name": "a", "type": "nope"}]}]}),
        json!({"tables": [{"name": "u", "columns": [{"name": "a", "type": "TEXT"}], "extra": 1}]}),
        // The same table twice, whatever the capitals.
        json!({"tables": [one.clone(), one.clone()]}),
        json!({"tables": [one.clone(), {"name": "T", "columns": [{"name": "b", "type": "TEXT"}]}]}),
    ] {
        assert!(parse_create_body(invalid.clone()).is_err(), "{invalid}");
    }
    // Errors say which table they are about.
    let msg = parse_create_body(
        json!({"tables": [one.clone(), {"name": "u", "columns": [{"name": "a", "type": "nope"}]}]}),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(
        msg.contains("tables[1]") && msg.contains("\"u\"") && msg.contains("unsupported type"),
        "{msg}"
    );
    let msg = parse_create_body(json!({"tables": [one.clone(), one.clone()]}))
        .err()
        .unwrap()
        .to_string();
    assert!(
        msg.contains("tables[1]") && msg.contains("more than once"),
        "{msg}"
    );
    // The single form keeps its plain messages.
    let msg = parse_create_body(json!({"name": "u", "columns": [{"name": "a", "type": "nope"}]}))
        .err()
        .unwrap()
        .to_string();
    assert!(!msg.contains("tables["), "{msg}");
    // Limit.
    let many = |n: usize| json!({"tables": (0..n).map(|i| json!({"name": format!("t{i}"), "columns": [{"name": "a", "type": "TEXT"}]})).collect::<Vec<_>>()});
    assert!(parse_create_body(many(MAX_TABLES_PER_REQUEST)).is_ok());
    assert!(parse_create_body(many(MAX_TABLES_PER_REQUEST + 1)).is_err());
}

#[tokio::test]
async fn the_request_from_the_feature_description_creates_all_three_tables() {
    let t = TestApp::new().await;
    let (status, body) = t.post("/v1/tables", stocks_metrics_facts()).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, JsonValue::Null));
    assert_eq!(names(&t.schema().await), ["facts", "metrics", "stocks"]);
    let facts = t.schema_of("facts").await;
    assert_eq!(facts["primary_key"], json!([]));
    assert_eq!(
        facts["columns"][0]["references"],
        json!({"table": "stocks", "column": "id"})
    );
    assert_eq!(
        facts["columns"][1]["references"],
        json!({"table": "metrics", "column": "id"})
    );
    assert_eq!(t.schema_of("stocks").await["primary_key"], json!(["id"]));
    // The tables are usable straight away, with the foreign keys enforced.
    assert_eq!(
        t.insert_into("stocks", json!(["symbol"]), json!([["AAPL"]]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        t.insert_into("metrics", json!(["name"]), json!([["eps"]]))
            .await
            .0,
        StatusCode::OK
    );
    let columns = json!(["stock_id", "metric_id", "frequency", "period", "value"]);
    assert_eq!(
        t.insert_into("facts", columns.clone(), json!([[1, 1, 1, 2024, 1.5]]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        t.insert_into("facts", columns, json!([[9, 1, 1, 2024, 1.5]]))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn sending_the_same_request_again_is_harmless_and_fills_in_what_is_missing() {
    let t = TestApp::new().await;
    t.create_table_ok(stocks_metrics_facts()).await;
    t.create_table_ok(stocks_metrics_facts()).await;
    assert_eq!(names(&t.schema().await).len(), 3);

    // Some of the tables exist already (identical), the others are created.
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "stocks", "columns": [{"name": "symbol", "type": "TEXT"}]}))
        .await;
    t.create_table_ok(stocks_metrics_facts()).await;
    assert_eq!(names(&t.schema().await), ["facts", "metrics", "stocks"]);
    // The one that existed was left alone (an identical definition), including its data.
    let t = TestApp::new().await;
    t.create_table_ok(json!({"name": "stocks", "columns": [{"name": "symbol", "type": "TEXT"}]}))
        .await;
    t.insert_into("stocks", json!(["symbol"]), json!([["AAPL"]]))
        .await;
    t.create_table_ok(stocks_metrics_facts()).await;
    assert_eq!(t.rows_of("stocks").await.len(), 1);
}

#[tokio::test]
async fn the_order_of_the_tables_in_the_request_does_not_matter() {
    let t = TestApp::new().await;
    let mut request = stocks_metrics_facts();
    request["tables"].as_array_mut().unwrap().reverse(); // facts first, then metrics, then stocks
    t.create_table_ok(request).await;
    assert_eq!(names(&t.schema().await), ["facts", "metrics", "stocks"]);
    assert_eq!(
        t.schema_of("facts").await["columns"][0]["references"]["table"],
        "stocks"
    );
    assert_eq!(
        t.insert_into(
            "facts",
            json!(["stock_id", "metric_id", "frequency", "period", "value"]),
            json!([[1, 1, 1, 1, 1.0]])
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "no parents yet"
    );

    // Tables may also reference each other: both exist afterwards.
    let t = TestApp::new().await;
    t.create_table_ok(json!({"tables": [
        {"name": "a", "columns": [{"name": "b_id", "type": "INTEGER", "nullable": true, "references": "b"}]},
        {"name": "b", "columns": [{"name": "a_id", "type": "INTEGER", "nullable": true, "references": "a"}]}]}))
        .await;
    assert_eq!(
        t.schema_of("a").await["columns"][1]["references"]["table"],
        "b"
    );
    assert_eq!(
        t.schema_of("b").await["columns"][1]["references"]["table"],
        "a"
    );
}

#[tokio::test]
async fn a_failing_table_creates_none_of_them() {
    let t = TestApp::new().await;
    t.create_table_ok(
        json!({"name": "metrics", "columns": [{"name": "different", "type": "TEXT"}]}),
    )
    .await;
    // `metrics` already exists with another definition, the second of three tables.
    let (status, body) = t.post("/v1/tables", stocks_metrics_facts()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("tables[1]")
            && msg.contains("\"metrics\"")
            && msg.contains("different definition"),
        "{msg}"
    );
    assert_eq!(
        names(&t.schema().await),
        ["metrics"],
        "stocks and facts were not created either"
    );

    // A reference to a table that is neither in the request nor in the database.
    let t = TestApp::new().await;
    let (status, body) = t
        .post("/v1/tables", json!({"tables": [
            {"name": "stocks", "columns": [{"name": "symbol", "type": "TEXT"}]},
            {"name": "orphan", "columns": [{"name": "x", "type": "INTEGER", "references": "nowhere"}]}]}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("tables[1]") && msg.contains("\"orphan\"") && msg.contains("does not exist"),
        "{msg}"
    );
    assert!(names(&t.schema().await).is_empty(), "nothing was created");

    // The name of a table is already taken by an index.
    t.create_table_ok(json!({"name": "base", "columns": [{"name": "a", "type": "TEXT"}]}))
        .await;
    t.create_table_ok_index("taken", "base", "a").await;
    let (status, _) = t
        .post("/v1/tables", json!({"tables": [{"name": "fresh", "columns": [{"name": "a", "type": "TEXT"}]}, {"name": "taken", "columns": [{"name": "a", "type": "TEXT"}]}]}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(names(&t.schema().await), ["base"]);
}

#[tokio::test]
async fn references_between_tables_of_one_request_are_checked_like_any_other() {
    let t = TestApp::new().await;
    let child = |references: JsonValue, sql_type: &str| {
        json!({"tables": [
        {"name": "parent", "columns": [{"name": "code", "type": "TEXT"}, {"name": "label", "type": "TEXT", "nullable": true}], "primary_key": ["code"]},
        {"name": "child", "primary_key": false, "columns": [{"name": "p", "type": sql_type, "references": references}]}]})
    };
    for (references, sql_type, text) in [
        (json!("parent"), "TEXT", "has no column \"id\""), // parent has no id
        (
            json!({"table": "parent", "column": "label"}),
            "TEXT",
            "not unique",
        ), // not a key
        (
            json!({"table": "parent", "column": "nope"}),
            "TEXT",
            "has no column \"nope\"",
        ),
        (
            json!({"table": "parent", "column": "code"}),
            "INTEGER",
            "types differ",
        ),
    ] {
        let (status, body) = t
            .post("/v1/tables", child(references.clone(), sql_type))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{references}: {body}");
        assert!(
            body["error"].as_str().unwrap().contains(text),
            "{references}: {body}"
        );
        assert!(
            names(&t.schema().await).is_empty(),
            "{references}: nothing was created"
        );
    }
    t.create_table_ok(child(json!({"table": "parent", "column": "code"}), "TEXT"))
        .await;
    assert_eq!(names(&t.schema().await), ["child", "parent"]);
}

#[tokio::test]
async fn an_empty_list_of_tables_does_nothing_and_the_single_form_still_works() {
    let t = TestApp::new().await;
    t.create_table_ok(json!({"tables": []})).await;
    assert!(names(&t.schema().await).is_empty());
    t.create_table_ok(json!({"name": "single", "columns": [{"name": "a", "type": "TEXT"}]}))
        .await;
    assert_eq!(names(&t.schema().await), ["single"]);
}

/// Creating tables while other tables are being written: the schema change waits for a quiet
/// moment (it is retried), and the writers are retried if it lands in the middle of a batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creating_tables_while_writers_are_busy_works() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let mut tasks = Vec::new();
    for writer in 0..4 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..20 {
                let rows: Vec<JsonValue> = (0..5).map(|i| json!([format!("W{writer}"), "m", format!("p{round}-{i}"), 1.0])).collect();
                let (status, body) = call(&router, Method::POST, "/v1/batch", Some(KEY), Some(json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows}))).await;
                assert_eq!(status, StatusCode::OK, "writer {writer} round {round}: {body}");
            }
        }));
    }
    let creator = {
        let router = t.router.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let (status, body) = call(
                &router,
                Method::POST,
                "/v1/tables",
                Some(KEY),
                Some(stocks_metrics_facts()),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        })
    };
    for task in tasks {
        task.await.unwrap();
    }
    creator.await.unwrap();
    assert_eq!(
        names(&t.schema().await),
        ["facts", "financial_metrics", "metrics", "stocks"]
    );
    assert_eq!(t.all_rows().await.len(), 4 * 20 * 5, "no write was lost");
}

#[tokio::test]
async fn body_and_content_type_errors_are_json() {
    let t = TestApp::new().await;
    let (status, body) = t
        .call(
            Method::POST,
            "/v1/query",
            Some(KEY),
            Some(json!({"table": "t", "pad": "x".repeat(Limits::default().max_body_bytes + 1)})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::PAYLOAD_TOO_LARGE, &json!("payload_too_large"))
    );

    let request = |content_type: Option<&str>, body: &str| {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/v1/query")
            .header("x-api-key", KEY);
        if let Some(ct) = content_type {
            b = b.header("content-type", ct);
        }
        b.body(Body::from(body.to_owned())).unwrap()
    };
    let (status, _) = raw(&t.router, request(Some("application/json"), "{not json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = raw(
        &t.router,
        request(Some("application/json"), "{\"table\": 1}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = raw(&t.router, request(Some("text/plain"), "{}")).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, _) = raw(&t.router, request(None, "{}")).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn sync_routes_do_not_exist_in_local_mode() {
    let t = TestApp::new().await;
    for (method, path) in [
        (Method::POST, "/v1/sync/push"),
        (Method::POST, "/v1/sync/pull"),
        (Method::GET, "/v1/sync/status"),
    ] {
        let (status, body) = t.call(method, path, Some(KEY), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body["code"], "not_found");
    }
}

#[tokio::test]
async fn without_an_api_key_no_authentication_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("noauth.db");
    let db = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::Default)
            .await
            .unwrap(),
    );
    let router = app(Arc::new(AppState {
        db,
        api_key: None,
        limiter: Arc::new(Semaphore::new(64)),
        request_timeout: Duration::from_secs(30),
        limits: Limits::default(),
    }));
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/tables",
        None,
        Some(metrics_table()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = call(
        &router,
        Method::POST,
        "/v1/query",
        None,
        Some(json!({"table": "financial_metrics"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A key sent anyway is simply ignored.
    let (status, _) = call(
        &router,
        Method::POST,
        "/v1/query",
        Some("whatever"),
        Some(json!({"table": "financial_metrics"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn sheds_load_with_429() {
    let t = TestApp::new().await;
    let state = Arc::new(AppState {
        db: t.db.clone(),
        api_key: Some(KEY.to_string()),
        limiter: Arc::new(Semaphore::new(1)),
        request_timeout: Duration::from_secs(30),
        limits: Limits::default(),
    });
    let router = app(state.clone());
    let _held = state.limiter.clone().try_acquire_owned().unwrap();
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/query",
        Some(KEY),
        Some(json!({"table": "t"})),
    )
    .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_requests"))
    );
    // Probes are not subject to the limit.
    assert_eq!(
        call(&router, Method::GET, "/health", None, None).await.0,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_and_readers() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let mut tasks = Vec::new();
    for writer in 0..16 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            let rows: Vec<JsonValue> = (0..50).map(|i| json!([format!("T{writer}"), "m", format!("p{i:03}"), i as f64])).collect();
            let (status, body) = call(
                &router,
                Method::POST,
                "/v1/batch",
                Some(KEY),
                Some(json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "writer {writer}: {body}");
            // Interleave a read.
            let (status, _) = call(&router, Method::POST, "/v1/query", Some(KEY), Some(json!({"table": "financial_metrics", "limit": 5}))).await;
            assert_eq!(status, StatusCode::OK);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    for writer in 0..16 {
        let (_, body) = t
            .post("/v1/query", json!({"table": "financial_metrics", "filters": {"ticker": format!("T{writer}")}, "limit": 100}))
            .await;
        assert_eq!(body["row_count"], 50, "writer {writer}");
    }
}

#[tokio::test]
async fn data_survives_reopening_the_database() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let (status, _) = t.insert(json!([["A", "m", "p1", 1.5]])).await;
    assert_eq!(status, StatusCode::OK);
    let path = t.dir.path().join("test.db");
    let TestApp { router, db, dir } = t;
    drop((router, db));

    let reopened = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::Default)
            .await
            .unwrap(),
    );
    let router = app(state_for(reopened));
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/query",
        Some(KEY),
        Some(json!({"table": "financial_metrics"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["rows"],
        json!([{"ticker": "A", "metric": "m", "period": "p1", "value": 1.5}])
    );
    drop(dir);
}

#[test]
fn conflict_backoff_grows_and_stays_bounded() {
    for attempt in 1..=MAX_WRITE_ATTEMPTS {
        let ceiling = 1_u64 << attempt.clamp(1, 6);
        for _ in 0..50 {
            let ms = conflict_backoff(attempt).as_millis() as u64;
            assert!(
                ms >= ceiling / 2 && ms <= ceiling,
                "attempt {attempt}: {ms}ms"
            );
        }
    }
}

#[tokio::test]
async fn conflict_errors_are_recognized() {
    use turso::Error;
    assert!(is_write_conflict(&Error::Error(
        "Write-write conflict".into()
    )));
    assert!(is_write_conflict(&Error::Error(
        "Database schema conflict".into()
    )));
    assert!(is_write_conflict(&Error::BusySnapshot("x".into())));
    assert!(!is_write_conflict(&Error::Constraint(
        "UNIQUE constraint failed".into()
    )));
    assert!(!is_write_conflict(&Error::Error("no such table".into())));
}

/// A transaction that is still open and has touched the same row makes the batch lose a
/// write-write conflict. Once that transaction commits, the retry must succeed on top of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_retries_after_losing_a_write_conflict() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["A", "m", "p1", 1.0]])).await;

    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute(
        "UPDATE financial_metrics SET value = 100 WHERE ticker = 'A'",
        (),
    )
    .await
    .unwrap();

    let api = t.post(
        "/v1/batch",
        json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"],
               "rows": [["A", "m", "p1", 200.0]], "on_conflict": "replace_all"}),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        tx.commit().await.unwrap();
    };
    let ((status, body), ()) = tokio::join!(api, release);
    assert_eq!(status, StatusCode::OK, "{body}");
    // The batch ran after the competing commit, so its value wins.
    assert_eq!(t.all_rows().await[0]["value"], 200.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_reports_write_conflict_when_retries_are_exhausted() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    t.insert(json!([["A", "m", "p1", 1.0]])).await;

    let mut holder = t.db.connect().await.unwrap();
    let tx = holder
        .transaction_with_behavior(TransactionBehavior::Concurrent)
        .await
        .unwrap();
    tx.execute(
        "UPDATE financial_metrics SET value = 100 WHERE ticker = 'A'",
        (),
    )
    .await
    .unwrap();

    // Longer than the maximum total backoff (~380 ms).
    let (status, body) = t
        .post(
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"],
                   "rows": [["B", "m", "p1", 5.0], ["A", "m", "p1", 200.0]], "on_conflict": "replace_all"}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("write_conflict")),
        "{body}"
    );
    tx.commit().await.unwrap();

    // Nothing from the failed batch (not even the conflict-free row B) was written.
    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["value"], 100.0);

    // And the same request works once the competing transaction is gone.
    let (status, _) = t
        .post(
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"],
                   "rows": [["A", "m", "p1", 200.0]], "on_conflict": "replace_all"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Sixteen writers all rewrite the same 20 rows at once. Each batch is one transaction, so
/// the final table must hold the values of a single writer, never a mixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_upserts_are_atomic_under_concurrency() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let seed: Vec<JsonValue> = (0..20)
        .map(|i| json!(["A", "m", format!("p{i:02}"), -1.0]))
        .collect();
    t.insert(json!(seed)).await;

    let mut tasks = Vec::new();
    for writer in 0..16 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            let rows: Vec<JsonValue> =
                (0..20).map(|i| json!(["A", "m", format!("p{i:02}"), f64::from(writer)])).collect();
            let (status, body) = call(
                &router,
                Method::POST,
                "/v1/batch",
                Some(KEY),
                Some(json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"],
                            "rows": rows, "on_conflict": "replace_all"})),
            )
            .await;
            (writer, status, body)
        }));
    }
    let mut committed = Vec::new();
    for task in tasks {
        let (writer, status, body) = task.await.unwrap();
        match status {
            StatusCode::OK => committed.push(f64::from(writer)),
            StatusCode::CONFLICT => assert_eq!(body["code"], "write_conflict", "{body}"),
            other => panic!("writer {writer}: unexpected {other}: {body}"),
        }
    }
    assert!(!committed.is_empty(), "at least one writer must win");

    let rows = t.all_rows().await;
    assert_eq!(rows.len(), 20);
    let winner = rows[0]["value"].as_f64().unwrap();
    assert!(
        rows.iter().all(|r| r["value"].as_f64().unwrap() == winner),
        "mixed writers: {rows:?}"
    );
    assert!(
        committed.contains(&winner),
        "{winner} not among committed {committed:?}"
    );
}

/// Schema changes while data transactions are in flight make those transactions fail with a
/// schema conflict; they must be retried transparently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schema_changes_do_not_break_concurrent_writers() {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let mut tasks = Vec::new();
    for writer in 0..8 {
        let router = t.router.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..5 {
                let rows: Vec<JsonValue> = (0..20)
                    .map(|i| json!([format!("T{writer}"), "m", format!("r{round}p{i:02}"), f64::from(i)]))
                    .collect();
                let (status, body) = call(
                    &router,
                    Method::POST,
                    "/v1/batch",
                    Some(KEY),
                    Some(json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": rows})),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "writer {writer} round {round}: {body}");
            }
        }));
    }
    let router = t.router.clone();
    tasks.push(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(2)).await;
        let (status, body) = call(
            &router,
            Method::POST,
            "/v1/indexes",
            Some(KEY),
            Some(json!({"name": "idx_value", "table": "financial_metrics", "columns": ["value"]})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }));
    for task in tasks {
        task.await.unwrap();
    }
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {"ticker": "T3"}, "limit": 500}),
        )
        .await;
    assert_eq!(body["row_count"], 100);
}

/// A database created earlier in WAL mode (for example by a previous Bonny version) is
/// converted on first start, keeping its data.
#[tokio::test]
async fn existing_wal_database_is_converted_to_mvcc() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    {
        let db = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        assert_eq!(journal_mode(&conn).await.unwrap(), "wal");
        conn.execute("CREATE TABLE old (a INTEGER PRIMARY KEY, b TEXT)", ())
            .await
            .unwrap();
        conn.execute("INSERT INTO old VALUES (1, 'kept')", ())
            .await
            .unwrap();
    }
    let db = Arc::new(
        Db::open_local(path.to_str().unwrap(), IoMode::Default)
            .await
            .unwrap(),
    );
    let router = app(state_for(db));
    let (_, ready) = call(&router, Method::GET, "/ready", None, None).await;
    assert_eq!(ready["journal_mode"], "mvcc");
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/query",
        Some(KEY),
        Some(json!({"table": "old"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"], json!([{"a": 1, "b": "kept"}]));
    let (status, _) = call(
        &router,
        Method::POST,
        "/v1/batch",
        Some(KEY),
        Some(json!({"table": "old", "columns": ["a", "b"], "rows": [[2, "new"]]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ----- optional: embedded replica against a real remote -----

/// Runs only when `TURSO_TEST_DATABASE_URL` and `TURSO_TEST_AUTH_TOKEN` point at a
/// disposable remote database; otherwise it is a no-op so `cargo test` stays hermetic.
#[tokio::test]
async fn replica_push_and_pull_against_a_real_remote() {
    let (Ok(url), Ok(token)) = (
        std::env::var("TURSO_TEST_DATABASE_URL"),
        std::env::var("TURSO_TEST_AUTH_TOKEN"),
    ) else {
        eprintln!("skipping: TURSO_TEST_DATABASE_URL / TURSO_TEST_AUTH_TOKEN not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.db");
    let db = Arc::new(
        Db::open_replica(
            path.to_str().unwrap(),
            &ReplicaConfig {
                url,
                auth_token: token,
            },
        )
        .await
        .unwrap(),
    );
    let router = app(state_for(db.clone()));
    let table = format!("bonny_test_{}", unix_now());
    let (status, body) = call(&router, Method::POST, "/v1/tables", Some(KEY), Some(json!({"name": table, "columns": [{"name": "id", "type": "INTEGER"}], "primary_key": ["id"]}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = call(
        &router,
        Method::POST,
        "/v1/batch",
        Some(KEY),
        Some(json!({"table": table, "columns": ["id"], "rows": [[1], [2]]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        call(&router, Method::POST, "/v1/sync/push", Some(KEY), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&router, Method::POST, "/v1/sync/pull", Some(KEY), None)
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = call(&router, Method::GET, "/v1/sync/status", Some(KEY), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pending_local_changes"], 0);
}

// ----- SQL injection -----
//
// Values are bound parameters; identifiers are validated and quoted; keywords come from fixed
// sets. These tests attack each of those three layers: a fuzz of the identifier parser, hostile
// names in every identifier slot of every route, and hostile values in every value slot.

/// A tiny deterministic generator, so the fuzz tests are repeatable without extra dependencies.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Characters that matter to SQL, to JSON and to URLs, plus look-alikes and invisible ones.
const HOSTILE_ALPHABET: &[char] = &[
    'a', 'Z', '_', '0', '9', '"', '\'', '`', ';', '-', '/', '*', '\\', ' ', '\t', '\n', '\r', '\0',
    '%', '?', ':', '$', '@', '(', ')', '[', ']', '{', '}', '=', ',', '.', '|', '&', '<', '>', '!',
    '#', 'é', 'і', 'ｔ', '\u{202e}', '\u{feff}', '\u{200b}', '💥',
];

fn fuzz_string(rng: &mut Lcg, max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| HOSTILE_ALPHABET[rng.below(HOSTILE_ALPHABET.len())])
        .collect()
}

/// What the identifier rules say, written independently of `Ident::parse`.
fn is_valid_identifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    let reserved = ["sqlite_", "turso_", "__turso"];
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENT_LEN
        && (bytes[0] == b'_' || bytes[0].is_ascii_alphabetic())
        && bytes
            .iter()
            .all(|b| *b == b'_' || b.is_ascii_alphanumeric())
        && !reserved
            .iter()
            .any(|prefix| s.to_ascii_lowercase().starts_with(prefix))
}

#[test]
fn sqli_fuzz_identifier_parser_matches_the_rules_exactly() {
    let mut rng = Lcg(0x5eed);
    for _ in 0..30_000 {
        let s = fuzz_string(&mut rng, 70);
        let parsed = Ident::parse("t", &s);
        assert_eq!(parsed.is_ok(), is_valid_identifier(&s), "{s:?}");
        if let Ok(ident) = parsed {
            // Whatever is accepted is quoted into a single harmless token.
            let quoted = ident.quoted();
            assert!(quoted.starts_with('"') && quoted.ends_with('"'), "{quoted}");
            let inner = &quoted[1..quoted.len() - 1];
            assert!(inner.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()));
        }
    }
}

#[test]
fn sqli_fuzz_one_hostile_character_anywhere_in_a_valid_name_is_rejected() {
    let hostile: Vec<char> = HOSTILE_ALPHABET
        .iter()
        .copied()
        .filter(|c| *c != '_' && *c != 'a' && *c != 'Z' && *c != '0' && *c != '9')
        .collect();
    for name in ["ticker", "financial_metrics", "_x", "T1"] {
        for position in 0..=name.len() {
            for c in &hostile {
                let mut mutated = name.to_owned();
                mutated.insert(position, *c);
                assert!(Ident::parse("t", &mutated).is_err(), "{mutated:?}");
            }
        }
    }
}

#[test]
fn sqli_names_from_the_catalog_are_quoted_with_embedded_quotes_doubled() {
    assert_eq!(quote_name("plain"), "\"plain\"");
    assert_eq!(quote_name("a\"b"), "\"a\"\"b\"");
    assert_eq!(
        quote_name("\"; DROP TABLE x; --"),
        "\"\"\"; DROP TABLE x; --\""
    );
    let mut rng = Lcg(0xbeef);
    for _ in 0..10_000 {
        let s = fuzz_string(&mut rng, 40);
        let quoted = quote_name(&s);
        assert!(quoted.starts_with('"') && quoted.ends_with('"') && quoted.len() >= 2);
        let inner = &quoted[1..quoted.len() - 1];
        // Every quote inside is doubled, so none can end the identifier early...
        assert!(!inner.replace("\"\"", "").contains('"'), "{s:?}");
        // ...and undoing the doubling gives the original name back.
        assert_eq!(inner.replace("\"\"", "\""), s);
    }
}

#[test]
fn sqli_every_sql_keyword_comes_from_a_fixed_set() {
    // Column types: only the allowlist, in any letter case, and nothing around it.
    for ok in ["integer", "TEXT", "Real", "blob", "numeric"] {
        assert!(parse_sql_type("c", ok).is_ok(), "{ok}");
    }
    for bad in [
        "TEXT); DROP TABLE x; --",
        "TEXT ",
        " TEXT",
        "TEXT PRIMARY KEY",
        "INT",
        "VARCHAR(10)",
        "TEXT\0",
        "",
        "TEXT,",
    ] {
        assert!(parse_sql_type("c", bad).is_err(), "{bad:?}");
    }
}

/// Names that are all invalid identifiers (and not reserved words of the request format).
fn hostile_names() -> Vec<String> {
    let mut names: Vec<String> = [
        "",
        " ",
        "x\"; DROP TABLE financial_metrics; --",
        "x\" OR \"1\"=\"1",
        "financial_metrics; DROP TABLE financial_metrics",
        "financial_metrics\"",
        "\"financial_metrics\"",
        "financial_metrics ",
        " financial_metrics",
        "financial_metrics\n",
        "financial_metrics\0",
        "ticker--",
        "ticker/*",
        "*/ticker",
        "ticker'",
        "ticker`",
        "[ticker]",
        "*",
        "ticker,metric",
        "ticker=1",
        "ticker)",
        "(ticker",
        "ticker;",
        "ticker UNION SELECT 1",
        "ticker\"\"",
        "ticker\\",
        "ticker%00",
        "?1",
        ":ticker",
        "$ticker",
        "@ticker",
        "sqlite_master",
        "SQLITE_SEQUENCE",
        "turso_cdc",
        "__turso_internal",
        "tіcker",
        "ｔicker",
        "1ticker",
        "ticker-1",
        "ticker$",
        "ticker\u{202e}",
        "\u{feff}ticker",
        "ticker\u{200b}",
        "💥",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    names.push("a".repeat(MAX_IDENT_LEN + 1));
    names
}

/// A request with `p` in one identifier (or keyword) slot: (slot, method, path, body).
type HostileRequest = (&'static str, Method, String, Option<JsonValue>);

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn hostile_requests(p: &str) -> Vec<HostileRequest> {
    let col = json!({"name": "a", "type": "TEXT"});
    let post = |slot, path: &str, body| (slot, Method::POST, path.to_owned(), Some(body));
    let patch = |slot, body| (slot, Method::PATCH, "/v1/table".to_owned(), Some(body));
    let row = json!(["a", "b", "c", 1]);
    let batch_columns = json!(["ticker", "metric", "period", "value"]);
    vec![
        // POST /v1/tables
        post(
            "tables.name",
            "/v1/tables",
            json!({"name": p, "columns": [col]}),
        ),
        post(
            "tables.column_name",
            "/v1/tables",
            json!({"name": "t1", "columns": [{"name": p, "type": "TEXT"}]}),
        ),
        post(
            "tables.column_type",
            "/v1/tables",
            json!({"name": "t1", "columns": [{"name": "a", "type": p}]}),
        ),
        post(
            "tables.primary_key",
            "/v1/tables",
            json!({"name": "t1", "columns": [col], "primary_key": [p]}),
        ),
        post(
            "tables.references",
            "/v1/tables",
            json!({"name": "t1", "columns": [{"name": "a", "type": "TEXT", "references": p}]}),
        ),
        post(
            "tables.references_table",
            "/v1/tables",
            json!({"name": "t1", "columns": [{"name": "a", "type": "TEXT", "references": {"table": p, "column": "id"}}]}),
        ),
        post(
            "tables.references_column",
            "/v1/tables",
            json!({"name": "t1", "columns": [{"name": "a", "type": "TEXT", "references": {"table": "sectors", "column": p}}]}),
        ),
        post(
            "tables.multi_name",
            "/v1/tables",
            json!({"tables": [{"name": p, "columns": [col]}]}),
        ),
        // POST /v1/indexes
        post(
            "indexes.name",
            "/v1/indexes",
            json!({"name": p, "table": "financial_metrics", "columns": ["ticker"]}),
        ),
        post(
            "indexes.table",
            "/v1/indexes",
            json!({"name": "i1", "table": p, "columns": ["ticker"]}),
        ),
        post(
            "indexes.column",
            "/v1/indexes",
            json!({"name": "i1", "table": "financial_metrics", "columns": [p]}),
        ),
        // POST /v1/batch
        post(
            "batch.table",
            "/v1/batch",
            json!({"table": p, "columns": batch_columns, "rows": [row]}),
        ),
        post(
            "batch.column",
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": ["ticker", p], "rows": [["a", "b"]]}),
        ),
        post(
            "batch.replace_column",
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": batch_columns, "rows": [row], "on_conflict": {"replace": [p]}}),
        ),
        post(
            "batch.conflict_target",
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": batch_columns, "rows": [row], "on_conflict": "replace_all", "conflict_target": [p]}),
        ),
        post(
            "batch.on_conflict",
            "/v1/batch",
            json!({"table": "financial_metrics", "columns": batch_columns, "rows": [row], "on_conflict": p}),
        ),
        post(
            "batches.table",
            "/v1/batch",
            json!({"batches": [{"table": p, "columns": batch_columns, "rows": [row]}]}),
        ),
        // POST /v1/query
        post("query.table", "/v1/query", json!({"table": p})),
        post(
            "query.column",
            "/v1/query",
            json!({"table": "financial_metrics", "columns": [p]}),
        ),
        post(
            "query.columns_object_table",
            "/v1/query",
            json!({"table": "financial_metrics", "columns": {p: ["ticker"]}}),
        ),
        post(
            "query.columns_object_column",
            "/v1/query",
            json!({"table": "financial_metrics", "columns": {"financial_metrics": [p]}}),
        ),
        post(
            "query.filter_column",
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {p: "x"}}),
        ),
        post(
            "query.filter_operator",
            "/v1/query",
            json!({"table": "financial_metrics", "filters": {"ticker": {p: "x"}}}),
        ),
        post(
            "query.sort_column",
            "/v1/query",
            json!({"table": "financial_metrics", "sort": [{p: "asc"}]}),
        ),
        post(
            "query.sort_direction",
            "/v1/query",
            json!({"table": "financial_metrics", "sort": [{"ticker": p}]}),
        ),
        post(
            "query.join_table",
            "/v1/query",
            json!({"table": "financial_metrics", "join": {p: "ticker"}}),
        ),
        post(
            "query.join_column",
            "/v1/query",
            json!({"table": "financial_metrics", "join": {"sectors": p}}),
        ),
        post(
            "query.join_to",
            "/v1/query",
            json!({"table": "financial_metrics", "join": {"sectors": {"column": "ticker", "to": p}}}),
        ),
        post(
            "query.join_type",
            "/v1/query",
            json!({"table": "financial_metrics", "join": {"sectors": {"column": "ticker", "to": "code", "type": p}}}),
        ),
        // POST /v1/delete
        post(
            "delete.table",
            "/v1/delete",
            json!({"table": p, "filters": {"ticker": "x"}}),
        ),
        post(
            "delete.filter_column",
            "/v1/delete",
            json!({"table": "financial_metrics", "filters": {p: "x"}}),
        ),
        post(
            "delete.filter_operator",
            "/v1/delete",
            json!({"table": "financial_metrics", "filters": {"ticker": {p: "x"}}}),
        ),
        // PATCH /v1/table
        patch(
            "patch.table",
            json!({"table": p, "column": "ticker", "rename": "t2"}),
        ),
        patch(
            "patch.column",
            json!({"table": "financial_metrics", "column": p, "rename": "t2"}),
        ),
        patch(
            "patch.rename",
            json!({"table": "financial_metrics", "column": "ticker", "rename": p}),
        ),
        patch(
            "patch.type",
            json!({"table": "financial_metrics", "column": "ticker", "type": p}),
        ),
        patch(
            "patch.references",
            json!({"table": "financial_metrics", "column": "ticker", "references": p}),
        ),
        // DELETE /v1/index
        (
            "index.drop",
            Method::DELETE,
            format!("/v1/index?name={}", percent_encode(p)),
            None,
        ),
    ]
}

/// A database with two tables, an index and some rows, plus a way to see all of it at once.
async fn injection_fixture() -> TestApp {
    let t = TestApp::new().await;
    t.create_metrics().await;
    let (status, body) = t
        .post("/v1/tables", json!({"name": "sectors", "columns": [{"name": "code", "type": "TEXT"}, {"name": "label", "type": "TEXT"}], "primary_key": ["code"]}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = t
        .post(
            "/v1/indexes",
            json!({"name": "idx_fm_ticker", "table": "financial_metrics", "columns": ["ticker"]}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = t
        .insert(json!([
            ["AAPL", "revenue", "2024-Q1", 1],
            ["AAPL", "revenue", "2024-Q2", 2],
            ["MSFT", "eps", "2024-Q1", 3]
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = t
        .post("/v1/batch", json!({"table": "sectors", "columns": ["code", "label"], "rows": [["tech", "Technology"], ["energy", "Energy"]]}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    t
}

/// The whole visible state: the schema and every row of both tables.
async fn snapshot(t: &TestApp) -> JsonValue {
    let (status, schema) = t.call(Method::GET, "/v1/schema", Some(KEY), None).await;
    assert_eq!(status, StatusCode::OK, "{schema}");
    let (_, metrics) = t
        .post("/v1/query", json!({"table": "financial_metrics", "sort": [{"ticker": "asc"}, {"metric": "asc"}, {"period": "asc"}]}))
        .await;
    let (_, sectors) = t
        .post(
            "/v1/query",
            json!({"table": "sectors", "sort": [{"code": "asc"}]}),
        )
        .await;
    json!({"schema": schema, "metrics": metrics, "sectors": sectors})
}

#[tokio::test]
async fn sqli_hostile_names_are_refused_in_every_identifier_slot_of_every_route() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    let mut sent = 0;
    for p in &hostile_names() {
        for (slot, method, path, body) in hostile_requests(p) {
            let (status, response) = t.call(method, &path, Some(KEY), body).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "slot {slot}, payload {p:?}: {response}"
            );
            sent += 1;
        }
    }
    assert!(sent > 1500, "only {sent} requests were sent");
    // Nothing was created, changed or dropped by any of them.
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_fuzzed_names_are_refused_with_400_and_change_nothing() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    let mut rng = Lcg(0xfeed);
    let mut sent = 0;
    for _ in 0..120 {
        let p = fuzz_string(&mut rng, 30);
        if is_valid_identifier(&p) {
            continue;
        }
        // Skip dotted names: in a column slot `a.b` is the qualified form `table.column`.
        let requests = hostile_requests(&p).into_iter().filter(|(slot, ..)| {
            !(p.contains('.')
                && matches!(
                    *slot,
                    "query.column"
                        | "query.columns_object_column"
                        | "query.filter_column"
                        | "query.filter_operator"
                        | "query.sort_column"
                        | "delete.filter_column"
                ))
        });
        for (slot, method, path, body) in requests {
            let (status, response) = t.call(method, &path, Some(KEY), body).await;
            assert!(
                status.is_client_error(),
                "slot {slot}, payload {p:?}: {status} {response}"
            );
            sent += 1;
        }
    }
    assert!(sent > 3000, "only {sent} requests were sent");
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_identifiers_that_are_not_strings_are_refused() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for bad in [
        json!(5),
        json!(null),
        json!(true),
        json!([]),
        json!({}),
        json!(["ticker"]),
        json!({"$": 1}),
    ] {
        let requests = [
            (
                "/v1/tables",
                json!({"name": bad, "columns": [{"name": "a", "type": "TEXT"}]}),
            ),
            (
                "/v1/tables",
                json!({"name": "t1", "columns": [{"name": bad, "type": "TEXT"}]}),
            ),
            (
                "/v1/tables",
                json!({"name": "t1", "columns": [{"name": "a", "type": bad}]}),
            ),
            (
                "/v1/indexes",
                json!({"name": bad, "table": "financial_metrics", "columns": ["ticker"]}),
            ),
            (
                "/v1/indexes",
                json!({"name": "i1", "table": bad, "columns": ["ticker"]}),
            ),
            (
                "/v1/batch",
                json!({"table": bad, "columns": ["ticker"], "rows": [["a"]]}),
            ),
            (
                "/v1/batch",
                json!({"table": "financial_metrics", "columns": [bad], "rows": [["a"]]}),
            ),
            ("/v1/query", json!({"table": bad})),
            (
                "/v1/query",
                json!({"table": "financial_metrics", "columns": [bad]}),
            ),
            (
                "/v1/query",
                json!({"table": "financial_metrics", "sort": [{"ticker": bad}]}),
            ),
            (
                "/v1/delete",
                json!({"table": bad, "filters": {"ticker": "x"}}),
            ),
        ];
        for (path, body) in requests {
            // An empty object in a column list is an empty per-table mapping: it names no column,
            // so the query selects them all. Every other non-string is refused.
            if bad == json!({}) && body.get("columns") == Some(&json!([bad])) && path == "/v1/query"
            {
                continue;
            }
            let (status, response) = t.post(path, body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {body}: {response}");
        }
    }
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_limit_and_offset_cannot_carry_sql() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for bad in [
        json!("1; DROP TABLE financial_metrics"),
        json!("1 OR 1"),
        json!("10"),
        json!(-1),
        json!(1.5),
        json!(4294967296u64),
        json!(1e30),
        json!([1]),
        json!({"a": 1}),
        json!(true),
    ] {
        for field in ["limit", "offset"] {
            let (status, body) = t
                .post(
                    "/v1/query",
                    json!({"table": "financial_metrics", field: bad}),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field} {bad}: {body}");
        }
    }
    assert_eq!(snapshot(&t).await, before);
}

/// Strings with a meaning in SQL, placeholders of every style, and look-alikes of both.
const HOSTILE_VALUES: &[&str] = &[
    "' OR '1'='1",
    "'; DROP TABLE financial_metrics; --",
    "\" OR 1=1 --",
    "%' OR 1=1 --",
    "x') OR ('1'='1",
    "x'||(SELECT group_concat(name) FROM sqlite_master)||'",
    "1; DELETE FROM financial_metrics",
    "0 OR 1=1",
    "AAPL' --",
    "AAPL\\",
    "?1",
    "?",
    ":a",
    "$a",
    "@a",
    "NULL",
    "null",
    "1e999",
    "\u{202e}AAPL",
    "💥",
    "\n",
    "/* */",
];

#[tokio::test]
async fn sqli_hostile_values_in_filters_match_nothing_and_change_nothing() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for v in HOSTILE_VALUES {
        let tr = &t;
        let query = |filters: JsonValue| async move {
            let (status, body) = tr
                .post(
                    "/v1/query",
                    json!({"table": "financial_metrics", "filters": filters.clone()}),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{v:?} {filters}: {body}");
            body["row_count"].as_u64().unwrap()
        };
        // The value is compared as a string, never parsed: no clause is added, none is dropped.
        assert_eq!(query(json!({"ticker": v})).await, 0, "eq {v:?}");
        assert_eq!(query(json!({"ticker": {"eq": v}})).await, 0, "eq {v:?}");
        assert_eq!(query(json!({"ticker": {"ne": v}})).await, 3, "ne {v:?}");
        assert_eq!(query(json!({"ticker": {"in": [v]}})).await, 0, "in {v:?}");
        assert_eq!(
            query(json!({"ticker": {"in": ["AAPL", v]}})).await,
            2,
            "in {v:?}"
        );
        assert_eq!(
            query(json!({"ticker": {"not_in": [v]}})).await,
            3,
            "not_in {v:?}"
        );
        assert_eq!(query(json!({"ticker": {"like": v}})).await, 0, "like {v:?}");
        assert_eq!(
            query(json!({"ticker": {"like": [v, v]}})).await,
            0,
            "like {v:?}"
        );
        assert_eq!(
            query(json!({"ticker": {"not_like": v}})).await,
            3,
            "not_like {v:?}"
        );
        // Ordering comparisons: only that they run and cannot widen the match to everything
        // by way of the value itself.
        query(json!({"ticker": {"gt": v}})).await;
        query(json!({"ticker": {"lte": v}})).await;
        // Combined with a real condition, the hostile value still only narrows the result.
        assert_eq!(
            query(json!({"ticker": "AAPL", "metric": v})).await,
            0,
            "and {v:?}"
        );
    }
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_hostile_values_in_deletes_remove_nothing_else() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for v in HOSTILE_VALUES {
        for filters in [
            json!({"ticker": v}),
            json!({"ticker": {"in": [v]}}),
            json!({"ticker": {"like": v}}),
            json!({"ticker": "AAPL", "metric": v}),
        ] {
            let (status, body) = t
                .delete(json!({"table": "financial_metrics", "filters": filters}))
                .await;
            assert_eq!(status, StatusCode::OK, "{v:?}: {body}");
            assert_eq!(body, json!({"rows": {"deleted": 0}}), "{v:?} {filters}");
        }
    }
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_hostile_values_are_stored_and_returned_verbatim() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for v in HOSTILE_VALUES {
        // Insert, upsert and read back by exact match.
        let rows = json!([[v, v, v, 1]]);
        let (status, body) = t.insert(rows.clone()).await;
        assert_eq!(status, StatusCode::OK, "{v:?}: {body}");
        let (status, body) = t
            .post("/v1/batch", json!({"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": [[v, v, v, 2]], "on_conflict": {"replace": ["value"]}}))
            .await;
        assert_eq!(status, StatusCode::OK, "{v:?}: {body}");
        let (_, body) = t
            .post("/v1/query", json!({"table": "financial_metrics", "filters": {"ticker": v, "metric": v, "period": v}}))
            .await;
        assert_eq!(body["row_count"], 1, "{v:?}");
        assert_eq!(body["rows"][0]["ticker"], *v);
        assert_eq!(body["rows"][0]["value"], 2.0);
        // The only thing a delete on that value can remove is the row just written.
        let (_, body) = t
            .delete(json!({"table": "financial_metrics", "filters": {"ticker": v}}))
            .await;
        assert_eq!(body, json!({"rows": {"deleted": 1}}), "{v:?}");
    }
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_hostile_values_in_defaults_and_in_multi_table_batches_stay_data() {
    let t = injection_fixture().await;
    for (i, v) in HOSTILE_VALUES.iter().enumerate() {
        // A default given to PATCH is bound once for the rows that already exist.
        let column = format!("note{i}");
        let (status, body) = t
            .patch(json!({"table": "sectors", "column": column, "type": "TEXT", "nullable": true, "default": v}))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{v:?}: {body}");
        let (_, body) = t
            .post(
                "/v1/query",
                json!({"table": "sectors", "columns": [column], "sort": [{"code": "asc"}]}),
            )
            .await;
        assert_eq!(body["rows"][0][&column], *v);
        assert_eq!(body["rows"][1][&column], *v);
    }
    // Several tables in one request, every value hostile.
    let v = HOSTILE_VALUES[1];
    let (status, body) = t
        .post("/v1/batch", json!({"batches": [
            {"table": "financial_metrics", "columns": ["ticker", "metric", "period", "value"], "rows": [[v, v, v, 1]]},
            {"table": "sectors", "columns": ["code", "label"], "rows": [[v, v]]}
        ]}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = t
        .post(
            "/v1/query",
            json!({"table": "sectors", "filters": {"code": v}}),
        )
        .await;
    assert_eq!(body["rows"][0]["label"], *v);
    // Both tables are still there.
    let (_, schema) = t.call(Method::GET, "/v1/schema", Some(KEY), None).await;
    let names: Vec<&str> = schema["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"financial_metrics") && names.contains(&"sectors"),
        "{names:?}"
    );
}

#[tokio::test]
async fn sqli_hostile_values_through_joins_stay_data() {
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    for v in HOSTILE_VALUES {
        let (status, body) = t
            .post(
                "/v1/query",
                json!({
                    "table": "financial_metrics",
                    "join": {"sectors": {"column": "ticker", "to": "code", "type": "left"}},
                    "columns": ["financial_metrics.ticker", "sectors.label"],
                    "filters": {"sectors.label": v, "financial_metrics.ticker": {"in": [v]}}
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{v:?}: {body}");
        assert_eq!(body["row_count"], 0, "{v:?}");
    }
    assert_eq!(snapshot(&t).await, before);
}

#[tokio::test]
async fn sqli_the_database_is_never_reached_by_an_unauthenticated_hostile_request() {
    // Authentication is checked before anything in the body is looked at.
    let t = injection_fixture().await;
    let before = snapshot(&t).await;
    let (status, _) = t
        .call(
            Method::POST,
            "/v1/delete",
            None,
            Some(json!({"table": "x\"; DROP TABLE financial_metrics; --", "filters": {"a": 1}})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = t
        .call(
            Method::POST,
            "/v1/delete",
            Some("wrong"),
            Some(json!({"table": "financial_metrics", "filters": {"ticker": {"like": "%"}}})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(snapshot(&t).await, before);
}
