//! Private, opt-in management API. Client protocol ports are never used for HTTP.
use axum::{
    body::Body,
    extract::{Extension, Path, Query},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hbb_common::{anyhow::anyhow, log, tokio, ResultType};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::RwLock,
    time::Instant,
};
use tokio::sync::{oneshot, Mutex};

pub const REDACTED: &str = "__REDACTED__";
static PEERS: Lazy<RwLock<Vec<Value>>> = Lazy::new(|| RwLock::new(Vec::new()));
static SESSIONS: Lazy<RwLock<HashMap<String, Session>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static BANS: Lazy<RwLock<Bans>> = Lazy::new(|| RwLock::new(Bans::default()));
static BAN_UPDATES: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static LOGS: Lazy<RwLock<VecDeque<String>>> = Lazy::new(|| RwLock::new(VecDeque::new()));

// Runtime view of the managed configuration. `values` holds the effective
// running value of every schema entry (secrets stay REDACTED), `overrides`
// holds the persisted desired values as submitted, and `pending` holds the
// restart-required entries that differ from the running values.
#[derive(Clone, Default)]
struct ManagedState {
    values: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
    pending: BTreeMap<String, String>,
}

static MANAGED: Lazy<RwLock<ManagedState>> = Lazy::new(|| RwLock::new(ManagedState::default()));
static CONFIG_UPDATES: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Applied by the owning binary for entries marked as dynamic in the schema.
// Returning false falls the entry back to restart-required handling.
pub type DynamicApplier = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;
static DYNAMIC_APPLY: Lazy<RwLock<Option<DynamicApplier>>> = Lazy::new(|| RwLock::new(None));

pub fn set_dynamic_apply(applier: DynamicApplier) {
    *DYNAMIC_APPLY.write().unwrap() = Some(applier);
}

fn apply_dynamic(name: &str, value: &str) -> bool {
    DYNAMIC_APPLY
        .read()
        .unwrap()
        .as_ref()
        .map(|applier| applier(name, value))
        .unwrap_or(false)
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bans {
    pub device_ids: Vec<String>,
    pub ips: Vec<String>,
}

impl Bans {
    fn validate(&mut self) -> ResultType<()> {
        if self.device_ids.len() > 10000 || self.ips.len() > 10000 {
            return Err(anyhow!("Too many ban rules"));
        }
        if self
            .device_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > 100 || id.chars().any(char::is_whitespace))
        {
            return Err(anyhow!("Invalid device ID"));
        }
        self.ips = self
            .ips
            .iter()
            .map(|ip| ip.parse::<IpAddr>().map(normalize_ip))
            .collect::<Result<Vec<_>, _>>()?;
        self.device_ids.sort();
        self.device_ids.dedup();
        self.ips.sort();
        self.ips.dedup();
        Ok(())
    }

    fn contains(&self, id: &str, ip: &str) -> bool {
        let normalized = normalize_client_ip(ip);
        (!id.is_empty() && self.device_ids.iter().any(|v| v == id))
            || self.ips.iter().any(|v| v == &normalized)
    }
}

// Forwarded headers may contain a bare IP, bracketed IPv6 or an endpoint.
// Preserve malformed values for the existing proxy/header compatibility policy.
pub fn normalize_client_ip(value: &str) -> String {
    let candidate = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value);
    candidate
        .parse::<IpAddr>()
        .or_else(|_| value.parse::<SocketAddr>().map(|addr| addr.ip()))
        .map(normalize_ip)
        .unwrap_or_else(|_| value.to_owned())
}

fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| ip.to_string()),
        ip => ip.to_string(),
    }
}

pub fn is_banned(id: &str, ip: &str) -> bool {
    BANS.read().unwrap().contains(id, ip)
}

#[allow(dead_code)]
pub fn set_peers(peers: Vec<Value>) {
    *PEERS.write().unwrap() = peers;
}

struct Session {
    info: Value,
    ids: Vec<String>,
    ips: Vec<String>,
    cancel: Option<oneshot::Sender<()>>,
}

pub fn open_session(
    uuid: &str,
    ids: Vec<String>,
    ips: Vec<String>,
    info: Value,
) -> Option<oneshot::Receiver<()>> {
    // Admission and policy updates use the same lock order. A ban cannot race
    // between admission checking and publishing the cancellation handle.
    let bans = BANS.read().unwrap();
    if ids.iter().any(|id| bans.contains(id, "")) || ips.iter().any(|ip| bans.contains("", ip)) {
        return None;
    }
    let mut sessions = SESSIONS.write().unwrap();
    if sessions.contains_key(uuid) {
        return None;
    }
    let (tx, rx) = oneshot::channel();
    sessions.insert(
        uuid.to_owned(),
        Session {
            info,
            ids,
            ips,
            cancel: Some(tx),
        },
    );
    Some(rx)
}

pub fn update_session(uuid: &str, bytes: usize, speed: usize) {
    if let Some(session) = SESSIONS.write().unwrap().get_mut(uuid) {
        session.info["bytes"] = json!(bytes);
        session.info["bytes_per_second"] = json!(speed);
    }
}

pub fn close_session(uuid: &str) {
    SESSIONS.write().unwrap().remove(uuid);
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    pub values: BTreeMap<String, String>,
}

pub fn data_path(service: &str, kind: &str) -> PathBuf {
    PathBuf::from(std::env::var("RD_MANAGEMENT_DIR").unwrap_or_else(|_| ".management".to_owned()))
        .join(format!("{service}-{kind}.json"))
}

pub fn schema(service: &str) -> Vec<Value> {
    let schema: Value = serde_json::from_str(include_str!("../management-schema.json")).unwrap();
    schema[service].as_array().unwrap().clone()
}

fn validate_value(definition: &Value, name: &str, value: &str) -> ResultType<()> {
    if value.len() > 4096 || value.contains('\0') || value == REDACTED {
        return Err(anyhow!("Invalid value for {name}"));
    }
    if definition["kind"] == "integer" || definition["kind"] == "number" {
        if definition["kind"] == "integer" {
            // Startup consumers parse integers rather than floating point strings.
            value.parse::<u64>()?;
        }
        let number: f64 = value.parse()?;
        if !number.is_finite()
            || number < definition["minimum"].as_f64().unwrap()
            || number > definition["maximum"].as_f64().unwrap()
            || (definition["kind"] == "integer" && number.fract() != 0.0)
        {
            return Err(anyhow!("Out of range: {name}"));
        }
    }
    if name == "bind" {
        crate::common::parse_bind_address(value)?;
    }
    if name == "always-use-relay" && value != "Y" && value != "N" {
        return Err(anyhow!("Expected Y or N"));
    }
    Ok(())
}

pub fn load_config(service: &str) -> ResultType<ManagedConfig> {
    let path = data_path(service, "config");
    let config: ManagedConfig = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => ManagedConfig::default(),
        Err(err) => return Err(err.into()),
    };
    let definitions = schema(service);
    for (name, value) in &config.values {
        let definition = definitions
            .iter()
            .find(|d| d["name"].as_str() == Some(name.as_str()))
            .ok_or_else(|| anyhow!("Unknown managed configuration: {name}"))?;
        validate_value(definition, name, value)?;
    }
    Ok(config)
}

impl ManagedConfig {
    pub fn apply(&self) {
        for (name, value) in &self.values {
            if name == "log" {
                std::env::set_var("RUST_LOG", value);
            } else {
                crate::common::set_arg(name, value);
            }
        }
    }
}

#[derive(Clone)]
struct ApiState {
    service: &'static str,
    token: String,
    started: Instant,

}

async fn authorize(request: Request<Body>, next: Next<Body>) -> Response {
    // Axum 0.5 from_fn middleware takes only Request and Next.
    let state = match request.extensions().get::<ApiState>() {
        Some(state) => state,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let expected = format!("Bearer {}", state.token);
    let actual = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Fixed-length comparison without early exit on a mismatching byte.
    let mut difference = actual.len() ^ expected.len();
    for (a, b) in actual.bytes().zip(expected.bytes()) {
        difference |= (a ^ b) as usize;
    }
    if difference != 0 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

async fn status(Extension(state): Extension<ApiState>) -> Json<Value> {
    Json(
        json!({"api_version":1,"service":state.service,"version":crate::version::VERSION,
        "uptime_seconds":state.started.elapsed().as_secs(),
        "public_key":std::fs::read_to_string("id_ed25519.pub").ok().map(|v| v.trim().to_owned())}),
    )
}

async fn config(Extension(state): Extension<ApiState>) -> Json<Value> {
    let managed = MANAGED.read().unwrap();
    let mut pending = Map::new();
    for (name, value) in &managed.pending {
        pending.insert(
            name.clone(),
            json!({
                "current": managed.values.get(name).cloned().unwrap_or_default(),
                "pending": value.clone(),
            }),
        );
    }
    Json(
        json!({"schema":schema(state.service),"values":managed.values.clone(),
        "pending_restart":pending}),
    )
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigUpdate {
    values: BTreeMap<String, String>,
}

fn definition_of(definitions: &[Value], name: &str) -> Option<Value> {
    definitions
        .iter()
        .find(|d| d["name"].as_str() == Some(name))
        .cloned()
}

fn bad_request(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": message})),
    )
        .into_response()
}

async fn replace_config(
    Extension(state): Extension<ApiState>,
    Json(update): Json<ConfigUpdate>,
) -> Response {
    // Validate the submission against the schema before touching any state.
    let definitions = schema(state.service);
    for (name, value) in &update.values {
        let Some(definition) = definition_of(&definitions, name) else {
            return bad_request(format!("Unknown managed configuration: {name}"));
        };
        if definition["secret"] == true && value == REDACTED {
            continue;
        }
        if let Err(err) = validate_value(&definition, name, value) {
            return bad_request(err.to_string());
        }
    }
    let service = state.service;
    // The task owns the update through persistence and activation even if the
    // HTTP caller disconnects while the blocking filesystem work is in flight.
    let result = tokio::spawn(async move {
        let _update = CONFIG_UPDATES.lock().await;
        let (mut values, mut overrides, mut pending) = {
            let managed = MANAGED.read().unwrap();
            (
                managed.values.clone(),
                managed.overrides.clone(),
                managed.pending.clone(),
            )
        };
        for (name, value) in &update.values {
            let Some(definition) = definition_of(&definitions, name) else {
                continue;
            };
            if definition["secret"] == true && value == REDACTED {
                continue;
            }
            overrides.insert(name.clone(), value.clone());
        }
        // Persist before activation; a write failure keeps the running state.
        let persisted = overrides.clone();
        tokio::task::spawn_blocking(move || persist_config(service, &persisted)).await??;
        let mut applied = Map::new();
        let mut pending_report = Map::new();
        for (name, value) in &overrides {
            let Some(definition) = definition_of(&definitions, name) else {
                continue;
            };
            let secret = definition["secret"] == true;
            // Secrets cannot be compared against the running value because the
            // effective view is redacted; only resubmitted secrets are reported.
            if secret && !update.values.contains_key(name) {
                continue;
            }
            let display = if secret {
                REDACTED.to_owned()
            } else {
                value.clone()
            };
            if !secret && values.get(name) == Some(&display) {
                pending.remove(name);
                continue;
            }
            if definition["dynamic"] == true && apply_dynamic(name, value) {
                values.insert(name.clone(), display.clone());
                pending.remove(name);
                applied.insert(name.clone(), json!(display));
            } else {
                let current = values.get(name).cloned().unwrap_or_default();
                pending.insert(name.clone(), display.clone());
                pending_report.insert(
                    name.clone(),
                    json!({"current": current, "pending": display}),
                );
            }
        }
        *MANAGED.write().unwrap() = ManagedState {
            values,
            overrides,
            pending,
        };
        Ok::<_, hbb_common::anyhow::Error>((applied, pending_report))
    })
    .await;
    match result {
        Ok(Ok((applied, pending_report))) => Json(
            json!({"state":"saved","applied":applied,"pending_restart":pending_report}),
        )
        .into_response(),
        Ok(Err(err)) => {
            log::error!("Unable to persist managed configuration: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(join) => {
            log::error!("Managed configuration update task failed: {join}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn persist_config(service: &str, overrides: &BTreeMap<String, String>) -> ResultType<()> {
    let path = data_path(service, "config");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let temporary = path.with_extension("tmp");
    let payload = serde_json::to_vec(&ManagedConfig {
        values: overrides.clone(),
    })?;
    std::fs::write(&temporary, payload)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub const LOG_CAPACITY: usize = 2000;
const LOG_LINE_LIMIT: usize = 2048;

// Called from the logging format hook in both binaries so management clients
// can read recent in-memory log lines without container log access.
pub fn push_log_line(line: &str) {
    let mut owned;
    let line = if line.len() > LOG_LINE_LIMIT {
        let mut end = LOG_LINE_LIMIT;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        owned = String::from(&line[..end]);
        owned.push_str("...");
        &owned
    } else {
        line
    };
    let mut logs = LOGS.write().unwrap();
    if logs.len() >= LOG_CAPACITY {
        logs.pop_front();
    }
    logs.push_back(line.to_owned());
}

#[derive(Clone, Copy, Deserialize)]
struct LogsQuery {
    #[serde(default)]
    tail: Option<usize>,
}

async fn logs(Query(query): Query<LogsQuery>) -> Response {
    let tail = query.tail.unwrap_or(200).min(LOG_CAPACITY);
    let logs = LOGS.read().unwrap();
    let skipped = logs.len().saturating_sub(tail);
    let data: Vec<String> = logs.iter().skip(skipped).cloned().collect();
    Json(json!({"data": data})).into_response()
}

async fn peers(Extension(state): Extension<ApiState>) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({"data":PEERS.read().unwrap().clone()})).into_response()
}

async fn sessions(Extension(state): Extension<ApiState>) -> Response {
    if state.service != "hbbr" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut data: Vec<Value> = SESSIONS
        .read()
        .unwrap()
        .values()
        .map(|s| s.info.clone())
        .collect();
    data.sort_by(|a, b| a["uuid"].as_str().cmp(&b["uuid"].as_str()));
    Json(json!({"data":data})).into_response()
}

async fn disconnect(Extension(state): Extension<ApiState>, Path(uuid): Path<String>) -> Response {
    if state.service != "hbbr" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut sessions = SESSIONS.write().unwrap();
    if let Some(session) = sessions.get_mut(&uuid) {
        if let Some(tx) = session.cancel.take() {
            let _ = tx.send(());
        }
        session.info["closing"] = json!(true);
        return (StatusCode::ACCEPTED, Json(json!({"state":"closing"}))).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn bans() -> Json<Bans> {
    Json(BANS.read().unwrap().clone())
}

async fn replace_bans(
    Extension(state): Extension<ApiState>,
    Json(mut bans): Json<Bans>,
) -> Response {
    if let Err(err) = bans.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":err.to_string()})),
        )
            .into_response();
    }
    // The task owns the update through persistence and activation even if the
    // HTTP caller disconnects while the blocking filesystem work is in flight.
    match tokio::spawn(async move {
        let _update = BAN_UPDATES.lock().await;
        if *BANS.read().unwrap() == bans {
            return Ok(());
        }
        let service = state.service;
        let persisted = bans.clone();
        tokio::task::spawn_blocking(move || persist_bans(service, &persisted)).await??;
        // Never hold the protocol admission lock during filesystem I/O.
        // Keep the BANS -> SESSIONS order for activation and admission.
        let mut current = BANS.write().unwrap();
        *current = bans;
        cancel_banned_sessions(&current);
        Ok::<(), hbb_common::anyhow::Error>(())
    })
    .await
    {
        Ok(Ok(())) => Json(json!({"state":"applied"})).into_response(),
        result => {
            log::error!("Unable to persist management bans: {result:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn cancel_banned_sessions(bans: &Bans) {
    for session in SESSIONS.write().unwrap().values_mut() {
        if session.ids.iter().any(|id| bans.contains(id, ""))
            || session.ips.iter().any(|ip| bans.contains("", ip))
        {
            if let Some(tx) = session.cancel.take() {
                let _ = tx.send(());
            }
            session.info["closing"] = json!(true);
        }
    }
}

fn persist_bans(service: &str, bans: &Bans) -> ResultType<()> {
    let path = data_path(service, "bans");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec(bans)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

// Persisted admission policy is independent of management HTTP exposure.
pub fn restore_bans(service: &str) -> ResultType<()> {
    match std::fs::read(data_path(service, "bans")) {
        Ok(bytes) => {
            let mut bans: Bans = serde_json::from_slice(&bytes)?;
            bans.validate()?;
            *BANS.write().unwrap() = bans;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

pub fn start(service: &'static str, port: u16) -> ResultType<()> {
    let bind = std::env::var("RD_MANAGEMENT_BIND").unwrap_or_default();
    if bind.is_empty() {
        return Ok(());
    }
    let token = std::env::var("RD_MANAGEMENT_TOKEN").unwrap_or_default();
    if token.len() < 32 {
        return Err(anyhow!(
            "RD_MANAGEMENT_TOKEN must contain at least 32 characters"
        ));
    }
    let overrides = load_config(service)?.values;
    let mut values = BTreeMap::new();
    for definition in schema(service) {
        let name = definition["name"].as_str().unwrap();
        let value = if name == "port" {
            port.to_string()
        } else if name == "log" {
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned())
        } else {
            crate::common::get_arg_or(name, definition["default"].as_str().unwrap().to_owned())
        };
        values.insert(
            name.to_owned(),
            if definition["secret"] == true {
                REDACTED.to_owned()
            } else {
                value
            },
        );
    }
    // Restart-required overrides took effect during startup, so nothing is
    // pending right after boot; dynamic entries were applied by the owner too.
    *MANAGED.write().unwrap() = ManagedState {
        values,
        overrides,
        pending: BTreeMap::new(),
    };
    let state = ApiState {
        service,
        token,
        started: Instant::now(),
    };
    let router = router(state);
    let listener = std::net::TcpListener::bind(&bind)?;
    listener.set_nonblocking(true)?;
    let server = axum::Server::from_tcp(listener)?.serve(router.into_make_service());
    log::info!("Management API for {service} listening on {bind}");
    tokio::spawn(async move {
        if let Err(err) = server.await {
            log::error!("Management API failed: {err}");
        }
    });
    Ok(())
}

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/config", get(config).put(replace_config))
        .route("/v1/logs", get(logs))
        .route("/v1/peers", get(peers))
        .route("/v1/sessions", get(sessions))
        .route("/v1/sessions/:uuid", axum::routing::delete(disconnect))
        .route("/v1/bans", get(bans).put(replace_bans))
        .layer(middleware::from_fn(authorize))
        .layer(Extension(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    static POLICY_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct PolicyFixture {
        directory: PathBuf,
        previous_directory: Option<String>,
        previous_bind: Option<String>,
        previous_bans: Bans,
    }
    impl PolicyFixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "rustdesk-policy-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let fixture = Self {
                directory,
                previous_directory: std::env::var("RD_MANAGEMENT_DIR").ok(),
                previous_bind: std::env::var("RD_MANAGEMENT_BIND").ok(),
                previous_bans: BANS.read().unwrap().clone(),
            };
            std::env::set_var("RD_MANAGEMENT_DIR", &fixture.directory);
            std::env::remove_var("RD_MANAGEMENT_BIND");
            *BANS.write().unwrap() = Bans::default();
            fixture
        }
    }
    impl Drop for PolicyFixture {
        fn drop(&mut self) {
            *BANS.write().unwrap() = self.previous_bans.clone();
            for (name, previous) in [
                ("RD_MANAGEMENT_DIR", &self.previous_directory),
                ("RD_MANAGEMENT_BIND", &self.previous_bind),
            ] {
                if let Some(value) = previous {
                    std::env::set_var(name, value);
                } else {
                    std::env::remove_var(name);
                }
            }
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn concurrent_policy_updates_persist_the_active_policy_and_write_failures_do_not_activate(
    ) {
        let _test = POLICY_TEST.lock().unwrap();
        let fixture = PolicyFixture::new();
        let state = ApiState {
            service: "hbbs",
            token: "test".into(),
            started: Instant::now(),

        };
        let a = Bans {
            device_ids: vec!["policy-a".into()],
            ips: vec![],
        };
        let b = Bans {
            device_ids: vec!["policy-b".into()],
            ips: vec![],
        };
        let (a_result, b_result) = tokio::join!(
            replace_bans(Extension(state.clone()), Json(a)),
            replace_bans(Extension(state.clone()), Json(b)),
        );
        assert_eq!(a_result.status(), StatusCode::OK);
        assert_eq!(b_result.status(), StatusCode::OK);
        let persisted: Bans =
            serde_json::from_slice(&std::fs::read(data_path("hbbs", "bans")).unwrap()).unwrap();
        assert!(*BANS.read().unwrap() == persisted);
        // Force the next rename to fail; the active policy must remain intact.
        std::fs::remove_file(data_path("hbbs", "bans")).unwrap();
        std::fs::create_dir(data_path("hbbs", "bans")).unwrap();
        let result = replace_bans(
            Extension(state),
            Json(Bans {
                device_ids: vec!["policy-c".into()],
                ips: vec![],
            }),
        )
        .await;
        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(*BANS.read().unwrap() == persisted);
        drop(fixture);
    }

    #[test]
    fn saved_policy_is_restored_when_management_listener_is_disabled() {
        let _test = POLICY_TEST.lock().unwrap();
        let _fixture = PolicyFixture::new();
        persist_bans(
            "hbbs",
            &Bans {
                device_ids: vec!["blocked-device".into()],
                ips: vec!["192.0.2.25".into()],
            },
        )
        .unwrap();
        restore_bans("hbbs").unwrap();
        start("hbbs", 21116).unwrap();
        assert!(is_banned("blocked-device", ""));
        assert!(is_banned("", "192.0.2.25"));
        std::fs::write(data_path("hbbs", "bans"), b"invalid policy").unwrap();
        assert!(restore_bans("hbbs").is_err());
    }
    #[tokio::test]
    async fn http_routes_require_authorization_and_do_not_leak_tokens() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let token = "test-management-token-that-is-at-least-32-characters";
        let app = router(ApiState {
            service: "hbbs",
            token: token.into(),
            started: Instant::now(),

        });
        let task = tokio::spawn(
            axum::Server::from_tcp(listener)
                .unwrap()
                .serve(app.into_make_service()),
        );
        for (credential, expected) in [("incorrect", "401"), (token, "200")] {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let request = format!("GET /v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")));
            assert!(!response.contains(token));
        }
        task.abort();
    }
    #[test]
    fn policy_normalizes_addresses_and_checks_both_rule_types() {
        let mut bans = Bans {
            device_ids: vec!["123456".into()],
            ips: vec!["::ffff:192.0.2.1".into()],
        };
        bans.validate().unwrap();
        assert!(bans.contains("123456", "192.0.2.2"));
        assert!(bans.contains("", "192.0.2.1"));
        assert!(!bans.contains("654321", "192.0.2.2"));
        assert_eq!(bans.ips, vec!["192.0.2.1"]);
    }
    #[test]
    fn endpoint_and_bracketed_forwarded_addresses_match_bare_ip_bans() {
        let bans = Bans {
            device_ids: vec![],
            ips: vec!["203.0.113.5".into(), "2001:db8::5".into()],
        };
        for ip in [
            "203.0.113.5",
            "203.0.113.5:443",
            "[::ffff:203.0.113.5]:443",
            "2001:db8::5",
            "[2001:db8::5]",
            "[2001:db8::5]:443",
        ] {
            assert!(
                bans.contains("", ip),
                "forwarded address must match ban: {ip}"
            );
        }
        assert!(!bans.contains("", "203.0.113.6:443"));
        assert_eq!(
            normalize_client_ip("unparseable:header"),
            "unparseable:header"
        );
    }
    #[test]
    fn bans_cancel_existing_sessions_and_duplicates_are_rejected() {
        let _test = POLICY_TEST.lock().unwrap();
        let mut rx = open_session(
            "test-session",
            vec!["123456".into()],
            vec!["192.0.2.1".into()],
            json!({"uuid":"test-session"}),
        )
        .unwrap();
        assert!(open_session("test-session", vec![], vec![], json!({})).is_none());
        cancel_banned_sessions(&Bans {
            device_ids: vec![],
            ips: vec!["192.0.2.1".into()],
        });
        assert!(rx.try_recv().is_ok());
        close_session("test-session");
    }

    struct ConfigFixture {
        directory: PathBuf,
        previous_directory: Option<String>,
        previous_managed: ManagedState,
        previous_applier: Option<DynamicApplier>,
    }

    impl ConfigFixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "rustdesk-config-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let fixture = Self {
                directory,
                previous_directory: std::env::var("RD_MANAGEMENT_DIR").ok(),
                previous_managed: MANAGED.read().unwrap().clone(),
                previous_applier: DYNAMIC_APPLY.write().unwrap().take(),
            };
            std::env::set_var("RD_MANAGEMENT_DIR", &fixture.directory);
            std::env::remove_var("RD_MANAGEMENT_BIND");
            *MANAGED.write().unwrap() = ManagedState::default();
            fixture
        }

        fn state(service: &'static str) -> ApiState {
            ApiState {
                service,
                token: "test".into(),
                started: Instant::now(),
            }
        }
    }

    impl Drop for ConfigFixture {
        fn drop(&mut self) {
            *MANAGED.write().unwrap() = self.previous_managed.clone();
            *DYNAMIC_APPLY.write().unwrap() = self.previous_applier.take();
            match &self.previous_directory {
                Some(value) => std::env::set_var("RD_MANAGEMENT_DIR", value),
                None => std::env::remove_var("RD_MANAGEMENT_DIR"),
            }
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn managed_values(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[tokio::test]
    async fn put_config_applies_dynamic_entries_and_reports_pending_restart() {
        let _test = POLICY_TEST.lock().unwrap();
        let _fixture = ConfigFixture::new();
        *MANAGED.write().unwrap() = ManagedState {
            values: managed_values(&[("limit-speed", "32"), ("port", "21117")]),
            overrides: BTreeMap::new(),
            pending: BTreeMap::new(),
        };
        set_dynamic_apply(Box::new(|name, _| {
            matches!(name, "limit-speed" | "single-bandwidth")
        }));
        let response = replace_config(
            Extension(ConfigFixture::state("hbbr")),
            Json(ConfigUpdate {
                values: managed_values(&[("limit-speed", "64"), ("port", "21118")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        assert_eq!(body["applied"]["limit-speed"], "64");
        assert_eq!(body["pending_restart"]["port"]["current"], "21117");
        assert_eq!(body["pending_restart"]["port"]["pending"], "21118");
        let managed = MANAGED.read().unwrap();
        assert_eq!(managed.values.get("limit-speed").unwrap(), "64");
        assert_eq!(managed.values.get("port").unwrap(), "21117");
        assert_eq!(managed.pending.get("port").unwrap(), "21118");
        let persisted: ManagedConfig = serde_json::from_slice(
            &std::fs::read(data_path("hbbr", "config")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.values, managed_values(&[("limit-speed", "64"), ("port", "21118")]));
        // The live config view reflects the dynamic change and the pending entry.
        let view = config(Extension(ConfigFixture::state("hbbr"))).await;
        assert_eq!(view["values"]["limit-speed"], "64");
        assert_eq!(view["values"]["port"], "21117");
        assert_eq!(view["pending_restart"]["port"]["pending"], "21118");
    }

    #[tokio::test]
    async fn put_config_write_failure_does_not_activate() {
        let _test = POLICY_TEST.lock().unwrap();
        let fixture = ConfigFixture::new();
        *MANAGED.write().unwrap() = ManagedState {
            values: managed_values(&[("limit-speed", "32")]),
            overrides: BTreeMap::new(),
            pending: BTreeMap::new(),
        };
        set_dynamic_apply(Box::new(|name, _| name == "limit-speed"));
        // Force the rename to fail; the running values must remain intact.
        std::fs::create_dir_all(data_path("hbbr", "config").parent().unwrap()).unwrap();
        std::fs::create_dir(data_path("hbbr", "config")).unwrap();
        let response = replace_config(
            Extension(ConfigFixture::state("hbbr")),
            Json(ConfigUpdate {
                values: managed_values(&[("limit-speed", "64")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            MANAGED.read().unwrap().values.get("limit-speed").unwrap(),
            "32"
        );
        assert!(MANAGED.read().unwrap().pending.is_empty());
        drop(fixture);
    }

    #[tokio::test]
    async fn put_config_rejects_unknown_and_invalid_values() {
        let _test = POLICY_TEST.lock().unwrap();
        let _fixture = ConfigFixture::new();
        let state = ConfigFixture::state("hbbr");
        let unknown = replace_config(
            Extension(state.clone()),
            Json(ConfigUpdate {
                values: managed_values(&[("unknown-entry", "1")]),
            }),
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        let out_of_range = replace_config(
            Extension(state.clone()),
            Json(ConfigUpdate {
                values: managed_values(&[("limit-speed", "0")]),
            }),
        )
        .await;
        assert_eq!(out_of_range.status(), StatusCode::BAD_REQUEST);
        let malformed_bind = replace_config(
            Extension(state),
            Json(ConfigUpdate {
                values: managed_values(&[("bind", "not-an-ip")]),
            }),
        )
        .await;
        assert_eq!(malformed_bind.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_config_keeps_secret_values_and_redacts_reports() {
        let _test = POLICY_TEST.lock().unwrap();
        let _fixture = ConfigFixture::new();
        *MANAGED.write().unwrap() = ManagedState {
            values: managed_values(&[("key", REDACTED), ("port", "21117")]),
            overrides: BTreeMap::new(),
            pending: BTreeMap::new(),
        };
        let response = replace_config(
            Extension(ConfigFixture::state("hbbr")),
            Json(ConfigUpdate {
                values: managed_values(&[("key", "replacement-secret")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        assert_eq!(body["pending_restart"]["key"]["pending"], REDACTED);
        assert!(!format!("{body:?}").contains("replacement-secret"));
        let persisted: ManagedConfig = serde_json::from_slice(
            &std::fs::read(data_path("hbbr", "config")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted.values.get("key").unwrap(),
            "replacement-secret"
        );
        // Resubmitting the placeholder keeps the stored secret untouched.
        let response = replace_config(
            Extension(ConfigFixture::state("hbbr")),
            Json(ConfigUpdate {
                values: managed_values(&[("key", REDACTED), ("port", "21117")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let persisted: ManagedConfig = serde_json::from_slice(
            &std::fs::read(data_path("hbbr", "config")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted.values.get("key").unwrap(),
            "replacement-secret"
        );
    }

    #[tokio::test]
    async fn log_ring_buffer_captures_tails_and_truncates() {
        for _ in 0..8 {
            push_log_line("short line");
        }
        let long: String = "x".repeat(LOG_LINE_LIMIT + 100);
        push_log_line(&long);
        let response = logs(Query(LogsQuery { tail: Some(3) })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], "short line");
        assert_eq!(data[1], "short line");
        let truncated = data[2].as_str().unwrap();
        assert!(truncated.starts_with('x'));
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= LOG_LINE_LIMIT + 3);
        // Reset the ring for other tests.
        LOGS.write().unwrap().clear();
    }
}
