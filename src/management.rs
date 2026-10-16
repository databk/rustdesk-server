//! Private, opt-in management API. Client protocol ports are never used for HTTP.
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Path,
    },
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::get,
    Json, Router,
};
use hbb_common::{anyhow::anyhow, log, tokio, ResultType};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_stream::{wrappers::ReceiverStream, StreamExt as _};

pub const REDACTED: &str = "__REDACTED__";
static PEERS: Lazy<RwLock<Vec<Value>>> = Lazy::new(|| RwLock::new(Vec::new()));
static SESSIONS: Lazy<RwLock<HashMap<String, Session>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static BANS: Lazy<RwLock<Bans>> = Lazy::new(|| RwLock::new(Bans::default()));
static BAN_UPDATES: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Aggregated event bus backing the /v1/events SSE stream. hbbs emits local
// events (peers, bans, relays) and forwards the events reported by connected
// relay servers.
static EVENTS: Lazy<broadcast::Sender<Value>> = Lazy::new(|| broadcast::channel(1024).0);

fn emit_event(kind: &str, data: Value) {
    let _ = EVENTS.send(json!({
        "kind": kind,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": data,
    }));
}

// Registered relay control channels (hbbs only). Each entry describes one
// live reverse connection established by an hbbr instance.
struct RelayConnection {
    id: String,
    info: Value,
    address: Option<String>,
    version: String,
    generation: u64,
    started: Instant,
    last_heartbeat: Instant,
    sessions: Vec<Value>,
    tx: mpsc::UnboundedSender<Message>,
}

static RELAYS: Lazy<RwLock<HashMap<String, RelayConnection>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static RELAY_GENERATION: AtomicU64 = AtomicU64::new(0);

// Registered by hbbs to fold discovered relay addresses back into the live
// relay server list (static configuration plus registered relays).
pub type RelaySync = Box<dyn Fn(Vec<String>) + Send + Sync>;
static RELAY_SYNC: Lazy<RwLock<Option<RelaySync>>> = Lazy::new(|| RwLock::new(None));

#[allow(dead_code)] // Only the hbbs binary registers a relay sync callback.
pub fn set_relay_sync(sync: RelaySync) {
    *RELAY_SYNC.write().unwrap() = Some(sync);
}

fn sync_relay_list() {
    let addresses: Vec<String> = RELAYS
        .read()
        .unwrap()
        .values()
        .filter_map(|relay| relay.address.clone())
        .collect();
    if let Some(sync) = &*RELAY_SYNC.read().unwrap() {
        sync(addresses);
    }
}

fn relay_command(relay_id: &str, payload: Value) -> ResultType<()> {
    let relays = RELAYS.read().unwrap();
    let relay = relays
        .get(relay_id)
        .ok_or_else(|| anyhow!("Unknown relay: {relay_id}"))?;
    relay
        .tx
        .send(Message::Text(payload.to_string()))
        .map_err(|_| anyhow!("Relay control channel is closed"))?;
    Ok(())
}

fn fanout_bans() {
    let payload = json!({"type": "bans", "bans": *BANS.read().unwrap()});
    let text = payload.to_string();
    for relay in RELAYS.read().unwrap().values() {
        let _ = relay.tx.send(Message::Text(text.clone()));
    }
}

// Outbound relay-side events (session lifecycle) consumed by the hbbr control
// client. Only meaningful inside the hbbr binary; sends without a consumer
// are dropped.
static CONTROL_OUT: Lazy<(
    mpsc::UnboundedSender<Value>,
    std::sync::Mutex<Option<mpsc::UnboundedReceiver<Value>>>,
)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (tx, std::sync::Mutex::new(Some(rx)))
});

fn control_emit(event: Value) {
    let _ = CONTROL_OUT.0.send(event);
}

pub fn take_control_receiver() -> Option<mpsc::UnboundedReceiver<Value>> {
    CONTROL_OUT.1.lock().unwrap().take()
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
    fn ids(snapshot: &[Value]) -> HashSet<String> {
        snapshot
            .iter()
            .filter_map(|peer| peer["id"].as_str().map(str::to_owned))
            .collect()
    }
    let previous = ids(&PEERS.read().unwrap());
    let current = ids(&peers);
    for id in current.difference(&previous) {
        emit_event("peer_online", json!({"id": id}));
    }
    for id in previous.difference(&current) {
        emit_event("peer_offline", json!({"id": id}));
    }
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
            info: info.clone(),
            ids,
            ips,
            cancel: Some(tx),
        },
    );
    control_emit(json!({"type": "event", "event": {
        "kind": "session_opened", "session": info, "uuid": uuid}}));
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
    control_emit(json!({"type": "event", "event": {
        "kind": "session_closed", "uuid": uuid}}));
}

// Snapshot of the active relay sessions, sorted by uuid.
pub fn sessions_snapshot() -> Vec<Value> {
    let mut data: Vec<Value> = SESSIONS
        .read()
        .unwrap()
        .values()
        .map(|s| s.info.clone())
        .collect();
    data.sort_by(|a, b| a["uuid"].as_str().cmp(&b["uuid"].as_str()));
    data
}

// Cancels a session by uuid; returns false when the session is unknown.
pub fn disconnect_session(uuid: &str) -> bool {
    let mut sessions = SESSIONS.write().unwrap();
    if let Some(session) = sessions.get_mut(uuid) {
        if let Some(tx) = session.cancel.take() {
            let _ = tx.send(());
        }
        session.info["closing"] = json!(true);
        true
    } else {
        false
    }
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
    values: BTreeMap<String, String>,
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
    Json(json!({"schema":schema(state.service),"values":state.values}))
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
    Json(json!({"data":sessions_snapshot()})).into_response()
}

async fn disconnect(Extension(state): Extension<ApiState>, Path(uuid): Path<String>) -> Response {
    if state.service != "hbbr" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if disconnect_session(&uuid) {
        return (StatusCode::ACCEPTED, Json(json!({"state":"closing"}))).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn bans() -> Json<Bans> {
    Json(BANS.read().unwrap().clone())
}

// Validates, persists and activates a ban policy. Shared by the HTTP handler
// and the relay control channel (hbbr applies the policies forwarded by hbbs).
// The update owns persistence through activation even if the caller
// disconnects while the blocking filesystem work is in flight.
pub async fn apply_bans_update(service: &'static str, mut bans: Bans) -> ResultType<()> {
    bans.validate()?;
    let _update = BAN_UPDATES.lock().await;
    if *BANS.read().unwrap() == bans {
        return Ok(());
    }
    let persisted = bans.clone();
    tokio::task::spawn_blocking(move || persist_bans(service, &persisted)).await??;
    // Never hold the protocol admission lock during filesystem I/O.
    // Keep the BANS -> SESSIONS order for activation and admission.
    let mut current = BANS.write().unwrap();
    *current = bans;
    cancel_banned_sessions(&current);
    Ok(())
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
    let service = state.service;
    let result = tokio::spawn(apply_bans_update(service, bans)).await;
    match result {
        Ok(Ok(())) => {
            if service == "hbbs" {
                fanout_bans();
            }
            emit_event("bans_replaced", json!({"service": service}));
            Json(json!({"state":"applied"})).into_response()
        }
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
    let state = ApiState {
        service,
        token,
        started: Instant::now(),
        values,
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


// Reverse control channel: hbbr connects here (hbbs only), registers itself,
// reports heartbeats and session events, and receives policy commands.
async fn control(Extension(state): Extension<ApiState>, ws: WebSocketUpgrade) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    ws.on_upgrade(move |socket| control_socket(socket))
}

fn valid_relay_text(value: &str, max: usize) -> Option<String> {
    if !value.is_empty() && value.len() <= max && !value.chars().any(char::is_whitespace) {
        Some(value.to_owned())
    } else {
        None
    }
}

async fn control_socket(mut socket: WebSocket) {
    // Registration is the first frame; the connection is dropped otherwise.
    let register = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => return,
    };
    let register: Value = match serde_json::from_str::<Value>(&register) {
        Ok(value) if value["type"] == "register" => value,
        _ => return,
    };
    let relay_id = match register["relay"]["id"]
        .as_str()
        .and_then(|id| valid_relay_text(id, 100))
    {
        Some(id) => id,
        None => return,
    };
    let address = register["relay"]["address"]
        .as_str()
        .and_then(|address| valid_relay_text(address, 253));
    let version = register["relay"]["version"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let info = register["relay"].clone();
    let generation = RELAY_GENERATION.fetch_add(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    {
        // A re-registering relay replaces its previous connection; the stale
        // generation prevents the old socket task from clearing the new entry.
        let mut relays = RELAYS.write().unwrap();
        if let Some(previous) = relays.remove(&relay_id) {
            let _ = previous.tx.send(Message::Close(None));
        }
        relays.insert(
            relay_id.clone(),
            RelayConnection {
                id: relay_id.clone(),
                info,
                address: address.clone(),
                version,
                generation,
                started: Instant::now(),
                last_heartbeat: Instant::now(),
                sessions: Vec::new(),
                tx: tx.clone(),
            },
        );
    }
    log::info!("Relay {relay_id} registered on the control channel");
    emit_event(
        "relay_registered",
        json!({"id": relay_id, "address": address, "generation": generation}),
    );
    sync_relay_list();
    // Bring the new relay up to date with the active policy and request a
    // session snapshot so aggregation is complete right after registration.
    let _ = tx.send(Message::Text(
        json!({"type": "bans", "bans": *BANS.read().unwrap()}).to_string(),
    ));
    let _ = tx.send(Message::Text(json!({"type": "get_sessions"}).to_string()));

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Text(text))) => {
                        handle_control_message(&relay_id, generation, &text);
                    }
                    Some(Ok(_)) => {}
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(message) => {
                        if socket.send(message).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let stale = RELAYS
                    .read()
                    .unwrap()
                    .get(&relay_id)
                    .map(|relay| {
                        relay.generation == generation
                            && relay.last_heartbeat.elapsed().as_secs() > 45
                    })
                    .unwrap_or(true);
                if stale {
                    break;
                }
            }
        }
    }
    {
        let mut relays = RELAYS.write().unwrap();
        if relays
            .get(&relay_id)
            .map(|relay| relay.generation == generation)
            .unwrap_or(false)
        {
            relays.remove(&relay_id);
            log::info!("Relay {relay_id} left the control channel");
            emit_event("relay_disconnected", json!({"id": relay_id}));
            sync_relay_list();
        }
    }
}

fn handle_control_message(relay_id: &str, generation: u64, text: &str) {
    let Ok(message) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let mut relays = RELAYS.write().unwrap();
    let Some(relay) = relays.get_mut(relay_id) else {
        return;
    };
    if relay.generation != generation {
        return;
    }
    match message["type"].as_str() {
        Some("heartbeat") => {
            relay.last_heartbeat = Instant::now();
        }
        Some("sessions") => {
            if let Some(data) = message["data"].as_array() {
                relay.sessions = data.clone();
            }
        }
        Some("event") => {
            // Relay-reported events join the aggregated event stream.
            let mut event = message["event"].clone();
            if let Some(object) = event.as_object_mut() {
                object.insert("relay_id".to_owned(), json!(relay_id));
            }
            if event["kind"].as_str() == Some("session_opened") {
                relay.last_heartbeat = Instant::now();
            }
            let kind = event["kind"].as_str().unwrap_or("relay_event").to_owned();
            emit_event(&kind, event);
        }
        _ => {}
    }
}

// Registered relays with health and aggregation metadata (hbbs only).
async fn relays(Extension(state): Extension<ApiState>) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut data: Vec<Value> = RELAYS
        .read()
        .unwrap()
        .values()
        .map(|relay| {
            json!({
                "id": relay.id,
                "address": relay.address,
                "version": relay.version,
                "info": relay.info,
                "uptime_seconds": relay.started.elapsed().as_secs(),
                "last_heartbeat_age_seconds": relay.last_heartbeat.elapsed().as_secs(),
                "sessions_count": relay.sessions.len(),
            })
        })
        .collect();
    data.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Json(json!({"data": data})).into_response()
}

async fn relay_sessions(
    Extension(state): Extension<ApiState>,
    Path(relay_id): Path<String>,
) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let relays = RELAYS.read().unwrap();
    match relays.get(&relay_id) {
        Some(relay) => Json(json!({"data": relay.sessions.clone()})).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn relay_disconnect(
    Extension(state): Extension<ApiState>,
    Path((relay_id, uuid)): Path<(String, String)>,
) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    match relay_command(&relay_id, json!({"type": "disconnect", "uuid": uuid})) {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"state":"closing"}))).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// Aggregated server-sent event stream: peer online/offline, relay session
// lifecycle, relay registration and policy changes.
async fn events() -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = mpsc::channel::<Value>(64);
    tokio::spawn(async move {
        let mut subscription = EVENTS.subscribe();
        loop {
            match subscription.recv().await {
                Ok(event) => {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });
    let stream = ReceiverStream::new(rx).map(|event| {
        Ok::<_, Infallible>(
            SseEvent::default()
                .event(event["kind"].as_str().unwrap_or("event").to_owned())
                .data(event.to_string()),
        )
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/config", get(config))
        .route("/v1/peers", get(peers))
        .route("/v1/sessions", get(sessions))
        .route("/v1/sessions/:uuid", axum::routing::delete(disconnect))
        .route("/v1/bans", get(bans).put(replace_bans))
        .route("/v1/events", get(events))
        .route("/v1/control", get(control))
        .route("/v1/relays", get(relays))
        .route("/v1/relays/:id/sessions", get(relay_sessions))
        .route(
            "/v1/relays/:id/sessions/:uuid",
            axum::routing::delete(relay_disconnect),
        )
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
            values: BTreeMap::new(),
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
            values: BTreeMap::new(),
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
    fn subscribe_events() -> broadcast::Receiver<Value> {
        EVENTS.subscribe()
    }

    fn register_test_relay(relay_id: &str, address: Option<&str>) -> mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = mpsc::unbounded_channel();
        RELAYS.write().unwrap().insert(
            relay_id.to_owned(),
            RelayConnection {
                id: relay_id.to_owned(),
                info: json!({"id": relay_id}),
                address: address.map(str::to_owned),
                version: "test".to_owned(),
                generation: RELAY_GENERATION.fetch_add(1, Ordering::SeqCst),
                started: Instant::now(),
                last_heartbeat: Instant::now(),
                sessions: Vec::new(),
                tx,
            },
        );
        rx
    }

    fn clear_relays() {
        RELAYS.write().unwrap().clear();
    }

    #[test]
    fn peer_snapshots_emit_online_and_offline_events() {
        *PEERS.write().unwrap() = Vec::new();
        let mut events = subscribe_events();
        set_peers(vec![json!({"id": "111111111"})]);
        set_peers(vec![json!({"id": "222222222"})]);
        let mut kinds = Vec::new();
        while let Ok(event) = events.try_recv() {
            kinds.push((
                event["kind"].as_str().unwrap().to_owned(),
                event["data"]["id"].as_str().unwrap_or_default().to_owned(),
            ));
        }
        assert!(kinds.contains(&("peer_online".to_owned(), "111111111".into())));
        assert!(kinds.contains(&("peer_offline".to_owned(), "111111111".into())));
        assert!(kinds.contains(&("peer_online".to_owned(), "222222222".into())));
        *PEERS.write().unwrap() = Vec::new();
    }

    #[tokio::test]
    async fn apply_bans_update_persists_and_activates_for_relay_use() {
        let _test = POLICY_TEST.lock().unwrap();
        let fixture = PolicyFixture::new();
        let bans = Bans {
            device_ids: vec!["relay-blocked".into()],
            ips: vec![],
        };
        apply_bans_update("hbbr", bans).await.unwrap();
        assert!(is_banned("relay-blocked", ""));
        let persisted: Bans =
            serde_json::from_slice(&std::fs::read(data_path("hbbr", "bans")).unwrap()).unwrap();
        assert!(persisted.device_ids.contains(&"relay-blocked".to_owned()));
        drop(fixture);
    }

    #[tokio::test]
    async fn replace_bans_fans_out_to_registered_relays() {
        let _test = POLICY_TEST.lock().unwrap();
        let fixture = PolicyFixture::new();
        clear_relays();
        let mut receiver = register_test_relay("relay-a", Some("relay-a:21117"));
        let state = ApiState {
            service: "hbbs",
            token: "test".into(),
            started: Instant::now(),
            values: BTreeMap::new(),
        };
        let response = replace_bans(
            Extension(state),
            Json(Bans {
                device_ids: vec!["fanout-device".into()],
                ips: vec![],
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let message = receiver
            .recv()
            .await
            .expect("the relay must receive the active policy");
        let Message::Text(text) = message else {
            panic!("expected a text message");
        };
        let payload: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(payload["type"], "bans");
        assert_eq!(payload["bans"]["device_ids"][0], "fanout-device");
        clear_relays();
        drop(fixture);
    }

    #[test]
    fn control_messages_update_heartbeat_sessions_and_forward_events() {
        clear_relays();
        let generation = RELAY_GENERATION.fetch_add(1, Ordering::SeqCst);
        let (tx, _rx) = mpsc::unbounded_channel();
        RELAYS.write().unwrap().insert(
            "relay-b".to_owned(),
            RelayConnection {
                id: "relay-b".to_owned(),
                info: json!({"id": "relay-b"}),
                address: None,
                version: "test".to_owned(),
                generation,
                started: Instant::now(),
                last_heartbeat: Instant::now()
                    - Duration::from_secs(120),
                sessions: Vec::new(),
                tx,
            },
        );
        let mut events = subscribe_events();
        handle_control_message(
            "relay-b",
            generation,
            r#"{"type":"heartbeat"}"#,
        );
        assert!(
            RELAYS.read().unwrap()["relay-b"].last_heartbeat.elapsed().as_secs() < 45,
            "heartbeat must refresh the liveness timestamp"
        );
        handle_control_message(
            "relay-b",
            generation,
            r#"{"type":"sessions","data":[{"uuid":"session-1"}]}"#,
        );
        assert_eq!(RELAYS.read().unwrap()["relay-b"].sessions.len(), 1);
        // Stale generations are ignored so old sockets cannot corrupt state.
        handle_control_message(
            "relay-b",
            generation + 1,
            r#"{"type":"sessions","data":[]}"#,
        );
        assert_eq!(RELAYS.read().unwrap()["relay-b"].sessions.len(), 1);
        handle_control_message(
            "relay-b",
            generation,
            r#"{"type":"event","event":{"kind":"session_opened","session":{"uuid":"session-1"}}}"#,
        );
        let event = events.try_recv().expect("relay events join the event bus");
        assert_eq!(event["kind"], "session_opened");
        assert_eq!(event["data"]["relay_id"], "relay-b");
        clear_relays();
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
}
