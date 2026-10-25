//! Private, opt-in management API. Client protocol ports are never used for HTTP.
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Path, Query,
    },
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get},
    Json, Router,
};
use hbb_common::{anyhow::anyhow, log, protobuf::Message as _, relay_control_proto as proto, tokio, ResultType};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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
// Releases a device id from the hbbs registry (in-memory map plus sqlite
// row); bridged in by the owning binary so the shared management API does
// not depend on protocol internals. hbbr never registers one.
pub type PeerReleaser = std::sync::Arc<
    dyn Fn(&str) -> hbb_common::futures::future::BoxFuture<'static, ResultType<bool>> + Send + Sync,
>;
static PEER_RELEASER: Lazy<RwLock<Option<PeerReleaser>>> = Lazy::new(|| RwLock::new(None));

pub fn set_peer_releaser(releaser: PeerReleaser) {
    *PEER_RELEASER.write().unwrap() = Some(releaser);
}
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
    // Most recent host stats reported in the heartbeat (see #1).
    stats: Value,
    // Highest event sequence observed from this relay; used to detect a
    // reconnect gap and request replay (see #15).
    last_event_seq: u64,
    // Most recent ban policy sequence the relay acknowledged (see #9).
    last_bans_seq: u64,
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

// Addresses reported by registered relays (used to merge the live relay list).
pub fn registered_relay_addresses() -> Vec<String> {
    RELAYS
        .read()
        .unwrap()
        .values()
        .filter_map(|relay| relay.address.clone())
        .collect()
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

// ---- protobuf <-> domain helpers for the control channel ----

fn encode(msg: &proto::ControlMessage) -> Vec<u8> {
    let mut v = Vec::new();
    msg.write_to_vec(&mut v).ok();
    v
}

fn bans_to_proto(bans: &Bans) -> proto::Bans {
    proto::Bans {
        device_ids: bans.device_ids.clone(),
        ips: bans.ips.clone(),
        ..Default::default()
    }
}

pub fn bans_from_proto(b: &proto::Bans) -> Bans {
    Bans {
        device_ids: b.device_ids.clone(),
        ips: b.ips.clone(),
    }
}

fn session_from_proto(s: &proto::SessionInfo) -> Value {
    json!({
        "uuid": s.uuid,
        "target_id": s.target_id,
        "peer_target_id": s.peer_target_id,
        "endpoints": s.endpoints,
        "transport": s.transport,
        "started_at": s.started_at,
        "bytes": s.bytes,
        "bytes_per_second": s.bytes_per_second,
        "closing": s.closing,
    })
}

pub fn session_to_proto(info: &Value) -> proto::SessionInfo {
    proto::SessionInfo {
        uuid: info["uuid"].as_str().unwrap_or_default().to_owned(),
        target_id: info["target_id"].as_str().unwrap_or_default().to_owned(),
        peer_target_id: info["peer_target_id"].as_str().unwrap_or_default().to_owned(),
        endpoints: info["endpoints"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        transport: info["transport"].as_str().unwrap_or_default().to_owned(),
        started_at: info["started_at"].as_i64().unwrap_or_default(),
        bytes: info["bytes"].as_u64().unwrap_or_default(),
        bytes_per_second: info["bytes_per_second"].as_u64().unwrap_or_default(),
        closing: info["closing"].as_bool().unwrap_or(false),
        ..Default::default()
    }
}

fn stats_from_proto(s: &proto::HostStats) -> Value {
    let mut v = json!({
        "active_sessions": s.active_sessions,
        "bytes_per_second": s.bytes_per_second,
    });
    if s.cpu_usage >= 0.0 {
        v["cpu_usage"] = json!(s.cpu_usage);
    }
    if s.mem_usage >= 0.0 {
        v["mem_usage"] = json!(s.mem_usage);
    }
    if s.max_sessions > 0 {
        v["max_sessions"] = json!(s.max_sessions);
    }
    v
}

fn relay_command(relay_id: &str, msg: &proto::ControlMessage) -> ResultType<()> {
    let relays = RELAYS.read().unwrap();
    let relay = relays
        .get(relay_id)
        .ok_or_else(|| anyhow!("Unknown relay: {relay_id}"))?;
    relay
        .tx
        .send(Message::Binary(encode(msg)))
        .map_err(|_| anyhow!("Relay control channel is closed"))?;
    Ok(())
}

// Monotonic sequence stamped onto every ban policy fanout so relays can
// acknowledge application and hbbs can track per-relay consistency (see #9).
static BANS_SEQ: AtomicU64 = AtomicU64::new(0);

fn fanout_bans() {
    let seq = BANS_SEQ.load(Ordering::SeqCst);
    let msg = proto::ControlMessage {
        payload: Some(proto::control_message::Payload::Bans(proto::BansUpdate {
            id: seq,
            bans: Some(bans_to_proto(&BANS.read().unwrap())).into(),
            ..Default::default()
        })),
    
        ..Default::default()
    };
    let bytes = encode(&msg);
    for relay in RELAYS.read().unwrap().values() {
        let _ = relay.tx.send(Message::Binary(bytes.clone()));
    }
}

// Pending request-response exchanges with registered relays: hbbs HTTP
// handlers await the completion channel while the relay socket loop resolves
// it from the "response" control message.
struct PendingRelayRequest {
    relay: String,
    responder: oneshot::Sender<proto::ControlResponse>,
}

static RELAY_REQUESTS: Lazy<std::sync::Mutex<HashMap<u64, PendingRelayRequest>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));
static RELAY_REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const RELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

// Sends a command carrying a request id to one relay and awaits the matching
// response, so HTTP handlers can proxy relay-scoped reads and writes. The
// caller supplies a closure that stamps the allocated id onto the message.
async fn relay_request<F>(relay_id: &str, make: F) -> ResultType<proto::ControlResponse>
where
    F: FnOnce(u64) -> proto::ControlMessage,
{
    let (responder, waiter) = oneshot::channel();
    let id = RELAY_REQUEST_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let msg = make(id);
    RELAY_REQUESTS.lock().unwrap().insert(
        id,
        PendingRelayRequest {
            relay: relay_id.to_owned(),
            responder,
        },
    );
    if let Err(err) = relay_command(relay_id, &msg) {
        RELAY_REQUESTS.lock().unwrap().remove(&id);
        return Err(err);
    }
    match tokio::time::timeout(RELAY_REQUEST_TIMEOUT, waiter).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(anyhow!("Relay control channel closed")),
        Err(_) => {
            RELAY_REQUESTS.lock().unwrap().remove(&id);
            Err(anyhow!("Relay did not answer in time"))
        }
    }
}

// Drops the pending exchanges of one relay; awaiting requests fail fast
// instead of waiting for the timeout.
fn cancel_relay_requests(relay_id: &str) {
    RELAY_REQUESTS
        .lock()
        .unwrap()
        .retain(|_, pending| pending.relay != relay_id);
}

// Outbound relay-side events (session lifecycle) consumed by the hbbr control
// client. Only meaningful inside the hbbr binary. Events are enqueued only
// after a consumer has taken the receiver, so a relay without the control
// channel does not accumulate session events forever.
static CONTROL_OUT: Lazy<(
    mpsc::UnboundedSender<proto::ControlMessage>,
    std::sync::Mutex<Option<mpsc::UnboundedReceiver<proto::ControlMessage>>>,
)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (tx, std::sync::Mutex::new(Some(rx)))
});
static CONTROL_CONSUMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Monotonic sequence stamped onto every relay-side event (session_opened /
// session_closed) plus a bounded ring buffer of recent events. On reconnect
// hbbs can ask the relay to replay events hbbs missed by sending replay_events
// with the next expected sequence (see #15).
static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);
static EVENT_BUFFER: Lazy<RwLock<VecDeque<proto::ControlMessage>>> =
    Lazy::new(|| RwLock::new(VecDeque::new()));
const EVENT_BUFFER_CAPACITY: usize = 1024;

// Highest event sequence observed from each relay, kept independently of the
// live RELAYS entry so the cursor survives disconnects (a control socket close
// removes the RELAYS row). Reset to 0 when a relay starts a new sequence epoch
// (reports a last_event_seq below the stored cursor, e.g. after a relay restart).
static RELAY_EVENT_CURSORS: Lazy<RwLock<HashMap<String, u64>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

fn control_emit(event: proto::SessionEvent) {
    if CONTROL_CONSUMED.load(std::sync::atomic::Ordering::Relaxed) {
        // Hold the buffer write lock across sequence assignment, buffering and
        // delivery so concurrent callers cannot assign a later sequence and
        // send it before an earlier one (see #15).
        let mut buffer = EVENT_BUFFER.write().unwrap();
        let seq = EVENT_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
        let mut event = event;
        event.seq = seq;
        let message = proto::ControlMessage {
            payload: Some(proto::control_message::Payload::Event(event)),
        
        ..Default::default()
    };
        buffer.push_back(message.clone());
        while buffer.len() > EVENT_BUFFER_CAPACITY {
            buffer.pop_front();
        }
        let _ = CONTROL_OUT.0.send(message);
    }
}

// Highest event sequence the relay has produced. Sent in register so hbbs can
// detect a gap after reconnect and request replay.
pub fn last_event_seq() -> u64 {
    EVENT_SEQ.load(Ordering::SeqCst)
}

// Returns buffered events with sequence numbers >= from_seq, oldest first.
// If the gap predates the buffer the replay is partial; hbbs learns the
// oldest available sequence from the returned events themselves.
pub fn replay_events_since(from_seq: u64) -> Vec<proto::ControlMessage> {
    EVENT_BUFFER
        .read()
        .unwrap()
        .iter()
        .filter(|msg| match &msg.payload {
            Some(proto::control_message::Payload::Event(ev)) => ev.seq >= from_seq,
            _ => false,
        })
        .cloned()
        .collect()
}

pub fn take_control_receiver() -> Option<mpsc::UnboundedReceiver<proto::ControlMessage>> {
    let receiver = CONTROL_OUT.1.lock().unwrap().take();
    if receiver.is_some() {
        CONTROL_CONSUMED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    receiver
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
    control_emit(proto::SessionEvent {
        kind: proto::session_event::Kind::SESSION_OPENED.into(),
        uuid: uuid.to_owned(),
        session: Some(session_to_proto(&info)).into(),
        ..Default::default()
    });
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
    control_emit(proto::SessionEvent {
        kind: proto::session_event::Kind::SESSION_CLOSED.into(),
        uuid: uuid.to_owned(),
        ..Default::default()
    });
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

// Live configuration view: schema, effective values and the pending restart
// diff. Shared by the HTTP endpoint and the relay control channel.
pub fn config_view(service: &str) -> Value {
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
    json!({"schema":schema(service),"values":managed.values.clone(),
    "pending_restart":pending})
}

async fn config(Extension(state): Extension<ApiState>) -> Json<Value> {
    Json(config_view(state.service))
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpdate {
    pub values: BTreeMap<String, String>,
}

fn definition_of(definitions: &[Value], name: &str) -> Option<Value> {
    definitions
        .iter()
        .find(|d| d["name"].as_str() == Some(name))
        .cloned()
}

fn bad_request(message: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": message}))).into_response()
}

// Validates a submission against the schema without touching any state.
// Returns the first violation as a message so callers can map it to their
// transport (HTTP bad request or a control channel error response).
pub fn validate_update(service: &str, update: &ConfigUpdate) -> Option<String> {
    let definitions = schema(service);
    for (name, value) in &update.values {
        let Some(definition) = definition_of(&definitions, name) else {
            return Some(format!("Unknown managed configuration: {name}"));
        };
        if definition["secret"] == true && value == REDACTED {
            continue;
        }
        if let Err(err) = validate_value(&definition, name, value) {
            return Some(err.to_string());
        }
    }
    None
}

// Validates, persists and activates a managed configuration update. Shared
// by the HTTP handler and the relay control channel (hbbr applies the
// updates forwarded by hbbs). The caller retains the update through
// persistence and activation even if it disconnects while the blocking
// filesystem work is in flight.
pub async fn apply_config_update(
    service: &'static str,
    update: ConfigUpdate,
) -> ResultType<(Map<String, Value>, Map<String, Value>)> {
    let definitions = schema(service);
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
    Ok((applied, pending_report))
}

async fn replace_config(
    Extension(state): Extension<ApiState>,
    Json(update): Json<ConfigUpdate>,
) -> Response {
    if let Some(err) = validate_update(state.service, &update) {
        return bad_request(err);
    }
    let service = state.service;
    // The task owns the update through persistence and activation even if
    // the HTTP caller disconnects while the blocking filesystem work is in
    // flight.
    let result = tokio::spawn(apply_config_update(service, update)).await;
    match result {
        Ok(Ok((applied, pending_report))) => {
            Json(json!({"state":"saved","applied":applied,"pending_restart":pending_report}))
                .into_response()
        }
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

// Recent in-memory log lines. Shared by the HTTP endpoint and the relay
// control channel (hbbs proxies relay log reads over the control channel).
pub fn logs_view(tail: usize) -> Value {
    let tail = tail.min(LOG_CAPACITY);
    let logs = LOGS.read().unwrap();
    let skipped = logs.len().saturating_sub(tail);
    let data: Vec<String> = logs.iter().skip(skipped).cloned().collect();
    json!({"data": data})
}

async fn logs(Query(query): Query<LogsQuery>) -> Response {
    Json(logs_view(query.tail.unwrap_or(200))).into_response()
}

// Ask the supervisor (container restart policy or systemd) to bring the
// service back: flush the response, then exit. Dynamic configuration is
// already active; pending entries take effect on the next startup.
async fn restart() -> Response {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        log::info!("Exiting for restart; the supervisor should bring the service back");
        std::process::exit(0);
    });
    (StatusCode::ACCEPTED, Json(json!({"state":"restarting"}))).into_response()
}

async fn peers(Extension(state): Extension<ApiState>) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({"data":PEERS.read().unwrap().clone()})).into_response()
}

// Releases a device id from the registry: forgets the in-memory entry and
// deletes the persisted row. Without this, a custom id (e.g. a hostname)
// stays bound to the retired machine's uuid and every registration of the
// replacement machine is rejected with UUID_MISMATCH.
async fn delete_peer(Path(id): Path<String>, Extension(state): Extension<ApiState>) -> Response {
    if state.service != "hbbs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let releaser = PEER_RELEASER.read().unwrap().clone();
    let Some(releaser) = releaser else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match releaser(&id).await {
        Ok(deleted) => {
            emit_event("peer_released", json!({"id": id}));
            Json(json!({"deleted": deleted})).into_response()
        }
        Err(err) => {
            log::error!("Unable to release peer {id}: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
                BANS_SEQ.fetch_add(1, Ordering::SeqCst);
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

// Populates the managed state from the schema, deployment arguments and saved
// overrides. Runs during startup for both services: the HTTP listener is
// optional, but the control channel and its proxied management requests need
// the state regardless.
pub fn init_managed_state(service: &'static str, port: u16) -> ResultType<()> {
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
    Ok(())
}

pub fn start(service: &'static str, port: u16) -> ResultType<()> {
    init_managed_state(service, port)?;
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
    let register_bytes = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Binary(bytes)))) => bytes,
        _ => return,
    };
    let message = match proto::ControlMessage::parse_from_bytes(&register_bytes) {
        Ok(msg) => msg,
        Err(_) => return,
    };
    let register = match message.payload {
        Some(proto::control_message::Payload::Register(r)) => r,
        _ => return,
    };
    let relay_id = match valid_relay_text(&register.relay.id, 100) {
        Some(id) => id,
        None => return,
    };
    let address = valid_relay_text(&register.relay.address, 253);
    let version = register.relay.version.clone();
    let info = serde_json::json!({"id": relay_id, "version": version, "address": address});
    let relay_last_event_seq = register.last_event_seq;
    let generation = RELAY_GENERATION.fetch_add(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // Read the observed event cursor from a map that survives control socket
    // disconnects (the RELAYS row is removed on close). If the relay reports a
    // last_event_seq below the stored cursor it has started a new sequence epoch
    // (e.g. after a relay restart), so reset the cursor to 0 and replay nothing.
    let previous_event_seq = {
        let mut cursors = RELAY_EVENT_CURSORS.write().unwrap();
        let stored = cursors.get(&relay_id).copied().unwrap_or(0);
        if relay_last_event_seq < stored {
            cursors.insert(relay_id.clone(), 0);
            0
        } else {
            stored
        }
    };
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
                stats: Value::Null,
                last_event_seq: previous_event_seq,
                last_bans_seq: 0,
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
    let bans_seq = BANS_SEQ.load(Ordering::SeqCst);
    let _ = tx.send(Message::Binary(encode(&proto::ControlMessage {
        payload: Some(proto::control_message::Payload::Bans(proto::BansUpdate {
            id: bans_seq,
            bans: Some(bans_to_proto(&BANS.read().unwrap())).into(),
            ..Default::default()
        })),
    
        ..Default::default()
    })));
    let _ = tx.send(Message::Binary(encode(&proto::ControlMessage {
        payload: Some(proto::control_message::Payload::GetSessions(
            proto::GetSessions::default(),
        )),
    
        ..Default::default()
    })));
    // If the relay produced events hbbs never observed, ask it to replay them
    // so the aggregated event stream stays complete across reconnects (see #15).
    if relay_last_event_seq > previous_event_seq {
        let _ = tx.send(Message::Binary(encode(&proto::ControlMessage {
            payload: Some(proto::control_message::Payload::ReplayEvents(
                proto::ReplayEvents {
                    from_seq: previous_event_seq + 1,
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })));
    }

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(msg) = proto::ControlMessage::parse_from_bytes(&bytes) {
                            handle_control_message(&relay_id, generation, &msg);
                        }
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
    // Drop the write guard before sync_relay_list(): it re-acquires RELAYS
    // for reading, which deadlocks while the write lock is held.
    let mut left = false;
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
            // Pending exchanges die with the connection; waiters fail fast.
            cancel_relay_requests(&relay_id);
            left = true;
        }
    }
    if left {
        sync_relay_list();
    }
}

fn handle_control_message(relay_id: &str, generation: u64, message: &proto::ControlMessage) {
    let mut relays = RELAYS.write().unwrap();
    let Some(relay) = relays.get_mut(relay_id) else {
        return;
    };
    if relay.generation != generation {
        return;
    }
    match &message.payload {
        Some(proto::control_message::Payload::Heartbeat(hb)) => {
            relay.last_heartbeat = Instant::now();
            // Persist the most recent host stats so the relays API can expose
            // load/capacity between heartbeats (see #1).
            if let Some(stats) = hb.stats.as_ref() {
                relay.stats = stats_from_proto(stats);
            }
        }
        Some(proto::control_message::Payload::Sessions(snap)) => {
            relay.sessions = snap.sessions.iter().map(session_from_proto).collect();
        }
        Some(proto::control_message::Payload::Event(ev)) => {
            // Only accept sequenced events that advance the contiguous observed
            // cursor; replayed older events (seq <= cursor) are duplicates.
            // seq == 0 means unsequenced (legacy) and is always accepted.
            let seq = ev.seq;
            let accept = if seq > 0 {
                let cursor = RELAY_EVENT_CURSORS
                    .read()
                    .unwrap()
                    .get(relay_id)
                    .copied()
                    .unwrap_or(0);
                if seq > cursor {
                    RELAY_EVENT_CURSORS
                        .write()
                        .unwrap()
                        .insert(relay_id.to_owned(), seq);
                    relay.last_event_seq = seq;
                    true
                } else {
                    false
                }
            } else {
                true
            };
            if accept {
                let kind_str = match ev.kind.enum_value_or_default() {
                    proto::session_event::Kind::SESSION_OPENED => "session_opened",
                    proto::session_event::Kind::SESSION_CLOSED => "session_closed",
                };
                let mut data = json!({"kind": kind_str, "uuid": ev.uuid, "relay_id": relay_id});
                if let Some(session) = ev.session.as_ref() {
                    data["session"] = session_from_proto(session);
                }
                if kind_str == "session_opened" {
                    relay.last_heartbeat = Instant::now();
                }
                emit_event(kind_str, data);
            }
        }
        Some(proto::control_message::Payload::Response(resp)) => {
            // Complete the pending proxy request awaiting this exchange.
            if let Some(pending) = RELAY_REQUESTS.lock().unwrap().remove(&resp.id) {
                let _ = pending.responder.send(resp.clone());
            }
        }
        Some(proto::control_message::Payload::BanAck(ack)) => {
            // Ban policy acknowledgement: record the applied sequence (see #9).
            relay.last_bans_seq = ack.id;
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
                "stats": relay.stats,
                "last_event_seq": relay.last_event_seq,
                "last_bans_seq": relay.last_bans_seq,
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
    if state.service != "hbbs" || !relay_available(&relay_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Correlate via relay_request so the HTTP client learns whether the
    // relay actually applied the disconnect instead of fire-and-forget (see #9).
    relay_response(
        relay_request(&relay_id, |id| proto::ControlMessage {
            payload: Some(proto::control_message::Payload::Disconnect(
                proto::Disconnect {
                    id,
                    uuid: uuid.clone(),
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })
        .await,
    )
}

fn relay_available(relay_id: &str) -> bool {
    RELAYS.read().unwrap().contains_key(relay_id)
}

// The relay answered with an HTTP-equivalent status and body; forward both so
// the proxy endpoints keep the semantics of the direct ones.
fn relay_response(result: ResultType<proto::ControlResponse>) -> Response {
    match result {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status as u16)
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let body: Value = serde_json::from_slice(&resp.body).unwrap_or_else(|_| json!({}));
            (status, Json(body)).into_response()
        }
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

// Relay-scoped proxies: management clients talk to hbbs only; hbbs forwards
// configuration and log requests to the target relay over the control channel.
async fn relay_config(
    Extension(state): Extension<ApiState>,
    Path(relay_id): Path<String>,
) -> Response {
    if state.service != "hbbs" || !relay_available(&relay_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    relay_response(
        relay_request(&relay_id, |id| proto::ControlMessage {
            payload: Some(proto::control_message::Payload::GetConfig(
                proto::GetConfig {
                    id,
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })
        .await,
    )
}

async fn relay_replace_config(
    Extension(state): Extension<ApiState>,
    Path(relay_id): Path<String>,
    Json(update): Json<ConfigUpdate>,
) -> Response {
    if state.service != "hbbs" || !relay_available(&relay_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    relay_response(
        relay_request(&relay_id, |id| proto::ControlMessage {
            payload: Some(proto::control_message::Payload::SetConfig(
                proto::SetConfig {
                    id,
                    values: update.values.into_iter().collect(),
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })
        .await,
    )
}

async fn relay_logs(
    Extension(state): Extension<ApiState>,
    Path(relay_id): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Response {
    if state.service != "hbbs" || !relay_available(&relay_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let tail = query.tail.unwrap_or(200).min(LOG_CAPACITY);
    relay_response(
        relay_request(&relay_id, |id| proto::ControlMessage {
            payload: Some(proto::control_message::Payload::GetLogs(
                proto::GetLogs {
                    id,
                    tail: tail as u64,
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })
        .await,
    )
}

// Restart is acknowledged before the relay exits: the relay sends the response
// first and then schedules the exit 250ms later, so the correlated exchange
// completes while the control channel is still up (see #9).
async fn relay_restart(
    Extension(state): Extension<ApiState>,
    Path(relay_id): Path<String>,
) -> Response {
    if state.service != "hbbs" || !relay_available(&relay_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    relay_response(
        relay_request(&relay_id, |id| proto::ControlMessage {
            payload: Some(proto::control_message::Payload::Restart(
                proto::Restart {
                    id,
                    ..Default::default()
                },
            )),
        
        ..Default::default()
    })
        .await,
    )
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
        .route("/v1/config", get(config).put(replace_config))
        .route("/v1/logs", get(logs))
        .route("/v1/peers", get(peers))
        .route("/v1/peers/:id", delete(delete_peer))
        .route("/v1/bans", get(bans).put(replace_bans))
        .route("/v1/restart", axum::routing::post(restart))
        .route("/v1/events", get(events))
        .route("/v1/control", get(control))
        .route("/v1/relays", get(relays))
        .route("/v1/relays/:id/sessions", get(relay_sessions))
        .route(
            "/v1/relays/:id/sessions/:uuid",
            axum::routing::delete(relay_disconnect),
        )
        .route(
            "/v1/relays/:id/config",
            get(relay_config).put(relay_replace_config),
        )
        .route("/v1/relays/:id/logs", get(relay_logs))
        .route("/v1/relays/:id/restart", axum::routing::post(relay_restart))
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
    async fn delete_peer_releases_the_id_through_the_bridged_releaser() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let requested = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let releaser: PeerReleaser = {
            let calls = calls.clone();
            let requested = requested.clone();
            Arc::new(move |id: &str| {
                let id = id.to_owned();
                let calls = calls.clone();
                let requested = requested.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    requested.lock().unwrap().push(id.clone());
                    Ok(!id.is_empty())
                })
            })
        };
        set_peer_releaser(releaser);

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
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "DELETE /v1/peers/host-a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"deleted\":true"), "{response}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*requested.lock().unwrap(), vec!["host-a".to_owned()]);

        // Without a bridged releaser the endpoint reports it is unavailable.
        *PEER_RELEASER.write().unwrap() = None;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        task.abort();
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
    fn subscribe_events() -> broadcast::Receiver<Value> {
        EVENTS.subscribe()
    }

    fn register_test_relay(
        relay_id: &str,
        address: Option<&str>,
    ) -> mpsc::UnboundedReceiver<Message> {
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
                stats: Value::Null,
                last_event_seq: 0,
                last_bans_seq: 0,
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
        let Message::Binary(bytes) = message else {
            panic!("expected a binary message");
        };
        let payload = proto::ControlMessage::parse_from_bytes(&bytes).unwrap();
        let bans = match payload.payload {
            Some(proto::control_message::Payload::Bans(b)) => b,
            _ => panic!("expected a bans update"),
        };
        assert_eq!(
            bans.bans.as_ref().unwrap().device_ids[0],
            "fanout-device"
        );
        clear_relays();
        drop(fixture);
    }

    #[test]
    fn control_events_are_enqueued_only_after_a_consumer_takes_the_receiver() {
        let _test = POLICY_TEST.lock().unwrap();
        // Events emitted before any consumer registered are dropped instead
        // of piling up in the unbounded channel.
        control_emit(proto::SessionEvent {
            kind: proto::session_event::Kind::SESSION_OPENED.into(),
            uuid: "dropped".to_owned(),
            ..Default::default()
        });
        let mut receiver = take_control_receiver().expect("first take returns the receiver");
        assert!(
            receiver.try_recv().is_err(),
            "events without a consumer must be dropped"
        );
        control_emit(proto::SessionEvent {
            kind: proto::session_event::Kind::SESSION_OPENED.into(),
            uuid: "kept-2".to_owned(),
            ..Default::default()
        });
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            Some(proto::control_message::Payload::Event(_))
        ));
        assert!(
            take_control_receiver().is_none(),
            "the receiver is handed out exactly once"
        );
        control_emit(proto::SessionEvent {
            kind: proto::session_event::Kind::SESSION_OPENED.into(),
            uuid: "kept-3".to_owned(),
            ..Default::default()
        });
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            Some(proto::control_message::Payload::Event(_))
        ));
    }

    #[test]
    fn control_messages_update_heartbeat_sessions_and_forward_events() {
        let _test = POLICY_TEST.lock().unwrap();
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
                last_heartbeat: Instant::now() - Duration::from_secs(120),
                sessions: Vec::new(),
                stats: Value::Null,
                last_event_seq: 0,
                last_bans_seq: 0,
                tx,
            },
        );
        let mut events = subscribe_events();
        handle_control_message(
            "relay-b",
            generation,
            &proto::ControlMessage {
                payload: Some(proto::control_message::Payload::Heartbeat(
                    proto::Heartbeat::default(),
                )),
                ..Default::default()
            },
        );
        assert!(
            RELAYS.read().unwrap()["relay-b"]
                .last_heartbeat
                .elapsed()
                .as_secs()
                < 45,
            "heartbeat must refresh the liveness timestamp"
        );
        handle_control_message(
            "relay-b",
            generation,
            &proto::ControlMessage {
                payload: Some(proto::control_message::Payload::Sessions(
                    proto::SessionsSnapshot {
                        sessions: vec![proto::SessionInfo {
                            uuid: "session-1".to_owned(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        );
        assert_eq!(RELAYS.read().unwrap()["relay-b"].sessions.len(), 1);
        // Stale generations are ignored so old sockets cannot corrupt state.
        handle_control_message(
            "relay-b",
            generation + 1,
            &proto::ControlMessage {
                payload: Some(proto::control_message::Payload::Sessions(
                    proto::SessionsSnapshot::default(),
                )),
                ..Default::default()
            },
        );
        assert_eq!(RELAYS.read().unwrap()["relay-b"].sessions.len(), 1);
        handle_control_message(
            "relay-b",
            generation,
            &proto::ControlMessage {
                payload: Some(proto::control_message::Payload::Event(proto::SessionEvent {
                    kind: proto::session_event::Kind::SESSION_OPENED.into(),
                    uuid: "session-1".to_owned(),
                    session: Some(proto::SessionInfo {
                        uuid: "session-1".to_owned(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })),
                ..Default::default()
            },
        );
        // The event bus is shared; wait for our own event instead of
        // assuming it is the next one on the channel.
        let mut event = None;
        for _ in 0..100 {
            match events.try_recv() {
                Ok(candidate) if candidate["data"]["relay_id"] == "relay-b" => {
                    event = Some(candidate);
                    break;
                }
                Ok(_) => continue,
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        let event = event.expect("relay events join the event bus");
        assert_eq!(event["kind"], "session_opened");
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
        let persisted: ManagedConfig =
            serde_json::from_slice(&std::fs::read(data_path("hbbr", "config")).unwrap()).unwrap();
        assert_eq!(
            persisted.values,
            managed_values(&[("limit-speed", "64"), ("port", "21118")])
        );
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
        let persisted: ManagedConfig =
            serde_json::from_slice(&std::fs::read(data_path("hbbr", "config")).unwrap()).unwrap();
        assert_eq!(persisted.values.get("key").unwrap(), "replacement-secret");
        // Resubmitting the placeholder keeps the stored secret untouched.
        let response = replace_config(
            Extension(ConfigFixture::state("hbbr")),
            Json(ConfigUpdate {
                values: managed_values(&[("key", REDACTED), ("port", "21117")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let persisted: ManagedConfig =
            serde_json::from_slice(&std::fs::read(data_path("hbbr", "config")).unwrap()).unwrap();
        assert_eq!(persisted.values.get("key").unwrap(), "replacement-secret");
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
    #[tokio::test]
    async fn relay_requests_proxy_config_logs_and_restart() {
        let _test = POLICY_TEST.lock().unwrap();
        let _fixture = ConfigFixture::new();
        clear_relays();
        let state = ConfigFixture::state("hbbs");
        // Unknown relays are reported as missing.
        let missing = relay_config(Extension(state.clone()), Path("missing".to_owned())).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let mut receiver = register_test_relay("relay-c", None);
        let generation = RELAYS.read().unwrap()["relay-c"].generation;
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<String>();
        // A background task plays the relay: every command is answered with
        // an HTTP-equivalent status and body through the control socket loop.
        let responder = tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                let Message::Binary(bytes) = message else {
                    continue;
                };
                let payload = proto::ControlMessage::parse_from_bytes(&bytes).unwrap();
                let (kind, id) = match &payload.payload {
                    Some(proto::control_message::Payload::GetConfig(g)) => ("get_config", g.id),
                    Some(proto::control_message::Payload::GetLogs(gl)) => ("get_logs", gl.id),
                    Some(proto::control_message::Payload::SetConfig(sc)) => ("set_config", sc.id),
                    Some(proto::control_message::Payload::Restart(r)) => ("restart", r.id),
                    Some(proto::control_message::Payload::Disconnect(d)) => ("disconnect", d.id),
                    _ => continue,
                };
                let _ = seen_tx.send(kind.to_owned());
                let (status, body) = match kind {
                    "get_config" => (200u32, json!({"values":{"limit-speed":"64"}})),
                    "get_logs" => (200, json!({"data":["relay-log-line"]})),
                    "set_config" => (400, json!({"error":"invalid value"})),
                    "restart" => (202, json!({"state":"restarting"})),
                    "disconnect" => (200, json!({"applied":true})),
                    _ => (200, json!({})),
                };
                let response = proto::ControlMessage {
                    payload: Some(proto::control_message::Payload::Response(
                        proto::ControlResponse {
                            id,
                            status,
                            body: serde_json::to_vec(&body).unwrap().into(),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                };
                if kind == "restart" {
                    // The relay acknowledges restart before exiting.
                    handle_control_message("relay-c", generation, &response);
                    break;
                }
                handle_control_message("relay-c", generation, &response);
            }
        });
        let response = relay_config(Extension(state.clone()), Path("relay-c".to_owned())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        assert_eq!(body["values"]["limit-speed"], "64");
        let response = relay_logs(
            Extension(state.clone()),
            Path("relay-c".to_owned()),
            Query(LogsQuery { tail: Some(5) }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        assert_eq!(body["data"][0], "relay-log-line");
        // Relay-reported statuses flow through (e.g. validation errors).
        let response = relay_replace_config(
            Extension(state.clone()),
            Path("relay-c".to_owned()),
            Json(ConfigUpdate {
                values: managed_values(&[("limit-speed", "64")]),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value =
            serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
                .unwrap();
        assert_eq!(body["error"], "invalid value");
        // Restart is acknowledged with 202 before the relay exits.
        let response = relay_restart(Extension(state.clone()), Path("relay-c".to_owned())).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        for expected in ["get_config", "get_logs", "set_config", "restart"] {
            assert_eq!(seen_rx.recv().await.unwrap(), expected);
        }
        responder.abort();
        clear_relays();
    }

    #[test]
    fn cancelling_relay_requests_releases_waiters() {
        let (responder, waiter) = oneshot::channel();
        RELAY_REQUESTS.lock().unwrap().insert(
            987_654,
            PendingRelayRequest {
                relay: "relay-y".to_owned(),
                responder,
            },
        );
        cancel_relay_requests("relay-y");
        assert!(waiter.blocking_recv().is_err());
    }

}
