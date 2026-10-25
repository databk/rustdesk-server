//! Reverse control channel client. When RD_HBBS_API_URL is set, hbbr connects
//! to the hbbs management API over WebSocket, registers itself, reports
//! heartbeats and session events, receives policy commands (bans, session
//! disconnect, snapshot requests) and answers proxied management requests
//! (configuration reads and writes, log reads, restart). The connection is
//! outbound-only so hbbr never exposes a management listener for aggregation.
use crate::management;
use hbb_common::futures_util::{sink::SinkExt as _, stream::StreamExt as _};
use hbb_common::tokio::sync::mpsc;
use hbb_common::{anyhow::anyhow, log, tokio, ResultType};
use reqwest::Url;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

type ControlSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub fn start(url: &str, token: &str) -> ResultType<()> {
    if token.len() < 32 {
        return Err(anyhow!(
            "RD_MANAGEMENT_TOKEN must contain at least 32 characters"
        ));
    }
    let url = normalize_control_url(url)?;
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| anyhow!("RD_MANAGEMENT_TOKEN must be a valid Bearer header value"))?;
    authorization.set_sensitive(true);
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        // The receiver is taken once for the whole task: run() must not take
        // it again on reconnects, or every later connection would lose the
        // session event feed.
        let mut events = management::take_control_receiver();
        loop {
            match run(&url, &authorization, &mut events).await {
                Ok(registered) => {
                    if registered {
                        // A healthy connection just ended; retry promptly
                        // instead of keeping the accumulated backoff.
                        backoff = Duration::from_secs(1);
                    }
                    log::info!("hbbs control channel closed; reconnecting")
                }
                Err(err) => log::warn!("hbbs control channel failed: {err}; reconnecting"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
    Ok(())
}

fn normalize_control_url(value: &str) -> ResultType<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("RD_HBBS_API_URL must contain a host"));
    }
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("ws://{value}")
    };
    // Reject an explicitly empty port such as "ws://hbbs:" or "ws://[::1]:/p"
    // before the parser silently drops it and falls back to the scheme default.
    let authority = candidate
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or("");
    if authority.ends_with(':') {
        return Err(anyhow!("RD_HBBS_API_URL must not specify an empty port"));
    }
    // Configuration must not be silently repaired by the URL parser (for
    // example, by dropping embedded newlines or accepting extra slashes).
    let malformed = Cell::new(false);
    let on_violation = |_| malformed.set(true);
    let mut url = Url::options()
        .syntax_violation_callback(Some(&on_violation))
        .parse(&candidate)
        .map_err(|err| anyhow!("RD_HBBS_API_URL is invalid: {err}"))?;
    // Port 0 is syntactically valid but unusable as a connect destination.
    if url.port() == Some(0) {
        return Err(anyhow!("RD_HBBS_API_URL must not use port 0"));
    }
    let scheme = match url.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        _ => {
            return Err(anyhow!("RD_HBBS_API_URL must use http, https, ws or wss"));
        }
    };
    if url.host_str().is_none() {
        return Err(anyhow!("RD_HBBS_API_URL must contain a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("RD_HBBS_API_URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "RD_HBBS_API_URL must not contain a query or fragment"
        ));
    }
    if malformed.get() {
        return Err(anyhow!("RD_HBBS_API_URL has invalid URL syntax"));
    }
    url.set_scheme(scheme)
        .map_err(|_| anyhow!("RD_HBBS_API_URL has an invalid scheme"))?;
    let path = url.path().trim_end_matches('/');
    let path = if path.is_empty() {
        "/v1/control".to_owned()
    } else {
        path.to_owned()
    };
    url.set_path(&path);
    // Validate the WebSocket request before spawning the reconnect loop.
    url.as_str()
        .into_client_request()
        .map_err(|_| anyhow!("RD_HBBS_API_URL is not a valid WebSocket URL"))?;
    Ok(url.into())
}

// Optional capacity cap advertised in heartbeats so hbbs can avoid selecting a
// relay that is already at its limit. Unset means "no configured limit".
fn max_sessions() -> Option<u64> {
    std::env::var("RD_MAX_SESSIONS")
        .ok()
        .and_then(|value| value.parse().ok())
}

// Lightweight host stats for heartbeat reporting. Reads /proc on Linux and
// degrades gracefully (returns None) on other platforms, so no new dependency
// is required and the relay stays cross-platform.
#[cfg(target_os = "linux")]
mod sys_stats {
    use std::sync::Mutex;

    static LAST_CPU: Mutex<Option<(u64, u64)>> = Mutex::new(None);

    pub fn cpu_usage() -> Option<f32> {
        let contents = std::fs::read_to_string("/proc/stat").ok()?;
        let first = contents.lines().next()?;
        let mut fields = first.split_whitespace();
        if fields.next()? != "cpu" {
            return None;
        }
        let nums: Vec<u64> = fields.filter_map(|s| s.parse().ok()).collect();
        if nums.len() < 4 {
            return None;
        }
        let idle = nums[3];
        let total: u64 = nums.iter().sum();
        let mut last = LAST_CPU.lock().ok()?;
        let usage = match *last {
            Some((prev_idle, prev_total)) => {
                let d_idle = idle.saturating_sub(prev_idle);
                let d_total = total.saturating_sub(prev_total);
                if d_total > 0 {
                    Some(((d_total - d_idle) as f32 / d_total as f32) * 100.0)
                } else {
                    None
                }
            }
            None => None,
        };
        *last = Some((idle, total));
        usage
    }

    pub fn mem_usage() -> Option<f32> {
        let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut total: Option<u64> = None;
        let mut available: Option<u64> = None;
        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            let key = parts.next()?;
            let value: u64 = parts.next().and_then(|v| v.parse().ok())?;
            match key {
                "MemTotal:" => total = Some(value),
                "MemAvailable:" => available = Some(value),
                _ => {}
            }
        }
        let (total, available) = (total?, available?);
        if total > 0 {
            Some(((total.saturating_sub(available)) as f32 / total as f32) * 100.0)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sys_stats {
    pub fn cpu_usage() -> Option<f32> {
        None
    }
    pub fn mem_usage() -> Option<f32> {
        None
    }
}

// The relay id identifies the node; the advertised address is optional.
// Without RD_RELAY_ADDRESS no address is reported: the id (often a container
// hostname) is not resolvable by clients and must not be broadcast as a relay
// server address.
fn relay_identity() -> (String, Option<String>) {
    let id = std::env::var("RD_RELAY_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "hbbr".to_owned());
    let address = std::env::var("RD_RELAY_ADDRESS")
        .ok()
        .and_then(|value| (!value.is_empty()).then_some(value));
    (id, address)
}

// Returns Ok(true) when the connection had registered successfully before it
// ended, which lets the caller reset its reconnect backoff.
async fn run(
    url: &str,
    authorization: &HeaderValue,
    events: &mut Option<mpsc::UnboundedReceiver<Value>>,
) -> ResultType<bool> {
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", authorization.clone());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    let (id, address) = relay_identity();
    let mut register = json!({
        "type": "register",
        "relay": {
            "id": id,
            "version": crate::version::VERSION,
        },
        // Tell hbbs the highest event sequence the relay has produced so a
        // reconnect can request replay of anything hbbs missed (see #15).
        "last_event_seq": management::last_event_seq(),
    });
    if let Some(address) = &address {
        register["relay"]["address"] = json!(address);
    }
    socket.send(Message::Text(register.to_string())).await?;
    log::info!("Registered on the hbbs control channel as {id}");
    // Any outcome from here happened after a successful registration, so the
    // caller resets its backoff even when the loop below fails.
    run_registered(&mut socket, events).await.map(|_| true)
}

async fn run_registered(
    socket: &mut ControlSocket,
    events: &mut Option<mpsc::UnboundedReceiver<Value>>,
) -> ResultType<()> {
    let started = Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                // Traffic counters only change inside hbbr; without a periodic
                // snapshot hbbs keeps the values from session_opened (0 bytes).
                let sessions = management::sessions_snapshot();
                let bytes_per_second: u64 = sessions
                    .iter()
                    .filter_map(|s| s["bytes_per_second"].as_u64())
                    .sum();
                let mut stats = json!({
                    "cpu_usage": sys_stats::cpu_usage(),
                    "mem_usage": sys_stats::mem_usage(),
                    "active_sessions": sessions.len() as u64,
                    "bytes_per_second": bytes_per_second,
                });
                if let Some(max) = max_sessions() {
                    stats["max_sessions"] = json!(max);
                }
                let beat = json!({
                    "type": "heartbeat",
                    "uptime_seconds": started.elapsed().as_secs(),
                    "stats": stats,
                });
                socket.send(Message::Text(beat.to_string())).await?;
                if !sessions.is_empty() {
                    let snapshot = json!({
                        "type": "sessions",
                        "data": sessions,
                    });
                    socket.send(Message::Text(snapshot.to_string())).await?;
                }
            }
            event = async {
                match events.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(event) = event else {
                    // The management module dropped its sender; nothing more to forward.
                    *events = None;
                    continue;
                };
                socket
                    .send(Message::Text(event.to_string()))
                    .await?;
                // Session lifecycle events are followed by a full snapshot so
                // the aggregating side stays consistent without polling.
                if event["event"]["kind"].as_str().is_some_and(|kind| {
                    kind == "session_opened" || kind == "session_closed"
                }) {
                    let snapshot = json!({
                        "type": "sessions",
                        "data": management::sessions_snapshot(),
                    });
                    socket.send(Message::Text(snapshot.to_string())).await?;
                }
            }
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(err) = handle_command(&text, socket).await {
                            log::warn!("hbbs control command failed: {err}");
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return Ok(()),
                }
            }
        }
    }
}

async fn handle_command(text: &str, socket: &mut ControlSocket) -> ResultType<()> {
    let message: Value = serde_json::from_str(text)?;
    let id = message["id"].clone();
    match message["type"].as_str() {
        Some("bans") => {
            let bans: management::Bans = serde_json::from_value(message["bans"].clone())?;
            // The aggregating hbbs owns the policy; relay-side persistence keeps
            // the policy active across relay restarts even if hbbs is down.
            management::apply_bans_update("hbbr", bans).await?;
            // Acknowledge so hbbs can track which relays have applied the
            // current policy sequence (see #9).
            if !id.is_null() {
                respond(socket, &id, 200, json!({"applied": true})).await?;
            }
        }
        Some("get_sessions") => {
            let snapshot = json!({
                "type": "sessions",
                "data": management::sessions_snapshot(),
            });
            socket.send(Message::Text(snapshot.to_string())).await?;
        }
        Some("disconnect") => {
            let applied = if let Some(uuid) = message["uuid"].as_str() {
                management::disconnect_session(uuid)
            } else {
                false
            };
            // Acknowledge correlated disconnect requests so hbbs HTTP handlers
            // can confirm execution instead of fire-and-forget (see #9).
            if !id.is_null() {
                respond(socket, &id, 200, json!({"applied": applied})).await?;
            }
        }
        Some("replay_events") => {
            // hbbs asks the relay to re-send events hbbs missed during a
            // reconnect gap; each replayed event keeps its original seq (see #15).
            let from_seq = message["from_seq"].as_u64().unwrap_or(0);
            for event in management::replay_events_since(from_seq) {
                socket.send(Message::Text(event.to_string())).await?;
            }
            if !id.is_null() {
                respond(socket, &id, 200, json!({"replayed": true})).await?;
            }
        }
        // The remaining commands are proxied management requests: hbbs
        // forwards relay-scoped reads and writes and awaits the matching
        // response, so each command answers with an HTTP-equivalent status
        // and body.
        Some("get_config") => {
            respond(socket, &id, 200, management::config_view("hbbr")).await?;
        }
        Some("set_config") => {
            let update = match serde_json::from_value::<management::ConfigUpdate>(json!({
                "values": message["values"].clone()
            })) {
                Ok(update) => update,
                Err(err) => {
                    respond(socket, &id, 400, json!({"error": err.to_string()})).await?;
                    return Ok(());
                }
            };
            if let Some(err) = management::validate_update("hbbr", &update) {
                respond(socket, &id, 400, json!({"error": err})).await?;
                return Ok(());
            }
            match management::apply_config_update("hbbr", update).await {
                Ok((applied, pending_restart)) => {
                    respond(
                        socket,
                        &id,
                        200,
                        json!({"state":"saved","applied":applied,"pending_restart":pending_restart}),
                    )
                    .await?;
                }
                Err(err) => {
                    log::error!("Unable to persist managed configuration: {err}");
                    respond(socket, &id, 500, json!({"error": err.to_string()})).await?;
                }
            }
        }
        Some("get_logs") => {
            let tail = message["tail"]
                .as_u64()
                .unwrap_or(200)
                .min(management::LOG_CAPACITY as u64) as usize;
            respond(socket, &id, 200, management::logs_view(tail)).await?;
        }
        Some("restart") => {
            respond(socket, &id, 202, json!({"state":"restarting"})).await?;
            schedule_restart();
        }
        _ => {}
    }
    Ok(())
}

// Answers a proxied request on the same control socket; hbbs correlates the
// exchange by request id and forwards the status and body to its client.
async fn respond(
    socket: &mut ControlSocket,
    id: &Value,
    status: u16,
    body: Value,
) -> ResultType<()> {
    let response = json!({
        "type": "response",
        "id": id,
        "status": status,
        "body": body,
    });
    socket.send(Message::Text(response.to_string())).await?;
    Ok(())
}

// Exits after the acknowledgement is flushed; the supervisor (container
// restart policy or systemd) brings the relay back with the persisted
// configuration and pending-restart entries applied.
fn schedule_restart() {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        log::info!("Exiting for restart; the supervisor should bring the relay back");
        std::process::exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    const TOKEN: &str = "relay-control-test-token-32-characters";

    #[test]
    fn normalizes_control_url_inputs() {
        for (input, expected) in [
            ("http://hbbs:21120", "ws://hbbs:21120/v1/control"),
            ("http://hbbs:21120/", "ws://hbbs:21120/v1/control"),
            ("https://example.com", "wss://example.com/v1/control"),
            ("ws://hbbs:21120", "ws://hbbs:21120/v1/control"),
            ("wss://example.com/", "wss://example.com/v1/control"),
            ("hbbs:21120", "ws://hbbs:21120/v1/control"),
            ("hbbs", "ws://hbbs/v1/control"),
            ("127.0.0.1:21120", "ws://127.0.0.1:21120/v1/control"),
            ("[::1]:21120", "ws://[::1]:21120/v1/control"),
            ("http://[::1]:21120", "ws://[::1]:21120/v1/control"),
            ("https://[2001:db8::1]", "wss://[2001:db8::1]/v1/control"),
            ("  \nhttp://hbbs:21120/\t ", "ws://hbbs:21120/v1/control"),
            ("ws://hbbs:21120/v1/control", "ws://hbbs:21120/v1/control"),
            (
                "https://example.com/proxy/v1/control///",
                "wss://example.com/proxy/v1/control",
            ),
            (
                "hbbs:21120/custom/control/",
                "ws://hbbs:21120/custom/control",
            ),
            (
                "ws://hbbs:21120/proxy%2Fcontrol/",
                "ws://hbbs:21120/proxy%2Fcontrol",
            ),
            ("HTTP://HBBS:21120", "ws://hbbs:21120/v1/control"),
            ("http://hbbs:80", "ws://hbbs/v1/control"),
            ("https://hbbs:443/", "wss://hbbs/v1/control"),
            ("ws://hbbs:65535", "ws://hbbs:65535/v1/control"),
        ] {
            assert_eq!(normalize_control_url(input).unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn invalid_configuration_fails_before_spawning() {
        // No Tokio runtime is present: trying to spawn for these inputs would
        // panic instead of returning the required configuration error.
        for input in [
            "",
            "   ",
            "http://",
            "ws://:21120",
            "http:///hbbs:21120",
            "//hbbs:21120",
            "ftp://hbbs:21120",
            "file:///tmp/hbbs",
            "hbbs:not-a-port",
            "ws://hbbs:65536",
            "ws://hbbs:-1",
            "ws://hbbs:0",
            "ws://hbbs:",
            "ws://[::1]:",
            "ws://[::1]:/v1/control",
            "ws://[:::1]:21120",
            "::1:21120",
            "ws://user:private-password@hbbs:21120",
            "ws://@hbbs:21120",
            "ws://hbbs:21120?token=private-token",
            "ws://hbbs:21120/?",
            "ws://hbbs:21120/#private-token",
            "ws://hbbs:21120/#",
            "ws://hb\nbs:21120",
            "ws://hbbs:21120/a b",
            "ws://hbbs:21120/a%zz",
            "ws://hbbs:21120\\v1\\control",
        ] {
            let error = start(input, TOKEN).unwrap_err().to_string();
            assert!(error.contains("RD_HBBS_API_URL"), "{input:?}: {error}");
            assert!(!error.contains("private-password"));
            assert!(!error.contains("private-token"));
            assert!(!error.contains(TOKEN));
        }
    }

    #[test]
    fn invalid_token_fails_before_spawning() {
        for token in ["short".to_owned(), format!("{TOKEN}\r\nX-Header: secret")] {
            let error = start("http://hbbs:21120", &token).unwrap_err().to_string();
            assert!(error.contains("RD_MANAGEMENT_TOKEN"));
            assert!(!error.contains(&token));
            assert!(!error.contains("secret"));
        }
    }

    #[tokio::test]
    async fn normalized_http_url_registers_over_websocket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &Request, response: Response| {
                    assert_eq!(request.uri().path(), "/v1/control");
                    assert_eq!(
                        request.headers()["authorization"],
                        format!("Bearer {TOKEN}")
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            let registration = socket.next().await.unwrap().unwrap().into_text().unwrap();
            let registration: Value = serde_json::from_str(&registration).unwrap();
            assert_eq!(registration["type"], "register");
            assert!(registration["relay"]["id"].is_string());
            let heartbeat = socket.next().await.unwrap().unwrap().into_text().unwrap();
            let heartbeat: Value = serde_json::from_str(&heartbeat).unwrap();
            assert_eq!(heartbeat["type"], "heartbeat");
            socket.close(None).await.unwrap();
            while let Some(message) = socket.next().await {
                if message.unwrap().is_close() {
                    break;
                }
            }
        });
        let url = normalize_control_url(&format!("http://{address}")).unwrap();
        let authorization = HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap();
        let mut events = None;
        let registered = tokio::time::timeout(
            Duration::from_secs(5),
            run(&url, &authorization, &mut events),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(registered);
        server.await.unwrap();
    }
}
