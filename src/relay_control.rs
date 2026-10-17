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
use serde_json::{json, Value};
use std::time::{Duration, Instant};
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
    let url = url.to_owned();
    let token = token.to_owned();
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        // The receiver is taken once for the whole task: run() must not take
        // it again on reconnects, or every later connection would lose the
        // session event feed.
        let mut events = management::take_control_receiver();
        loop {
            match run(&url, &token, &mut events).await {
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
    token: &str,
    events: &mut Option<mpsc::UnboundedReceiver<Value>>,
) -> ResultType<bool> {
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    let (id, address) = relay_identity();
    let mut register = json!({
        "type": "register",
        "relay": {
            "id": id,
            "version": crate::version::VERSION,
        }
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
                let beat = json!({
                    "type": "heartbeat",
                    "uptime_seconds": started.elapsed().as_secs(),
                });
                socket.send(Message::Text(beat.to_string())).await?;
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
        }
        Some("get_sessions") => {
            let snapshot = json!({
                "type": "sessions",
                "data": management::sessions_snapshot(),
            });
            socket.send(Message::Text(snapshot.to_string())).await?;
        }
        Some("disconnect") => {
            if let Some(uuid) = message["uuid"].as_str() {
                management::disconnect_session(uuid);
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
