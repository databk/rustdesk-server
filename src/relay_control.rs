//! Reverse control channel client. When RD_HBBS_API_URL is set, hbbr connects
//! to the hbbs management API over WebSocket, registers itself, reports
//! heartbeats and session events, and receives policy commands (bans,
//! session disconnect, snapshot requests). The connection is outbound-only so
//! hbbr never exposes a management listener for aggregation.
use crate::management;
use hbb_common::futures_util::{sink::SinkExt as _, stream::StreamExt as _};
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
        loop {
            match run(&url, &token).await {
                Ok(()) => log::info!("hbbs control channel closed; reconnecting"),
                Err(err) => log::warn!("hbbs control channel failed: {err}; reconnecting"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
    Ok(())
}

fn relay_identity() -> (String, String) {
    let id = std::env::var("RD_RELAY_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "hbbr".to_owned());
    let address = std::env::var("RD_RELAY_ADDRESS")
        .ok()
        .and_then(|value| (!value.is_empty()).then_some(value))
        .unwrap_or_else(|| id.clone());
    (id, address)
}

async fn run(url: &str, token: &str) -> ResultType<()> {
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    let (id, address) = relay_identity();
    let register = json!({
        "type": "register",
        "relay": {
            "id": id,
            "address": address,
            "version": crate::version::VERSION,
        }
    });
    socket
        .send(Message::Text(register.to_string()))
        .await?;
    let mut events = management::take_control_receiver();
    let started = Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    log::info!("Registered on the hbbs control channel as {id}");
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
                    events = None;
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
                        if let Err(err) = handle_command(&text, &mut socket).await {
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
        _ => {}
    }
    Ok(())
}