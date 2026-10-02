use super::*;
use async_speed_limit::Limiter;
use hbb_common::{
    allow_err, bail,
    bytes::Bytes,
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{interval, Duration},
    },
    ResultType,
};
use std::{net::SocketAddr, sync::atomic::Ordering};

pub(crate) async fn io_loop(
    listener: TcpListener,
    listener2: TcpListener,
    listener_console: Option<TcpListener>,
    key: &str,
) {
    command::check_params();
    let limiter = <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = crate::common::accept_or_pending(listener_console.as_ref()) => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("console listener.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    limiter: &Limiter,
    key: &str,
    ws: bool,
) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = command::check_cmd(data, limiter).await;
                    stream.write(res.as_bytes()).await.ok();
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    if crate::management::is_banned("", &ip) {
        return;
    }
    if BLOCKLIST.read().await.get(&ip).is_some() {
        log::info!("{} blocked", ip);
        return;
    }
    let key = key.to_owned();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, &key, limiter, ws).await);
    });
}

async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    let socket_ip = addr.ip().to_string();
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let callback = |req: &Request, response: Response| {
            let headers = req.headers();
            // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
            // client IP is preserved when the WebSocket port runs behind a
            // reverse proxy (WSS). They are NOT validated: anyone who can reach
            // this port directly can spoof an arbitrary IP, bypassing IP-based
            // rate limiting / blocking and corrupting logged IPs. Do not expose
            // the WebSocket port directly to untrusted networks; only the
            // reverse proxy, which overwrites these headers, should be able to
            // connect to it.
            // https://github.com/rustdesk/rustdesk-server/issues/634
            let real_ip = headers
                .get("X-Real-IP")
                .or_else(|| headers.get("X-Forwarded-For"))
                .and_then(|header_value| header_value.to_str().ok());
            if let Some(ip) = real_ip {
                if ip.contains('.') {
                    addr = format!("{ip}:0").parse().unwrap_or(addr);
                } else {
                    addr = format!("[{ip}]:0").parse().unwrap_or(addr);
                }
            }
            Ok(response)
        };
        let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
        make_pair_(ws_stream, addr, key, limiter, socket_ip).await;
    } else {
        make_pair_(
            FramedStream::from(stream, addr),
            addr,
            key,
            limiter,
            socket_ip,
        )
        .await;
    }
    Ok(())
}

async fn make_pair_(
    stream: impl super::stream::StreamTrait,
    addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    socket_ip: String,
) {
    let mut stream = stream;
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !key.is_empty() && rf.licence_key != key {
                    log::warn!("Relay authentication failed from {} - invalid key", addr);
                    return;
                }
                if !rf.uuid.is_empty()
                    && rf.uuid.len() <= 128
                    && !crate::management::is_banned(&rf.id, &addr.ip().to_string())
                {
                    let mut peers = PEERS.lock().await;
                    let mut pending = match peers.remove(&rf.uuid) {
                        Some(pending) => pending,
                        None => {
                            let generation = uuid::Uuid::new_v4().to_string();
                            peers.insert(
                                rf.uuid.clone(),
                                PendingPeer {
                                    stream: Box::new(stream),
                                    address: addr,
                                    target_id: rf.id,
                                    socket_ip,
                                    generation: generation.clone(),
                                },
                            );
                            drop(peers);
                            sleep(30.).await;
                            let mut peers = PEERS.lock().await;
                            if peers.get(&rf.uuid).map(|p| &p.generation) == Some(&generation) {
                                peers.remove(&rf.uuid);
                            }
                            return;
                        }
                    };
                    drop(peers);
                    let peer = &mut pending.stream;
                    let info = serde_json::json!({"uuid":rf.uuid,"target_id":rf.id,
                        "peer_target_id":pending.target_id,"endpoints":[pending.address.to_string(),addr.to_string()],
                        "transport":if stream.is_ws() || peer.is_ws() {"websocket"} else {"tcp"},
                        "started_at":crate::common::now(),"bytes":0,"bytes_per_second":0,"closing":false});
                    let cancel = crate::management::open_session(
                        &rf.uuid,
                        vec![rf.id.clone(), pending.target_id.clone()],
                        vec![
                            addr.ip().to_string(),
                            pending.address.ip().to_string(),
                            socket_ip,
                            pending.socket_ip.clone(),
                        ],
                        info,
                    );
                    let mut cancel = match cancel {
                        Some(cancel) => cancel,
                        None => return,
                    };
                    let id = format!("{}:{}", addr.ip(), addr.port());
                    USAGE.write().await.insert(id.clone(), Default::default());
                    if !stream.is_ws() && !peer.is_ws() {
                        peer.set_raw();
                        stream.set_raw();
                    }
                    let result = tokio::select! {
                        result = relay(addr, &mut stream, peer, limiter, id.clone(), &rf.uuid, pending.address) => result,
                        _ = &mut cancel => Ok(()),
                    };
                    if let Err(err) = result {
                        log::info!("Relay {} closed: {}", rf.uuid, err);
                    }
                    crate::management::close_session(&rf.uuid);
                    USAGE.write().await.remove(&id);
                }
            }
        }
    }
}

async fn relay(
    addr: SocketAddr,
    stream: &mut impl super::stream::StreamTrait,
    peer: &mut Box<dyn super::stream::StreamTrait>,
    total_limiter: Limiter,
    id: String,
    session_uuid: &str,
    peer_address: SocketAddr,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    let peer_ip = peer_address.ip().to_string();
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let limiter = <Limiter>::new(sb);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as _);
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100. / 1000.) as usize; // in bit/ms
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            if BLOCKLIST.read().await.get(&ip).is_some()
                || BLOCKLIST.read().await.get(&peer_ip).is_some()
            {
                log::info!("{} blocked", ip);
                break;
            }
            blacked = BLACKLIST.read().await.get(&ip).is_some();
            tm = std::time::Instant::now();
            let speed = total_s / n;
            crate::management::update_session(session_uuid, total / 8, total_s * 1000 / n / 8);
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total > elapsed * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}
