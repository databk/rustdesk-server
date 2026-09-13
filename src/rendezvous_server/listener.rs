use super::*;
use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err,
    bail,
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{
        sink::SinkExt,
        stream::StreamExt,
    },
    log,
    rendezvous_proto::*,
    tcp::{Encrypt, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::Mutex,
    },
    tokio_util::codec::Framed,
    try_into_v4,
    ResultType,
};
use sodiumoxide::crypto::{box_, sign};
use std::net::SocketAddr;
use std::sync::Arc;

impl RendezvousServer {
    pub(crate) async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = hbb_common::tcp::FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    /// Perform secure_tcp handshake for non-WS TCP connections.
    /// Returns (encrypt, first_message):
    /// - encrypt: Some if handshake succeeded, None if no server key or fallback
    /// - first_message: Some(bytes) if client sent a non-KeyExchange response (fallback mode)
    async fn secure_tcp_handshake(
        &self,
        framed: &mut Framed<TcpStream, BytesCodec>,
    ) -> ResultType<(Option<Encrypt>, Option<hbb_common::bytes::BytesMut>)> {
        let sign_sk = match &self.inner.sk {
            Some(sk) => sk,
            None => return Ok((None, None)),
        };

        // Generate box_ keypair for this connection
        let (_server_box_pk, server_box_sk) = box_::gen_keypair();

        // Sign the box_ public key with the server's sign secret key
        let signed_pk = sign::sign(_server_box_pk.as_ref(), sign_sk);

        // Send KeyExchange message: only the signed public key
        // Client extracts the box_ public key via sign::verify(&keys[0], &server_pk)
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![signed_pk.into()],
            ..Default::default()
        });
        let bytes = msg_out.write_to_bytes()?;
        framed.send(Bytes::from(bytes)).await?;

        // Receive KeyExchange response from client
        let result = timeout(10_000, framed.next()).await;
        match result {
            Ok(Some(Ok(bytes))) => {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    if let Some(rendezvous_message::Union::KeyExchange(ref ke)) = msg_in.union {
                        if ke.keys.len() >= 2 {
                            // Client sends: keys[0] = client's temporary public key
                            //                keys[1] = encrypted symmetric key
                            let client_box_pk_bytes = &ke.keys[0];
                            let symmetric_data = &ke.keys[1];
                            match Encrypt::decode(symmetric_data, client_box_pk_bytes, &server_box_sk) {
                                Ok(key) => {
                                    log::debug!("secure_tcp handshake completed");
                                    return Ok((Some(Encrypt::new(key)), None));
                                }
                                Err(e) => {
                                    log::error!("secure_tcp handshake decode failed: {}", e);
                                    return Err(e);
                                }
                            }
                        }
                    }
                    // Not a KeyExchange response - client didn't perform secure_tcp handshake.
                    // Log level depends on whether the message type is expected to be plain:
                    // - Always encrypted (RegisterPk, HealthCheck): warn, unexpected
                    // - Conditionally encrypted (PunchHoleRequest, RequestRelay): debug, possible
                    // - Never encrypted (PunchHoleSent, LocalAddr, RelayResponse, etc.): debug, expected
                    match &msg_in.union {
                        Some(rendezvous_message::Union::RegisterPk(_))
                        | Some(rendezvous_message::Union::Hc(_)) => {
                            log::warn!(
                                "Received {:?} without secure_tcp handshake, this message type should always be encrypted",
                                msg_in.union
                            );
                        }
                        _ => {
                            log::debug!(
                                "Client sent non-KeyExchange message, falling back to plain mode"
                            );
                        }
                    }
                    return Ok((None, Some(bytes)));
                }
                // Unparseable message - fall back to no-encryption mode
                log::debug!(
                    "TCP client sent unparseable message during handshake, falling back to plain mode"
                );
                return Ok((None, Some(bytes)));
            }
            Ok(Some(Err(e))) => {
                bail!("secure_tcp handshake failed: {}", e);
            }
            Ok(None) => {
                bail!("secure_tcp handshake failed: connection closed");
            }
            Err(_) => {
                bail!("secure_tcp handshake failed: timeout");
            }
        }
    }

    pub(crate) async fn handle_listener(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let mut forwarded_ip: Option<String> = None;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let forwarded_ip_cell: std::sync::Arc<std::sync::Mutex<Option<String>>> =
                Default::default();
            let forwarded_ip_cb = forwarded_ip_cell.clone();
            let callback = move |req: &Request, response: Response| {
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
                    .and_then(|header_value| header_value.to_str().ok())
                    // X-Forwarded-For can be a comma-separated chain; the
                    // original client is always the first entry.
                    .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
                    .filter(|s| !s.is_empty());
                if let Some(ip) = real_ip {
                    *forwarded_ip_cb.lock().unwrap() = Some(ip);
                }
                Ok(response)
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
            forwarded_ip = forwarded_ip_cell.lock().unwrap().clone();
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            while let Ok(Some(res)) = timeout(30_000, b.next()).await {
                match res {
                    Ok(tungstenite::Message::Binary(bytes)) => {
                        // Handle heartbeat (empty message), mirroring the plain-TCP
                        // branch below. Without this, a client's periodic empty
                        // keep-alive is treated as "unhandled" by handle_tcp(),
                        // which returns false and closes the WS connection.
                        if bytes.is_empty() {
                            if let Some(s) = sink.as_mut() {
                                Self::send_to_sink(s, RendezvousMessage::new()).await;
                            }
                            continue;
                        }
                        if !self
                            .handle_tcp(&bytes, &mut sink, addr, key, ws, forwarded_ip.as_deref())
                            .await
                        {
                            break;
                        }
                    }
                    Ok(tungstenite::Message::Close(_)) => {
                        // Explicit close frame: stop immediately instead of waiting
                        // for the 30s idle timeout to expire.
                        break;
                    }
                    Ok(_) => {
                        // Ping/Pong/Text/Frame: not part of the protocol, ignore
                        // but keep the connection alive (already resets the
                        // 30s timeout since we got here).
                    }
                    Err(err) => {
                        log::debug!("WS read error from {:?}: {}", addr, err);
                        break;
                    }
                }
            }
        } else {
            let mut framed = Framed::new(stream, BytesCodec::new());

            // Try secure_tcp handshake for non-WS TCP connections
            // Falls back to no-encryption mode if client doesn't support it
            let (sink_encrypt, mut recv_encrypt, first_msg) =
                match self.secure_tcp_handshake(&mut framed).await {
                    Ok((Some(encrypt), None)) => (Some(encrypt.clone()), Some(encrypt), None),
                    Ok((None, first_msg)) => (None, None, first_msg),
                    Ok((Some(_), Some(_))) => unreachable!(),
                    Err(e) => {
                        log::debug!("TCP handshake failed for {:?}: {}", addr, e);
                        return Err(e);
                    }
                };

            let (a, mut b) = framed.split();
            sink = Some(Sink::TcpStream(TcpSink {
                inner: a,
                encrypt: sink_encrypt,
            }));

            // Process first message from fallback mode (client sent non-KeyExchange response)
            if let Some(bytes) = first_msg {
                if !bytes.is_empty() {
                    if !self.handle_tcp(&bytes, &mut sink, addr, key, ws, None).await {
                        return Ok(());
                    }
                }
            }

            while let Ok(Some(Ok(bytes))) = timeout(REG_TIMEOUT as u64, b.next()).await {
                // Decrypt if encryption is enabled
                let bytes = if let Some(enc) = recv_encrypt.as_mut() {
                    let mut bytes = bytes;
                    if enc.dec(&mut bytes).is_err() {
                        log::error!("Decryption error from {:?}", addr);
                        break;
                    }
                    bytes
                } else {
                    bytes
                };

                // Handle heartbeat (empty message)
                if bytes.is_empty() {
                    // Update last_reg_time if peer is registered
                    if let Some(s) = sink.as_mut() {
                        Self::send_to_sink(s, RendezvousMessage::new()).await;
                    }
                    continue;
                }

                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws, None).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        // Clean up ws_map on WS connection close
        if ws {
            self.ws_map.lock().await.remove(&try_into_v4(addr));
        } else {
            // Clean up tcp_map on TCP connection close
            self.tcp_map.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }
}