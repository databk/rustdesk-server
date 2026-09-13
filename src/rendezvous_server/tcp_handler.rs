use super::*;
use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err,
    bytes::BytesMut,
    log,
    protobuf::MessageField,
    rendezvous_proto::*,
    try_into_v4,
    AddrMangle,
    ResultType,
};
use hbb_common::tokio::sync::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

impl RendezvousServer {
    #[inline]
    pub(crate) async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        forwarded_ip: Option<&str>,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        // Check if target is a WS/TCP peer with persistent connection
                        let addr_v4 = try_into_v4(peer_addr);
                        let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
                        if let Some(sink_arc) = sink_arc {
                            let mut ws_sink = sink_arc.lock().await;
                            Self::send_to_sink(&mut *ws_sink, msg_out).await;
                        } else {
                            let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
                            if let Some(sink_arc) = sink_arc {
                                let mut tcp_sink = sink_arc.lock().await;
                                Self::send_to_sink(&mut *tcp_sink, msg_out).await;
                            } else {
                                self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                            }
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    let addr_v4 = try_into_v4(addr);
                    let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
                    if let Some(sink_arc) = sink_arc {
                        let mut ws_sink = sink_arc.lock().await;
                        Self::send_to_sink(&mut *ws_sink, msg_out).await;
                    } else {
                        let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
                        if let Some(sink_arc) = sink_arc {
                            let mut tcp_sink = sink_arc.lock().await;
                            Self::send_to_sink(&mut *tcp_sink, msg_out).await;
                        } else if let Some(s) = sink.as_mut() {
                            Self::send_to_sink(s, msg_out).await;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() {
                        return false;
                    }
                    let id = rk.id.clone();
                    let ip = forwarded_ip
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|| addr.ip().to_string());
                    if rk.pk.is_empty() {
                        // change-id pre-check: validate availability without persisting
                        let result = self.validate_change_id(&id, &rk.uuid, &ip).await;
                        let msg_out = Self::make_register_pk_response(result);
                        if let Some(s) = sink.as_mut() {
                            Self::send_to_sink(s, msg_out).await;
                        }
                        return false;
                    }
                    match self.validate_register_pk(&id, &rk.uuid, &rk.pk, &ip).await {
                        Ok((peer, changed, _ip_changed)) => {
                            // Always update for WS/TCP peers: socket_addr must reflect the
                            // current connection address even when key/uuid unchanged
                            if changed || ws {
                                self.pm.update_pk(id.clone(), peer, addr, rk.uuid, rk.pk, ip).await;
                            }
                            // Ensure socket_addr and last_reg_time are always up-to-date
                            if let Some(p) = self.pm.get_in_memory(&id).await {
                                let mut p = p.write().await;
                                p.socket_addr = addr;
                                p.last_reg_time = Instant::now();
                            }
                            let msg_out = Self::make_register_pk_response(register_pk_response::Result::OK);
                            if let Some(s) = sink.as_mut() { Self::send_to_sink(s, msg_out).await; }
                            // Store sink in persistent map for later message delivery
                            if let Some(s) = sink.take() {
                                if ws {
                                    self.ws_map.lock().await.insert(try_into_v4(addr), Arc::new(Mutex::new(s)));
                                } else {
                                    self.tcp_map.lock().await.insert(try_into_v4(addr), Arc::new(Mutex::new(s)));
                                }
                            }
                            return true;
                        }
                        Err(msg_out) => {
                            if let Some(s) = sink.as_mut() { Self::send_to_sink(s, msg_out).await; }
                            return false;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // TCP/WS peer registration and heartbeat
                    if !rp.id.is_empty() {
                        if let Some(p) = self.pm.get_in_memory(&rp.id).await {
                            let (request_pk, ip_change) = {
                                let p = p.read().await;
                                let ip = addr.ip();
                                let ip_change = if p.socket_addr.port() != 0 {
                                    ip != p.socket_addr.ip()
                                } else {
                                    ip.to_string() != p.info.ip
                                } && !ip.is_loopback();
                                let request_pk = p.pk.is_empty() || ip_change;
                                (request_pk, ip_change)
                            };
                            if !request_pk {
                                let mut p = p.write().await;
                                p.socket_addr = addr;
                                p.last_reg_time = Instant::now();
                            } else if ip_change {
                                log::info!(
                                    "{} peer {} IP changed, requiring re-registration",
                                    if ws { "WS" } else { "TCP" },
                                    rp.id
                                );
                            }
                        } else {
                            // New peer, request pk registration
                            let request_pk = true;
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_register_peer_response(RegisterPeerResponse {
                                request_pk,
                                ..Default::default()
                            });
                            if let Some(s) = sink.as_mut() {
                                Self::send_to_sink(s, msg_out).await;
                            }
                            // Send config update if needed
                            if self.inner.serial > rp.serial {
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_configure_update(ConfigUpdate {
                                    serial: self.inner.serial,
                                    rendezvous_servers: (*self.rendezvous_servers).clone(),
                                    ..Default::default()
                                });
                                if let Some(s) = sink.as_mut() {
                                    Self::send_to_sink(s, msg_out).await;
                                }
                            }
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::OnlineRequest(or)) => {
                    // WS/TCP peer checking which peers are online
                    let peers = or.peers;
                    let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
                    for (i, peer_id) in peers.iter().enumerate() {
                        if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                            let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                            let states_idx = i / 8;
                            let bit_idx = 7 - i % 8;
                            if elapsed < REG_TIMEOUT {
                                states[states_idx] |= 0x01 << bit_idx;
                            }
                        }
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_online_response(OnlineResponse {
                        states: states.into(),
                        ..Default::default()
                    });
                    // Send via persistent map (sink was stored during RegisterPk)
                    let addr_v4 = try_into_v4(addr);
                    let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
                    if let Some(sink_arc) = sink_arc {
                        let mut ws_sink = sink_arc.lock().await;
                        Self::send_to_sink(&mut *ws_sink, msg_out).await;
                    } else {
                        let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
                        if let Some(sink_arc) = sink_arc {
                            let mut tcp_sink = sink_arc.lock().await;
                            Self::send_to_sink(&mut *tcp_sink, msg_out).await;
                        } else if let Some(s) = sink.as_mut() {
                            Self::send_to_sink(s, msg_out).await;
                        }
                    }
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    #[inline]
    pub(crate) async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(to_addr) = to_addr {
            // Check if target is a WS/TCP peer with persistent connection
            let addr_v4 = try_into_v4(to_addr);
            let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
            if let Some(sink_arc) = sink_arc {
                let mut ws_sink = sink_arc.lock().await;
                Self::send_to_sink(&mut *ws_sink, msg).await;
            } else {
                let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
                if let Some(sink_arc) = sink_arc {
                    let mut tcp_sink = sink_arc.lock().await;
                    Self::send_to_sink(&mut *tcp_sink, msg).await;
                } else {
                    self.tx.send(Data::Msg(msg.into(), to_addr))?;
                }
            }
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }
}