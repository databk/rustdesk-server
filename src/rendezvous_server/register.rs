use super::*;
use crate::common::*;
use crate::peer::*;
use hbb_common::{
    log,
    rendezvous_proto::{
        register_pk_response::Result::{ID_EXISTS, INVALID_ID_FORMAT, TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
};
use std::collections::HashMap;
use std::time::Instant;

impl RendezvousServer {
    pub(crate) fn make_register_pk_response(
        result: register_pk_response::Result,
    ) -> RendezvousMessage {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_pk_response(RegisterPkResponse {
            result: result.into(),
            ..Default::default()
        });
        msg_out
    }

    /// Validates a change-id pre-check request (RegisterPk with empty pk).
    ///
    /// The client sends this before persisting a new id locally to verify the
    /// new id is available on every rendezvous server. No state is persisted;
    /// this only checks availability and returns the appropriate
    /// `RegisterPkResponse::Result`.
    pub(crate) async fn validate_change_id(
        &self,
        id: &str,
        uuid: &[u8],
        ip: &str,
    ) -> register_pk_response::Result {
        if !hbb_common::is_valid_custom_id(id) {
            return INVALID_ID_FORMAT;
        }
        if !self.check_ip_blocker(ip, id).await {
            return TOO_FREQUENT;
        }
        if let Some(peer) = self.pm.get(id).await {
            let peer = peer.read().await;
            if !peer.uuid.is_empty() && peer.uuid.as_ref() != uuid {
                return ID_EXISTS;
            }
        }
        register_pk_response::Result::OK
    }

    /// Validates a RegisterPk request. Returns Ok((peer, changed, ip_changed)) on success,
    /// or Err(response_message) on validation failure.
    /// Side effects: updates reg_pk rate limiting and IP_CHANGES tracking on success.
    pub(crate) async fn validate_register_pk(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        ip: &str,
    ) -> Result<(LockPeer, bool, bool), RendezvousMessage> {
        if id.len() < 6 {
            return Err(Self::make_register_pk_response(UUID_MISMATCH));
        }
        if !self.check_ip_blocker(ip, id).await {
            return Err(Self::make_register_pk_response(TOO_FREQUENT));
        }
        let peer = self.pm.get_or(id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == uuid {
                    if peer.info.ip != ip && peer.pk != pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id, ip, pk, peer.info.ip, peer.pk,
                        );
                        return Err(Self::make_register_pk_response(UUID_MISMATCH));
                    }
                } else {
                    log::warn!(
                        "Peer {} uuid mismatch: {:?} vs {:?}",
                        id, uuid, peer.uuid
                    );
                    return Err(Self::make_register_pk_response(UUID_MISMATCH));
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != uuid || peer.pk != pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            return Err(Self::make_register_pk_response(TOO_FREQUENT));
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.to_owned(), 1);
                } else if let Some(v) = ips.get_mut(ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.to_owned(), 1);
                }
            } else {
                lock.insert(
                    id.to_owned(),
                    (Instant::now(), HashMap::from([(ip.to_owned(), 1)])),
                );
            }
        }
        Ok((peer, changed, ip_changed))
    }

    pub(crate) async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }
}