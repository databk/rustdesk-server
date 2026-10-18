use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
#[allow(dead_code)]
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = get_arg_opt("DB_URL").unwrap_or_else(|| {
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        // Hold the write lock across the database read: `release` removes
        // the map entry and deletes the row under the same lock, so a
        // lookup that misses the map can never read the row before the
        // delete and re-insert the retired peer afterwards.
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return Some(p.clone());
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            w.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    pub(crate) async fn management_snapshot(&self) -> Vec<serde_json::Value> {
        let entries: Vec<_> = self
            .map
            .read()
            .await
            .iter()
            .map(|(id, peer)| (id.clone(), peer.clone()))
            .collect();
        let mut snapshot = Vec::with_capacity(entries.len());
        for (id, peer) in entries {
            let peer = peer.read().await;
            let elapsed = peer.last_reg_time.elapsed().as_secs();
            let banned = crate::management::is_banned(&id, &peer.info.ip);
            snapshot.push(serde_json::json!({"id":id,"uuid":base64::encode(&peer.uuid),
                "address":peer.socket_addr.to_string(),"ip":peer.info.ip,"online":elapsed < 30 && !banned,
                "last_registration_age_seconds":elapsed,"banned":banned}));
        }
        snapshot.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        snapshot
    }

    // Releases a device id entirely: forgets the in-memory entry and deletes
    // the persisted row, so a replacement machine (a different uuid) can
    // claim the id again. Custom ids such as hostnames would otherwise stay
    // bound to the retired machine and every later registration would be
    // rejected with UUID_MISMATCH.
    #[inline]
    pub(crate) async fn release(&self, id: &str) -> ResultType<bool> {
        // A release happened when either the in-memory entry or the
        // persisted row existed; the response must not report "nothing
        // released" for an id that only had a live map entry.
        let removed = self.map.write().await.remove(id).is_some();
        let deleted = self.db.delete_peer(id).await? > 0;
        Ok(removed || deleted)
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::rendezvous_proto::register_pk_response;
    use hbb_common::tokio;

    #[tokio::test]
    async fn release_forgets_the_id_for_a_replacement_machine() {
        let path = std::env::temp_dir().join(format!(
            "rustdesk-peer-release-{}-{:?}.sqlite3",
            std::process::id(),
            std::thread::current().id()
        ));
        crate::common::set_arg("DB_URL", path.to_str().unwrap());
        let pm = PeerMap::new().await.unwrap();
        let register = |uuid: [u8; 2], pm: &PeerMap| {
            let mut pm = pm.clone();
            async move {
                let peer = pm.get_or("host-a").await;
                pm.update_pk(
                    "host-a".to_owned(),
                    peer,
                    "127.0.0.1:1".parse().unwrap(),
                    Bytes::from(uuid.to_vec()),
                    Bytes::from(vec![9]),
                    "127.0.0.1".to_owned(),
                )
                .await
            }
        };
        // Note: the uuid-mismatch rejection itself lives in
        // validate_register_pk on the server; this test covers the registry
        // state that makes it reject (and stops rejecting after release).
        assert_eq!(
            register([1, 1], &pm).await,
            register_pk_response::Result::OK
        );
        let registered = pm.get("host-a").await.unwrap();
        assert_eq!(
            registered.read().await.uuid,
            Bytes::from(vec![1, 1]),
            "the id is bound to the first machine's uuid"
        );
        // Releasing the id drops both the in-memory entry and the row.
        assert!(pm.release("host-a").await.unwrap());
        assert!(pm.get("host-a").await.is_none());
        // An id with only a live in-memory entry (no persisted row) also
        // reports a release.
        let peer = pm.get_or("host-b").await;
        peer.write().await.uuid = Bytes::from(vec![5, 5]);
        assert!(pm.release("host-b").await.unwrap());
        // The replacement machine (a different uuid) can claim the id now.
        assert_eq!(
            register([2, 2], &pm).await,
            register_pk_response::Result::OK
        );
        let registered = pm.get("host-a").await.unwrap();
        assert_eq!(registered.read().await.uuid, Bytes::from(vec![2, 2]));
        drop(pm);
        let _ = std::fs::remove_file(&path);
    }
}
