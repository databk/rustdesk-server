//! Read and maintenance bridge behind the management API's `/v1/connections`
//! and `/v1/abuse/*` endpoints. It exposes the state the local text console
//! (`command.rs`) already works on, as structured JSON.
use super::*;
use crate::management::Inspect;
use crate::peer::*;
use hbb_common::ResultType;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::SystemTime;

// The connection log was unbounded; the oldest entries are dropped past this.
pub(crate) const PUNCH_REQS_MAX: usize = 10_000;
// Same thresholds `check_ip_blocker` enforces on registration traffic.
const RATE_LIMIT_REQUESTS: u32 = 30;
const ID_FLOOD_LIMIT: usize = 300;
const BLOCKER_IDS_REPORTED: usize = 1000;

pub(crate) async fn inspect(request: Inspect) -> ResultType<Value> {
    Ok(match request {
        Inspect::Connections { offset, limit } => connections(offset, limit).await,
        Inspect::ClearConnections => {
            let mut lock = PUNCH_REQS.lock().await;
            let cleared = lock.len();
            lock.clear();
            json!({ "cleared": cleared })
        }
        Inspect::IpBlockers { offset, limit } => ip_blockers(offset, limit).await,
        Inspect::IpBlocker { ip } => match IP_BLOCKER.lock().await.get(&ip) {
            Some((rate, ids)) => ip_blocker_entry(&ip, rate, ids, true),
            None => Value::Null,
        },
        Inspect::ReleaseIpBlocker { ip } => {
            json!({ "deleted": IP_BLOCKER.lock().await.remove(&ip).is_some() })
        }
        Inspect::IpChanges { offset, limit } => ip_changes(offset, limit).await,
        Inspect::IpChange { id } => match IP_CHANGES.lock().await.get(&id) {
            Some((since, ips)) => ip_change_entry(&id, since, ips),
            None => Value::Null,
        },
        Inspect::ReleaseIpChange { id } => {
            json!({ "deleted": IP_CHANGES.lock().await.remove(&id).is_some() })
        }
    })
}

fn rfc3339_ago(age: std::time::Duration) -> String {
    let at = SystemTime::now()
        .checked_sub(age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    chrono::DateTime::<chrono::Utc>::from(at).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// Newest first; `total` lets clients page without a second request.
async fn connections(offset: usize, limit: usize) -> Value {
    let lock = PUNCH_REQS.lock().await;
    let data: Vec<Value> = lock
        .iter()
        .rev()
        .skip(offset)
        .take(limit)
        .map(|e| {
            json!({
                "time": rfc3339_ago(e.tm.elapsed()),
                "age_seconds": e.tm.elapsed().as_secs(),
                "from_ip": e.from_ip,
                "to_id": e.to_id,
                "to_ip": e.to_ip,
            })
        })
        .collect();
    json!({ "total": lock.len(), "offset": offset, "limit": limit, "data": data })
}

fn ip_blocker_entry(
    ip: &str,
    rate: &(u32, Instant),
    ids: &(HashSet<String>, Instant),
    with_ids: bool,
) -> Value {
    let window_age = rate.1.elapsed().as_secs();
    let ids_age = ids.1.elapsed().as_secs();
    let mut entry = json!({
        "ip": ip,
        "requests_in_window": rate.0,
        "window_age_seconds": window_age,
        // Registrations from this address are refused while this holds.
        "rate_limited": rate.0 > RATE_LIMIT_REQUESTS && window_age <= IP_BLOCK_DUR,
        "distinct_ids_24h": ids.0.len(),
        "ids_age_seconds": ids_age,
        // Further new ids from this address are refused while this holds.
        "id_flood": ids.0.len() > ID_FLOOD_LIMIT && ids_age <= DAY_SECONDS,
    });
    if with_ids {
        let mut sorted: Vec<&String> = ids.0.iter().collect();
        sorted.sort();
        entry["ids"] = json!(sorted
            .into_iter()
            .take(BLOCKER_IDS_REPORTED)
            .collect::<Vec<_>>());
    }
    entry
}

async fn ip_blockers(offset: usize, limit: usize) -> Value {
    let mut lock = IP_BLOCKER.lock().await;
    // Same expiry the text console applies before listing.
    lock.retain(|_, (a, b)| {
        a.1.elapsed().as_secs() <= IP_BLOCK_DUR || b.1.elapsed().as_secs() <= DAY_SECONDS
    });
    let mut entries: Vec<Value> = lock
        .iter()
        .map(|(ip, (rate, ids))| ip_blocker_entry(ip, rate, ids, false))
        .collect();
    // Blocked addresses first, then the busiest, then by address for stable pages.
    entries.sort_by(|a, b| {
        let blocked = |v: &Value| v["rate_limited"] == true || v["id_flood"] == true;
        blocked(b)
            .cmp(&blocked(a))
            .then(
                b["requests_in_window"]
                    .as_u64()
                    .cmp(&a["requests_in_window"].as_u64()),
            )
            .then(a["ip"].as_str().cmp(&b["ip"].as_str()))
    });
    let total = entries.len();
    let data: Vec<Value> = entries.into_iter().skip(offset).take(limit).collect();
    json!({ "total": total, "offset": offset, "limit": limit, "data": data })
}

fn ip_change_entry(id: &str, since: &Instant, ips: &HashMap<String, i32>) -> Value {
    let mut by_ip: Vec<(&String, &i32)> = ips.iter().collect();
    by_ip.sort();
    json!({
        "id": id,
        "age_seconds": since.elapsed().as_secs(),
        "distinct_ips": ips.len(),
        "ips": by_ip
            .into_iter()
            .map(|(ip, count)| json!({ "ip": ip, "registrations": count }))
            .collect::<Vec<_>>(),
    })
}

async fn ip_changes(offset: usize, limit: usize) -> Value {
    let mut lock = IP_CHANGES.lock().await;
    lock.retain(|_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
    let mut entries: Vec<Value> = lock
        .iter()
        .map(|(id, (since, ips))| ip_change_entry(id, since, ips))
        .collect();
    entries.sort_by(|a, b| {
        b["distinct_ips"]
            .as_u64()
            .cmp(&a["distinct_ips"].as_u64())
            .then(a["id"].as_str().cmp(&b["id"].as_str()))
    });
    let total = entries.len();
    let data: Vec<Value> = entries.into_iter().skip(offset).take(limit).collect();
    json!({ "total": total, "offset": offset, "limit": limit, "data": data })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocker(requests: u32, ids: usize) -> ((u32, Instant), (HashSet<String>, Instant)) {
        (
            (requests, Instant::now()),
            ((0..ids).map(|i| format!("id{i}")).collect(), Instant::now()),
        )
    }

    #[hbb_common::tokio::test]
    async fn ip_blocker_reports_limits_and_can_be_released() {
        IP_BLOCKER
            .lock()
            .await
            .insert("198.51.100.7".to_owned(), blocker(31, 2));
        IP_BLOCKER
            .lock()
            .await
            .insert("198.51.100.8".to_owned(), blocker(1, 301));

        let busy = inspect(Inspect::IpBlocker {
            ip: "198.51.100.7".into(),
        })
        .await
        .unwrap();
        assert_eq!(busy["rate_limited"], true);
        assert_eq!(busy["id_flood"], false);
        assert_eq!(busy["ids"], json!(["id0", "id1"]));

        let flooder = inspect(Inspect::IpBlocker {
            ip: "198.51.100.8".into(),
        })
        .await
        .unwrap();
        assert_eq!(flooder["rate_limited"], false);
        assert_eq!(flooder["id_flood"], true);
        // The id list is only part of the single-entry view.
        let list = inspect(Inspect::IpBlockers {
            offset: 0,
            limit: 1000,
        })
        .await
        .unwrap();
        assert!(list["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("ids").is_none()));

        for ip in ["198.51.100.7", "198.51.100.8"] {
            let released = inspect(Inspect::ReleaseIpBlocker { ip: ip.into() })
                .await
                .unwrap();
            assert_eq!(released["deleted"], true);
            let missing = inspect(Inspect::IpBlocker { ip: ip.into() }).await.unwrap();
            assert!(missing.is_null());
            let again = inspect(Inspect::ReleaseIpBlocker { ip: ip.into() })
                .await
                .unwrap();
            assert_eq!(again["deleted"], false);
        }
    }

    #[hbb_common::tokio::test]
    async fn ip_changes_list_most_active_first_and_release_by_id() {
        let entry = |ips: &[(&str, i32)]| {
            (
                Instant::now(),
                ips.iter()
                    .map(|(ip, n)| (ip.to_string(), *n))
                    .collect::<HashMap<_, _>>(),
            )
        };
        {
            let mut lock = IP_CHANGES.lock().await;
            lock.insert(
                "ch-two".into(),
                entry(&[("203.0.113.1", 1), ("203.0.113.2", 4)]),
            );
            lock.insert(
                "ch-three".into(),
                entry(&[("203.0.113.1", 1), ("203.0.113.2", 1), ("203.0.113.3", 1)]),
            );
            // A single address is not a change and is dropped from listings.
            lock.insert("ch-one".into(), entry(&[("203.0.113.1", 1)]));
        }
        let list = inspect(Inspect::IpChanges {
            offset: 0,
            limit: 1000,
        })
        .await
        .unwrap();
        let ids: Vec<&str> = list["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .filter(|id| id.starts_with("ch-"))
            .collect();
        assert_eq!(ids, vec!["ch-three", "ch-two"]);

        let two = inspect(Inspect::IpChange {
            id: "ch-two".into(),
        })
        .await
        .unwrap();
        assert_eq!(two["distinct_ips"], 2);
        assert_eq!(
            two["ips"][1],
            json!({"ip": "203.0.113.2", "registrations": 4})
        );

        for id in ["ch-two", "ch-three"] {
            let released = inspect(Inspect::ReleaseIpChange { id: id.into() })
                .await
                .unwrap();
            assert_eq!(released["deleted"], true);
        }
        assert!(inspect(Inspect::IpChange {
            id: "ch-two".into()
        })
        .await
        .unwrap()
        .is_null());
    }

    // One test owns PUNCH_REQS: it is a process-wide log shared by all tests.
    #[hbb_common::tokio::test]
    async fn connection_log_pages_newest_first_and_clears() {
        {
            let mut lock = PUNCH_REQS.lock().await;
            lock.clear();
            for n in 0..5 {
                lock.push(PunchReqEntry {
                    tm: Instant::now(),
                    from_ip: format!("192.0.2.{n}"),
                    to_ip: "192.0.2.100".into(),
                    to_id: format!("{n}"),
                });
            }
        }
        let page = inspect(Inspect::Connections {
            offset: 1,
            limit: 2,
        })
        .await
        .unwrap();
        assert_eq!(page["total"], 5);
        let from: Vec<&str> = page["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["from_ip"].as_str().unwrap())
            .collect();
        assert_eq!(from, vec!["192.0.2.3", "192.0.2.2"]);
        assert!(page["data"][0]["time"].as_str().unwrap().ends_with('Z'));

        let cleared = inspect(Inspect::ClearConnections).await.unwrap();
        assert_eq!(cleared["cleared"], 5);
        let empty = inspect(Inspect::Connections {
            offset: 0,
            limit: 10,
        })
        .await
        .unwrap();
        assert_eq!(empty["total"], 0);
    }
}
