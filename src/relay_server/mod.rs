mod command;
mod connection;
mod helper;
mod server;
mod stream;

use async_speed_limit::Limiter;
use hbb_common::{
    tokio::sync::{Mutex, RwLock},
};
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicUsize, Ordering},
};

pub use server::start_with_bind;

pub(crate) type Usage = (usize, usize, usize, usize);

lazy_static::lazy_static! {
    pub(crate) static ref PEERS: Mutex<HashMap<String, Box<dyn stream::StreamTrait>>> = Default::default();
    pub(crate) static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    pub(crate) static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    pub(crate) static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
}

pub(crate) static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
pub(crate) static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
pub(crate) static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
pub(crate) static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
pub(crate) static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s

pub(crate) const BLACKLIST_FILE: &str = "blacklist.txt";
pub(crate) const BLOCKLIST_FILE: &str = "blocklist.txt";
