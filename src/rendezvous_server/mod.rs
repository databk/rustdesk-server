mod command;
mod helper;
mod listener;
mod punch_hole;
mod register;
mod relay;
mod server;
mod sink;
mod tcp_handler;
mod udp_handler;

use crate::peer::*;
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    protobuf::MessageField,
    rendezvous_proto::*,
    tcp::Encrypt,
    tokio::{
        self,
        net::TcpStream,
        sync::{mpsc, Mutex},
    },
    tokio_util::codec::Framed,
    udp::FramedSocket,
    ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicUsize},
    sync::Arc,
    time::Instant,
};


pub(crate) const REG_TIMEOUT: i64 = 30_000;
pub(crate) const CHECK_RELAY_TIMEOUT: u64 = 3_000;
pub(crate) const PUNCH_REQ_DEDUPE_SEC: u64 = 60;

pub(crate) static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
pub(crate) static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

pub(crate) type TcpStreamSink =
    hbb_common::futures_util::stream::SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
pub(crate) type WsSink = hbb_common::futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<TcpStream>,
    tungstenite::Message,
>;
pub(crate) type Sender = mpsc::UnboundedSender<Data>;
pub(crate) type Receiver = mpsc::UnboundedReceiver<Data>;
pub(crate) type RelayServers = Vec<String>;

#[derive(Clone, Debug)]
pub(crate) enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

pub(crate) struct TcpSink {
    pub(crate) inner: TcpStreamSink,
    pub(crate) encrypt: Option<Encrypt>,
}

pub(crate) enum Sink {
    TcpStream(TcpSink),
    Ws(WsSink),
}

#[derive(Clone)]
pub(crate) struct PunchReqEntry {
    pub(crate) tm: Instant,
    pub(crate) from_ip: String,
    pub(crate) to_ip: String,
    pub(crate) to_id: String,
}

use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex;

pub(crate) static PUNCH_REQS: Lazy<TokioMutex<Vec<PunchReqEntry>>> =
    Lazy::new(|| TokioMutex::new(Vec::new()));

#[derive(Clone)]
pub(crate) struct Inner {
    pub(crate) serial: i32,
    pub(crate) version: String,
    pub(crate) software_url: String,
    pub(crate) mask: Option<Ipv4Network>,
    pub(crate) local_ip: String,
    pub(crate) sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    pub(crate) tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pub(crate) pm: PeerMap,
    pub(crate) tx: Sender,
    pub(crate) relay_servers: Arc<RelayServers>,
    pub(crate) relay_servers0: Arc<RelayServers>,
    pub(crate) rendezvous_servers: Arc<Vec<String>>,
    pub(crate) inner: Arc<Inner>,
    pub(crate) ws_map: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<Sink>>>>>,
    pub(crate) tcp_map: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<Sink>>>>>,
}

pub(crate) enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let socket = helper::create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }
}
