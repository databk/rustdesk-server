use super::*;
use crate::common::*;
use hbb_common::{
    allow_err,
    bytes::Bytes,
    futures_util::sink::SinkExt,
    rendezvous_proto::*,
    try_into_v4,
    ResultType,
};
use std::net::SocketAddr;

impl RendezvousServer {
    #[inline]
    pub(crate) async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let addr_v4 = try_into_v4(addr);
        // Check ws_map first
        let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
        if let Some(sink_arc) = sink_arc {
            let mut ws_sink = sink_arc.lock().await;
            Self::send_to_sink(&mut *ws_sink, msg).await;
            return;
        }
        // Check tcp_map for persistent TCP connections
        let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
        if let Some(sink_arc) = sink_arc {
            let mut tcp_sink = sink_arc.lock().await;
            Self::send_to_sink(&mut *tcp_sink, msg).await;
            return;
        }
        // Fall back to tcp_punch for one-shot TCP connections
        let mut tcp = self.tcp_punch.lock().await.remove(&addr_v4);
        tokio::spawn(async move {
            if let Some(s) = tcp.as_mut() {
                Self::send_to_sink(s, msg).await;
            }
        });
    }

    #[inline]
    pub(crate) async fn send_to_sink(sink: &mut Sink, msg: RendezvousMessage) {
        if let Ok(bytes) = msg.write_to_bytes() {
            match sink {
                Sink::TcpStream(s) => {
                    let data = if let Some(enc) = s.encrypt.as_mut() {
                        Bytes::from(enc.enc(&bytes))
                    } else {
                        Bytes::from(bytes)
                    };
                    allow_err!(s.inner.send(data).await);
                }
                Sink::Ws(ws) => {
                    allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                }
            }
        }
    }

    #[inline]
    pub(crate) async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let addr_v4 = try_into_v4(addr);
        // Check ws_map first
        let sink_arc = self.ws_map.lock().await.get(&addr_v4).cloned();
        if let Some(sink_arc) = sink_arc {
            let mut ws_sink = sink_arc.lock().await;
            Self::send_to_sink(&mut *ws_sink, msg).await;
            return Ok(());
        }
        // Check tcp_map for persistent TCP connections
        let sink_arc = self.tcp_map.lock().await.get(&addr_v4).cloned();
        if let Some(sink_arc) = sink_arc {
            let mut tcp_sink = sink_arc.lock().await;
            Self::send_to_sink(&mut *tcp_sink, msg).await;
            return Ok(());
        }
        // Fall back to tcp_punch
        let mut sink = self.tcp_punch.lock().await.remove(&addr_v4);
        if let Some(s) = sink.as_mut() {
            Self::send_to_sink(s, msg).await;
        }
        Ok(())
    }
}