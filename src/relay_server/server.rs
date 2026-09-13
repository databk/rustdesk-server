use super::*;
use hbb_common::{
    log,
    tokio,
    ResultType,
};
use std::{
    io::prelude::*,
    net::IpAddr,
};

#[tokio::main(flavor = "multi_thread")]
pub async fn start_with_bind(
    bind_addr: Option<IpAddr>,
    port: &str,
    key: &str,
) -> ResultType<()> {
    let key = helper::get_server_sk(key);
    if let Ok(mut file) = std::fs::File::open(BLACKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blacklist({}): {}",
        BLACKLIST_FILE,
        BLACKLIST.read().await.len()
    );
    if let Ok(mut file) = std::fs::File::open(BLOCKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blocklist({}): {}",
        BLOCKLIST_FILE,
        BLOCKLIST.read().await.len()
    );
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            connection::io_loop(
                crate::common::listen_tcp(bind_addr, port).await?,
                crate::common::listen_tcp(bind_addr, port2).await?,
                crate::common::listen_console(bind_addr, port).await?,
                &key,
            )
            .await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}