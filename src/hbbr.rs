use clap::App;
mod common;
mod management;
mod relay_server;
use flexi_logger::*;
use hbb_common::{config::RELAY_PORT, ResultType};
use relay_server::*;
mod version;

fn main() -> ResultType<()> {
    management::restore_bans("hbbr")?;
    let managed = management::load_config("hbbr")?;
    managed.apply();
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-b, --bind=[IP] 'Sets the IP address to bind to (default: all interfaces)'
        -p, --port=[NUMBER(default={RELAY_PORT})] 'Sets the listening port'
        -k, --key=[KEY] 'Only allow the client with the same key'
        ",
    );
    let matches = App::new("hbbr")
        .version(version::VERSION)
        .author("Purslane Ltd. <info@rustdesk.com>")
        .about("RustDesk Relay Server")
        .args_from_usage(&args)
        .get_matches();
    if let Ok(v) = ini::Ini::load_from_file(".env") {
        if let Some(section) = v.section(None::<String>) {
            section.iter().for_each(|(k, v)| common::set_arg(k, v));
        }
    }
    managed.apply();
    let mut port = RELAY_PORT;
    if let Some(v) = common::get_arg_opt("PORT") {
        let v: i32 = v.parse().unwrap_or_default();
        if v > 0 {
            port = v + 1;
        }
    }
    let bind = matches
        .value_of("bind")
        .map(str::to_owned)
        .unwrap_or_else(|| common::get_arg("BIND"));
    let bind_addr = common::parse_bind_address(&bind)?;
    let key = matches
        .value_of("key")
        .map(str::to_owned)
        .unwrap_or_else(|| common::get_arg("KEY"));
    let bind_addr = if managed.values.contains_key("bind") {
        common::parse_bind_address(&common::get_arg("bind"))?
    } else {
        bind_addr
    };
    let key = managed.values.get("key").cloned().unwrap_or(key);
    let port = managed.values.get("port").cloned().unwrap_or_else(|| {
        matches
            .value_of("port")
            .map(str::to_owned)
            .unwrap_or_else(|| port.to_string())
    });
    common::set_arg(
        "bind",
        &bind_addr.map(|ip| ip.to_string()).unwrap_or_default(),
    );
    start_with_bind(bind_addr, &port, &key)?;
    Ok(())
}
