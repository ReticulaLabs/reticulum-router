use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;

use reticulum_sdk::destination::DestinationName;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::backbone::{BackboneClient, BackboneServer};
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::iface::udp::UdpInterface;
use reticulum_sdk::transport::{Transport, TransportConfig};

#[path = "rngit/config.rs"]
mod config;
#[path = "../config.rs"]
mod router_config;
#[path = "rngit/gitutil.rs"]
mod gitutil;
#[path = "rngit/perms.rs"]
mod perms;
#[path = "rngit/transfer.rs"]
mod transfer;
#[path = "rngit/server.rs"]
mod server;

use config::{APP_ASPECT, APP_NAME};
use server::Rngit;

/// Number of announces sent at startup so late-subscribing peers can
/// discover this destination and resolve its identity for link crypto.
const STARTUP_ANNOUNCES: u32 = 5;

fn load_identity() -> Result<PrivateIdentity, Box<dyn std::error::Error>> {
    let path = config::ident_path();
    if path.is_file() {
        let hex = std::fs::read_to_string(&path)?;
        return PrivateIdentity::new_from_hex_string(hex.trim())
            .map_err(|e| format!("bad identity {path:?}: {e:?}").into());
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    let id = PrivateIdentity::new_from_rand(&mut rng);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let hex = format!("{}\n", id.to_hex_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, hex)?;
    }
    log::info!("rngit: created identity at {path:?}");
    Ok(id)
}

async fn make_transport(identity: &PrivateIdentity) -> Result<Transport, Box<dyn std::error::Error>> {
    let mut tcfg = TransportConfig::new("rngit", identity, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_rpc_instance(true);
    let t = Transport::new(tcfg);
    let on_rpc = t.rpc_connected().await;
    let mgr = t.iface_manager();

    if on_rpc {
        log::info!("rngit: connected to local reticulum instance over rpc");
        return Ok(t);
    }

    // Load explicit interfaces from the Reticulum config only when running
    // standalone (no rpc instance). When connected to a running daemon via
    // the rpc instance, the daemon already manages all network connectivity.
    if let Some(path) = router_config::Config::find_existing() {
        match router_config::Config::from_file(&path) {
            Ok(cfg) => {
                log::info!("rngit: loading interfaces from {}", path.display());
                for iface in &cfg.interfaces {
                    let enabled = match &iface.config {
                        router_config::InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::BackboneInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
                        _ => false,
                    };
                    if !enabled {
                        continue;
                    }
                    match &iface.config {
                        router_config::InterfaceConfig::TCPServerInterface { bind_host, bind_port, .. } => {
                            let addr = format!("{bind_host}:{bind_port}");
                            log::info!("rngit: TCP server on {addr}");
                            let _ = mgr.lock().await.spawn(
                                TcpServer::new(addr, mgr.clone()),
                                TcpServer::spawn,
                            );
                        }
                        router_config::InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                            let addr = format!("{target_host}:{target_port}");
                            log::info!("rngit: TCP client to {addr}");
                            let _ = mgr.lock().await.spawn(TcpClient::new(addr), TcpClient::spawn);
                        }
                        router_config::InterfaceConfig::BackboneInterface { bind_host, target_host, port, .. } => {
                            match (bind_host, target_host) {
                                (Some(host), None) => {
                                    let addr = format!("{host}:{port}");
                                    log::info!("rngit: backbone server on {addr}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneServer::new(addr, mgr.clone()),
                                        BackboneServer::spawn,
                                    );
                                }
                                (None, Some(host)) => {
                                    let addr = format!("{host}:{port}");
                                    log::info!("rngit: backbone client to {addr}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneClient::new(addr),
                                        BackboneClient::spawn,
                                    );
                                }
                                _ => log::warn!("rngit: skipping invalid backbone interface"),
                            }
                        }
                        router_config::InterfaceConfig::UDPInterface { listen_ip, listen_port, forward_ip, forward_port, .. } => {
                            let bind = format!("{listen_ip}:{listen_port}");
                            let forward = format!("{forward_ip}:{forward_port}");
                            log::info!("rngit: UDP {bind} -> {forward}");
                            let _ = mgr.lock().await.spawn(
                                UdpInterface::new(bind, Some(forward)),
                                UdpInterface::spawn,
                            );
                        }
                        router_config::InterfaceConfig::AutoInterface { .. } => {
                            log::warn!("rngit: AutoInterface unsupported")
                        }
                        _ => log::warn!("rngit: skipping unsupported interface"),
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => log::warn!("rngit: could not load Reticulum config: {e}"),
        }
    } else {
        log::warn!("rngit: no Reticulum config found; running with no interfaces");
    }

    Ok(t)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = config::load_cfg(None);
    let identity = load_identity()?;
    let mut transport = make_transport(&identity).await?;

    let dest = transport
        .add_destination(identity, DestinationName::new(APP_NAME, APP_ASPECT))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    log::info!(
        "rngit: identity {} listening on {}.{} at {}",
        dest.lock().await.desc.identity.address_hash.to_hex_string(),
        APP_NAME,
        APP_ASPECT,
        dest_hash.to_hex_string()
    );

    for _ in 0..STARTUP_ANNOUNCES {
        transport.send_announce(&dest, None).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let transport = Arc::new(transport);

    let announce_interval = cfg.rngit.announce_interval;
    if announce_interval > 0 {
        let t2 = transport.clone();
        let d2 = dest.clone();
        tokio::spawn(async move {
            loop {
                t2.send_announce(&d2, None).await;
                tokio::time::sleep(Duration::from_secs(announce_interval * 60)).await;
            }
        });
    }

    let rngit = Rngit::new(cfg);
    rngit.run(transport).await?;
    Ok(())
}
