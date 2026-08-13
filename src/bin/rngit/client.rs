use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmpv::{Value, encode::write_value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use reticulum_sdk::destination::link::{
    Link, LinkEvent, LinkEventData, LinkResourcePacket,
};
use reticulum_sdk::destination::resource::{Resource, ResourceAdvertisement, MAX_ADV_RETRIES};
use reticulum_sdk::destination::{DestinationDesc, DestinationName};
use reticulum_sdk::error::RnsError;
use reticulum_sdk::hash::{ADDRESS_HASH_SIZE, AddressHash, Hash};
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::packet::{Packet, PacketContext};
use reticulum_sdk::transport::Transport;

use super::config::APP_NAME;
use super::transfer;

pub type TResult<T> = Result<T, String>;

/// How long to wait for the link to activate when connecting.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default per-request timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Interval between outbound advertisement retries while no part requests
/// have arrived for a resource we are sending.
const ADV_RETRY_INTERVAL: Duration = Duration::from_secs(2);

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn err(e: RnsError) -> String {
    format!("rns error: {e}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hash a request path the same way the server does.
pub fn path_hash(path: &str) -> AddressHash {
    transfer::path_hash(path)
}

/// Pack a request payload the way `Link::request_packet` does:
/// `[requested_at, path_hash, data]`.
pub fn pack_request(path: &str, data: &Value) -> TResult<Vec<u8>> {
    let request = Value::Array(vec![
        Value::F64(now_seconds()),
        Value::Binary(path_hash(path).as_slice().to_vec()),
        data.clone(),
    ]);
    let mut packed = Vec::new();
    write_value(&mut packed, &request).map_err(|e| format!("could not pack request: {e}"))?;
    Ok(packed)
}

/// Compute the request id the Python reference and the server use for
/// inline requests: first 16 bytes of SHA-256 over the packet's hashable
/// part (`meta_flags & 0x0F | destination | context | ciphertext`).
fn python_request_id(packet: &Packet) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([packet.header.to_meta() & 0b0000_1111]);
    hasher.update(packet.destination.as_slice());
    hasher.update([packet.context as u8]);
    hasher.update(packet.data.as_slice());
    let digest = hasher.finalize();
    digest[..ADDRESS_HASH_SIZE].to_vec()
}

/// Request id for resource requests: first 16 bytes of SHA-256 over the
/// packed request payload (as the reference derives it for packed requests).
fn packed_request_id(packed: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(packed);
    digest[..ADDRESS_HASH_SIZE].to_vec()
}

/// A response to a client request: either carried inline or assembled from
/// an inbound resource transfer.
pub enum ClientResponse {
    Bytes(Vec<u8>),
    Resource(Vec<u8>),
}

struct OutboundResource {
    resource: Resource,
    adv_retries: usize,
}

struct InboundResource {
    resource: Resource,
    request_id: Vec<u8>,
}

/// An authenticated rngit client session on a single link.
pub struct Client {
    transport: Arc<Transport>,
    link: Arc<Mutex<Link>>,
    link_id: AddressHash,
    events: tokio::sync::broadcast::Receiver<LinkEventData>,
    outbound: HashMap<Hash, OutboundResource>,
    inbound: HashMap<Hash, InboundResource>,
    responses: HashMap<Vec<u8>, ClientResponse>,
}

impl Client {
    /// Establish a link to the server destination, wait for activation and
    /// identify ourselves so the server can resolve permissions.
    pub async fn connect(
        transport: Arc<Transport>,
        identity: &PrivateIdentity,
        dest_hash: AddressHash,
        timeout: Duration,
    ) -> TResult<Self> {
        let deadline = Instant::now() + timeout;

        // Resolve the server's public identity from its announce. Falls back
        // to the local identity file (same host via a shared daemon = same
        // keys) when announces don't propagate between clients.
        transport.request_path(&dest_hash, None, None).await;
        let remote_identity = 'ident: loop {
            if let Some(dest) = transport.get_out_destination(&dest_hash).await {
                let identity = dest.lock().await.desc.identity;
                log::info!("rngit: resolved server identity from announce");
                break 'ident identity;
            }
            if Instant::now() >= deadline {
                log::warn!("rngit: no announce for destination, falling back to local identity file");
                break *identity.as_identity();
            }
            transport.request_path(&dest_hash, None, None).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        let dest_desc = DestinationDesc {
            identity: remote_identity,
            address_hash: dest_hash,
            name: DestinationName::new(APP_NAME, ""),
            ratchet_public_key: None,
        };

        log::info!("rngit: linking to {}", dest_hash);
        let link_arc = transport.link(dest_desc).await;
        let link_id = *link_arc.lock().await.id();
        let mut events = transport.out_link_events();

        // Wait for activation.
        let mut activated = false;
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Ok(ev)) if ev.id == link_id => match ev.event {
                    LinkEvent::Activated => {
                        activated = true;
                        break;
                    }
                    LinkEvent::Closed => return Err("link closed during activation".into()),
                    _ => {}
                },
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return Err("link event channel closed".into()),
                Err(_) => {}
            }
        }
        if !activated {
            return Err("link activation timed out".into());
        }
        log::info!("rngit: link active");

        // Identify so the server knows who is connecting.
        tokio::time::sleep(Duration::from_millis(300)).await;
        transport.link_identify(link_id, identity).await.map_err(err)?;
        log::info!("rngit: identity sent");

        Ok(Self {
            transport,
            link: link_arc,
            link_id,
            events,
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            responses: HashMap::new(),
        })
    }

    /// Send a request to the server and wait for the matching response.
    ///
    /// Requests that fit the link MDU are sent inline; larger payloads (such
    /// as a push bundle) are sent as a resource request, mirroring the
    /// reference implementation.
    pub async fn request(&mut self, path: &str, data: Value, timeout: Duration) -> TResult<ClientResponse> {
        let deadline = Instant::now() + timeout;

        let packed = pack_request(path, &data)?;
        let request_id = {
            let link = self.link.lock().await;
            if packed.len() <= link.mdu() {
                let packet = link.request_packet(path, data).map_err(err)?;
                let rid = python_request_id(&packet);
                drop(link);
                self.transport.send_packet(packet).await;
                rid
            } else {
                let rid = packed_request_id(&packed);
                drop(link);
                let resource = self.new_request_resource(&packed, rid.clone())?;
                transfer::send_advertisement(&self.transport, &self.link, &resource).await?;
                let hash = *resource.hash();
                self.outbound.insert(
                    hash,
                    OutboundResource {
                        resource,
                        adv_retries: 0,
                    },
                );
                rid
            }
        };
        log::debug!("rngit: request {path} id {}", hex(&request_id));

        let mut last_adv_retry = Instant::now();
        while Instant::now() < deadline {
            if Instant::now() - last_adv_retry >= ADV_RETRY_INTERVAL {
                last_adv_retry = Instant::now();
                self.retry_advertisements().await?;
            }
            if let Some(resp) = self.responses.remove(&request_id) {
                return Ok(resp);
            }
            match tokio::time::timeout(Duration::from_millis(100), self.events.recv()).await {
                Ok(Ok(ev)) if ev.id == self.link_id => match ev.event {
                    LinkEvent::Response(resp) => {
                        log::debug!("rngit: recv response id {}", hex(resp.request_id.as_slice()));
                        if resp.request_id.as_slice() == request_id.as_slice() {
                            match resp.data.as_slice() {
                                Some(bytes) => {
                                    return Ok(ClientResponse::Bytes(bytes.to_vec()))
                                }
                                None => return Err("invalid response payload".into()),
                            }
                        }
                    }
                    LinkEvent::Resource(rp) => {
                        log::debug!("rngit: recv resource context {:?}", rp.context);
                        self.handle_resource(&rp).await?;
                    }
                    LinkEvent::Closed => return Err("link closed during request".into()),
                    _ => {}
                },
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return Err("link event channel closed".into()),
                Err(_) => {}
            }
        }
        Err(format!("request {path} timed out"))
    }

    /// Re-advertise outbound resources that have not received any part
    /// requests yet, mirroring the server's advertisement retry tick.
    async fn retry_advertisements(&mut self) -> TResult<()> {
        let mut to_retry: Vec<Hash> = Vec::new();
        for (hash, ob) in self.outbound.iter_mut() {
            if ob.resource.sent_parts() == 0 && ob.adv_retries < MAX_ADV_RETRIES {
                ob.adv_retries += 1;
                to_retry.push(*hash);
            }
        }
        for hash in to_retry {
            if let Some(ob) = self.outbound.get(&hash) {
                transfer::send_advertisement(&self.transport, &self.link, &ob.resource).await?;
            }
        }
        Ok(())
    }

    /// Process an inbound resource-context packet (mirroring the server).
    async fn handle_resource(&mut self, rp: &LinkResourcePacket) -> TResult<()> {
        match rp.context {
            PacketContext::ResourceAdvertisement => {
                let adv = ResourceAdvertisement::unpack(&rp.data)
                    .map_err(|e| format!("invalid resource advertisement: {e}"))?;
                let is_response = (adv.flags & 0x10) != 0;
                let is_request = (adv.flags & 0x08) != 0;
                if is_request {
                    return Ok(());
                }
                if is_response {
                    let (resource, request_bytes) =
                        transfer::start_inbound(&self.link, &adv).await?;
                    let request_id = adv.request_id.clone().unwrap_or_default();
                    let hash = *resource.hash();
                    transfer::send_part_request(&self.transport, &self.link, &request_bytes).await?;
                    self.inbound.insert(
                        hash,
                        InboundResource {
                            resource,
                            request_id,
                        },
                    );
                }
            }
            PacketContext::ResourceRequest => {
                let hash = transfer::resource_hash_from_request(&rp.data)
                    .ok_or("invalid part request")?;
                let mut ob = {
                    self.outbound.remove(&hash).ok_or("no outbound resource")?
                };
                let result = transfer::process_part_request(
                    &self.transport,
                    &self.link,
                    &mut ob.resource,
                    &rp.data,
                    rp.packet_hash,
                )
                .await;
                self.outbound.insert(hash, ob);
                result?;
            }
            PacketContext::ResourceHashUpdate => {
                let hash =
                    transfer::resource_hash_from_hmu(&rp.data).ok_or("invalid hashmap update")?;
                let request_bytes = {
                    let inbound =
                        self.inbound.get_mut(&hash).ok_or("no inbound resource")?;
                    transfer::process_hashmap_update(&mut inbound.resource, &rp.data).await?
                };
                transfer::send_part_request(&self.transport, &self.link, &request_bytes).await?;
            }
            PacketContext::Resource => {
                let mut completed: Vec<Hash> = Vec::new();
                let mut followup: Vec<Hash> = Vec::new();
                for (hash, inbound) in self.inbound.iter_mut() {
                    if transfer::receive_part(&mut inbound.resource, &rp.data) {
                        if inbound.resource.all_parts_received() {
                            completed.push(*hash);
                        } else if inbound.resource.outstanding_parts() < inbound.resource.window() {
                            followup.push(*hash);
                        }
                    }
                }
                for hash in followup {
                    let request_bytes = {
                        let inbound =
                            self.inbound.get_mut(&hash).ok_or("no inbound resource")?;
                        inbound.resource.build_request().ok()
                    };
                    if let Some(request_bytes) = request_bytes {
                        transfer::send_part_request(&self.transport, &self.link, &request_bytes)
                            .await?;
                    }
                }
                for hash in completed {
                    let inbound = self.inbound.remove(&hash);
                    if let Some(mut inbound) = inbound {
                        let plaintext = transfer::assemble_and_prove(
                            &self.transport,
                            &self.link,
                            &mut inbound.resource,
                        )
                        .await?;
                        if !inbound.request_id.is_empty() {
                            self.responses
                                .insert(inbound.request_id, ClientResponse::Resource(plaintext));
                        }
                    }
                }
            }
            PacketContext::ResourceProof => {
                let hash = transfer::resource_hash_from_proof(&rp.data).ok_or("invalid proof")?;
                if let Some(ob) = self.outbound.get(&hash)
                    && transfer::validate_proof(&ob.resource, &rp.data)
                {
                    log::debug!("rngit: resource {} proved", hash);
                    self.outbound.remove(&hash);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Build an outbound request resource from a packed request payload.
    fn new_request_resource(&self, packed: &[u8], request_id: Vec<u8>) -> TResult<Resource> {
        let (mdu, l) = {
            let guard = self.link.try_lock().map_err(|_| "link busy".to_string())?;
            (guard.mdu(), guard)
        };
        let resource = Resource::new(
            packed,
            mdu,
            |plain, out_buf| l.encrypt(plain, out_buf).map(|s| s.len()),
            Some(request_id),
            false,
            true,
        )
        .map_err(err)?;
        Ok(resource)
    }
}

/// Parse an rns:// URL or a bare destination hex into `(hash, repo_path)`.
///
/// Accepted forms:
/// - `rns://<hex_hash>/<group>/<repo>`
/// - `<hex_hash>/<group>/<repo>`
/// - `rns://<hex_hash> group/repo` (two positional args joined by the caller)
pub fn parse_rns_url(url: &str) -> TResult<(AddressHash, String)> {
    let rest = url
        .strip_prefix("rns://")
        .or_else(|| url.strip_prefix("rns:"))
        .unwrap_or(url);
    let mut parts = rest.split('/');
    let hash_hex = parts.next().ok_or("invalid rns url")?;
    let group = parts.next().ok_or("invalid rns url")?;
    let repo = parts.next().ok_or("invalid rns url")?;
    if parts.next().is_some() {
        return Err("invalid rns url: too many path components".into());
    }
    if hash_hex.len() != ADDRESS_HASH_SIZE * 2 {
        return Err(format!(
            "destination must be {} hex chars",
            ADDRESS_HASH_SIZE * 2
        ));
    }
    let hash = AddressHash::new_from_hex_string(hash_hex)
        .map_err(|_| "invalid destination hash".to_string())?;
    if group.is_empty() || repo.is_empty() {
        return Err("invalid rns url: missing group or repository".into());
    }
    Ok((hash, format!("{group}/{repo}")))
}
