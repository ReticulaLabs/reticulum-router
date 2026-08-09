use std::sync::Arc;

use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use reticulum_sdk::destination::link::Link;
use reticulum_sdk::destination::resource::{MAPHASH_LEN, Resource, ResourceAdvertisement};
use reticulum_sdk::error::RnsError;
use reticulum_sdk::hash::{ADDRESS_HASH_SIZE, AddressHash, Hash, HASH_SIZE};
use reticulum_sdk::packet::PacketContext;
use reticulum_sdk::transport::Transport;

pub type TResult<T> = Result<T, String>;

// rngit protocol constants (matching Python RNS/Utilities/rngit).
pub const RES_OK: u8 = 0x00;
pub const RES_DISALLOWED: u8 = 0x01;
pub const RES_INVALID_REQ: u8 = 0x02;
pub const RES_NOT_FOUND: u8 = 0x03;
pub const RES_REMOTE_FAIL: u8 = 0xFF;
pub const IDX_REPOSITORY: i64 = 0x00;
pub const IDX_RESULT_CODE: i64 = 0x01;

pub const PATH_LIST: &str = "/git/list";
pub const PATH_FETCH: &str = "/git/fetch";
pub const PATH_PUSH: &str = "/git/push";
pub const PATH_DELETE: &str = "/git/delete";
pub const PATH_CREATE: &str = "/git/create";

/// Hash a request path the way Python does (`truncated_hash`).
pub fn path_hash(path: &str) -> AddressHash {
    let digest = Sha256::digest(path.as_bytes());
    let mut hash = [0u8; ADDRESS_HASH_SIZE];
    hash.copy_from_slice(&digest[..ADDRESS_HASH_SIZE]);
    AddressHash::new(hash)
}

/// Pack resource metadata: 3-byte big-endian length + msgpack payload.
pub fn pack_metadata(metadata: &Value) -> TResult<Vec<u8>> {
    let mut packed = Vec::new();
    write_value(&mut packed, metadata).map_err(|e| format!("could not pack metadata: {e}"))?;
    if packed.len() > 0x00FF_FFFF {
        return Err("resource metadata too large".into());
    }
    let mut out = Vec::with_capacity(3 + packed.len());
    out.push(((packed.len() >> 16) & 0xFF) as u8);
    out.push(((packed.len() >> 8) & 0xFF) as u8);
    out.push((packed.len() & 0xFF) as u8);
    out.extend_from_slice(&packed);
    Ok(out)
}

/// A decoded incoming request payload (`[requested_at, path_hash, data]`).
pub struct UnpackedRequest {
    /// Client timestamp for the request. Part of the wire format; kept for
    /// protocol fidelity and potential staleness checks.
    #[allow(dead_code)]
    pub requested_at: f64,
    pub path_hash: Vec<u8>,
    pub data: Value,
}

pub fn unpack_request(packed: &[u8]) -> Option<UnpackedRequest> {
    let value = read_value(&mut &packed[..]).ok()?;
    let arr = value.as_array()?;
    if arr.len() != 3 {
        return None;
    }
    Some(UnpackedRequest {
        requested_at: arr[0].as_f64()?,
        path_hash: arr[1].as_slice()?.to_vec(),
        data: arr[2].clone(),
    })
}

fn copy_hash(slice: &[u8]) -> Option<Hash> {
    if slice.len() < HASH_SIZE {
        return None;
    }
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&slice[..HASH_SIZE]);
    Some(Hash::new(h))
}

/// Extract the resource hash from a part-request payload. Layout matches
/// Python: `[0x00|0xFF, (map_hash if exhausted), hash, requested_hashes]`.
pub fn resource_hash_from_request(data: &[u8]) -> Option<Hash> {
    if data.is_empty() {
        return None;
    }
    let exhausted = data[0] == 0xFF;
    let pad = if exhausted { 1 + MAPHASH_LEN } else { 1 };
    copy_hash(data.get(pad..)?)
}

/// Extract the resource hash from a hashmap-update payload:
/// `hash + msgpack([segment, hashmap])`.
pub fn resource_hash_from_hmu(data: &[u8]) -> Option<Hash> {
    copy_hash(data)
}

/// Extract the resource hash from a proof payload: `hash + proof_hash`.
pub fn resource_hash_from_proof(data: &[u8]) -> Option<Hash> {
    copy_hash(data)
}

fn err(e: RnsError) -> String {
    format!("rns error: {e}")
}

/// Send a resource advertisement (segment 0) over the link.
pub async fn send_advertisement(
    transport: &Arc<Transport>,
    link: &Arc<Mutex<Link>>,
    resource: &Resource,
) -> TResult<()> {
    let adv = ResourceAdvertisement::from_resource(resource);
    let packed = {
        let l = link.lock().await;
        adv.pack(0, l.mdu()).map_err(err)?
    };
    let packet = link
        .lock()
        .await
        .resource_packet(PacketContext::ResourceAdvertisement, &packed)
        .map_err(err)?;
    transport.send_packet(packet).await;
    Ok(())
}

/// Handle an incoming part request on an outbound resource: send requested
/// parts (raw) and any hashmap update.
pub async fn process_part_request(
    transport: &Arc<Transport>,
    link: &Arc<Mutex<Link>>,
    resource: &mut Resource,
    request_data: &[u8],
    packet_hash: Hash,
) -> TResult<()> {
    let result = resource
        .handle_request(request_data, Some(packet_hash))
        .map_err(err)?;

    for part in result.parts {
        let packet = link
            .lock()
            .await
            .resource_part_packet(&part)
            .map_err(err)?;
        transport.send_packet(packet).await;
    }

    if let Some(hmu) = result.hmu_packet {
        let packet = link
            .lock()
            .await
            .resource_packet(PacketContext::ResourceHashUpdate, &hmu)
            .map_err(err)?;
        transport.send_packet(packet).await;
    }

    Ok(())
}

/// Set up an inbound resource from an advertisement and return the first
/// part-request payload to send.
pub async fn start_inbound(
    link: &Arc<Mutex<Link>>,
    adv: &ResourceAdvertisement,
) -> TResult<(Resource, Vec<u8>)> {
    let (mdu, rtt) = {
        let l = link.lock().await;
        (l.mdu(), l.rtt().clone())
    };
    let mut resource = Resource::new_from_advertisement(adv, mdu, rtt, adv.request_id.clone())
        .map_err(err)?;
    let request = resource.start_receive(&adv.hashmap).map_err(err)?;
    Ok((resource, request))
}

/// Send an encrypted part-request payload for an inbound resource.
pub async fn send_part_request(
    transport: &Arc<Transport>,
    link: &Arc<Mutex<Link>>,
    request_data: &[u8],
) -> TResult<()> {
    let packet = link
        .lock()
        .await
        .resource_packet(PacketContext::ResourceRequest, request_data)
        .map_err(err)?;
    transport.send_packet(packet).await;
    Ok(())
}

/// Feed a received part into an inbound resource. Returns whether it was
/// accepted (matched a hashmap entry).
pub fn receive_part(resource: &mut Resource, part_data: &[u8]) -> bool {
    resource.receive_part(part_data)
}

/// Process an incoming hashmap update for an inbound resource. Returns the
/// next part-request payload to send.
pub async fn process_hashmap_update(
    resource: &mut Resource,
    hmu_data: &[u8],
) -> TResult<Vec<u8>> {
    let body = match hmu_data.get(HASH_SIZE..) {
        Some(b) => b,
        None => return Err("invalid hashmap update".into()),
    };
    let value = read_value(&mut &body[..]).map_err(|e| format!("invalid hashmap update: {e}"))?;
    let arr = value.as_array().ok_or("invalid hashmap update")?;
    if arr.len() != 2 {
        return Err("invalid hashmap update".into());
    }
    let segment = arr[0].as_u64().ok_or("invalid hashmap update")? as usize;
    let hashmap = arr[1].as_slice().ok_or("invalid hashmap update")?;
    resource.apply_hashmap(segment, hashmap).map_err(err)?;
    resource.build_request().map_err(err)
}

/// Assemble an inbound resource and send the proof. Returns the assembled
/// plaintext.
pub async fn assemble_and_prove(
    transport: &Arc<Transport>,
    link: &Arc<Mutex<Link>>,
    resource: &mut Resource,
) -> TResult<Vec<u8>> {
    let plaintext = {
        let l = link.lock().await;
        resource
            .assemble(|data, buf| l.decrypt(data, buf).map(|s| s.len()).map_err(|e| e))
            .map_err(err)?
    };
    let proof = resource.build_proof();
    let packet = link
        .lock()
        .await
        .resource_proof_packet(&proof)
        .map_err(err)?;
    transport.send_packet(packet).await;
    Ok(plaintext)
}

/// Validate a proof received for an outbound resource.
pub fn validate_proof(resource: &Resource, proof_data: &[u8]) -> bool {
    resource.validate_proof(proof_data)
}

/// Create an outbound response resource. `data` is the full plaintext
/// (metadata prefix + payload for metadata responses). The caller sets
/// `has_metadata` via the returned handle when appropriate.
pub fn new_response_resource(
    link: &Arc<Mutex<Link>>,
    data: Vec<u8>,
    request_id: Option<Vec<u8>>,
) -> TResult<Resource> {
    let (mdu, l) = {
        let guard = link.try_lock().map_err(|_| "link busy".to_string())?;
        (guard.mdu(), guard)
    };
    let resource = Resource::new(
        &data,
        mdu,
        |plain, out_buf| l.encrypt(plain, out_buf).map(|s| s.len()).map_err(|e| e),
        request_id,
        true,
    )
    .map_err(err)?;
    Ok(resource)
}
