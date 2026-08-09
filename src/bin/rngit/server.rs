use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmpv::Value;
use tokio::sync::Mutex;

use reticulum_sdk::destination::link::{Link, LinkEvent, LinkEventData, LinkId, LinkRequest, LinkResourcePacket};
use reticulum_sdk::destination::resource::ResourceAdvertisement;
use reticulum_sdk::error::RnsError;
use reticulum_sdk::hash::{ADDRESS_HASH_SIZE, Hash};
use reticulum_sdk::packet::PacketContext;
use reticulum_sdk::transport::Transport;

use super::config::Cfg;
use super::gitutil::{self, TempDir};
use super::perms::{AccessLists, Perm, permissions_from_allowed_input, resolve_permission, resolve_group_permission};
use super::transfer::{self, TResult};

/// How often the server re-advertises pending outbound resources.
const TICK_INTERVAL: Duration = Duration::from_secs(30);
const MAX_ADV_RETRIES: u8 = 4;

pub struct Rngit {
    pub cfg: Cfg,
}

pub struct LinkState {
    pub link: Arc<Mutex<Link>>,
    /// Remote peer identity hash (16 bytes), once identified.
    pub peer: Option<[u8; ADDRESS_HASH_SIZE]>,
    pub outbound: HashMap<Hash, OutboundResource>,
    pub inbound: HashMap<Hash, InboundResource>,
}

pub struct OutboundResource {
    pub resource: reticulum_sdk::destination::resource::Resource,
    pub adv_retries: u8,
}

pub struct InboundResource {
    pub resource: reticulum_sdk::destination::resource::Resource,
    /// Python request id from the request resource advertisement.
    pub request_id: Vec<u8>,
}

impl LinkState {
    fn new(link: Arc<Mutex<Link>>) -> Self {
        Self {
            link,
            peer: None,
            outbound: HashMap::new(),
            inbound: HashMap::new(),
        }
    }
}

/// Outcome of a handled request.
enum Response {
    /// Send an inline response payload.
    Bytes(Vec<u8>),
    /// Send a resource (used for fetch bundles).
    Resource {
        resource: reticulum_sdk::destination::resource::Resource,
    },
}

impl Rngit {
    pub fn new(cfg: Cfg) -> Self {
        Self { cfg }
    }

    pub async fn run(&self, transport: Arc<Transport>) -> TResult<()> {
        let mut links: HashMap<LinkId, LinkState> = HashMap::new();
        let mut in_ev = transport.in_link_events();
        let mut ticker = tokio::time::interval(TICK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                res = in_ev.recv() => {
                    match res {
                        Ok(data) => self.handle_event(transport.clone(), &mut links, data).await?,
                        Err(e) => {
                            log::error!("rngit: link event channel error: {e:?}");
                            return Ok(());
                        }
                    }
                }
                _ = ticker.tick() => {
                    self.tick(transport.clone(), &mut links).await;
                }
            }
        }
    }

    async fn handle_event(
        &self,
        transport: Arc<Transport>,
        links: &mut HashMap<LinkId, LinkState>,
        data: LinkEventData,
    ) -> TResult<()> {
        match data.event {
            LinkEvent::Activated => {
                log::info!("rngit: inbound link {}", data.id);
                if let Some(link) = transport.find_in_link(&data.id).await {
                    links.insert(data.id, LinkState::new(link));
                }
            }
            LinkEvent::RemoteIdentified(identity) => {
                log::info!("rngit: link {} identified by {}", data.id, identity.address_hash);
                if let Some(state) = links.get_mut(&data.id) {
                    let mut hash = [0u8; ADDRESS_HASH_SIZE];
                    hash.copy_from_slice(identity.address_hash.as_slice());
                    state.peer = Some(hash);
                }
            }
            LinkEvent::Closed => {
                log::info!("rngit: link {} closed", data.id);
                links.remove(&data.id);
            }
            LinkEvent::Request(request) => {
                if let Some(link) = transport.find_in_link(&data.id).await {
                    self.handle_inline_request(transport, links, &data.id, link, request)
                        .await?;
                }
            }
            LinkEvent::Resource(rp) => {
                if let Some(link) = transport.find_in_link(&data.id).await {
                    self.handle_resource_packet(transport, links, &data.id, link, &rp)
                        .await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_inline_request(
        &self,
        transport: Arc<Transport>,
        links: &mut HashMap<LinkId, LinkState>,
        link_id: &LinkId,
        link: Arc<Mutex<Link>>,
        request: LinkRequest,
    ) -> TResult<()> {
        let peer = links.get(link_id).and_then(|s| s.peer);
        match self
            .route_request(&link, peer, &request.path_hash_raw, request.data, &request.request_id_raw)
            .await?
        {
            Response::Bytes(response) => {
                let packet = link
                    .lock()
                    .await
                    .response_packet_raw(&request.request_id_raw, Value::Binary(response))
                    .map_err(err)?;
                transport.send_packet(packet).await;
            }
            Response::Resource { resource } => {
                transfer::send_advertisement(&transport, &link, &resource).await?;
                let hash = *resource.hash();
                if let Some(state) = links.get_mut(link_id) {
                    state.outbound.insert(
                        hash,
                        OutboundResource {
                            resource,
                            adv_retries: 0,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    async fn handle_resource_packet(
        &self,
        transport: Arc<Transport>,
        links: &mut HashMap<LinkId, LinkState>,
        link_id: &LinkId,
        link: Arc<Mutex<Link>>,
        rp: &LinkResourcePacket,
    ) -> TResult<()> {
        match rp.context {
            PacketContext::ResourceAdvertisement => {
                let adv = ResourceAdvertisement::unpack(&rp.data)
                    .map_err(|e| format!("invalid resource advertisement: {e}"))?;
                let is_response = (adv.flags & 0x10) != 0;
                let is_request = (adv.flags & 0x08) != 0;
                if is_response {
                    return Ok(());
                }
                if is_request {
                    let (resource, request_bytes) =
                        transfer::start_inbound(&link, &adv).await?;
                    let request_id = adv.request_id.clone().unwrap_or_default();
                    let hash = *resource.hash();
                    transfer::send_part_request(&transport, &link, &request_bytes).await?;
                    if let Some(state) = links.get_mut(link_id) {
                        state.inbound.insert(
                            hash,
                            InboundResource {
                                resource,
                                request_id,
                            },
                        );
                    }
                }
            }
            PacketContext::ResourceRequest => {
                let hash = transfer::resource_hash_from_request(&rp.data)
                    .ok_or("invalid part request")?;
                let mut ob = {
                    let state = links.get_mut(link_id).ok_or("no link state")?;
                    state.outbound.remove(&hash).ok_or("no outbound resource")?
                };
                let result = transfer::process_part_request(
                    &transport,
                    &link,
                    &mut ob.resource,
                    &rp.data,
                    rp.packet_hash,
                )
                .await;
                let state = links.get_mut(link_id).ok_or("no link state")?;
                state.outbound.insert(hash, ob);
                result?;
            }
            PacketContext::ResourceHashUpdate => {
                let hash =
                    transfer::resource_hash_from_hmu(&rp.data).ok_or("invalid hashmap update")?;
                let request_bytes = {
                    let state = links.get_mut(link_id).ok_or("no link state")?;
                    let inbound = state.inbound.get_mut(&hash).ok_or("no inbound resource")?;
                    transfer::process_hashmap_update(&mut inbound.resource, &rp.data).await?
                };
                transfer::send_part_request(&transport, &link, &request_bytes).await?;
            }
            PacketContext::Resource => {
                let mut completed: Vec<Hash> = Vec::new();
                {
                    let state = links.get_mut(link_id).ok_or("no link state")?;
                    for (hash, inbound) in state.inbound.iter_mut() {
                        if transfer::receive_part(&mut inbound.resource, &rp.data)
                            && inbound.resource.all_parts_received()
                        {
                            completed.push(*hash);
                        }
                    }
                }
                for hash in completed {
                    let peer = links.get(link_id).and_then(|s| s.peer);
                    let inbound = {
                        let state = links.get_mut(link_id).ok_or("no link state")?;
                        state.inbound.remove(&hash)
                    };
                    if let Some(mut inbound) = inbound {
                        let plaintext =
                            transfer::assemble_and_prove(&transport, &link, &mut inbound.resource)
                                .await?;
                        match transfer::unpack_request(&plaintext) {
                            Some(unpacked) => {
                                let response = self
                                    .route_request(
                                        &link,
                                        peer,
                                        &unpacked.path_hash,
                                        unpacked.data,
                                        &inbound.request_id,
                                    )
                                    .await?;
                                match response {
                                    Response::Bytes(response) => {
                                        let packet = link
                                            .lock()
                                            .await
                                            .response_packet_raw(&inbound.request_id, Value::Binary(response))
                                            .map_err(err)?;
                                        transport.send_packet(packet).await;
                                    }
                                    Response::Resource { resource } => {
                                        transfer::send_advertisement(&transport, &link, &resource)
                                            .await?;
                                        let hash = *resource.hash();
                                        if let Some(state) = links.get_mut(link_id) {
                                            state.outbound.insert(
                                                hash,
                                                OutboundResource {
                                                    resource,
                                                    adv_retries: 0,
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                            None => {
                                log::warn!("rngit: could not decode packed request resource");
                            }
                        }
                    }
                }
            }
            PacketContext::ResourceProof => {
                let hash =
                    transfer::resource_hash_from_proof(&rp.data).ok_or("invalid proof")?;
                let state = links.get_mut(link_id).ok_or("no link state")?;
                if let Some(ob) = state.outbound.get(&hash) {
                    if transfer::validate_proof(&ob.resource, &rp.data) {
                        log::debug!("rngit: resource {} proved", hash);
                        state.outbound.remove(&hash);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn tick(
        &self,
        transport: Arc<Transport>,
        links: &mut HashMap<LinkId, LinkState>,
    ) {
        for (link_id, state) in links.iter_mut() {
            let mut to_remove: Vec<Hash> = Vec::new();
            let mut to_retry: Vec<(Hash, Arc<Mutex<Link>>)> = Vec::new();
            for (hash, ob) in state.outbound.iter_mut() {
                if ob.resource.sent_parts() == 0 {
                    if ob.adv_retries < MAX_ADV_RETRIES {
                        ob.adv_retries += 1;
                        to_retry.push((*hash, state.link.clone()));
                    } else {
                        to_remove.push(*hash);
                    }
                }
            }
            for (hash, link) in to_retry {
                if let Some(ob) = state.outbound.get(&hash) {
                    log::debug!("rngit: re-advertising resource {}", hash);
                    if transfer::send_advertisement(&transport, &link, &ob.resource)
                        .await
                        .is_err()
                    {
                        to_remove.push(hash);
                    }
                }
            }
            for hash in to_remove {
                state.outbound.remove(&hash);
            }
            let _ = link_id;
        }
    }

    /// Route a decoded request to its handler and produce a response.
    async fn route_request(
        &self,
        link: &Arc<Mutex<Link>>,
        peer: Option<[u8; ADDRESS_HASH_SIZE]>,
        path_hash: &[u8],
        data: Value,
        request_id: &[u8],
    ) -> TResult<Response> {
        let path = match path_hash {
            p if p == transfer::path_hash(transfer::PATH_LIST).as_slice() => transfer::PATH_LIST,
            p if p == transfer::path_hash(transfer::PATH_FETCH).as_slice() => transfer::PATH_FETCH,
            p if p == transfer::path_hash(transfer::PATH_PUSH).as_slice() => transfer::PATH_PUSH,
            p if p == transfer::path_hash(transfer::PATH_DELETE).as_slice() => transfer::PATH_DELETE,
            p if p == transfer::path_hash(transfer::PATH_CREATE).as_slice() => transfer::PATH_CREATE,
            _ => return Err("unknown request path".into()),
        };

        match path {
            transfer::PATH_LIST => {
                let response = self.handle_list(peer, &data);
                Ok(Response::Bytes(response))
            }
            transfer::PATH_FETCH => {
                Ok(self.handle_fetch(link, peer, &data, request_id).await?)
            }
            transfer::PATH_PUSH => {
                let response = self.handle_push(peer, &data);
                Ok(Response::Bytes(response))
            }
            transfer::PATH_DELETE => {
                let response = self.handle_delete(peer, &data);
                Ok(Response::Bytes(response))
            }
            transfer::PATH_CREATE => {
                let response = self.handle_create(peer, &data);
                Ok(Response::Bytes(response))
            }
            _ => unreachable!(),
        }
    }

    // ------------------------------------------------------------------
    // Handler helpers
    // ------------------------------------------------------------------

    fn not_identified() -> Vec<u8> {
        let mut r = vec![transfer::RES_DISALLOWED];
        r.extend_from_slice(b"Not identified");
        r
    }

    fn invalid_request() -> Vec<u8> {
        let mut r = vec![transfer::RES_INVALID_REQ];
        r.extend_from_slice(b"Invalid request");
        r
    }

    fn error_response(code: u8, msg: &str) -> Vec<u8> {
        let mut r = vec![code];
        r.extend_from_slice(msg.as_bytes());
        r
    }

    fn repo_repository(data: &Value) -> Option<String> {
        data.as_map()?
            .iter()
            .find(|(k, _)| k.as_i64() == Some(transfer::IDX_REPOSITORY))
            .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
    }

    fn resolve_repo_access(
        &self,
        group: &str,
        repo: &str,
    ) -> Option<(PathBuf, AccessLists, AccessLists)> {
        let group_path = PathBuf::from(self.cfg.repositories.get(group)?);
        if !group_path.is_dir() {
            return None;
        }
        let repo_path = group_path.join(repo);
        if !repo_path.is_dir() {
            return None;
        }
        let group_lists = self.group_access(group, &group_path);
        let repo_lists = self.repo_access(&repo_path);
        Some((repo_path, repo_lists, group_lists))
    }

    fn group_access(&self, group: &str, group_path: &Path) -> AccessLists {
        let allowed = PathBuf::from(format!("{}.allowed", group_path.display()));
        let mut input = String::new();
        if let Ok(content) = std::fs::read_to_string(&allowed) {
            input.push_str(&content);
            input.push('\n');
        }
        if let Some(entries) = self.cfg.access.get(group) {
            for e in entries {
                input.push_str(e);
                input.push('\n');
            }
        }
        permissions_from_allowed_input(&input, &self.cfg.aliases)
    }

    fn repo_access(&self, repo_path: &Path) -> AccessLists {
        let allowed = PathBuf::from(format!("{}.allowed", repo_path.display()));
        let mut lists = AccessLists::default();
        if let Ok(content) = std::fs::read_to_string(&allowed) {
            lists = permissions_from_allowed_input(&content, &self.cfg.aliases);
        }
        lists
    }

    fn resolve_perm(
        &self,
        peer: [u8; ADDRESS_HASH_SIZE],
        group: &str,
        repo: &str,
        perm: Perm,
    ) -> bool {
        if self
            .cfg
            .blocked_identities
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&hex::encode(peer)))
        {
            return false;
        }
        match self.resolve_repo_access(group, repo) {
            Some((_, repo_lists, group_lists)) => {
                resolve_permission(&repo_lists, &group_lists, &peer, perm)
            }
            None => false,
        }
    }

    fn resolve_group_perm(
        &self,
        peer: [u8; ADDRESS_HASH_SIZE],
        group: &str,
        perm: Perm,
    ) -> bool {
        if self
            .cfg
            .blocked_identities
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&hex::encode(peer)))
        {
            return false;
        }
        let Some(group_path) = self.cfg.repositories.get(group) else {
            return false;
        };
        let group_path = PathBuf::from(group_path);
        if !group_path.is_dir() {
            return false;
        }
        let group_lists = self.group_access(group, &group_path);
        resolve_group_permission(&group_lists, &peer, perm)
    }

    // ------------------------------------------------------------------
    // Handlers
    // ------------------------------------------------------------------

    fn handle_list(&self, peer: Option<[u8; ADDRESS_HASH_SIZE]>, data: &Value) -> Vec<u8> {
        let Some(peer) = peer else {
            return Self::not_identified();
        };
        let Some(repo_path) = Self::repo_repository(data) else {
            return Self::invalid_request();
        };
        let Some((group, repo)) = gitutil::parse_request_repository_path(&repo_path) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        let for_push = data
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("for_push")))
            .and_then(|(_, v)| v.as_bool())
            .unwrap_or(false);

        let read = self.resolve_perm(peer, group, repo, Perm::Read);
        let write = self.resolve_perm(peer, group, repo, Perm::Write);
        let access = if for_push { write } else { read };

        if !access {
            return if read {
                Self::error_response(transfer::RES_NOT_FOUND, "Not allowed")
            } else {
                Self::error_response(transfer::RES_NOT_FOUND, "Not found")
            };
        }

        let Some((repo_path, _, _)) = self.resolve_repo_access(group, repo) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        match gitutil::list_refs(&repo_path) {
            Ok(refs) => {
                let mut response = vec![0x00];
                response.extend_from_slice(&refs);
                response
            }
            Err(_) => Self::error_response(transfer::RES_REMOTE_FAIL, "Could not list refs"),
        }
    }

    async fn handle_fetch(
        &self,
        link: &Arc<Mutex<Link>>,
        peer: Option<[u8; ADDRESS_HASH_SIZE]>,
        data: &Value,
        request_id: &[u8],
    ) -> TResult<Response> {
        let Some(peer) = peer else {
            return Ok(Response::Bytes(Self::not_identified()));
        };
        let Some(repo_path) = Self::repo_repository(data) else {
            return Ok(Response::Bytes(Self::invalid_request()));
        };
        let Some((group, repo)) = gitutil::parse_request_repository_path(&repo_path) else {
            return Ok(Response::Bytes(Self::error_response(transfer::RES_NOT_FOUND, "Not found")));
        };

        if !self.resolve_perm(peer, group, repo, Perm::Read) {
            return Ok(Response::Bytes(Self::error_response(
                transfer::RES_NOT_FOUND,
                "Not found",
            )));
        }

        let Some((repo_path, _, _)) = self.resolve_repo_access(group, repo) else {
            return Ok(Response::Bytes(Self::error_response(
                transfer::RES_NOT_FOUND,
                "Not found",
            )));
        };

        let Some(map) = data.as_map() else {
            return Ok(Response::Bytes(Self::invalid_request()));
        };

        let refs = match map
            .iter()
            .find(|(k, _)| k.as_str() == Some("refs"))
            .map(|(_, v)| v)
        {
            Some(Value::Array(refs)) => refs,
            _ => {
                return Ok(Response::Bytes(Self::error_response(
                    transfer::RES_INVALID_REQ,
                    "No refs specified",
                )));
            }
        };

        let mut fetch_refs: Vec<(String, Option<String>)> = Vec::new();
        let mut have_shas: Vec<String> = Vec::new();

        for r in refs {
            let r = match r.as_map() {
                Some(m) => m,
                None => return Ok(Response::Bytes(Self::invalid_request())),
            };
            let ref_name = match r
                .iter()
                .find(|(k, _)| k.as_str() == Some("ref"))
                .and_then(|(_, v)| v.as_str())
            {
                Some(n) if gitutil::san_ref(n).is_some() => n.to_string(),
                _ => return Ok(Response::Bytes(Self::invalid_request())),
            };
            let have = r
                .iter()
                .find(|(k, _)| k.as_str() == Some("have"))
                .and_then(|(_, v)| v.as_str());
            let have = match have {
                Some(h) => {
                    if gitutil::san_sha(h).is_none() {
                        return Ok(Response::Bytes(Self::error_response(
                            transfer::RES_INVALID_REQ,
                            "Invalid SHA",
                        )));
                    }
                    Some(h.to_string())
                }
                None => None,
            };
            fetch_refs.push((ref_name, have));
        }

        if let Some(Value::Array(haves)) = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("have"))
            .map(|(_, v)| v)
        {
            for h in haves {
                match h.as_str() {
                    Some(s) if gitutil::san_sha(s).is_some() => have_shas.push(s.to_string()),
                    _ => {
                        return Ok(Response::Bytes(Self::error_response(
                            transfer::RES_INVALID_REQ,
                            "Invalid SHA",
                        )))
                    }
                }
            }
        }

        let tmp = TempDir::new("rngit-fetch").map_err(|e| format!("{e}"))?;
        let bundle_path = tmp.path().join("fetch.bundle");

        match gitutil::create_fetch_bundle(&repo_path, &bundle_path, &fetch_refs, &have_shas) {
            Ok(None) => {
                // Empty bundle: all objects already on the client.
                Ok(Response::Bytes(vec![0x00]))
            }
            Ok(Some(())) => {
                let bundle = match std::fs::read(&bundle_path) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(Response::Bytes(Self::error_response(
                            transfer::RES_REMOTE_FAIL,
                            "Could not fetch refs",
                        )))
                    }
                };

                // Metadata: {IDX_RESULT_CODE: RES_OK}
                let metadata = Value::Map(vec![(
                    Value::from(transfer::IDX_RESULT_CODE),
                    Value::from(transfer::RES_OK as i64),
                )]);
                let metadata_prefix = transfer::pack_metadata(&metadata)?;
                let mut data = metadata_prefix;
                data.extend_from_slice(&bundle);

                let mut resource = transfer::new_response_resource(
                    link,
                    data,
                    Some(request_id.to_vec()),
                )?;
                resource.set_has_metadata(true);
                log::debug!("rngit: sending fetch bundle resource for {}", request_id.iter().map(|b| format!("{b:02x}")).collect::<String>());
                Ok(Response::Resource { resource })
            }
            Err(e) => {
                log::error!("rngit: bundle creation failed: {e}");
                Ok(Response::Bytes(Self::error_response(
                    transfer::RES_REMOTE_FAIL,
                    "Could not fetch refs",
                )))
            }
        }
    }

    fn handle_push(&self, peer: Option<[u8; ADDRESS_HASH_SIZE]>, data: &Value) -> Vec<u8> {
        let Some(peer) = peer else {
            return Self::not_identified();
        };
        let Some(repo_path) = Self::repo_repository(data) else {
            return Self::invalid_request();
        };
        let Some((group, repo)) = gitutil::parse_request_repository_path(&repo_path) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        let read = self.resolve_perm(peer, group, repo, Perm::Read);
        let write = self.resolve_perm(peer, group, repo, Perm::Write);

        if !write {
            return if read {
                Self::error_response(transfer::RES_DISALLOWED, "Not allowed")
            } else {
                Self::error_response(transfer::RES_NOT_FOUND, "Not found")
            };
        }

        let Some((repo_path, _, _)) = self.resolve_repo_access(group, repo) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        let Some(map) = data.as_map() else {
            return Self::invalid_request();
        };

        let get_str = |key: &str| -> Option<String> {
            map.iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .and_then(|(_, v)| v.as_str())
                .map(|s| s.to_string())
        };

        let local_ref = get_str("local_ref");
        let remote_ref = get_str("remote_ref");
        let force = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("force"))
            .and_then(|(_, v)| v.as_bool())
            .unwrap_or(false);
        let bundle_data = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("bundle"))
            .and_then(|(_, v)| v.as_slice())
            .map(|s| s.to_vec());

        if let Some(bundle_data) = bundle_data {
            let (Some(local_ref), Some(remote_ref)) = (local_ref, remote_ref) else {
                return Self::error_response(transfer::RES_INVALID_REQ, "Missing ref specification");
            };
            if gitutil::san_ref(&local_ref).is_none() || gitutil::san_ref(&remote_ref).is_none() {
                return Self::invalid_request();
            }
            match gitutil::apply_push_bundle(&repo_path, &bundle_data, &local_ref, &remote_ref, force)
            {
                Ok(()) => {
                    log::info!("rngit: push {local_ref}:{remote_ref} to {group}/{repo}");
                    vec![0x00]
                }
                Err(e) => {
                    log::error!("rngit: push failed: {e}");
                    Self::error_response(transfer::RES_REMOTE_FAIL, "Could not verify bundle")
                }
            }
        } else if let Some(operations) = map
            .iter()
            .find(|(k, _)| k.as_str() == Some("operations"))
            .and_then(|(_, v)| v.as_array())
        {
            for op in operations {
                let Some(op_map) = op.as_map() else {
                    return Self::error_response(transfer::RES_INVALID_REQ, "Invalid data for operations");
                };
                let op_get = |key: &str| -> Option<String> {
                    op_map
                        .iter()
                        .find(|(k, _)| k.as_str() == Some(key))
                        .and_then(|(_, v)| v.as_str())
                        .map(|s| s.to_string())
                };
                let action = op_get("action").unwrap_or_default();
                let ref_name = op_get("ref");
                let sha = op_get("sha");
                let op_force = op_map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("force"))
                    .and_then(|(_, v)| v.as_bool())
                    .unwrap_or(false);

                if action != "update_ref" {
                    return Self::error_response(
                        transfer::RES_INVALID_REQ,
                        &format!("Unknown operation: {action}"),
                    );
                }
                let Some(ref_name) = ref_name else {
                    return Self::invalid_request();
                };
                if gitutil::san_ref(&ref_name).is_none() || !ref_name.starts_with("refs/") {
                    return Self::invalid_request();
                }
                let Some(sha) = sha else {
                    return Self::error_response(transfer::RES_INVALID_REQ, "Invalid SHA");
                };
                if gitutil::san_sha(&sha).is_none() {
                    return Self::error_response(transfer::RES_INVALID_REQ, "Invalid SHA");
                }
                match gitutil::update_ref(&repo_path, &ref_name, &sha, op_force) {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("rngit: update-ref {ref_name} failed: {e}");
                        return Self::error_response(
                            transfer::RES_REMOTE_FAIL,
                            "Could not update refs",
                        );
                    }
                }
            }
            log::info!("rngit: push operations applied to {group}/{repo}");
            vec![0x00]
        } else {
            Self::error_response(transfer::RES_INVALID_REQ, "Invalid request data")
        }
    }

    fn handle_delete(&self, peer: Option<[u8; ADDRESS_HASH_SIZE]>, data: &Value) -> Vec<u8> {
        let Some(peer) = peer else {
            return Self::not_identified();
        };
        let Some(repo_path) = Self::repo_repository(data) else {
            return Self::invalid_request();
        };
        let Some((group, repo)) = gitutil::parse_request_repository_path(&repo_path) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        let read = self.resolve_perm(peer, group, repo, Perm::Read);
        let write = self.resolve_perm(peer, group, repo, Perm::Write);

        if !write {
            return if read {
                Self::error_response(transfer::RES_DISALLOWED, "Not allowed")
            } else {
                Self::error_response(transfer::RES_NOT_FOUND, "Not found")
            };
        }

        let Some((repo_path, _, _)) = self.resolve_repo_access(group, repo) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };

        let ref_name = data
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("ref")))
            .and_then(|(_, v)| v.as_str())
            .map(|s| s.to_string());

        let Some(ref_name) = ref_name else {
            return Self::invalid_request();
        };
        if gitutil::san_ref(&ref_name).is_none() || !ref_name.starts_with("refs/") {
            return Self::invalid_request();
        }

        match gitutil::delete_ref(&repo_path, &ref_name) {
            Ok(()) => {
                log::info!("rngit: deleted ref {ref_name} in {group}/{repo}");
                vec![0x00]
            }
            Err(e) => {
                log::error!("rngit: delete-ref {ref_name} failed: {e}");
                Self::error_response(transfer::RES_REMOTE_FAIL, "Could not delete ref")
            }
        }
    }

    fn handle_create(&self, peer: Option<[u8; ADDRESS_HASH_SIZE]>, data: &Value) -> Vec<u8> {
        let Some(peer) = peer else {
            return Self::not_identified();
        };
        let Some(repo_path) = Self::repo_repository(data) else {
            return Self::invalid_request();
        };
        let Some((group, repo)) = gitutil::parse_request_repository_path(&repo_path) else {
            return Self::invalid_request();
        };
        let Some(group_path) = self.cfg.repositories.get(group) else {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        };
        let group_path = PathBuf::from(group_path);
        if !group_path.is_dir() {
            return Self::error_response(transfer::RES_NOT_FOUND, "Not found");
        }

        let read = self.resolve_group_perm(peer, group, Perm::Read);
        let create = self.resolve_group_perm(peer, group, Perm::Create);

        if !create {
            return if read {
                Self::error_response(transfer::RES_DISALLOWED, "Not allowed")
            } else {
                Self::error_response(transfer::RES_NOT_FOUND, "Not found")
            };
        }

        let repository_path = group_path.join(repo);
        if repository_path.exists() {
            let existing_read = self.resolve_perm(peer, group, repo, Perm::Read);
            return if existing_read {
                Self::error_response(transfer::RES_DISALLOWED, "Repository already exists")
            } else {
                Self::error_response(transfer::RES_NOT_FOUND, "Not found")
            };
        }

        let creator_hash = hex::encode(peer);
        match gitutil::create_repository(&group_path, repo, &creator_hash) {
            Ok(()) => {
                log::info!("rngit: created repository {group}/{repo}");
                vec![0x00]
            }
            Err(e) => {
                log::error!("rngit: create repository {group}/{repo} failed: {e}");
                Self::error_response(transfer::RES_REMOTE_FAIL, "Could not initialize repository")
            }
        }
    }
}

fn err(e: RnsError) -> String {
    format!("rns error: {e}")
}
