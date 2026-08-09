use std::collections::HashMap;

/// Permission targets, mirroring the Python rngit permission model.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    None,
    All,
    Identity(Vec<u8>),
}

impl Target {
    fn is_none(&self) -> bool {
        matches!(self, Target::None)
    }

    fn is_all(&self) -> bool {
        matches!(self, Target::All)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    Read,
    Write,
    ReadWrite,
    Create,
    Stats,
    Release,
    Interact,
    Propose,
    Admin,
}

/// Permission lists for one permission type, e.g. read access.
#[derive(Debug, Clone, Default)]
pub struct AccessLists {
    pub read: Vec<Target>,
    pub write: Vec<Target>,
    pub create: Vec<Target>,
    pub stats: Vec<Target>,
    pub release: Vec<Target>,
    pub interact: Vec<Target>,
    pub propose: Vec<Target>,
    pub admin: Vec<Target>,
}

impl AccessLists {
    fn list_for(&self, perm: Perm) -> &Vec<Target> {
        match perm {
            Perm::Read | Perm::ReadWrite => &self.read,
            Perm::Write => &self.write,
            Perm::Create => &self.create,
            Perm::Stats => &self.stats,
            Perm::Release => &self.release,
            Perm::Interact => &self.interact,
            Perm::Propose => &self.propose,
            Perm::Admin => &self.admin,
        }
    }
}

/// Parse a permission line such as `r:all`, `adm:9710b86ba12c42d1d8f30f74fe509286`
/// or `rw:nobody`. Identity aliases are resolved first. Returns `None` for
/// invalid entries (which are silently skipped, matching the reference).
pub fn parse_permission(line: &str, aliases: &HashMap<String, String>) -> Option<(Perm, Target)> {
    let line = line.trim();
    let (perm_str, target_str) = line.split_once(':')?;
    let perm = match perm_str.to_lowercase().as_str() {
        "r" | "read" => Perm::Read,
        "w" | "write" => Perm::Write,
        "rw" | "readwrite" => Perm::ReadWrite,
        "c" | "create" => Perm::Create,
        "s" | "stats" => Perm::Stats,
        "rel" | "release" => Perm::Release,
        "i" | "interact" => Perm::Interact,
        "p" | "propose" => Perm::Propose,
        "adm" | "admin" => Perm::Admin,
        _ => return None,
    };

    Some((perm, parse_target(target_str, aliases)?))
}

fn parse_target(target: &str, aliases: &HashMap<String, String>) -> Option<Target> {
    let t = target.trim();
    let lower = t.to_lowercase();
    match lower.as_str() {
        "n" | "none" | "nobody" => return Some(Target::None),
        "a" | "all" | "everyone" => return Some(Target::All),
        _ => {}
    }
    if let Some(alias_hash) = aliases.get(t) {
        return decode_identity_hash(alias_hash).map(Target::Identity);
    }
    decode_identity_hash(t).map(Target::Identity)
}

fn decode_identity_hash(h: &str) -> Option<Vec<u8>> {
    let h = h.trim();
    if h.len() != 32 {
        return None;
    }
    let bytes = hex::decode(h).ok()?;
    Some(bytes)
}

/// Build access lists from the raw contents of a `.allowed` file or a
/// group's `[access]` config entries.
pub fn permissions_from_allowed_input(
    input: &str,
    aliases: &HashMap<String, String>,
) -> AccessLists {
    let mut lists = AccessLists::default();
    for entry in input.lines() {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if let Some((perm, target)) = parse_permission(entry, aliases) {
            let push = |list: &mut Vec<Target>| {
                if !list.contains(&target) {
                    list.push(target.clone());
                }
            };
            match perm {
                Perm::Read => push(&mut lists.read),
                Perm::Write => push(&mut lists.write),
                Perm::ReadWrite => {
                    push(&mut lists.read);
                    push(&mut lists.write);
                }
                Perm::Create => push(&mut lists.create),
                Perm::Stats => push(&mut lists.stats),
                Perm::Release => push(&mut lists.release),
                Perm::Interact => push(&mut lists.interact),
                Perm::Propose => push(&mut lists.propose),
                Perm::Admin => push(&mut lists.admin),
            }
        }
    }
    lists
}

fn contains_identity(list: &[Target], hash: &[u8]) -> bool {
    list.iter().any(|t| matches!(t, Target::Identity(h) if h == hash))
}

/// Resolve whether `remote_hash` is granted `perm`, checking the repository's
/// own lists first and falling back to the group's lists. Mirrors the Python
/// `resolve_permission` logic exactly.
pub fn resolve_permission(
    repo: &AccessLists,
    group: &AccessLists,
    remote_hash: &[u8],
    perm: Perm,
) -> bool {
    let repo_list = repo.list_for(perm);
    let group_list = group.list_for(perm);
    let repo_admins = &repo.admin;
    let group_admins = &group.admin;

    if repo_list.iter().any(|t| t.is_none()) {
        false
    } else if repo_list.iter().any(|t| t.is_all()) {
        true
    } else if contains_identity(repo_list, remote_hash) {
        true
    } else if contains_identity(repo_admins, remote_hash) {
        true
    } else if !repo_list.is_empty() {
        false
    } else if group_list.iter().any(|t| t.is_none()) {
        false
    } else if group_list.iter().any(|t| t.is_all()) {
        true
    } else if contains_identity(group_list, remote_hash) {
        true
    } else if contains_identity(group_admins, remote_hash) {
        true
    } else {
        false
    }
}

pub fn resolve_group_permission(group: &AccessLists, remote_hash: &[u8], perm: Perm) -> bool {
    let list = group.list_for(perm);
    if list.iter().any(|t| t.is_none()) {
        false
    } else if list.iter().any(|t| t.is_all()) {
        true
    } else if contains_identity(list, remote_hash) {
        true
    } else if contains_identity(&group.admin, remote_hash) {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    const ALICE: &str = "00000000000000000000000000000001";
    const BOB: &str = "00000000000000000000000000000002";

    #[test]
    fn parse_basic_entries() {
        let aliases = HashMap::new();
        assert!(matches!(
            parse_permission("r:all", &aliases),
            Some((Perm::Read, Target::All))
        ));
        assert!(matches!(
            parse_permission("adm:nobody", &aliases),
            Some((Perm::Admin, Target::None))
        ));
        assert!(matches!(
            parse_permission("w:00000000000000000000000000000001", &aliases),
            Some((Perm::Write, Target::Identity(_)))
        ));
        assert!(parse_permission("x:all", &aliases).is_none());
        assert!(parse_permission("r:tooshort", &aliases).is_none());
        assert!(parse_permission("garbage", &aliases).is_none());
        assert!(parse_permission("", &aliases).is_none());
    }

    #[test]
    fn aliases_resolve() {
        let mut aliases = HashMap::new();
        aliases.insert("alice".to_string(), ALICE.to_string());
        let (_, t) = parse_permission("r:alice", &aliases).unwrap();
        assert!(matches!(t, Target::Identity(h) if h == hash(ALICE)));
    }

    #[test]
    fn build_lists_from_input() {
        let aliases = HashMap::new();
        let input = format!("# comment\nr:all\nw:{ALICE}\nbad entry\nadm:{BOB}");
        let lists = permissions_from_allowed_input(&input, &aliases);
        assert_eq!(lists.read.len(), 1);
        assert_eq!(lists.write.len(), 1);
        assert_eq!(lists.admin.len(), 1);
        assert!(lists.read.iter().any(|t| t.is_all()));
    }

    #[test]
    fn repo_overrides_group() {
        // Group grants read to everyone, repo denies it -> denied.
        let mut group = AccessLists::default();
        group.read.push(Target::All);
        let mut repo = AccessLists::default();
        repo.read.push(Target::None);
        assert!(!resolve_permission(&repo, &group, &hash(ALICE), Perm::Read));

        // Repo grants read to alice explicitly -> allowed.
        let mut repo = AccessLists::default();
        repo.read.push(Target::Identity(hash(ALICE)));
        assert!(resolve_permission(&repo, &group, &hash(ALICE), Perm::Read));
        assert!(!resolve_permission(&repo, &group, &hash(BOB), Perm::Read));
    }

    #[test]
    fn admin_grants_access() {
        let mut group = AccessLists::default();
        group.admin.push(Target::Identity(hash(ALICE)));
        let repo = AccessLists::default();
        assert!(resolve_permission(&repo, &group, &hash(ALICE), Perm::Write));
        assert!(!resolve_permission(&repo, &group, &hash(BOB), Perm::Write));
    }

    #[test]
    fn rw_entry_expands() {
        let aliases = HashMap::new();
        let input = format!("rw:{ALICE}");
        let lists = permissions_from_allowed_input(&input, &aliases);
        assert_eq!(lists.read.len(), 1);
        assert_eq!(lists.write.len(), 1);
    }
}
