use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type GResult<T> = Result<T, String>;

/// Validate a ref name, mirroring the Python reference.
pub fn san_ref(ref_name: &str) -> Option<&str> {
    if ref_name.starts_with('-') {
        return None;
    }
    if ref_name.starts_with('/') {
        return None;
    }
    if ref_name.ends_with('/') {
        return None;
    }
    if ref_name.ends_with('.') {
        return None;
    }
    if ref_name.contains(' ') {
        return None;
    }
    if !ref_name.contains('/') {
        return None;
    }
    if ref_name.contains("..") || ref_name.contains("/.") || ref_name.contains("//") {
        return None;
    }
    if ref_name.contains('\\') {
        return None;
    }
    for comp in ref_name.split('/') {
        if comp.ends_with(".lock") {
            return None;
        }
    }
    for c in ref_name.chars() {
        let code = c as u32;
        if code < 40 || code == 0x7f {
            return None;
        }
    }
    for bad in ['~', '^', ':', '?', '*', '[', '@'] {
        if ref_name.contains(bad) {
            return None;
        }
    }
    if ref_name.contains("@{" ) || ref_name == "@" {
        return None;
    }
    Some(ref_name)
}

/// Validate a git object SHA (40 hex chars, matching the reference).
pub fn san_sha(sha: &str) -> Option<&str> {
    if sha.len() < 40 {
        return None;
    }
    if !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(sha)
}

/// Parse a "group/repo" request repository path.
pub fn parse_request_repository_path(path: &str) -> Option<(&str, &str)> {
    let mut comps = path.splitn(3, '/');
    let group = comps.next()?;
    let repo = comps.next()?;
    if comps.next().is_some() {
        return None;
    }
    if group.is_empty() || repo.is_empty() {
        return None;
    }
    if group.len() > 256 || repo.len() > 256 {
        return None;
    }
    Some((group, repo))
}

fn git(repo_path: &Path, args: &[&str]) -> GResult<std::process::Output> {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    Ok(out)
}

/// Read the HEAD symref of a bare repository, defaulting to "master".
fn head_ref(repo_path: &Path) -> String {
    let head_path = repo_path.join("HEAD");
    if let Ok(content) = std::fs::read(&head_path) {
        if let Some(rest) = content.strip_prefix(b"ref: ") {
            let s = String::from_utf8_lossy(rest).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "master".to_string()
}

/// Build the `/git/list` response payload (refs + `@<head_ref> HEAD`).
pub fn list_refs(repo_path: &Path) -> GResult<Vec<u8>> {
    let head_ref = head_ref(repo_path);
    let out = git(repo_path, &["for-each-ref", "--format", "%(objectname) %(refname)"])?;
    if !out.status.success() {
        return Err(format!(
            "git for-each-ref failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let mut seen = std::collections::HashSet::new();
    let mut lines: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let _sha = parts.next();
        let Some(ref_name) = parts.next() else { continue };
        if seen.insert(ref_name.to_string()) {
            lines.push(line.to_string());
        }
    }

    let mut response = String::new();
    for line in &lines {
        response.push_str(line);
        response.push('\n');
    }
    response.push_str(&format!("@{head_ref} HEAD\n"));
    Ok(response.into_bytes())
}

/// Object existence check within a repository.
pub fn object_exists(repo_path: &Path, sha: &str) -> bool {
    git(repo_path, &["cat-file", "-t", sha])
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Check whether a ref resolves to an object in the repository.
pub fn ref_exists(repo_path: &Path, ref_name: &str) -> bool {
    git(repo_path, &["rev-parse", "--verify", "--quiet", ref_name])
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Create a git bundle containing the requested refs, excluding objects the
/// client already has. Returns `Ok(None)` when the bundle would be empty
/// (all requested objects already present on the client).
pub fn create_fetch_bundle(
    repo_path: &Path,
    bundle_path: &Path,
    refs: &[(String, Option<String>)],
    have_shas: &[String],
) -> GResult<Option<()>> {
    let mut args: Vec<String> = vec![
        "bundle".into(),
        "create".into(),
        "--no-progress".into(),
        bundle_path.to_string_lossy().into_owned(),
    ];

    let mut refs_added = 0;
    for (ref_name, have) in refs {
        let ref_name = san_ref(ref_name).ok_or("invalid ref")?;
        if !ref_exists(repo_path, ref_name) {
            // Unborn or unknown ref: there is nothing to transfer for it.
            continue;
        }
        refs_added += 1;
        args.push(ref_name.to_string());
        if let Some(have_sha) = have {
            if let Some(have_sha) = san_sha(have_sha) {
                if object_exists(repo_path, have_sha) {
                    args.push(format!("^{have_sha}"));
                }
            } else {
                return Err("invalid SHA".into());
            }
        }
    }

    for sha in have_shas {
        if let Some(sha) = san_sha(sha) {
            if object_exists(repo_path, sha) {
                args.push(format!("^{sha}"));
            }
        } else {
            return Err("invalid SHA".into());
        }
    }

    if refs_added == 0 {
        // No requested refs exist on the server: nothing to send.
        return Ok(None);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = git(repo_path, &arg_refs)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("empty bundle") {
            return Ok(None);
        }
        return Err(format!("could not create bundle: {stderr}"));
    }
    Ok(Some(()))
}

/// Verify and apply a received push bundle.
pub fn apply_push_bundle(
    repo_path: &Path,
    bundle_data: &[u8],
    local_ref: &str,
    remote_ref: &str,
    force: bool,
) -> GResult<()> {
    let tmp = TempDir::new("rngit-push")?;
    let bundle_path = tmp.path().join("push.bundle");
    {
        let mut f = std::fs::File::create(&bundle_path)
            .map_err(|e| format!("could not create bundle file: {e}"))?;
        f.write_all(bundle_data)
            .map_err(|e| format!("could not write bundle file: {e}"))?;
    }

    let verify = git(
        repo_path,
        &[
            "bundle",
            "verify",
            bundle_path.to_str().unwrap_or_default(),
        ],
    )?;
    if !verify.status.success() {
        return Err(format!(
            "bundle verification failed: {}",
            String::from_utf8_lossy(&verify.stderr)
        ));
    }

    let local_ref = san_ref(local_ref).ok_or("invalid local ref")?;
    let remote_ref = san_ref(remote_ref).ok_or("invalid remote ref")?;

    let mut fetch_args = vec![
        "fetch".to_string(),
        bundle_path.to_string_lossy().into_owned(),
        format!("{local_ref}:{remote_ref}"),
    ];
    if force {
        fetch_args.push("--force".to_string());
    }
    let arg_refs: Vec<&str> = fetch_args.iter().map(|s| s.as_str()).collect();
    let fetch = git(repo_path, &arg_refs)?;
    if !fetch.status.success() {
        return Err(format!(
            "bundle fetch failed: {}",
            String::from_utf8_lossy(&fetch.stderr)
        ));
    }
    Ok(())
}

/// Apply a ref update operation (empty-bundle push path).
pub fn update_ref(repo_path: &Path, ref_name: &str, sha: &str, force: bool) -> GResult<()> {
    let ref_name = san_ref(ref_name).ok_or("invalid ref")?;
    if !ref_name.starts_with("refs/") {
        return Err("invalid ref".into());
    }
    let sha = san_sha(sha).ok_or("invalid SHA")?;

    if !object_exists(repo_path, sha) {
        return Err(format!("object {sha} does not exist in repository"));
    }

    // Existing ref pointing elsewhere requires force.
    let rev = git(repo_path, &["rev-parse", ref_name])?;
    if rev.status.success() {
        let existing = String::from_utf8_lossy(&rev.stdout).trim().to_string();
        if !existing.is_empty() && existing != sha && !force {
            return Err(format!(
                "ref {ref_name} already exists at different SHA (force required)"
            ));
        }
    }

    let update = git(repo_path, &["update-ref", ref_name, sha])?;
    if !update.status.success() {
        return Err(format!(
            "could not update ref: {}",
            String::from_utf8_lossy(&update.stderr)
        ));
    }
    Ok(())
}

/// Delete a ref (push deletion path).
pub fn delete_ref(repo_path: &Path, ref_name: &str) -> GResult<()> {
    let ref_name = san_ref(ref_name).ok_or("invalid ref")?;
    if !ref_name.starts_with("refs/") {
        return Err("invalid ref".into());
    }
    if !ref_exists(repo_path, ref_name) {
        return Err(format!("ref {ref_name} does not exist"));
    }
    let del = git(repo_path, &["update-ref", "-d", ref_name])?;
    if !del.status.success() {
        return Err(format!(
            "could not delete ref: {}",
            String::from_utf8_lossy(&del.stderr)
        ));
    }
    Ok(())
}

/// Initialize a new bare repository and grant the creator admin access.
pub fn create_repository(group_path: &Path, repo_name: &str, creator_hash: &str) -> GResult<()> {
    let repo_path = group_path.join(repo_name);
    if repo_path.exists() {
        return Err("repository already exists".into());
    }

    std::fs::create_dir_all(&repo_path).map_err(|e| format!("could not create dir: {e}"))?;

    let init = git(&repo_path, &["init", "--bare"]);
    match init {
        Ok(out) if out.status.success() => {}
        _ => {
            let _ = std::fs::remove_dir_all(&repo_path);
            return Err("could not initialize repository".into());
        }
    }

    let allowed_path = repo_path.with_extension("allowed");
    let allowed_content = format!("adm:{creator_hash}\n");
    if std::fs::write(&allowed_path, allowed_content).is_err() {
        let _ = std::fs::remove_dir_all(&repo_path);
        return Err("could not set repository permissions".into());
    }

    Ok(())
}

/// List local refs (heads and tags) of a working repository as `(sha, ref)`.
pub fn local_refs(repo_path: &Path) -> GResult<Vec<(String, String)>> {
    let out = git(
        repo_path,
        &[
            "for-each-ref",
            "--format",
            "%(objectname) %(refname)",
            "refs/heads",
            "refs/tags",
        ],
    )?;
    if !out.status.success() {
        return Err(format!(
            "git for-each-ref failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    parse_ref_lines(&out.stdout)
}

/// Parse `for-each-ref`-style `sha refname` lines.
pub fn parse_ref_lines(bytes: &[u8]) -> GResult<Vec<(String, String)>> {
    let mut refs = Vec::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((sha, refname)) = line.split_once(' ') else {
            continue;
        };
        if san_sha(sha).is_none() || refname.is_empty() {
            continue;
        }
        refs.push((sha.to_string(), refname.to_string()));
    }
    Ok(refs)
}

/// Check whether `old` is an ancestor of `new` (for fast-forward checks).
pub fn is_ancestor(repo_path: &Path, old: &str, new: &str) -> bool {
    git(
        repo_path,
        &[
            "merge-base",
            "--is-ancestor",
            old,
            new,
        ],
    )
    .map(|out| out.status.success())
    .unwrap_or(false)
}

/// Create a git bundle from the given refs, excluding objects the receiver
/// already has (prerequisites). Errors when there is nothing to send.
pub fn create_push_bundle(
    repo_path: &Path,
    bundle_path: &Path,
    refs: &[String],
    prerequisites: &[String],
) -> GResult<()> {
    if refs.is_empty() {
        return Err("no refs to push".into());
    }
    let mut args: Vec<String> = vec![
        "bundle".into(),
        "create".into(),
        "--no-progress".into(),
        bundle_path.to_string_lossy().into_owned(),
    ];
    for r in refs {
        let r = san_ref(r).ok_or("invalid ref")?;
        args.push(r.to_string());
    }
    for p in prerequisites {
        let p = san_sha(p).ok_or("invalid prerequisite SHA")?;
        args.push(format!("^{p}"));
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = git(repo_path, &arg_refs)?;
    if !out.status.success() {
        return Err(format!(
            "could not create bundle: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Initialize a new non-bare repository with an optional default branch.
pub fn init_repository(dir: &Path, default_branch: Option<&str>) -> GResult<()> {
    let mut args = vec!["init".to_string()];
    if let Some(branch) = default_branch {
        if !branch.is_empty() {
            args.push("-b".into());
            args.push(branch.to_string());
        }
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = Command::new("git")
        .args(&arg_refs)
        .arg(dir)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Fetch a bundle into a repository with the given refspecs.
pub fn fetch_bundle(repo_path: &Path, bundle_path: &Path, refspecs: &[&str]) -> GResult<()> {
    if refspecs.is_empty() {
        return Err("no refspecs".into());
    }
    let mut args: Vec<String> = vec!["fetch".to_string()];
    args.push(bundle_path.to_string_lossy().into_owned());
    for r in refspecs {
        args.push(r.to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = git(repo_path, &arg_refs)?;
    if !out.status.success() {
        return Err(format!(
            "bundle fetch failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Verify a bundle against the objects present in a repository.
pub fn verify_bundle(repo_path: &Path, bundle_path: &Path) -> GResult<()> {
    let out = git(
        repo_path,
        &["bundle", "verify", bundle_path.to_str().unwrap_or_default()],
    )?;
    if !out.status.success() {
        return Err(format!(
            "bundle verification failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Check out a branch in a working repository, creating it from origin if
/// needed. Returns true when a checkout was performed.
pub fn checkout_branch(repo_path: &Path, branch: &str) -> GResult<bool> {
    let short = branch.strip_prefix("refs/heads/").unwrap_or(branch);
    if ref_exists(repo_path, &format!("refs/heads/{short}")) {
        let out = git(repo_path, &["checkout", short])?;
        if !out.status.success() {
            return Err(format!(
                "git checkout failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(true);
    }
    let remote = format!("refs/remotes/origin/{short}");
    if ref_exists(repo_path, &remote) {
        let out = git(repo_path, &["checkout", "-b", short, &remote])?;
        if !out.status.success() {
            return Err(format!(
                "git checkout failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

/// Set a git config key in a repository.
pub fn config_set(repo_path: &Path, key: &str, value: &str) -> GResult<()> {
    let out = git(repo_path, &["config", key, value])?;
    if !out.status.success() {
        return Err(format!(
            "git config failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Add a remote.
pub fn remote_add(repo_path: &Path, name: &str, url: &str) -> GResult<()> {
    let out = git(repo_path, &["remote", "add", name, url])?;
    if !out.status.success() {
        return Err(format!(
            "git remote add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// A minimal self-cleaning temp directory (avoided a tempfile dependency).
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> GResult<Self> {
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            rand::random::<u32>()
        );
        let path = std::env::temp_dir().join(format!("{prefix}-{unique}"));
        std::fs::create_dir_all(&path).map_err(|e| format!("could not create temp dir: {e}"))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_validation() {
        assert!(san_ref("refs/heads/main").is_some());
        assert!(san_ref("refs/tags/v1.0").is_some());
        assert!(san_ref("main").is_none());
        assert!(san_ref("-refs/heads/x").is_none());
        assert!(san_ref("refs/heads/x..y").is_none());
        assert!(san_ref("refs/heads/x").is_some());
        assert!(san_ref("refs/heads/feat space").is_none());
    }

    #[test]
    fn sha_validation() {
        let good = "0123456789abcdef0123456789abcdef01234567";
        assert!(san_sha(good).is_some());
        assert!(san_sha(&good[..39]).is_none());
        assert!(san_sha("gg123456789abcdef0123456789abcdef0123456").is_none());
    }

    #[test]
    fn repo_path_parsing() {
        assert_eq!(
            parse_request_repository_path("public/myrepo"),
            Some(("public", "myrepo"))
        );
        assert!(parse_request_repository_path("public").is_none());
        assert!(parse_request_repository_path("public/a/b").is_none());
        assert!(parse_request_repository_path("").is_none());
    }

    #[test]
    fn fetch_bundle_unborn_ref_is_empty() {
        let tmp = TempDir::new("rngit-test-fetch").unwrap();
        let repo_path = tmp.path().join("repo.git");
        let init = Command::new("git")
            .args(["init", "--bare", "-b", "main"])
            .arg(&repo_path)
            .output()
            .expect("git init");
        assert!(init.status.success());

        let bundle_path = tmp.path().join("fetch.bundle");
        let refs = vec![("refs/heads/main".to_string(), None)];
        let result = create_fetch_bundle(&repo_path, &bundle_path, &refs, &[]).unwrap();
        assert!(result.is_none(), "unborn ref should yield an empty bundle");
        assert!(!bundle_path.exists(), "no bundle file should be created");
    }
}
