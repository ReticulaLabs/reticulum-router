use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const APP_NAME: &str = "git";
pub const APP_ASPECT: &str = "repositories";

#[derive(Debug, Clone, Deserialize)]
pub struct Cfg {
    #[serde(default)]
    pub rngit: CfgRngit,
    /// Repository group name -> filesystem path containing bare repos.
    #[serde(default)]
    pub repositories: HashMap<String, String>,
    /// Group name -> list of permission entries (e.g. "r:all", "adm:0abc...").
    #[serde(default)]
    pub access: HashMap<String, Vec<String>>,
    /// Identity alias -> 32-character identity hash.
    #[serde(default)]
    pub aliases: HashMap<String, String>,
    /// Identity hashes that are blocked from all access.
    #[serde(default)]
    pub blocked_identities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgRngit {
    /// Announce interval in seconds. Set to 0 to disable announces.
    #[serde(default = "default_announce_interval")]
    pub announce_interval: u64,
    /// Free-form node name shown in logs/announces.
    #[allow(dead_code)]
    #[serde(default)]
    pub node_name: String,
}

fn default_announce_interval() -> u64 {
    600
}

impl Default for CfgRngit {
    fn default() -> Self {
        Self {
            announce_interval: default_announce_interval(),
            node_name: String::new(),
        }
    }
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            rngit: CfgRngit::default(),
            repositories: HashMap::new(),
            access: HashMap::new(),
            aliases: HashMap::new(),
            blocked_identities: Vec::new(),
        }
    }
}

pub fn rngit_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap()
        .join(".config/rngit")
}

pub fn config_path() -> PathBuf {
    rngit_dir().join("config")
}

pub fn ident_path() -> PathBuf {
    rngit_dir().join("rngit")
}

pub fn load_cfg(path: Option<&Path>) -> Cfg {
    let mut cfg = Cfg::default();
    let f = match path {
        Some(p) => p.to_path_buf(),
        None => config_path(),
    };
    log::info!("rngit: loading config from {f:?}");
    if f.exists() {
        if let Ok(s) = fs::read_to_string(&f) {
            if let Ok(parsed) = toml::from_str::<Cfg>(&s) {
                cfg = parsed;
            }
        }
    }
    cfg
}
