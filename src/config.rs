//! File + CLI config. Mirrors Node `service/config/default.json` fields that matter.

use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::path::PathBuf;

/// SHA-512("user") — **dev / bench / tests only**, never a production default.
pub const DEFAULT_USER_TOKEN: &str = "user";
pub const DEFAULT_USER_TOKEN_HASH: &str =
    "b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2";

/// SHA-512("admin") — matches Node `auth.test.js`. **dev / bench / tests only**.
pub const DEFAULT_ADMIN_TOKEN: &str = "admin";
pub const DEFAULT_ADMIN_TOKEN_HASH: &str =
    "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec";

/// Intel PCS, same as Node `service/config/default.json`.
pub const DEFAULT_URI: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";
pub const DEFAULT_REFRESH: &str = "0 0 1 * * *";

/// Node `pccs_server.js` server timeouts.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;
pub const DEFAULT_HEADERS_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_KEEPALIVE_TIMEOUT_SECS: u64 = 60;

/// Upstream client limits (see `pcs.rs`).
pub const DEFAULT_UPSTREAM_MAX_CONCURRENT: usize = 64;
/// Node `pcs_client.js` MAX_RETRY_COUNT.
pub const DEFAULT_UPSTREAM_MAX_ATTEMPTS: u32 = 6;

pub const DEFAULT_MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// RocksDB memory knobs. Defaults match stock RocksDB (8 MiB LRU, 64 MiB write buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbOpts {
    pub block_cache_mb: usize,
    pub write_buffer_mb: usize,
    pub max_write_buffers: i32,
    pub max_open_files: i32,
}

impl Default for RocksDbOpts {
    fn default() -> Self {
        Self {
            block_cache_mb: 8,
            write_buffer_mb: 64,
            max_write_buffers: 2,
            max_open_files: -1,
        }
    }
}

impl RocksDbOpts {
    pub fn block_cache_bytes(&self) -> usize {
        self.block_cache_mb.saturating_mul(1024 * 1024)
    }

    pub fn write_buffer_bytes(&self) -> usize {
        self.write_buffer_mb.saturating_mul(1024 * 1024)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CacheMode {
    Lazy,
    Offline,
    Req,
}

impl CacheMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lazy => "LAZY",
            Self::Offline => "OFFLINE",
            Self::Req => "REQ",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "LAZY" => Some(Self::Lazy),
            "OFFLINE" => Some(Self::Offline),
            "REQ" => Some(Self::Req),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "pccs-rs",
    about = "Rust PCCS — Intel PCCS replacement (RocksDB, Caddy-friendly HTTP)"
)]
pub struct Cli {
    #[arg(long, env = "PCCS_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long, env = "PCCS_HOST")]
    pub host: Option<String>,

    #[arg(long, env = "PCCS_PORT")]
    pub port: Option<u16>,

    /// Plain HTTP (Caddy / reverse-proxy). Default on unless --https.
    #[arg(long, default_value_t = false)]
    pub http: bool,

    #[arg(long, default_value_t = false)]
    pub https: bool,

    #[arg(long)]
    pub cert: Option<PathBuf>,

    #[arg(long)]
    pub key: Option<PathBuf>,

    #[arg(long, value_enum, env = "PCCS_CACHE_MODE")]
    pub cache_mode: Option<CacheMode>,

    #[arg(long, env = "PCCS_USER_TOKEN_HASH")]
    pub user_token_hash: Option<String>,

    #[arg(long, env = "PCCS_ADMIN_TOKEN_HASH")]
    pub admin_token_hash: Option<String>,

    #[arg(long, env = "PCCS_URI")]
    pub uri: Option<String>,

    #[arg(long, env = "PCCS_API_KEY")]
    pub api_key: Option<String>,

    #[arg(long, env = "PCCS_PROXY")]
    pub proxy: Option<String>,

    #[arg(long, env = "PCCS_REFRESH_SCHEDULE")]
    pub refresh_schedule: Option<String>,

    #[arg(long, env = "PCCS_DB_PATH")]
    pub db_path: Option<PathBuf>,

    #[arg(long, env = "PCCS_LOG_LEVEL")]
    pub log_level: Option<String>,

    #[arg(long, env = "PCCS_MAX_BODY")]
    pub max_body_size: Option<String>,

    #[arg(long, env = "PCCS_SEED")]
    pub seed: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub no_seed: bool,

    /// RocksDB uncompressed block cache (MiB). Default 8 (stock LRU).
    #[arg(long = "rocksdb-block-cache-mb", env = "PCCS_ROCKSDB_BLOCK_CACHE_MB")]
    pub block_cache_mb: Option<usize>,

    /// RocksDB memtable write buffer (MiB). Default 64.
    #[arg(long = "rocksdb-write-buffer-mb", env = "PCCS_ROCKSDB_WRITE_BUFFER_MB")]
    pub write_buffer_mb: Option<usize>,

    /// Max in-memory memtables. Default 2.
    #[arg(long = "rocksdb-max-write-buffers")]
    pub max_write_buffers: Option<i32>,

    /// Max open files (-1 = unlimited). Default -1.
    #[arg(long = "rocksdb-max-open-files", allow_hyphen_values = true)]
    pub max_open_files: Option<i32>,

    /// Time allowed to *receive* a request (headers + body), like Node's
    /// `server.requestTimeout`. Does not bound response production. Default 15.
    #[arg(long, env = "PCCS_REQUEST_TIMEOUT_SECONDS")]
    pub request_timeout_seconds: Option<u64>,

    /// Request-header read timeout (seconds). Default 10.
    #[arg(long, env = "PCCS_HEADERS_TIMEOUT_SECONDS")]
    pub headers_timeout_seconds: Option<u64>,

    /// Keep-alive idle timeout (seconds). Default 60.
    #[arg(long, env = "PCCS_KEEPALIVE_TIMEOUT_SECONDS")]
    pub keepalive_timeout_seconds: Option<u64>,

    /// Max concurrent upstream PCS requests. Default 64.
    #[arg(long, env = "PCCS_UPSTREAM_MAX_CONCURRENT")]
    pub upstream_max_concurrent: Option<usize>,

    /// Max attempts per upstream PCS request. Default 6.
    #[arg(long, env = "PCCS_UPSTREAM_MAX_ATTEMPTS")]
    pub upstream_max_attempts: Option<u32>,

    /// Enable the built-in dev token hashes (SHA-512 of "user" / "admin").
    /// Local development and benchmarking only — never in production.
    #[arg(long, default_value_t = false)]
    pub dev_tokens: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    #[serde(rename = "HTTPS_PORT")]
    https_port: Option<u16>,
    #[serde(rename = "hosts")]
    hosts: Option<String>,
    uri: Option<String>,
    #[serde(rename = "ApiKey")]
    api_key: Option<String>,
    proxy: Option<String>,
    #[serde(rename = "RefreshSchedule")]
    refresh_schedule: Option<String>,
    #[serde(rename = "UserTokenHash")]
    user_token_hash: Option<String>,
    #[serde(rename = "AdminTokenHash")]
    admin_token_hash: Option<String>,
    #[serde(rename = "CachingFillMode")]
    caching_fill_mode: Option<String>,
    #[serde(rename = "LogLevel")]
    log_level: Option<String>,
    #[serde(rename = "DB_PATH")]
    db_path: Option<PathBuf>,
    #[serde(rename = "MaxRequestBodySize")]
    max_request_body_size: Option<String>,
    #[serde(rename = "RocksDbBlockCacheMb")]
    block_cache_mb: Option<usize>,
    #[serde(rename = "RocksDbWriteBufferMb")]
    write_buffer_mb: Option<usize>,
    #[serde(rename = "RocksDbMaxWriteBuffers")]
    max_write_buffers: Option<i32>,
    #[serde(rename = "RocksDbMaxOpenFiles")]
    max_open_files: Option<i32>,
    #[serde(rename = "RequestTimeoutSeconds")]
    request_timeout_seconds: Option<u64>,
    #[serde(rename = "HeadersTimeoutSeconds")]
    headers_timeout_seconds: Option<u64>,
    #[serde(rename = "KeepAliveTimeoutSeconds")]
    keepalive_timeout_seconds: Option<u64>,
    #[serde(rename = "UpstreamMaxConcurrent")]
    upstream_max_concurrent: Option<usize>,
    #[serde(rename = "UpstreamMaxAttempts")]
    upstream_max_attempts: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub http: bool,
    pub https: bool,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub cache_mode: CacheMode,
    pub user_token_hash: String,
    pub admin_token_hash: String,
    pub uri: String,
    pub api_key: String,
    pub proxy: String,
    pub refresh_schedule: String,
    pub db_path: PathBuf,
    pub log_level: String,
    pub max_body_size: usize,
    pub seed: Option<PathBuf>,
    pub no_seed: bool,
    pub block_cache_mb: usize,
    pub write_buffer_mb: usize,
    pub max_write_buffers: i32,
    pub max_open_files: i32,
    pub request_timeout_secs: u64,
    pub headers_timeout_secs: u64,
    pub keepalive_timeout_secs: u64,
    pub upstream_max_concurrent: usize,
    pub upstream_max_attempts: u32,
    /// Problems noticed while parsing config, before tracing exists. `main`
    /// logs these right after the subscriber is installed; see
    /// `parse_body_size_reporting`.
    pub warnings: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let rocks = RocksDbOpts::default();
        Self {
            host: "127.0.0.1".into(),
            port: 8081,
            http: true,
            https: false,
            cert: PathBuf::from("certs/file.crt"),
            key: PathBuf::from("certs/private.pem"),
            cache_mode: CacheMode::Lazy,
            // Fail closed: no built-in token hash. An unset hash means every
            // request that needs that token gets 401 (see `validate_token_hashes`).
            user_token_hash: String::new(),
            admin_token_hash: String::new(),
            uri: DEFAULT_URI.into(),
            api_key: String::new(),
            proxy: String::new(),
            refresh_schedule: DEFAULT_REFRESH.into(),
            db_path: PathBuf::from("pccs-db"),
            log_level: "info".into(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            seed: None,
            no_seed: false,
            block_cache_mb: rocks.block_cache_mb,
            write_buffer_mb: rocks.write_buffer_mb,
            max_write_buffers: rocks.max_write_buffers,
            max_open_files: rocks.max_open_files,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            headers_timeout_secs: DEFAULT_HEADERS_TIMEOUT_SECS,
            keepalive_timeout_secs: DEFAULT_KEEPALIVE_TIMEOUT_SECS,
            upstream_max_concurrent: DEFAULT_UPSTREAM_MAX_CONCURRENT,
            upstream_max_attempts: DEFAULT_UPSTREAM_MAX_ATTEMPTS,
            warnings: Vec::new(),
        }
    }
}

impl Config {
    /// Tests / bench: temp DB, no upstream, built-in dev token hashes.
    pub fn test_default() -> Self {
        let dir = std::env::temp_dir().join(format!("pccs-rs-test-{}", uuid::Uuid::new_v4()));
        Self {
            uri: String::new(),
            db_path: dir,
            no_seed: false,
            cache_mode: CacheMode::Lazy,
            user_token_hash: DEFAULT_USER_TOKEN_HASH.into(),
            admin_token_hash: DEFAULT_ADMIN_TOKEN_HASH.into(),
            ..Self::default()
        }
    }

    /// Node `middleware/auth.js` `validateTokenHashes`: an unset or malformed
    /// hash disables the endpoints guarded by that token (they answer 401).
    pub fn validate_token_hashes(&self) {
        for (name, hash, what) in [
            (
                "UserTokenHash",
                &self.user_token_hash,
                "user-token endpoints",
            ),
            (
                "AdminTokenHash",
                &self.admin_token_hash,
                "admin-token endpoints",
            ),
        ] {
            if !is_sha512_hex(hash) {
                tracing::error!("{name} not configured: {what} disabled");
            }
        }
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn pcs_version(&self) -> u32 {
        crate::validate::api_version_from_url(&self.uri).unwrap_or(4)
    }

    pub fn uri_host(&self) -> Option<String> {
        uri_host(&self.uri)
    }

    pub fn is_intel_upstream(&self) -> bool {
        self.uri_host().is_some_and(|h| {
            h == "trustedservices.intel.com" || h.ends_with(".trustedservices.intel.com")
        })
    }

    pub fn has_upstream(&self) -> bool {
        !self.uri.trim().is_empty()
    }

    pub fn rocksdb_opts(&self) -> RocksDbOpts {
        RocksDbOpts {
            block_cache_mb: self.block_cache_mb,
            write_buffer_mb: self.write_buffer_mb,
            max_write_buffers: self.max_write_buffers,
            max_open_files: self.max_open_files,
        }
    }
}

/// `128` lowercase/uppercase hex characters, like Node's `SHA512_HEX_REGEX`.
pub fn is_sha512_hex(s: &str) -> bool {
    s.len() == 128 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Host part of a URL, lowercased. No scheme is tolerated (`host:port/path`).
pub fn uri_host(uri: &str) -> Option<String> {
    let rest = match uri.split_once("://") {
        Some((_, r)) => r,
        None => uri,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// `"2MB"` / `"512KB"` / `"1048576"` / `"1048576B"`. Anything else falls back to
/// the 2MB default instead of silently returning a few bytes.
///
/// Config parsing runs *before* the tracing subscriber exists, so a `warn!`
/// here would be swallowed. Callers that can report push onto
/// `Config::warnings`, which `main` drains once logging is up.
pub fn parse_body_size(s: &str) -> usize {
    parse_body_size_reporting(s, &mut Vec::new())
}

fn parse_body_size_reporting(s: &str, warnings: &mut Vec<String>) -> usize {
    match try_parse_body_size(s) {
        Some(n) => n,
        None => {
            warnings.push(format!(
                "MaxRequestBodySize {s:?} is not a valid size; using 2MB"
            ));
            DEFAULT_MAX_BODY_SIZE
        }
    }
}

fn try_parse_body_size(s: &str) -> Option<usize> {
    let t = s.trim();
    let upper = t.to_ascii_uppercase();
    let (num, mul) = if let Some(n) = upper.strip_suffix("MB") {
        (n.trim(), 1024 * 1024)
    } else if let Some(n) = upper.strip_suffix("KB") {
        (n.trim(), 1024)
    } else if let Some(n) = upper.strip_suffix('B') {
        (n.trim(), 1)
    } else {
        (upper.trim(), 1)
    };
    let n = num.parse::<usize>().ok()?;
    n.checked_mul(mul).filter(|v| *v > 0)
}

/// A config file that was named but cannot be read or parsed is fatal: silently
/// running on built-in defaults would hide a wrong `uri` or missing token hash.
fn load_file(path: &std::path::Path) -> FileConfig {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("config file {}: {e}", path.display());
        std::process::exit(1);
    });
    serde_json::from_str(&s).unwrap_or_else(|e| {
        eprintln!("config file {}: invalid JSON: {e}", path.display());
        std::process::exit(1);
    })
}

impl From<Cli> for Config {
    fn from(c: Cli) -> Self {
        let file = c.config.as_deref().map(load_file).unwrap_or_default();

        let mut cfg = Config::default();
        if let Some(h) = file.hosts {
            cfg.host = h;
        }
        if let Some(p) = file.https_port {
            cfg.port = p;
        }
        if let Some(u) = file.uri {
            cfg.uri = u;
        }
        if let Some(k) = file.api_key {
            cfg.api_key = k;
        }
        if let Some(p) = file.proxy {
            cfg.proxy = p;
        }
        if let Some(s) = file.refresh_schedule {
            cfg.refresh_schedule = s;
        }
        if let Some(h) = file.user_token_hash.filter(|s| !s.is_empty()) {
            cfg.user_token_hash = h;
        }
        if let Some(h) = file.admin_token_hash.filter(|s| !s.is_empty()) {
            cfg.admin_token_hash = h;
        }
        if let Some(m) = file.caching_fill_mode.as_deref().and_then(CacheMode::parse) {
            cfg.cache_mode = m;
        }
        if let Some(l) = file.log_level {
            cfg.log_level = l;
        }
        if let Some(p) = file.db_path {
            cfg.db_path = p;
        }
        if let Some(s) = file.max_request_body_size {
            cfg.max_body_size = parse_body_size_reporting(&s, &mut cfg.warnings);
        }
        if let Some(n) = file.block_cache_mb {
            cfg.block_cache_mb = n;
        }
        if let Some(n) = file.write_buffer_mb {
            cfg.write_buffer_mb = n;
        }
        if let Some(n) = file.max_write_buffers {
            cfg.max_write_buffers = n;
        }
        if let Some(n) = file.max_open_files {
            cfg.max_open_files = n;
        }
        if let Some(n) = file.request_timeout_seconds {
            cfg.request_timeout_secs = n;
        }
        if let Some(n) = file.headers_timeout_seconds {
            cfg.headers_timeout_secs = n;
        }
        if let Some(n) = file.keepalive_timeout_seconds {
            cfg.keepalive_timeout_secs = n;
        }
        if let Some(n) = file.upstream_max_concurrent {
            cfg.upstream_max_concurrent = n;
        }
        if let Some(n) = file.upstream_max_attempts {
            cfg.upstream_max_attempts = n;
        }

        if let Some(h) = c.host {
            cfg.host = h;
        }
        if let Some(p) = c.port {
            cfg.port = p;
        }
        cfg.https = c.https;
        cfg.http = c.http || !c.https;
        if let Some(p) = c.cert {
            cfg.cert = p;
        }
        if let Some(p) = c.key {
            cfg.key = p;
        }
        if let Some(m) = c.cache_mode {
            cfg.cache_mode = m;
        }
        if let Some(h) = c.user_token_hash {
            cfg.user_token_hash = h;
        }
        if let Some(h) = c.admin_token_hash {
            cfg.admin_token_hash = h;
        }
        if let Some(u) = c.uri {
            cfg.uri = u;
        }
        if let Some(k) = c.api_key {
            cfg.api_key = k;
        }
        if let Some(p) = c.proxy {
            cfg.proxy = p;
        }
        if let Some(s) = c.refresh_schedule {
            cfg.refresh_schedule = s;
        }
        if let Some(p) = c.db_path {
            cfg.db_path = p;
        }
        if let Some(l) = c.log_level {
            cfg.log_level = l;
        }
        if let Some(s) = c.max_body_size {
            cfg.max_body_size = parse_body_size_reporting(&s, &mut cfg.warnings);
        }
        if let Some(n) = c.block_cache_mb {
            cfg.block_cache_mb = n;
        }
        if let Some(n) = c.write_buffer_mb {
            cfg.write_buffer_mb = n;
        }
        if let Some(n) = c.max_write_buffers {
            cfg.max_write_buffers = n;
        }
        if let Some(n) = c.max_open_files {
            cfg.max_open_files = n;
        }
        if let Some(n) = c.request_timeout_seconds {
            cfg.request_timeout_secs = n;
        }
        if let Some(n) = c.headers_timeout_seconds {
            cfg.headers_timeout_secs = n;
        }
        if let Some(n) = c.keepalive_timeout_seconds {
            cfg.keepalive_timeout_secs = n;
        }
        if let Some(n) = c.upstream_max_concurrent {
            cfg.upstream_max_concurrent = n;
        }
        if let Some(n) = c.upstream_max_attempts {
            cfg.upstream_max_attempts = n;
        }
        if c.dev_tokens {
            if cfg.user_token_hash.is_empty() {
                cfg.user_token_hash = DEFAULT_USER_TOKEN_HASH.into();
            }
            if cfg.admin_token_hash.is_empty() {
                cfg.admin_token_hash = DEFAULT_ADMIN_TOKEN_HASH.into();
            }
        }
        cfg.seed = c.seed;
        cfg.no_seed = c.no_seed;
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rocksdb_opts_presets_differ() {
        let default = RocksDbOpts::default();
        let tiny = RocksDbOpts {
            block_cache_mb: 1,
            write_buffer_mb: 4,
            max_write_buffers: 1,
            max_open_files: 64,
        };
        assert_eq!(default.block_cache_mb, 8);
        assert_eq!(default.write_buffer_mb, 64);
        assert_eq!(default.max_write_buffers, 2);
        assert_eq!(default.max_open_files, -1);
        assert_ne!(default, tiny);
        assert_ne!(default.block_cache_bytes(), tiny.block_cache_bytes());
        assert_ne!(default.write_buffer_bytes(), tiny.write_buffer_bytes());
        assert_eq!(tiny.block_cache_bytes(), 1024 * 1024);
        assert_eq!(default.block_cache_bytes(), 8 * 1024 * 1024);
        assert_eq!(default.write_buffer_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn body_size_parses_or_falls_back_to_2mb() {
        assert_eq!(parse_body_size("2MB"), 2 * 1024 * 1024);
        assert_eq!(parse_body_size("512KB"), 512 * 1024);
        assert_eq!(parse_body_size("1048576"), 1048576);
        assert_eq!(parse_body_size("1048576B"), 1048576);
        assert_eq!(parse_body_size("2 mb"), 2 * 1024 * 1024);
        assert_eq!(parse_body_size("hello"), DEFAULT_MAX_BODY_SIZE);
        assert_eq!(parse_body_size(""), DEFAULT_MAX_BODY_SIZE);
        assert_eq!(parse_body_size("0"), DEFAULT_MAX_BODY_SIZE);
    }

    #[test]
    fn intel_upstream_is_a_host_check() {
        let intel = |uri: &str| {
            Config {
                uri: uri.into(),
                ..Config::default()
            }
            .is_intel_upstream()
        };
        assert!(intel(
            "https://api.trustedservices.intel.com/sgx/certification/v4/"
        ));
        assert!(intel(
            "https://validation.api.trustedservices.intel.com/sgx/certification/v4/"
        ));
        // Substring matches that must NOT leak the Intel API key.
        assert!(!intel("https://trustedservices.intel.com.evil.test/sgx/"));
        assert!(!intel("https://evil.test/?x=api.trustedservices.intel.com"));
        assert!(!intel("https://pccs.phala.network/sgx/certification/v4/"));
        assert!(!intel(""));
    }

    #[test]
    fn default_config_has_no_token_hashes() {
        let cfg = Config::default();
        assert!(cfg.user_token_hash.is_empty());
        assert!(cfg.admin_token_hash.is_empty());
        assert_eq!(cfg.uri, DEFAULT_URI);
        assert!(is_sha512_hex(DEFAULT_USER_TOKEN_HASH));
        assert!(is_sha512_hex(
            Config::test_default().admin_token_hash.as_str()
        ));
    }

    #[test]
    fn file_and_cli_override_rocksdb_knobs() {
        let json = r#"{
            "RocksDbBlockCacheMb": 2,
            "RocksDbWriteBufferMb": 8,
            "RocksDbMaxWriteBuffers": 2,
            "RocksDbMaxOpenFiles": 128
        }"#;
        let file: FileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(file.block_cache_mb, Some(2));
        assert_eq!(file.write_buffer_mb, Some(8));
        assert_eq!(file.max_write_buffers, Some(2));
        assert_eq!(file.max_open_files, Some(128));

        let cli = Cli::parse_from([
            "pccs-rs",
            "--rocksdb-block-cache-mb",
            "1",
            "--rocksdb-write-buffer-mb",
            "4",
            "--rocksdb-max-write-buffers",
            "1",
            "--rocksdb-max-open-files",
            "64",
        ]);
        let cfg = Config::from(cli);
        assert_eq!(
            cfg.rocksdb_opts(),
            RocksDbOpts {
                block_cache_mb: 1,
                write_buffer_mb: 4,
                max_write_buffers: 1,
                max_open_files: 64,
            }
        );
    }
}
