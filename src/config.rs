//! File + CLI config. Serve reads TOML; `config import` maps Node `pccs.json`.

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use toml_edit::{value, DocumentMut};

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

/// Packaged default path. systemd always passes `--config` pointing here.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/pccs-rs/config.toml";

/// Node `pccs_server.js` server timeouts.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;
pub const DEFAULT_HEADERS_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_KEEPALIVE_TIMEOUT_SECS: u64 = 60;

/// Upstream client limits (see `pcs.rs`).
pub const DEFAULT_UPSTREAM_MAX_CONCURRENT: usize = 64;
/// Node `pcs_client.js` MAX_RETRY_COUNT.
pub const DEFAULT_UPSTREAM_MAX_ATTEMPTS: u32 = 6;
/// How long an upstream connection may sit idle in the client pool before it is
/// dropped. Kept below the idle timeout of the peers we talk to (Intel PCS /
/// Azure front door, and a PCCS behind Caddy, all >= 90s) so we never hand a
/// request to a socket the far end has already closed. 0 disables pooling.
pub const DEFAULT_UPSTREAM_POOL_IDLE_SECS: u64 = 60;

pub const DEFAULT_MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

const DEFAULT_CONFIG_TOML: &str = include_str!("../packaging/config.toml");

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
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Start the PCCS HTTP server
    Serve(ServeArgs),
    /// Convert or update configuration files
    Config(ConfigCmd),
}

#[derive(Debug, Clone, Parser)]
pub struct ConfigCmd {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigCommand {
    /// Read a Node PCCS JSON config and write or update a TOML config
    Import {
        /// Path to pccs.json / default.json
        from: PathBuf,
        /// Destination TOML path
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        to: PathBuf,
    },
}

#[derive(Debug, Clone, Parser)]
pub struct ServeArgs {
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

    /// How long an idle upstream connection is kept pooled (seconds).
    /// 0 disables connection reuse. Default 60.
    #[arg(long, env = "PCCS_UPSTREAM_POOL_IDLE_SECONDS")]
    pub upstream_pool_idle_seconds: Option<u64>,

    /// Enable the built-in dev token hashes (SHA-512 of "user" / "admin").
    /// Local development and benchmarking only — never in production.
    #[arg(long, default_value_t = false)]
    pub dev_tokens: bool,
}

/// Node `service/config/default.json` / `pccs.json` field names.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct JsonConfig {
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
    #[serde(rename = "UpstreamPoolIdleSeconds")]
    upstream_pool_idle_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct TomlConfig {
    host: Option<String>,
    port: Option<u16>,
    https: Option<bool>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    cache_mode: Option<String>,
    user_token_hash: Option<String>,
    admin_token_hash: Option<String>,
    uri: Option<String>,
    api_key: Option<String>,
    proxy: Option<String>,
    refresh_schedule: Option<String>,
    db_path: Option<PathBuf>,
    log_level: Option<String>,
    max_request_body_size: Option<String>,
    rocksdb_block_cache_mb: Option<usize>,
    rocksdb_write_buffer_mb: Option<usize>,
    rocksdb_max_write_buffers: Option<i32>,
    rocksdb_max_open_files: Option<i32>,
    request_timeout_seconds: Option<u64>,
    headers_timeout_seconds: Option<u64>,
    keepalive_timeout_seconds: Option<u64>,
    upstream_max_concurrent: Option<usize>,
    upstream_max_attempts: Option<u32>,
    upstream_pool_idle_seconds: Option<u64>,
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
    pub upstream_pool_idle_secs: u64,
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
            upstream_pool_idle_secs: DEFAULT_UPSTREAM_POOL_IDLE_SECS,
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

    /// `implicit_config` is loaded when `--config` / `PCCS_CONFIG` is unset
    /// and that path exists. Tests pass `None` so a machine-local
    /// `/etc/pccs-rs/config.toml` cannot leak into them.
    pub fn from_serve_args(c: ServeArgs, implicit_config: Option<&Path>) -> Self {
        let path = match c.config.as_deref() {
            Some(p) => Some(p.to_path_buf()),
            None => implicit_config
                .filter(|p| p.is_file())
                .map(Path::to_path_buf),
        };
        let file = path.as_deref().map(load_toml).unwrap_or_default();

        let mut cfg = Config::default();
        apply_toml(&mut cfg, file);
        apply_cli(&mut cfg, c);
        cfg
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
fn load_toml(path: &Path) -> TomlConfig {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("config file {}: {e}", path.display());
        std::process::exit(1);
    });
    toml::from_str(&s).unwrap_or_else(|e| {
        eprintln!("config file {}: invalid TOML: {e}", path.display());
        std::process::exit(1);
    })
}

fn apply_toml(cfg: &mut Config, file: TomlConfig) {
    if let Some(h) = file.host {
        cfg.host = h;
    }
    if let Some(p) = file.port {
        cfg.port = p;
    }
    if let Some(https) = file.https {
        cfg.https = https;
        cfg.http = !https;
    }
    if let Some(p) = file.cert {
        cfg.cert = p;
    }
    if let Some(p) = file.key {
        cfg.key = p;
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
    if let Some(m) = file.cache_mode.as_deref().and_then(CacheMode::parse) {
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
    if let Some(n) = file.rocksdb_block_cache_mb {
        cfg.block_cache_mb = n;
    }
    if let Some(n) = file.rocksdb_write_buffer_mb {
        cfg.write_buffer_mb = n;
    }
    if let Some(n) = file.rocksdb_max_write_buffers {
        cfg.max_write_buffers = n;
    }
    if let Some(n) = file.rocksdb_max_open_files {
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
    if let Some(n) = file.upstream_pool_idle_seconds {
        cfg.upstream_pool_idle_secs = n;
    }
}

fn apply_cli(cfg: &mut Config, c: ServeArgs) {
    if let Some(h) = c.host {
        cfg.host = h;
    }
    if let Some(p) = c.port {
        cfg.port = p;
    }
    // Only override the file when a transport flag is actually passed.
    // `--https` / `--http` are clap store-true, so the unset default is false.
    if c.https {
        cfg.https = true;
        cfg.http = false;
    } else if c.http {
        cfg.https = false;
        cfg.http = true;
    }
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
    if let Some(n) = c.upstream_pool_idle_seconds {
        cfg.upstream_pool_idle_secs = n;
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
}

impl From<ServeArgs> for Config {
    fn from(c: ServeArgs) -> Self {
        Self::from_serve_args(c, Some(Path::new(DEFAULT_CONFIG_PATH)))
    }
}

fn load_json(path: &Path) -> Result<JsonConfig, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("config file {}: {e}", path.display()))?;
    serde_json::from_str(&s)
        .map_err(|e| format!("config file {}: invalid JSON: {e}", path.display()))
}

fn toml_i64(n: impl Into<i64>) -> toml_edit::Item {
    value(n.into())
}

fn apply_json_to_toml(doc: &mut DocumentMut, src: &JsonConfig) {
    if let Some(ref v) = src.hosts {
        doc["host"] = value(v.as_str());
    }
    if let Some(v) = src.https_port {
        doc["port"] = toml_i64(v);
    }
    if let Some(ref v) = src.uri {
        doc["uri"] = value(v.as_str());
    }
    if let Some(ref v) = src.api_key {
        doc["api_key"] = value(v.as_str());
    }
    if let Some(ref v) = src.proxy {
        doc["proxy"] = value(v.as_str());
    }
    if let Some(ref v) = src.refresh_schedule {
        doc["refresh_schedule"] = value(v.as_str());
    }
    if let Some(ref v) = src.user_token_hash {
        doc["user_token_hash"] = value(v.as_str());
    }
    if let Some(ref v) = src.admin_token_hash {
        doc["admin_token_hash"] = value(v.as_str());
    }
    if let Some(ref v) = src.caching_fill_mode {
        let mode = CacheMode::parse(v)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_else(|| v.to_ascii_lowercase());
        doc["cache_mode"] = value(mode);
    }
    if let Some(ref v) = src.log_level {
        doc["log_level"] = value(v.as_str());
    }
    if let Some(ref v) = src.db_path {
        doc["db_path"] = value(v.display().to_string());
    }
    if let Some(ref v) = src.max_request_body_size {
        doc["max_request_body_size"] = value(v.as_str());
    }
    if let Some(n) = src.block_cache_mb {
        doc["rocksdb_block_cache_mb"] = value(n as i64);
    }
    if let Some(n) = src.write_buffer_mb {
        doc["rocksdb_write_buffer_mb"] = value(n as i64);
    }
    if let Some(n) = src.max_write_buffers {
        doc["rocksdb_max_write_buffers"] = toml_i64(n);
    }
    if let Some(n) = src.max_open_files {
        doc["rocksdb_max_open_files"] = toml_i64(n);
    }
    if let Some(n) = src.request_timeout_seconds {
        doc["request_timeout_seconds"] = value(n as i64);
    }
    if let Some(n) = src.headers_timeout_seconds {
        doc["headers_timeout_seconds"] = value(n as i64);
    }
    if let Some(n) = src.keepalive_timeout_seconds {
        doc["keepalive_timeout_seconds"] = value(n as i64);
    }
    if let Some(n) = src.upstream_max_concurrent {
        doc["upstream_max_concurrent"] = value(n as i64);
    }
    if let Some(n) = src.upstream_max_attempts {
        doc["upstream_max_attempts"] = value(n as i64);
    }
    if let Some(n) = src.upstream_pool_idle_seconds {
        doc["upstream_pool_idle_seconds"] = value(n as i64);
    }
}

/// Read a Node PCCS JSON config and write or update `to` as TOML.
///
/// Missing destination: start from the packaged template. Existing
/// destination: keep keys and comments that the JSON does not mention.
pub fn import_pccs_json(from: &Path, to: &Path) -> Result<(), String> {
    let src = load_json(from)?;
    let mut doc = if to.is_file() {
        let s = std::fs::read_to_string(to).map_err(|e| format!("{}: {e}", to.display()))?;
        s.parse::<DocumentMut>()
            .map_err(|e| format!("{}: invalid TOML: {e}", to.display()))?
    } else {
        DEFAULT_CONFIG_TOML
            .parse::<DocumentMut>()
            .expect("packaged config.toml is valid TOML")
    };
    apply_json_to_toml(&mut doc, &src);
    if let Some(parent) = to.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(to, doc.to_string()).map_err(|e| format!("write {}: {e}", to.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ServeArgs` reads `PCCS_*` env vars for any flag not given inline; drop
    /// them so the process environment cannot leak into these tests. The
    /// environment is process-global and tests run in parallel, so the whole
    /// clear-and-parse sequence is serialised behind a lock.
    fn clear_pccs_env() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (key, _) in std::env::vars() {
            if key.starts_with("PCCS_") {
                std::env::remove_var(key);
            }
        }
        guard
    }

    fn parse_serve<I, T>(args: I) -> Config
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = ServeArgs::parse_from(args);
        Config::from_serve_args(cli, None)
    }

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
    fn cache_mode_parse_and_as_str() {
        assert_eq!(CacheMode::parse("LAZY"), Some(CacheMode::Lazy));
        assert_eq!(CacheMode::parse("offline"), Some(CacheMode::Offline));
        assert_eq!(CacheMode::parse("Req"), Some(CacheMode::Req));
        assert_eq!(CacheMode::parse("bogus"), None);
        assert_eq!(CacheMode::Lazy.as_str(), "LAZY");
        assert_eq!(CacheMode::Offline.as_str(), "OFFLINE");
        assert_eq!(CacheMode::Req.as_str(), "REQ");
    }

    #[test]
    fn uri_host_variants() {
        assert_eq!(
            uri_host("https://API.Example.COM:8443/sgx/").as_deref(),
            Some("api.example.com")
        );
        // No scheme is tolerated (`host:port/path`).
        assert_eq!(
            uri_host("example.com:8081/x").as_deref(),
            Some("example.com")
        );
        // Userinfo is stripped.
        assert_eq!(
            uri_host("https://user:pass@example.com/x").as_deref(),
            Some("example.com")
        );
        // IPv6 literal in brackets.
        assert_eq!(uri_host("http://[::1]:8081/").as_deref(), Some("::1"));
        assert_eq!(uri_host(""), None);
        assert_eq!(uri_host("https:///path"), None);
    }

    #[test]
    fn derived_values() {
        let cfg = Config {
            host: "0.0.0.0".into(),
            port: 9999,
            uri: "https://example.test/sgx/certification/v3/".into(),
            ..Config::default()
        };
        assert_eq!(cfg.bind_addr(), "0.0.0.0:9999");
        assert_eq!(cfg.pcs_version(), 3);
        assert!(cfg.has_upstream());
        // A URI without a version segment falls back to v4.
        assert_eq!(Config::default().pcs_version(), 4);
        let empty = Config {
            uri: "  ".into(),
            ..Config::default()
        };
        assert!(!empty.has_upstream());
    }

    #[test]
    fn sha512_hex_check() {
        assert!(is_sha512_hex(&"a".repeat(128)));
        assert!(is_sha512_hex(&"A0".repeat(64)));
        assert!(!is_sha512_hex(&"a".repeat(127)));
        assert!(!is_sha512_hex(&"g".repeat(128)));
    }

    #[test]
    fn validate_token_hashes_only_logs() {
        // Must not panic or mutate; it only logs which endpoints are disabled.
        Config::default().validate_token_hashes();
        Config::test_default().validate_token_hashes();
    }

    #[test]
    fn file_then_cli_precedence() {
        let _env = clear_pccs_env();
        let dir = std::env::temp_dir().join(format!("pccs-rs-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
                port = 8443
                host = "0.0.0.0"
                uri = "https://file.example/sgx/certification/v4/"
                api_key = "file-key"
                proxy = "http://proxy.example:8080"
                refresh_schedule = "0 0 2 * * *"
                user_token_hash = "file-user-hash"
                admin_token_hash = "file-admin-hash"
                cache_mode = "OFFLINE"
                log_level = "debug"
                db_path = "/tmp/file-db"
                max_request_body_size = "1MB"
                request_timeout_seconds = 5
                headers_timeout_seconds = 6
                keepalive_timeout_seconds = 7
                upstream_max_concurrent = 8
                upstream_max_attempts = 9
                upstream_pool_idle_seconds = 10
            "#,
        )
        .unwrap();

        // File values apply where the CLI is silent.
        let cfg = parse_serve(["pccs-rs", "--config", path.to_str().unwrap()]);
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.uri, "https://file.example/sgx/certification/v4/");
        assert_eq!(cfg.api_key, "file-key");
        assert_eq!(cfg.proxy, "http://proxy.example:8080");
        assert_eq!(cfg.refresh_schedule, "0 0 2 * * *");
        assert_eq!(cfg.user_token_hash, "file-user-hash");
        assert_eq!(cfg.admin_token_hash, "file-admin-hash");
        assert_eq!(cfg.cache_mode, CacheMode::Offline);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.db_path, PathBuf::from("/tmp/file-db"));
        assert_eq!(cfg.max_body_size, 1024 * 1024);
        assert_eq!(cfg.request_timeout_secs, 5);
        assert_eq!(cfg.headers_timeout_secs, 6);
        assert_eq!(cfg.keepalive_timeout_secs, 7);
        assert_eq!(cfg.upstream_max_concurrent, 8);
        assert_eq!(cfg.upstream_max_attempts, 9);
        assert_eq!(cfg.upstream_pool_idle_secs, 10);

        // CLI wins over the file.
        let cfg = parse_serve([
            "pccs-rs",
            "--config",
            path.to_str().unwrap(),
            "--host",
            "127.0.0.2",
            "--port",
            "9000",
            "--cache-mode",
            "req",
            "--user-token-hash",
            "cli-user",
            "--admin-token-hash",
            "cli-admin",
            "--uri",
            "https://cli.example/",
            "--api-key",
            "cli-key",
            "--proxy",
            "http://cli-proxy:1",
            "--refresh-schedule",
            "0 0 3 * * *",
            "--db-path",
            "/tmp/cli-db",
            "--log-level",
            "trace",
            "--max-body-size",
            "4MB",
            "--request-timeout-seconds",
            "15",
            "--headers-timeout-seconds",
            "16",
            "--keepalive-timeout-seconds",
            "17",
            "--upstream-max-concurrent",
            "18",
            "--upstream-max-attempts",
            "19",
            "--upstream-pool-idle-seconds",
            "20",
            "--seed",
            "/tmp/seed.json",
            "--no-seed",
            "--https",
            "--cert",
            "/tmp/c.crt",
            "--key",
            "/tmp/k.pem",
        ]);
        assert_eq!(cfg.host, "127.0.0.2");
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.cache_mode, CacheMode::Req);
        assert_eq!(cfg.user_token_hash, "cli-user");
        assert_eq!(cfg.admin_token_hash, "cli-admin");
        assert_eq!(cfg.uri, "https://cli.example/");
        assert_eq!(cfg.api_key, "cli-key");
        assert_eq!(cfg.proxy, "http://cli-proxy:1");
        assert_eq!(cfg.refresh_schedule, "0 0 3 * * *");
        assert_eq!(cfg.db_path, PathBuf::from("/tmp/cli-db"));
        assert_eq!(cfg.log_level, "trace");
        assert_eq!(cfg.max_body_size, 4 * 1024 * 1024);
        assert_eq!(cfg.request_timeout_secs, 15);
        assert_eq!(cfg.headers_timeout_secs, 16);
        assert_eq!(cfg.keepalive_timeout_secs, 17);
        assert_eq!(cfg.upstream_max_concurrent, 18);
        assert_eq!(cfg.upstream_max_attempts, 19);
        assert_eq!(cfg.upstream_pool_idle_secs, 20);
        assert_eq!(cfg.seed, Some(PathBuf::from("/tmp/seed.json")));
        assert!(cfg.no_seed);
        assert!(cfg.https);
        assert!(!cfg.http, "--https turns plain HTTP off");
        assert_eq!(cfg.cert, PathBuf::from("/tmp/c.crt"));
        assert_eq!(cfg.key, PathBuf::from("/tmp/k.pem"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn toml_https_survives_without_cli_flag() {
        let _env = clear_pccs_env();
        let dir = std::env::temp_dir().join(format!("pccs-rs-https-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "https = true\ncert = \"/tmp/c.crt\"\nkey = \"/tmp/k.pem\"\n",
        )
        .unwrap();
        let cfg = parse_serve(["pccs-rs", "--config", path.to_str().unwrap()]);
        assert!(cfg.https);
        assert!(!cfg.http);
        assert_eq!(cfg.cert, PathBuf::from("/tmp/c.crt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_flag_and_dev_tokens() {
        let _env = clear_pccs_env();
        let cfg = parse_serve(["pccs-rs", "--http", "--dev-tokens"]);
        assert!(cfg.http);
        assert!(!cfg.https);
        assert_eq!(cfg.user_token_hash, DEFAULT_USER_TOKEN_HASH);
        assert_eq!(cfg.admin_token_hash, DEFAULT_ADMIN_TOKEN_HASH);

        // --dev-tokens never overwrites an explicit hash.
        let cfg = parse_serve(["pccs-rs", "--dev-tokens", "--user-token-hash", "custom"]);
        assert_eq!(cfg.user_token_hash, "custom");
        assert_eq!(cfg.admin_token_hash, DEFAULT_ADMIN_TOKEN_HASH);
    }

    #[test]
    fn bad_max_body_warns_instead_of_panicking() {
        let _env = clear_pccs_env();
        let cfg = parse_serve(["pccs-rs", "--max-body-size", "huge"]);
        assert_eq!(cfg.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("huge"));
    }

    #[test]
    fn file_and_cli_override_rocksdb_knobs() {
        let _env = clear_pccs_env();
        let raw = r#"
            rocksdb_block_cache_mb = 2
            rocksdb_write_buffer_mb = 8
            rocksdb_max_write_buffers = 2
            rocksdb_max_open_files = 128
        "#;
        let file: TomlConfig = toml::from_str(raw).unwrap();
        assert_eq!(file.rocksdb_block_cache_mb, Some(2));
        assert_eq!(file.rocksdb_write_buffer_mb, Some(8));
        assert_eq!(file.rocksdb_max_write_buffers, Some(2));
        assert_eq!(file.rocksdb_max_open_files, Some(128));

        let cfg = parse_serve([
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

    #[test]
    fn implicit_config_path_only_when_file_exists() {
        let _env = clear_pccs_env();
        let dir = std::env::temp_dir().join(format!("pccs-rs-implicit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        let missing = ServeArgs::parse_from(["pccs-rs"]);
        let cfg = Config::from_serve_args(missing, Some(path.as_path()));
        assert_eq!(cfg.api_key, "");

        std::fs::write(&path, "api_key = \"from-implicit\"\n").unwrap();
        let present = ServeArgs::parse_from(["pccs-rs"]);
        let cfg = Config::from_serve_args(present, Some(path.as_path()));
        assert_eq!(cfg.api_key, "from-implicit");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn top_level_cli_requires_subcommand() {
        let _env = clear_pccs_env();
        assert!(Cli::try_parse_from(["pccs-rs"]).is_err());
        let cli = Cli::try_parse_from(["pccs-rs", "serve", "--http"]).unwrap();
        assert!(matches!(cli.command, Command::Serve(_)));
    }

    #[test]
    fn packaged_config_template_is_valid_toml() {
        let file: TomlConfig = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(file.api_key.as_deref(), Some(""));
        assert_eq!(file.db_path.as_deref(), Some(Path::new("/var/lib/pccs-rs")));
    }

    #[test]
    fn import_pccs_json_creates_and_merges() {
        let dir = std::env::temp_dir().join(format!("pccs-rs-import-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("pccs.json");
        let toml_path = dir.join("config.toml");
        std::fs::write(
            &json,
            r#"{
                "HTTPS_PORT": 8443,
                "hosts": "0.0.0.0",
                "uri": "https://file.example/sgx/certification/v4/",
                "ApiKey": "imported-key",
                "CachingFillMode": "REQ",
                "DB_PATH": "/tmp/imported-db",
                "RocksDbMaxOpenFiles": -1
            }"#,
        )
        .unwrap();

        import_pccs_json(&json, &toml_path).unwrap();
        let text = std::fs::read_to_string(&toml_path).unwrap();
        assert!(text.contains("Intel PCS"), "template comments kept");
        let file: TomlConfig = toml::from_str(&text).unwrap();
        assert_eq!(file.port, Some(8443));
        assert_eq!(file.host.as_deref(), Some("0.0.0.0"));
        assert_eq!(file.api_key.as_deref(), Some("imported-key"));
        assert_eq!(file.cache_mode.as_deref(), Some("req"));
        assert_eq!(file.db_path.as_deref(), Some(Path::new("/tmp/imported-db")));
        assert_eq!(file.rocksdb_max_open_files, Some(-1));

        // Merge: keep keys the JSON does not mention, update those it does.
        std::fs::write(
            &toml_path,
            "# keep me\napi_key = \"old\"\nlog_level = \"trace\"\n",
        )
        .unwrap();
        std::fs::write(&json, r#"{"ApiKey":"new-key"}"#).unwrap();
        import_pccs_json(&json, &toml_path).unwrap();
        let text = std::fs::read_to_string(&toml_path).unwrap();
        assert!(text.contains("# keep me"));
        let file: TomlConfig = toml::from_str(&text).unwrap();
        assert_eq!(file.api_key.as_deref(), Some("new-key"));
        assert_eq!(file.log_level.as_deref(), Some("trace"));

        let err = import_pccs_json(&dir.join("missing.json"), &toml_path).unwrap_err();
        assert!(err.contains("missing.json"));
        std::fs::write(&json, "not-json").unwrap();
        let err = import_pccs_json(&json, &toml_path).unwrap_err();
        assert!(err.contains("invalid JSON"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
