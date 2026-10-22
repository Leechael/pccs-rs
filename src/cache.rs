//! CachingFillMode: LAZY / REQ / OFFLINE. Miss path talks to `PcsClient`.

use crate::config::{CacheMode, Config};
use crate::error::{self, PccsError};
use crate::keys;
use crate::pcs::{PckCertsResponse, PcsClient};
use crate::store::{
    AmdKdsRecord, IdentityRecord, NvidiaOcspRecord, PckCertRecord, PckCrlRecord, PlatformCert,
    PlatformCredentials, PlatformPool, PlatformPublication, RegisteredPlatform, Store, TcbRecord,
};
use crate::validate::UpdateType;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Node `Constants.PLATF_REG_NEW` / `PLATF_REG_NOT_AVAILABLE`.
const PLATF_REG_NEW: u8 = 0;
const PLATF_REG_NOT_AVAILABLE: u8 = 1;

/// Desired fetch credentials plus the context observed before an unknown
/// platform fetch or authenticated registration. No Debug: this value contains secret credentials.
struct PckFetchContext<'a> {
    enc_ppid: &'a str,
    platform_manifest: &'a str,
    expected: Option<PlatformCredentials>,
    unknown_get: bool,
}

impl PckFetchContext<'_> {
    fn publication(&self) -> PlatformPublication<'_> {
        if self.unknown_get && self.expected.is_none() {
            PlatformPublication::AbsentGet {
                enc_ppid: self.enc_ppid,
                platform_manifest: self.platform_manifest,
            }
        } else {
            PlatformPublication::Observed(self.expected.as_ref())
        }
    }
}

pub struct Cache {
    pub store: Store,
    pub pcs: PcsClient,
    pub mode: CacheMode,
    pub pcs_version: u32,
    pub is_intel: bool,
    /// Intel PCS + LAZY only: re-fetch a known platform's pool when a GET asks
    /// for a raw TCB the pool has never seen.
    pub pool_refetch_on_new_tcb: bool,
    /// Re-fetch known platform pools during the scheduled refresh.
    pub scheduled_pool_refresh: bool,
    /// Minimum time between two re-fetches of one platform.
    pub pool_refetch_interval: std::time::Duration,
    /// Wall-clock bound on one synchronous pool re-fetch.
    pub refetch_timeout: std::time::Duration,
    /// Bounded concurrency for the scheduled pool refresh.
    pub refresh_concurrency: usize,
    amd_kds_uri: String,
    amd_kds_cache_ttl_secs: u64,
    nvidia_rim_uri: String,
    nvidia_rim_cache_ttl_secs: u64,
    nvidia_nras_uri: String,
    nvidia_ocsp_uri: String,
    nvidia_ocsp_max_ttl_secs: u64,
    nvidia_ocsp_default_ttl_secs: u64,
    /// Per-key locks so N concurrent misses on the same key produce one
    /// upstream request; the losers re-read the store after acquiring.
    inflight: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    /// Only one refresh at a time; a second admin call waits for the first.
    refresh_lock: Mutex<()>,
    /// Recent upstream failures / non-200 responses per key; see `key_lock`.
    failures: Mutex<HashMap<String, (std::time::Instant, RecentOutcome)>>,
    /// Last attempted pool re-fetch per platform, success or failure. In
    /// memory only: losing it on restart just allows one extra fetch.
    refetch_marks: Mutex<HashMap<String, std::time::Instant>>,
}

/// How long a failed upstream fetch suppresses a retry by the requests already
/// queued behind it. Short on purpose — this is stampede control, not caching.
pub const FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Hard cap on remembered outcomes. Callers choose the keys, so a burst of
/// distinct keys inside one `FAILURE_TTL` must not grow the map without bound;
/// past the cap a new outcome is simply not remembered.
const RECENT_OUTCOMES_MAX: usize = 1024;

/// Largest non-200 body kept for replay. Larger ones are relayed, not memoised.
const RECENT_BODY_MAX: usize = 64 * 1024;

/// Upper bound on the synchronous pool re-fetch a `/pckcert` GET may run.
/// DCAP clients cache the PCK cert, so a stale first answer sticks: answer
/// inside a request-sized budget instead of the full upstream retry budget.
const POOL_REFETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Platforms refreshed at once by the scheduled run. The upstream client bounds
/// the requests themselves; this only bounds the tasks.
const POOL_REFRESH_CONCURRENCY: usize = 8;
#[derive(Clone)]
enum RecentOutcome {
    Err(PccsError),
    Response(AmdKdsResponse),
}

#[derive(Clone)]
pub struct AmdKdsResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub retry_after: Option<String>,
}

impl From<AmdKdsRecord> for AmdKdsResponse {
    fn from(rec: AmdKdsRecord) -> Self {
        Self {
            status: 200,
            body: rec.body,
            content_type: rec.content_type,
            content_disposition: rec.content_disposition,
            retry_after: None,
        }
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// AMD KDS host. A legacy `.../vcek/v1` or `.../vlek/v1` suffix is stripped so
/// `/vcek/` and `/vlek/` request paths can be appended without doubling.
fn normalize_amd_kds_host(uri: &str) -> String {
    let mut host = uri.trim().trim_end_matches('/').to_string();
    for suffix in ["/vcek/v1", "/vlek/v1"] {
        if let Some(stripped) = host.strip_suffix(suffix) {
            host = stripped.trim_end_matches('/').to_string();
            break;
        }
    }
    host
}

/// NVIDIA RIM host. A legacy `.../v1/rim` suffix is stripped so `/v1/rim/`
/// request paths can be appended without doubling.
fn normalize_nvidia_rim_host(uri: &str) -> String {
    let host = uri.trim().trim_end_matches('/').to_string();
    host.strip_suffix("/v1/rim")
        .map(|stripped| stripped.trim_end_matches('/').to_string())
        .unwrap_or(host)
}

fn join_host_path(host: &str, path_and_query: &str) -> String {
    let path_and_query = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    format!("{host}{path_and_query}")
}

fn split_path_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    }
}

fn is_alnum_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

const AMD_HWID_QUERY_PARAMS: &[&str] = &["blSPL", "fmcSPL", "snpSPL", "teeSPL", "ucodeSPL"];

fn is_spl_value(value: &str) -> bool {
    (1..=3).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u8>().is_ok()
}

fn canonicalize_query(query: Option<&str>, allowed: &[&str]) -> Result<String, PccsError> {
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return Ok(String::new());
    };
    let mut seen: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.is_empty() {
            return Err(error::INVALID_REQ);
        }
        if !allowed.iter().any(|allowed| *allowed == key) {
            return Err(error::INVALID_REQ);
        }
        if !is_spl_value(value) {
            return Err(error::INVALID_REQ);
        }
        if seen.iter().any(|(k, _)| k == key) {
            return Err(error::INVALID_REQ);
        }
        seen.push((key.to_string(), value.to_string()));
    }
    if seen.is_empty() {
        return Ok(String::new());
    }
    seen.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let encoded = seen.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    Ok(format!("?{encoded}"))
}

fn canonicalize_amd_kds(path_and_query: &str) -> Result<String, PccsError> {
    let (path, query) = split_path_query(path_and_query);
    let (prefix, rest) = if let Some(rest) = path.strip_prefix("/vcek/") {
        ("/vcek/", rest)
    } else if let Some(rest) = path.strip_prefix("/vlek/") {
        ("/vlek/", rest)
    } else {
        return Err(error::INVALID_REQ);
    };
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.len() != 3 || segs[0] != "v1" || !is_alnum_segment(segs[1]) {
        return Err(error::INVALID_REQ);
    }
    let product = segs[1];
    let last = segs[2];
    let query = match last {
        "cert_chain" | "crl" => canonicalize_query(query, &[])?,
        hwid if is_alnum_segment(hwid) => canonicalize_query(query, AMD_HWID_QUERY_PARAMS)?,
        _ => return Err(error::INVALID_REQ),
    };
    Ok(format!("{prefix}v1/{product}/{last}{query}"))
}

fn is_rim_id(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn canonicalize_nvidia_rim(path_and_query: &str) -> Result<String, PccsError> {
    let (path, query) = split_path_query(path_and_query);
    let rest = path.strip_prefix("/v1/rim/").ok_or(error::INVALID_REQ)?;
    if rest.contains('/') || !is_rim_id(rest) {
        return Err(error::INVALID_REQ);
    }
    let query = canonicalize_query(query, &[])?;
    Ok(format!("/v1/rim/{rest}{query}"))
}

impl Cache {
    pub fn new(store: Store, pcs: PcsClient, cfg: &Config) -> Self {
        Self {
            mode: cfg.cache_mode,
            pcs_version: cfg.pcs_version(),
            is_intel: cfg.is_intel_upstream(),
            amd_kds_uri: normalize_amd_kds_host(&cfg.amd_kds_uri),
            amd_kds_cache_ttl_secs: cfg.amd_kds_cache_ttl_secs,
            nvidia_rim_uri: normalize_nvidia_rim_host(&cfg.nvidia_rim_uri),
            nvidia_rim_cache_ttl_secs: cfg.nvidia_rim_cache_ttl_secs,
            nvidia_nras_uri: cfg.nvidia_nras_uri.trim().trim_end_matches('/').to_string(),
            nvidia_ocsp_uri: cfg.nvidia_ocsp_uri.trim().trim_end_matches('/').to_string(),
            nvidia_ocsp_max_ttl_secs: cfg.nvidia_ocsp_max_ttl_secs,
            nvidia_ocsp_default_ttl_secs: cfg.nvidia_ocsp_default_ttl_secs,
            store,
            pcs,
            pool_refetch_on_new_tcb: cfg.pool_refetch_on_new_tcb,
            scheduled_pool_refresh: cfg.scheduled_pool_refresh,
            pool_refetch_interval: std::time::Duration::from_secs(cfg.pool_refetch_interval_secs),
            refetch_timeout: POOL_REFETCH_TIMEOUT,
            refresh_concurrency: POOL_REFRESH_CONCURRENCY.min(cfg.upstream_max_concurrent.max(1)),
            inflight: Mutex::new(HashMap::new()),
            refresh_lock: Mutex::new(()),
            failures: Mutex::new(HashMap::new()),
            refetch_marks: Mutex::new(HashMap::new()),
        }
    }

    fn miss_v3(&self, version: u32) -> PccsError {
        if version == 3 && self.mode == CacheMode::Lazy {
            error::PCS_V3_REACHED_EOL
        } else {
            error::NO_CACHE_DATA
        }
    }

    /// Single-flight gate for one cache key.
    ///
    /// Returns `Err` instead of a guard when a sibling request failed upstream
    /// within the last `FAILURE_TTL`. Without that, N waiters queued behind a
    /// failing fetch each take their turn and hit the upstream serially, so one
    /// dead upstream turns a burst of requests into a burst of upstream calls
    /// (and a burst of `FAILURE_TTL`-long stalls). The window is deliberately
    /// short: it suppresses the stampede, it does not cache the error.
    async fn key_lock(&self, key: &str) -> Result<OwnedMutexGuard<()>, PccsError> {
        let lock = {
            let mut map = self.inflight.lock().await;
            if map.len() > 1024 {
                map.retain(|_, weak| weak.strong_count() > 0);
            }
            match map.get(key).and_then(Weak::upgrade) {
                Some(existing) => existing,
                None => {
                    let fresh = Arc::new(Mutex::new(()));
                    map.insert(key.to_string(), Arc::downgrade(&fresh));
                    fresh
                }
            }
        };
        let guard = lock.lock_owned().await;
        // Checked *after* acquiring, so it reflects the fetch we waited on.
        if let Some(e) = self.recent_failure(key).await {
            tracing::debug!("reusing recent upstream failure for {key}");
            return Err(e);
        }
        Ok(guard)
    }

    /// The error a sibling just got for this key, if it is still fresh.
    async fn recent_failure(&self, key: &str) -> Option<PccsError> {
        match self.recent_outcome(key).await {
            Some(RecentOutcome::Err(e)) => Some(e),
            _ => None,
        }
    }

    async fn recent_non200(&self, key: &str) -> Option<AmdKdsResponse> {
        match self.recent_outcome(key).await {
            Some(RecentOutcome::Response(r)) => Some(r),
            _ => None,
        }
    }

    async fn recent_outcome(&self, key: &str) -> Option<RecentOutcome> {
        let mut map = self.failures.lock().await;
        match map.get(key) {
            Some((at, outcome)) if at.elapsed() < FAILURE_TTL => Some(outcome.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    async fn remember(&self, key: &str, outcome: RecentOutcome) {
        if matches!(&outcome, RecentOutcome::Response(r) if r.body.len() > RECENT_BODY_MAX) {
            return;
        }
        let mut map = self.failures.lock().await;
        if map.len() >= RECENT_OUTCOMES_MAX && !map.contains_key(key) {
            map.retain(|_, (at, _)| at.elapsed() < FAILURE_TTL);
            if map.len() >= RECENT_OUTCOMES_MAX {
                tracing::debug!("recent outcome map is full; not remembering {key}");
                return;
            }
        }
        map.insert(key.to_string(), (std::time::Instant::now(), outcome));
    }

    /// Pass a fetch result through, remembering an upstream failure briefly so
    /// the waiters behind us do not each repeat it. Used as
    /// `self.note(&key, fetch().await)?`.
    async fn note<T>(&self, key: &str, result: Result<T, PccsError>) -> Result<T, PccsError> {
        if let Err(e) = &result {
            self.remember(key, RecentOutcome::Err(e.clone())).await;
        }
        result
    }

    /// Intel's issuer chain header is what makes a cached collateral verifiable.
    /// Node stores whatever `getHeaderValue` returned (`''` when the header is
    /// missing), which permanently poisons the cache with an unusable record.
    /// We still answer the request 1:1, but refuse to persist it, so the next
    /// request retries upstream instead of serving a chain-less body forever.
    fn cacheable(name: &str, chain: &str) -> bool {
        if chain.trim().is_empty() {
            tracing::warn!("upstream response is missing {name}; not caching it");
            return false;
        }
        true
    }

    pub async fn get_amd_kds(&self, path_and_query: &str) -> Result<AmdKdsResponse, PccsError> {
        let path_and_query = canonicalize_amd_kds(path_and_query)?;
        let url = join_host_path(&self.amd_kds_uri, &path_and_query);
        self.get_cached_url(
            url,
            self.amd_kds_cache_ttl_secs,
            "amd kds",
            keys::amd_kds,
            error::AMD_KDS_ACCESS_FAILURE,
            Store::get_amd_kds,
            Store::put_amd_kds,
        )
        .await
    }

    pub async fn get_nvidia_rim(&self, path_and_query: &str) -> Result<AmdKdsResponse, PccsError> {
        let path_and_query = canonicalize_nvidia_rim(path_and_query)?;
        let url = join_host_path(&self.nvidia_rim_uri, &path_and_query);
        self.get_cached_url(
            url,
            self.nvidia_rim_cache_ttl_secs,
            "nvidia rim",
            keys::nvidia_rim,
            error::NVIDIA_RIM_ACCESS_FAILURE,
            Store::get_nvidia_rim,
            Store::put_nvidia_rim,
        )
        .await
    }

    /// Stateless NVIDIA NRAS GPU attestation proxy. Not cached: the result is
    /// nonce-bound. OFFLINE never calls upstream. LAZY and REQ both proxy.
    pub async fn get_nvidia_nras(
        &self,
        body: &serde_json::Value,
    ) -> Result<AmdKdsResponse, PccsError> {
        if self.mode == CacheMode::Offline {
            return Err(error::SERVICE_UNAVAILABLE);
        }
        if self.nvidia_nras_uri.is_empty() {
            return Err(error::NVIDIA_NRAS_ACCESS_FAILURE);
        }
        let url = format!("{}/v3/attest/gpu", self.nvidia_nras_uri);
        let payload = serde_json::to_vec(body).map_err(|_| error::INVALID_REQ)?;
        self.store.record_upstream();
        let (status, hdrs, body) = self
            .pcs
            .post_json_once(&url, &payload)
            .await
            .map_err(|_| error::NVIDIA_NRAS_ACCESS_FAILURE)?;
        Ok(AmdKdsResponse {
            status,
            body,
            content_type: hdrs
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            content_disposition: None,
            retry_after: hdrs
                .get(hyper::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        })
    }
    /// Cached NVIDIA OCSP proxy. Cache key hashes the DER requestList.
    /// Expired entries are never served. OFFLINE never calls upstream;
    /// non-LAZY misses return NO_CACHE_DATA. A nonce-bearing request is a miss
    /// that is never cached: the responder echoes the nonce in its signed
    /// response, so a stored copy would fail another client's nonce check.
    pub async fn get_nvidia_ocsp(&self, body: &[u8]) -> Result<AmdKdsResponse, PccsError> {
        let request = crate::ocsp::parse_request(body)?;
        if request.has_nonce {
            self.store.record_miss();
            if self.mode != CacheMode::Lazy {
                return Err(error::NO_CACHE_DATA);
            }
            self.store.record_upstream();
            return self.post_nvidia_ocsp(body).await;
        }
        let cache_key = request.cache_key;
        let store_key = keys::nvidia_ocsp(&cache_key);
        let now = unix_time();
        if let Some(rec) = self.store.get_nvidia_ocsp(&cache_key) {
            if rec.expires_at > now {
                self.store.record_hit();
                tracing::debug!("cache hit nvidia ocsp");
                return Ok(AmdKdsResponse {
                    status: 200,
                    body: rec.body,
                    content_type: rec.content_type,
                    content_disposition: None,
                    retry_after: None,
                });
            }
            // LAZY drops it under the key lock instead.
            if self.mode != CacheMode::Lazy {
                self.drop_expired(&store_key);
            }
        }
        self.store.record_miss();
        tracing::info!("cache miss nvidia ocsp key={cache_key}");
        if self.mode != CacheMode::Lazy {
            return Err(error::NO_CACHE_DATA);
        }

        let _guard = self.key_lock(&store_key).await?;
        if let Some(rec) = self.recent_non200(&store_key).await {
            return Ok(rec);
        }
        let now = unix_time();
        if let Some(rec) = self.store.get_nvidia_ocsp(&cache_key) {
            if rec.expires_at > now {
                return Ok(AmdKdsResponse {
                    status: 200,
                    body: rec.body,
                    content_type: rec.content_type,
                    content_disposition: None,
                    retry_after: None,
                });
            }
            self.drop_expired(&store_key);
        }

        self.store.record_upstream();
        let resp = self.note(&store_key, self.post_nvidia_ocsp(body).await).await?;
        if resp.status != 200 {
            self.remember(&store_key, RecentOutcome::Response(resp.clone())).await;
            return Ok(resp);
        }

        let now_i64 = i64::try_from(unix_time()).map_err(|_| error::INTERNAL_ERROR)?;
        let expires_at = match crate::ocsp::response_cache_expiry(
            &resp.body,
            now_i64,
            self.nvidia_ocsp_max_ttl_secs,
            self.nvidia_ocsp_default_ttl_secs,
        ) {
            Ok(expires_at) => expires_at,
            Err(err) => {
                tracing::warn!("nvidia ocsp response not cacheable: {err}");
                // Still relay a successful upstream answer; just do not persist it.
                return Ok(resp);
            }
        };
        // deferred: hard size bound for the OCSP cache | impact: /ocsp is unauthenticated, so distinct CertIDs the responder answers with 200 can fill disk until their nextUpdate (at most nvidia_ocsp_max_ttl_secs) and the next scheduled sweep | trigger: auth or a quota on /ocsp is decided
        let rec = NvidiaOcspRecord {
            cache_key,
            body: resp.body.clone(),
            content_type: resp.content_type.clone(),
            fetched_at: unix_time(),
            expires_at,
        };
        self.store.put_nvidia_ocsp(&rec)?;
        Ok(AmdKdsResponse { retry_after: None, ..resp })
    }

    /// One POST to the OCSP responder. No configured host, 1xx and 3xx count
    /// as an access failure; every other status is relayed.
    async fn post_nvidia_ocsp(&self, body: &[u8]) -> Result<AmdKdsResponse, PccsError> {
        if self.nvidia_ocsp_uri.is_empty() {
            return Err(error::NVIDIA_OCSP_ACCESS_FAILURE);
        }
        let (status, headers, body) = self
            .pcs
            .post_bytes_once(&self.nvidia_ocsp_uri, "application/ocsp-request", body)
            .await
            .map_err(|_| error::NVIDIA_OCSP_ACCESS_FAILURE)?;
        if (100..200).contains(&status) || (300..400).contains(&status) {
            return Err(error::NVIDIA_OCSP_ACCESS_FAILURE);
        }
        let header = |name| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(AmdKdsResponse {
            status,
            body,
            content_type: header(axum::http::header::CONTENT_TYPE)
                .or_else(|| Some("application/ocsp-response".into())),
            content_disposition: None,
            retry_after: header(axum::http::header::RETRY_AFTER),
        })
    }

    async fn get_cached_url(
        &self,
        url: String,
        ttl: u64,
        kind: &'static str,
        key_for: fn(&str) -> String,
        access_failure: PccsError,
        load: fn(&Store, &str) -> Option<AmdKdsRecord>,
        save: fn(&Store, &AmdKdsRecord) -> Result<(), PccsError>,
    ) -> Result<AmdKdsResponse, PccsError> {
        let key = key_for(&url);
        let now = unix_time();
        if let Some(rec) = load(&self.store, &url) {
            // deferred: stale-if-error for AMD/NVIDIA | impact: after TTL expiry a throttled upstream turns every request into 502 while a copy exists on disk | trigger: user decision
            if now.saturating_sub(rec.fetched_at) < ttl {
                self.store.record_hit();
                tracing::debug!("cache hit {kind}");
                return Ok(rec.into());
            }
            // LAZY drops it under the key lock instead, so a concurrent fill
            // that just replaced it is never deleted.
            if self.mode != CacheMode::Lazy {
                self.drop_expired(&key);
            }
        }
        self.store.record_miss();
        tracing::info!("cache miss {kind} url={url}");
        if self.mode != CacheMode::Lazy {
            return Err(error::NO_CACHE_DATA);
        }

        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.recent_non200(&key).await {
            return Ok(rec);
        }
        let now = unix_time();
        if let Some(rec) = load(&self.store, &url) {
            // deferred: stale-if-error for AMD/NVIDIA | impact: after TTL expiry a throttled upstream turns every request into 502 while a copy exists on disk | trigger: user decision
            if now.saturating_sub(rec.fetched_at) < ttl {
                return Ok(rec.into());
            }
            self.drop_expired(&key);
        }

        self.store.record_upstream();
        let fetched = self.pcs.get_url(&url).await.map_err(|_| access_failure.clone());
        let (status, headers, body) = self.note(&key, fetched).await?;
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_disposition = headers
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let retry_after = headers
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if (100..200).contains(&status) || (300..400).contains(&status) {
            return self.note(&key, Err(access_failure)).await;
        }
        if status != 200 {
            let rec =
                AmdKdsResponse { status, body, content_type, content_disposition, retry_after };
            self.remember(&key, RecentOutcome::Response(rec.clone())).await;
            return Ok(rec);
        }
        let rec =
            AmdKdsRecord { url, body, content_type, content_disposition, fetched_at: unix_time() };
        save(&self.store, &rec)?;
        Ok(rec.into())
    }

    /// Read-through records are only replaced when the same URL is requested
    /// again, so an expired one is deleted as soon as a lookup sees it.
    fn drop_expired(&self, key: &str) {
        if let Err(e) = self.store.delete_key(key) {
            tracing::warn!("failed to delete expired {key}: {e}");
        }
    }

    /// Delete the expired read-through records no request came back for.
    fn sweep_expired(&self) {
        let now = unix_time();
        for (prefix, ttl) in [
            (keys::AMD_KDS, self.amd_kds_cache_ttl_secs),
            (keys::NVIDIA_RIM, self.nvidia_rim_cache_ttl_secs),
        ] {
            let expired = |rec: &AmdKdsRecord| now.saturating_sub(rec.fetched_at) >= ttl;
            log_sweep(prefix, self.store.sweep_prefix(prefix, expired));
        }
        let expired = |rec: &NvidiaOcspRecord| rec.expires_at <= now;
        log_sweep(keys::NVIDIA_OCSP, self.store.sweep_prefix(keys::NVIDIA_OCSP, expired));
    }

    // ---------------- pckcert ----------------

    /// Intel `pckcertService.getPckCert`: known platforms use a cached GET or
    /// local selection. The PCCS mirror adapter can forward missing raw keys in
    /// LAZY mode when local selection is unavailable.
    ///
    /// One documented deviation, Intel PCS + LAZY only: a request for a raw TCB
    /// the platform's pool has never seen re-fetches that pool first through
    /// `refetch_pool_for_new_raw_tcb`. Every other case keeps Node's behaviour.
    pub async fn get_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        enc_ppid: Option<&str>,
        version: u32,
    ) -> Result<PckCertRecord, PccsError> {
        // Hot path: an existence check, not a full pool deserialize. The pool
        // itself is only needed on a miss (local PCK cert selection below).
        let known_platform = self.store.has_platform(qeid, pceid);
        if known_platform {
            if let Some(rec) = self.store.get_pckcert(qeid, cpusvn, pcesvn, pceid) {
                self.store.record_hit();
                tracing::debug!("cache hit pckcert");
                return Ok(rec);
            }
        }
        self.store.record_miss();
        tracing::info!("cache miss pckcert qeid={qeid} pceid={pceid}");

        // Try local selection BEFORE upstream single-flight/negative-cache
        // handling: an unknown GET failure must not block selection after POST.
        // Intel 1.24 makes this terminal; only the separate LAZY PCCS adapter
        // may forward a raw key that cannot be selected locally.
        if known_platform {
            // Deviation from Node parity (Intel PCS + LAZY only): a raw TCB this
            // platform has never seen may have a certificate upstream now (TCB
            // raised by a BIOS/microcode update, or an Intel TCB recovery).
            // Re-fetch the pool with the *stored* credential, bounded and
            // throttled; on any failure fall through to exactly today's local
            // selection.
            if let Some(rec) =
                self.refetch_pool_for_new_raw_tcb(qeid, pceid, cpusvn, pcesvn, version).await
            {
                return Ok(rec);
            }
            match self.store.select_platform_cert(qeid, pceid, true, |pool| {
                self.select_from_pool(pool, cpusvn, pcesvn, pceid)
            }) {
                Ok(rec) => return Ok(rec),
                Err(e) if self.is_intel || self.mode != CacheMode::Lazy => return Err(e),
                Err(_) => {}
            }
        }

        let key = keys::pckcert(qeid, pceid, cpusvn, pcesvn);
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_pckcert(qeid, cpusvn, pcesvn, pceid) {
            return Ok(rec);
        }
        match self.mode {
            CacheMode::Offline | CacheMode::Req => Err(error::platform_unknown()),
            CacheMode::Lazy => {
                if version == 3 {
                    return Err(error::PCS_V3_REACHED_EOL);
                }
                let expected = self.store.get_platform_pool(qeid, pceid).map(|p| p.credentials());
                // A platform may have been registered while waiting for this
                // raw key. Intel still must not refill a known platform.
                if self.is_intel && expected.is_some() {
                    return self.store.select_platform_cert(qeid, pceid, true, |pool| {
                        self.select_from_pool(pool, cpusvn, pcesvn, pceid)
                    });
                }
                // PCCS GET is a proxy protocol, not Intel enrollment: forward
                // only the caller's optional PPID, never saved credentials.
                self.note(
                    &key,
                    self.fill_pckcert(
                        qeid,
                        cpusvn,
                        pcesvn,
                        pceid,
                        PckFetchContext {
                            enc_ppid: enc_ppid.unwrap_or(""),
                            platform_manifest: "",
                            expected,
                            unknown_get: true,
                        },
                    )
                    .await
                    .and_then(|rec| rec.ok_or(error::NO_CACHE_DATA)),
                )
                .await
            }
        }
    }

    /// Compute Node `pckcertService.pckCertSelection` without persistence.
    /// The store publishes the selected GET key and its raw mapping together.
    fn select_from_pool(
        &self,
        pool: &PlatformPool,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
    ) -> Result<PckCertRecord, PccsError> {
        if pool.certs.is_empty() {
            return Err(error::NO_CACHE_DATA);
        }
        // Node: always the SGX TCB info, EARLY first then STANDARD.
        let tcb = self
            .store
            .get_tcb(0, &pool.fmspc, self.pcs_version, UpdateType::Early)
            .or_else(|| self.store.get_tcb(0, &pool.fmspc, self.pcs_version, UpdateType::Standard))
            .ok_or_else(|| {
                tracing::error!("No TCB info for the fmspc : {}", pool.fmspc);
                error::NO_CACHE_DATA
            })?;
        self.select_from_pool_with_tcb(pool, cpusvn, pcesvn, pceid, &tcb)
    }

    /// Selection may use freshly fetched collateral without publishing it.
    fn select_from_pool_with_tcb(
        &self,
        pool: &PlatformPool,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        tcb: &TcbRecord,
    ) -> Result<PckCertRecord, PccsError> {
        let info = tcb.tcbinfo.get("tcbInfo").unwrap_or(&tcb.tcbinfo);
        let (tcbm, cert) =
            crate::selection::select_best_pck_cert(cpusvn, pcesvn, pceid, &pool.cert_pairs(), info)
                .map_err(|e| {
                    tracing::error!("Error during selection of PCK Cert: {e}");
                    error::NO_CACHE_DATA
                })?;

        let rec = PckCertRecord {
            qeid: pool.qe_id.clone(),
            pceid: pool.pce_id.clone(),
            cpusvn: cpusvn.to_ascii_uppercase(),
            pcesvn: pcesvn.to_ascii_uppercase(),
            cert,
            tcbm,
            fmspc: pool.fmspc.clone(),
            ca: pool.ca.clone(),
            issuer_chain: pool.issuer_chain.clone(),
            encrypted_ppid: if pool.enc_ppid.is_empty() {
                None
            } else {
                Some(pool.enc_ppid.clone())
            },
            platform_manifest: pool.platform_manifest.clone(),
        };
        Ok(rec)
    }

    /// Was `(cpusvn, pcesvn)` already mapped for this platform?
    fn raw_tcb_known(pool: &PlatformPool, cpusvn: &str, pcesvn: &str) -> bool {
        pool.raw_tcbs.iter().any(|r| {
            r.cpu_svn.eq_ignore_ascii_case(cpusvn) && r.pce_svn.eq_ignore_ascii_case(pcesvn)
        })
    }

    /// A full pool can only be re-fetched with a stored credential. The
    /// caller's request PPID is never one: Node stores it only for a platform
    /// the cache did not know, and an all-zero PPID is refused upstream.
    fn has_stored_credential(pool: &PlatformPool) -> bool {
        if !pool.platform_manifest.is_empty() {
            return true;
        }
        !pool.enc_ppid.is_empty() && !pool.enc_ppid.bytes().all(|b| b == b'0')
    }

    /// Whether this platform's last re-fetch attempt is old enough to retry.
    async fn refetch_due(&self, platform: &str) -> bool {
        if self.pool_refetch_interval.is_zero() {
            return true;
        }
        let marks = self.refetch_marks.lock().await;
        marks.get(platform).is_none_or(|at| at.elapsed() >= self.pool_refetch_interval)
    }

    /// Record an attempt *before* it runs: a broken upstream must not be retried
    /// by every new raw TCB of the same platform.
    async fn mark_refetch(&self, platform: &str) {
        let now = std::time::Instant::now();
        let mut marks = self.refetch_marks.lock().await;
        if marks.len() > 1024 {
            let interval = self.pool_refetch_interval;
            marks.retain(|_, at| interval.is_zero() || at.elapsed() < interval);
        }
        marks.insert(platform.to_string(), now);
    }

    /// Deviation from Node parity (Intel PCS + LAZY only). A raw TCB the pool
    /// has never seen means the platform's TCB was raised: BIOS/microcode update,
    /// or Intel publishing a TCB recovery. Intel then issues PCK certs for the
    /// new levels, but a locally cached pool can only answer with a lower-TCB
    /// cert, which DCAP appraises as `OutOfDate`.
    ///
    /// Verified upstream behaviour: `GET /pckcerts` with the encrypted PPID
    /// already stored for the platform returns the new levels, and a manifest
    /// POST with the stored manifest does too. No new registration is needed, so
    /// the pool is re-fetched with the stored credential and every known raw TCB
    /// is re-selected exactly as registration and refresh publish it.
    ///
    /// Runs synchronously — DCAP clients cache the PCK cert, so a stale first
    /// answer sticks — bounded by `refetch_timeout`. Any failure or timeout
    /// returns `None`, leaving the request to today's local selection with the
    /// old pool untouched: never worse than without this deviation.
    async fn refetch_pool_for_new_raw_tcb(
        &self,
        qeid: &str,
        pceid: &str,
        cpusvn: &str,
        pcesvn: &str,
        version: u32,
    ) -> Option<PckCertRecord> {
        if !self.pool_refetch_on_new_tcb
            || self.mode != CacheMode::Lazy
            || !self.is_intel
            || !self.pcs.enabled()
            || version < 4
            || self.pcs_version < 4
        {
            return None;
        }
        let pool = self.store.get_platform_pool(qeid, pceid)?;
        if Self::raw_tcb_known(&pool, cpusvn, pcesvn) || !Self::has_stored_credential(&pool) {
            return None;
        }
        // Single-flight per platform through the existing per-key lock, with
        // the throttle check inside it so queued requests do not each fetch.
        let platform = platform_key(&pool.qe_id, &pool.pce_id);
        let _guard = self.key_lock(&format!("pool-refetch/{platform}")).await.ok()?;
        // Re-read under the lock: a concurrent fill or registration may have
        // published the level, replaced the pool, or changed the credential.
        let pool = self.store.get_platform_pool(qeid, pceid)?;
        if Self::raw_tcb_known(&pool, cpusvn, pcesvn) || !Self::has_stored_credential(&pool) {
            return None;
        }
        if !self.refetch_due(&platform).await {
            tracing::debug!("PCK cert pool re-fetch is throttled; selecting locally");
            return None;
        }
        self.mark_refetch(&platform).await;
        self.store.record_upstream();
        let context = PckFetchContext {
            enc_ppid: &pool.enc_ppid,
            platform_manifest: &pool.platform_manifest,
            expected: Some(pool.credentials()),
            unknown_get: false,
        };
        let fetched = tokio::time::timeout(self.refetch_timeout, async {
            let resp = if !pool.platform_manifest.is_empty() {
                self.pcs
                    .fetch_pckcerts_intel_manifest(&pool.platform_manifest, &pool.pce_id)
                    .await?
            } else {
                self.pcs.fetch_pckcerts_intel(&pool.enc_ppid, &pool.pce_id).await?
            };
            self.store_pckcerts(&pool.qe_id, &pool.pce_id, &context, &resp, Some((cpusvn, pcesvn)))
                .await
        })
        .await;
        match fetched {
            Ok(Ok(Some(rec))) => {
                tracing::info!("re-fetched a PCK cert pool after an unknown raw TCB");
                Some(rec)
            }
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                tracing::warn!("PCK cert pool re-fetch failed; selecting locally: {e}");
                None
            }
            Err(_) => {
                tracing::warn!("PCK cert pool re-fetch timed out; selecting locally");
                None
            }
        }
    }

    /// Node `commonCacheLogic.getPckCertFromPCS`.
    async fn fill_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        context: PckFetchContext<'_>,
    ) -> Result<Option<PckCertRecord>, PccsError> {
        let enc_ppid = context.enc_ppid;
        let platform_manifest = context.platform_manifest;
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        if self.is_intel && enc_ppid.is_empty() && platform_manifest.is_empty() {
            tracing::error!("Missing encrypted ppid or platform manifest.");
            return Err(error::INVALID_REQ);
        }
        self.store.record_upstream();

        // A PCCS upstream without a platform manifest serves a single cert.
        if !self.is_intel && platform_manifest.is_empty() {
            let rec = self
                .pcs
                .fetch_pckcert_pccs(
                    qeid,
                    cpusvn,
                    pcesvn,
                    pceid,
                    (!enc_ppid.is_empty()).then_some(enc_ppid),
                )
                .await?;
            if !Self::cacheable(crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, &rec.issuer_chain)
            {
                return Ok(Some(rec));
            }
            // This is one selected cert, not a complete Intel pool. Preserve
            // the old inventory and publish its new raw/GET mapping atomically.
            self.store.merge_pckcert_after_fetch(&rec, context.publication())?;
            return Ok(Some(rec));
        }

        let resp = if platform_manifest.is_empty() {
            self.pcs.fetch_pckcerts_intel(enc_ppid, pceid).await?
        } else {
            self.pcs.fetch_pckcerts_intel_manifest(platform_manifest, pceid).await?
        };
        let requested = if cpusvn.is_empty() || pcesvn.is_empty() {
            // Manifest registration fills a pool without inventing a raw TCB.
            None
        } else {
            Some((cpusvn, pcesvn))
        };
        self.store_pckcerts(qeid, pceid, &context, &resp, requested).await
    }

    /// Flush and rewrite the platform's cert pool, its TCB infos, and every
    /// already-known raw TCB (Node re-runs selection for all of them).
    async fn store_pckcerts(
        &self,
        qeid: &str,
        pceid: &str,
        context: &PckFetchContext<'_>,
        resp: &PckCertsResponse,
        requested: Option<(&str, &str)>,
    ) -> Result<Option<PckCertRecord>, PccsError> {
        let pool =
            self.pckcert_pool(qeid, pceid, context.enc_ppid, context.platform_manifest, resp)?;
        let tcbs = self.fetch_tcb_infos(&resp.fmspc).await?;
        // Even a manifest-only pool has no raw selection to validate its
        // fetched collateral. Validate EVERY staged document, including SGX
        // STANDARD when EARLY was chosen, and TDX's shared SGX platform fields.
        let certs = pool.cert_pairs();
        for rec in &tcbs {
            let info = rec.tcbinfo.get("tcbInfo").unwrap_or(&rec.tcbinfo);
            let expected_id = if rec.prod_type == 0 { "SGX" } else { "TDX" };
            if info.get("id").and_then(|v| v.as_str()) != Some(expected_id)
                || !info
                    .get("fmspc")
                    .and_then(|v| v.as_str())
                    .is_some_and(|fmspc| fmspc.eq_ignore_ascii_case(&pool.fmspc))
            {
                tracing::error!("Fetched TCB document conflicts with its product/FMSPC key");
                return Err(error::NO_CACHE_DATA);
            }
            let validation = if rec.prod_type == 0 {
                crate::selection::validate_pck_cert_pool(pceid, &certs, info)
            } else {
                crate::selection::validate_tdx_pck_cert_pool(pceid, &certs, info)
            };
            validation.map_err(|e| {
                tracing::error!("Invalid staged TCB collateral: {e}");
                error::NO_CACHE_DATA
            })?;
        }
        // Select with fresh SGX EARLY, otherwise fresh STANDARD, never an old
        // shared cached document. Fetches and selections precede publication.
        let tcb = tcbs
            .iter()
            .find(|t| t.prod_type == 0 && t.update_type == "EARLY")
            .or_else(|| tcbs.iter().find(|t| t.prod_type == 0 && t.update_type == "STANDARD"))
            .ok_or(error::NO_CACHE_DATA)?;
        let selected = requested
            .map(|(cpu, pce)| self.select_from_pool_with_tcb(&pool, cpu, pce, pceid, tcb))
            .transpose()?;
        // An unavailable new raw level must not become an untracked GET hit.
        let persist = self.mode != CacheMode::Lazy || resp.not_available.is_empty();
        self.store.replace_platform_certs_after_fetch(
            &pool,
            context.publication(),
            &tcbs,
            selected.as_ref().filter(|_| persist),
            |fresh, raw| {
                self.select_from_pool_with_tcb(fresh, &raw.cpu_svn, &raw.pce_svn, pceid, tcb)
            },
        )?;
        Ok(selected)
    }

    /// Validate the fetched cert pool without writing any collateral.
    fn pckcert_pool(
        &self,
        qeid: &str,
        pceid: &str,
        enc_ppid: &str,
        platform_manifest: &str,
        resp: &PckCertsResponse,
    ) -> Result<PlatformPool, PccsError> {
        self.process_not_available(qeid, pceid, enc_ppid, platform_manifest, resp)?;
        if resp.certs.is_empty() {
            tracing::error!("No valid PCK certificates in the response.");
            return Err(error::NO_CACHE_DATA);
        }
        if !Self::cacheable(crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, &resp.issuer_chain) {
            return Err(error::PCS_ACCESS_FAILURE);
        }
        Ok(PlatformPool {
            qe_id: qeid.to_ascii_uppercase(),
            pce_id: pceid.to_ascii_uppercase(),
            enc_ppid: enc_ppid.to_ascii_uppercase(),
            platform_manifest: platform_manifest.to_string(),
            fmspc: resp.fmspc.clone(),
            ca: resp.ca.clone(),
            issuer_chain: resp.issuer_chain.clone(),
            certs: resp
                .certs
                .iter()
                .map(|(tcbm, cert)| PlatformCert { tcbm: tcbm.clone(), cert: cert.clone() })
                .collect(),
            // Filled in by atomic replacement from the existing record;
            // the pool must never be written with these dropped.
            raw_tcbs: Vec::new(),
        })
    }

    /// Node `ReqCachingMode.processNotAvailableTcbs`: TCB levels whose cert is
    /// `"Not available"` go into the registration queue with state
    /// `PLATF_REG_NOT_AVAILABLE` so an operator can supply them out of band.
    /// LAZY and OFFLINE do nothing here, as in Node.
    fn process_not_available(
        &self,
        qeid: &str,
        pceid: &str,
        enc_ppid: &str,
        platform_manifest: &str,
        resp: &PckCertsResponse,
    ) -> Result<(), PccsError> {
        if self.mode != CacheMode::Req || resp.not_available.is_empty() {
            return Ok(());
        }
        for tcb in &resp.not_available {
            let Some(cpu_svn) = raw_cpusvn_from_tcb(tcb) else {
                tracing::warn!("'Not available' TCB level has no sgxtcbcomp svn fields");
                continue;
            };
            let Some(pce_svn) = tcb.get("pcesvn").and_then(|v| v.as_u64()) else {
                continue;
            };
            self.store.register_platform(RegisteredPlatform {
                qe_id: qeid.to_string(),
                pce_id: pceid.to_string(),
                cpu_svn,
                // Node writes `pckcert.tcb.pcesvn`, the raw integer.
                pce_svn: pce_svn.to_string(),
                enc_ppid: enc_ppid.to_string(),
                platform_manifest: platform_manifest.to_string(),
                state: PLATF_REG_NOT_AVAILABLE,
            })?;
        }
        Ok(())
    }

    /// Stage Node `fetchTcbInfo` results without writing shared collateral.
    /// The pool publication batch owns the eventual `upsertTcbInfos` writes.
    async fn fetch_tcb_infos(&self, fmspc: &str) -> Result<Vec<TcbRecord>, PccsError> {
        let mut wanted: Vec<(u8, UpdateType)> =
            vec![(0, UpdateType::Early), (0, UpdateType::Standard)];
        if self.pcs_version >= 4 {
            wanted.push((1, UpdateType::Early));
            wanted.push((1, UpdateType::Standard));
        }
        let mut sgx_standard = false;
        let mut tcbs = Vec::new();
        for (prod, update) in wanted {
            match self.pcs.fetch_tcb(prod, fmspc, self.pcs_version, update).await {
                Ok(rec) => {
                    if prod == 0 && update == UpdateType::Standard {
                        sgx_standard = true;
                    }
                    if Self::cacheable(
                        crate::headers::tcb_issuer_chain_name(self.pcs_version),
                        &rec.issuer_chain,
                    ) {
                        tcbs.push(rec);
                    }
                }
                Err(e) => tracing::debug!("no tcb info for {fmspc} ({prod}, {update:?}): {e}"),
            }
        }
        if !sgx_standard {
            tracing::error!("The TCB info doesn't include standard update type.");
            return Err(error::NO_CACHE_DATA);
        }
        Ok(tcbs)
    }

    // ---------------- tcb / identity / crl ----------------

    pub async fn get_tcb(
        &self,
        prod_type: u8,
        fmspc: &str,
        version: u32,
        update: UpdateType,
    ) -> Result<TcbRecord, PccsError> {
        if let Some(rec) = self.store.get_tcb(prod_type, fmspc, version, update) {
            self.store.record_hit();
            return Ok(rec);
        }
        self.store.record_miss();
        if self.mode != CacheMode::Lazy {
            return Err(self.miss_v3(version));
        }
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let key = keys::tcb(keys::prod_name(prod_type), version, fmspc, update.as_str());
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_tcb(prod_type, fmspc, version, update) {
            return Ok(rec);
        }
        self.store.record_upstream();
        let rec =
            self.note(&key, self.pcs.fetch_tcb(prod_type, fmspc, version, update).await).await?;
        if Self::cacheable(crate::headers::tcb_issuer_chain_name(version), &rec.issuer_chain) {
            self.store.put_tcb(&rec)?;
        }
        Ok(rec)
    }

    pub async fn get_identity(
        &self,
        enclave_id: u8,
        version: u32,
        update: UpdateType,
    ) -> Result<IdentityRecord, PccsError> {
        if let Some(rec) = self.store.get_identity(enclave_id, version, update) {
            self.store.record_hit();
            return Ok(rec);
        }
        self.store.record_miss();
        if self.mode != CacheMode::Lazy {
            return Err(self.miss_v3(version));
        }
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let key = keys::identity(keys::identity_name(enclave_id), version, update.as_str());
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_identity(enclave_id, version, update) {
            return Ok(rec);
        }
        self.store.record_upstream();
        let rec =
            self.note(&key, self.pcs.fetch_identity(enclave_id, version, update).await).await?;
        if Self::cacheable(crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, &rec.issuer_chain) {
            self.store.put_identity(&rec)?;
        }
        Ok(rec)
    }

    pub async fn get_pckcrl(&self, ca: &str, version: u32) -> Result<PckCrlRecord, PccsError> {
        if let Some(rec) = self.store.get_pckcrl(ca) {
            self.store.record_hit();
            return Ok(rec);
        }
        self.store.record_miss();
        if self.mode != CacheMode::Lazy {
            return Err(self.miss_v3(version));
        }
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let key = keys::pckcrl(ca);
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_pckcrl(ca) {
            return Ok(rec);
        }
        self.store.record_upstream();
        let rec = self.note(&key, self.pcs.fetch_pckcrl(ca).await).await?;
        if Self::cacheable(crate::headers::SGX_PCK_CRL_ISSUER_CHAIN, &rec.issuer_chain) {
            self.store.put_pckcrl(&rec)?;
        }
        Ok(rec)
    }

    pub async fn get_rootcacrl(&self, version: u32) -> Result<Vec<u8>, PccsError> {
        if let Some(rec) = self.store.get_rootcacrl() {
            self.store.record_hit();
            return Ok(rec);
        }
        self.store.record_miss();
        if self.mode != CacheMode::Lazy {
            return Err(self.miss_v3(version));
        }
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let key = keys::rootcacrl();
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_rootcacrl() {
            return Ok(rec);
        }
        self.store.record_upstream();
        let rec = self.note(&key, self.pcs.fetch_rootcacrl().await).await?;
        self.store.put_rootcacrl(&rec)?;
        Ok(rec)
    }

    pub async fn get_crl(&self, uri: &str, version: u32) -> Result<Vec<u8>, PccsError> {
        if let Some(rec) = self.store.get_crl(uri) {
            self.store.record_hit();
            return Ok(rec);
        }
        self.store.record_miss();
        if self.mode != CacheMode::Lazy {
            return Err(self.miss_v3(version));
        }
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let key = keys::crl(uri);
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_crl(uri) {
            return Ok(rec);
        }
        self.store.record_upstream();
        let rec = self.note(&key, self.pcs.fetch_crl(uri).await).await?;
        self.store.put_crl(uri, &rec)?;
        Ok(rec)
    }

    // ---------------- registration ----------------

    /// Node `platformsRegService.checkPCKCertCacheStatus`.
    fn is_cached(&self, p: &mut RegisteredPlatform) -> bool {
        let Some(platform) = self.store.get_platform_pool(&p.qe_id, &p.pce_id) else {
            return false;
        };
        if p.platform_manifest.is_empty() {
            // Node: a cached manifest counts as a match when the request omits it.
            p.platform_manifest = platform.platform_manifest.clone();
            return self.store.get_pckcert(&p.qe_id, &p.cpu_svn, &p.pce_svn, &p.pce_id).is_some();
        }
        platform.platform_manifest == p.platform_manifest
    }

    /// Node `cachingMode.registerPlatforms` for the three modes.
    pub async fn register_platform(
        &self,
        mut p: RegisteredPlatform,
        update: UpdateType,
    ) -> Result<(), PccsError> {
        // Observed credentials differ from the desired Manifest on a valid
        // update. Only an intervening mutation makes the eventual fill stale.
        let expected =
            self.store.get_platform_pool(&p.qe_id, &p.pce_id).map(|pool| pool.credentials());
        let cached = self.is_cached(&mut p);
        match self.mode {
            CacheMode::Offline => {
                if !cached {
                    self.store
                        .register_platform(RegisteredPlatform { state: PLATF_REG_NEW, ..p })?;
                }
                Ok(())
            }
            CacheMode::Req => {
                if !cached {
                    let queued = RegisteredPlatform { state: PLATF_REG_NEW, ..p.clone() };
                    self.store.register_platform(queued.clone())?;
                    // Node propagates a fill failure and leaves the NEW row in
                    // the queue; the POST must not answer 200.
                    self.fill_pckcert(
                        &p.qe_id,
                        &p.cpu_svn,
                        &p.pce_svn,
                        &p.pce_id,
                        PckFetchContext {
                            enc_ppid: &p.enc_ppid,
                            platform_manifest: &p.platform_manifest,
                            expected,
                            unknown_get: false,
                        },
                    )
                    .await?;
                    // Only this platform's own row leaves the queue.
                    self.store.delete_registered(&queued)?;
                }
                self.fill_qv_collateral(update).await;
                Ok(())
            }
            CacheMode::Lazy => {
                if !cached {
                    self.fill_pckcert(
                        &p.qe_id,
                        &p.cpu_svn,
                        &p.pce_svn,
                        &p.pce_id,
                        PckFetchContext {
                            enc_ppid: &p.enc_ppid,
                            platform_manifest: &p.platform_manifest,
                            expected,
                            unknown_get: false,
                        },
                    )
                    .await?;
                }
                self.fill_qv_collateral(update).await;
                Ok(())
            }
        }
    }

    /// Node `qvCollateralLogic.checkQuoteVerificationCollateral`.
    async fn fill_qv_collateral(&self, update: UpdateType) {
        if !self.pcs.enabled() {
            return;
        }
        let updates = match update {
            UpdateType::All => vec![UpdateType::Standard, UpdateType::Early],
            other => vec![other],
        };
        for ca in ["PROCESSOR", "PLATFORM"] {
            if self.store.get_pckcrl(ca).is_none() {
                if let Ok(r) = self.pcs.fetch_pckcrl(ca).await {
                    if Self::cacheable(crate::headers::SGX_PCK_CRL_ISSUER_CHAIN, &r.issuer_chain) {
                        let _ = self.store.put_pckcrl(&r);
                    }
                }
            }
        }
        for id in [1u8, 2, 3] {
            for u in &updates {
                if self.store.get_identity(id, self.pcs_version, *u).is_none() {
                    if let Ok(r) = self.pcs.fetch_identity(id, self.pcs_version, *u).await {
                        if Self::cacheable(
                            crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                            &r.issuer_chain,
                        ) {
                            let _ = self.store.put_identity(&r);
                        }
                    }
                }
            }
        }
        if self.store.get_rootcacrl().is_none() {
            if let Ok(r) = self.pcs.fetch_rootcacrl().await {
                let _ = self.store.put_rootcacrl(&r);
            }
        }
    }

    // ---------------- refresh ----------------

    /// Node `refreshService.refreshCache`. The controller validates parameters
    /// before the service decides whether the mode is refreshable, so an
    /// invalid fmspc is a 400 even in OFFLINE mode.
    pub async fn refresh(
        self: &Arc<Self>,
        typ: Option<&str>,
        fmspc: Option<&str>,
    ) -> Result<(), PccsError> {
        let certs_fmspc = match typ {
            Some("certs") => Some(crate::validate::fmspc(fmspc)?),
            Some(other) => {
                tracing::error!("Invalid refresh type : {other}");
                return Err(error::INVALID_REQ);
            }
            None => None,
        };
        if self.mode == CacheMode::Offline {
            return Err(error::SERVICE_UNAVAILABLE);
        }
        // Node has no guard and lets two refreshes interleave; we serialise
        // them so a second admin call waits rather than doubling upstream load.
        let _guard = self.refresh_lock.lock().await;
        match certs_fmspc {
            Some(f) => self.refresh_certs(&f).await,
            None => self.refresh_collateral().await,
        }
    }

    async fn refresh_collateral(self: &Arc<Self>) -> Result<(), PccsError> {
        if !self.pcs.enabled() {
            return Ok(());
        }
        // Node `refreshPckCrls`: a failed CRL refresh is a 503.
        for rec in self.blocking(|c| c.store.list_pckcrls()).await? {
            let fresh = self.pcs.fetch_pckcrl(&rec.ca).await.map_err(|e| {
                tracing::error!("Failed to refresh PCK CRL for {}: {e}", rec.ca);
                error::SERVICE_UNAVAILABLE
            })?;
            if Self::cacheable(crate::headers::SGX_PCK_CRL_ISSUER_CHAIN, &fresh.issuer_chain) {
                self.store.put_pckcrl(&fresh)?;
            }
        }

        // Node `refreshAllTcbs` → `refreshOneTcb`: a failure is a 503.
        for rec in self.blocking(|c| c.store.list_tcbs()).await? {
            if rec.version == 3 {
                continue;
            }
            let upd = if rec.update_type.eq_ignore_ascii_case("EARLY") {
                UpdateType::Early
            } else {
                UpdateType::Standard
            };
            let fresh =
                self.pcs.fetch_tcb(rec.prod_type, &rec.fmspc, rec.version, upd).await.map_err(
                    |e| {
                        tracing::error!("Failed to get tcbinfo for fmspc:{} ({e})", rec.fmspc);
                        error::SERVICE_UNAVAILABLE
                    },
                )?;
            if Self::cacheable(
                crate::headers::tcb_issuer_chain_name(rec.version),
                &fresh.issuer_chain,
            ) {
                self.store.put_tcb(&fresh)?;
            }
        }

        // Node probes the complete identity set, not just cached rows, and
        // tolerates missing collateral. v3 is EOL: never fetch its identities.
        if self.pcs_version >= 4 {
            for id in [1u8, 2, 3] {
                for upd in [UpdateType::Standard, UpdateType::Early] {
                    match self.pcs.fetch_identity(id, 4, upd).await {
                        Ok(fresh) => {
                            if Self::cacheable(
                                crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                                &fresh.issuer_chain,
                            ) {
                                self.store.put_identity(&fresh)?;
                            }
                        }
                        Err(e) => tracing::debug!(
                            "Couldn't get enclave identity for (id:{id},version:4): {e}"
                        ),
                    }
                }
            }
        }

        // Node `refreshRootcaCrl`: a missing root CA certificate is a 500. We
        // have no separate root-cert row, so the equivalent condition is
        // "the root CA CRL is cached but can no longer be refreshed".
        let had_rootcacrl = self.store.get_rootcacrl().is_some();
        match self.pcs.fetch_rootcacrl().await {
            Ok(fresh) => self.store.put_rootcacrl(&fresh)?,
            Err(e) if had_rootcacrl => {
                tracing::error!("Failed to refresh the root CA CRL: {e}");
                return Err(error::INTERNAL_ERROR);
            }
            Err(e) => tracing::debug!("root CA CRL not refreshed: {e}"),
        }

        // Node `refreshCachedCrls` skips invalid URIs and propagates download
        // failures.
        for rec in self.blocking(|c| c.store.list_crls()).await? {
            if !crate::validate::is_valid_crl_uri(&rec.uri) {
                tracing::error!("Invalid CDP URI.");
                continue;
            }
            let fresh = self.pcs.fetch_crl(&rec.uri).await?;
            self.store.put_crl(&rec.uri, &fresh)?;
        }
        Ok(())
    }

    /// Node `refreshAllPckcerts`: one upstream call per platform, then
    /// re-selection for every raw TCB that platform has. The admin
    /// `/refresh?type=certs` path stops at the first failure.
    async fn refresh_certs(self: &Arc<Self>, fmspc: &str) -> Result<(), PccsError> {
        if !self.pcs.enabled() || self.pcs_version == 3 {
            return Ok(());
        }
        for pool in self.blocking(|c| c.store.list_platform_pools()).await? {
            if !pool.fmspc.eq_ignore_ascii_case(fmspc) {
                continue;
            }
            // Node uses the cert-pool endpoint whenever a manifest is stored,
            // whichever upstream serves it; only a manifest-less PCCS mirror
            // falls back to one selected cert per raw TCB.
            if self.is_intel || !pool.platform_manifest.is_empty() {
                self.refresh_platform_pool(&pool).await?;
                continue;
            }
            let expected = pool.credentials();
            // A PCCS upstream has no cert-pool endpoint; re-fetch the selected
            // cert for every known raw TCB instead.
            for raw in &pool.raw_tcbs {
                if let Ok(fresh) = self
                    .pcs
                    .fetch_pckcert_pccs(
                        &pool.qe_id,
                        &raw.cpu_svn,
                        &raw.pce_svn,
                        &pool.pce_id,
                        Some(&pool.enc_ppid),
                    )
                    .await
                {
                    if Self::cacheable(
                        crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                        &fresh.issuer_chain,
                    ) {
                        self.store.merge_pckcert(&fresh, Some(&expected))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Re-fetch one platform's pool and re-select every raw TCB it knows. The
    /// credential is always the pool's own; the caller's PPID is irrelevant.
    async fn refresh_platform_pool(&self, pool: &PlatformPool) -> Result<(), PccsError> {
        let expected = pool.credentials();
        let resp = if !pool.platform_manifest.is_empty() {
            self.pcs.fetch_pckcerts_intel_manifest(&pool.platform_manifest, &pool.pce_id).await
        } else {
            self.pcs.fetch_pckcerts_intel(&pool.enc_ppid, &pool.pce_id).await
        }
        .map_err(|e| {
            tracing::error!("Failed to refresh PCK certs for {}: {e}", pool.qe_id);
            error::NO_CACHE_DATA
        })?;
        let fresh = self.pckcert_pool(
            &pool.qe_id,
            &pool.pce_id,
            &pool.enc_ppid,
            &pool.platform_manifest,
            &resp,
        )?;
        // Intel refreshService uses SGX EARLY only, ephemerally. This refresh
        // must not overwrite shared TCB collateral (even on a selection
        // failure), nor depend on SGX STANDARD or TDX fetches.
        let tcb = self.pcs.fetch_tcb(0, &fresh.fmspc, self.pcs_version, UpdateType::Early).await?;
        self.store.replace_platform_certs_with_selection(
            &fresh,
            Some(&expected),
            &[],
            None,
            |fresh, raw| {
                self.select_from_pool_with_tcb(
                    fresh,
                    &raw.cpu_svn,
                    &raw.pce_svn,
                    &fresh.pce_id,
                    &tcb,
                )
            },
        )
    }

    /// The cron scheduler's run: Node `refreshService.refreshCache` collateral,
    /// then (deviation, Intel PCS + LAZY only) every known platform's pool.
    /// Node refreshes collateral only, so a TCB raise no client has hit yet
    /// would never reach the cache.
    ///
    /// The two halves are independent: a collateral failure is logged and the
    /// pool sweep still runs (the collateral result is what this returns), and
    /// a per-platform pool failure never affects the collateral result.
    pub async fn scheduled_refresh(self: &Arc<Self>) -> Result<(), PccsError> {
        // Local only, so it runs in every mode, OFFLINE included.
        if let Err(e) = self.blocking(Cache::sweep_expired).await {
            tracing::warn!("expired record sweep: {e}");
        }
        if self.mode == CacheMode::Offline {
            return Err(error::SERVICE_UNAVAILABLE);
        }
        let _guard = self.refresh_lock.lock().await;
        // Collateral first, exactly as before: the pool pass is additive, so a
        // collateral failure still reports the way it always has.
        let collateral = self.refresh_collateral().await;
        if let Err(e) = &collateral {
            tracing::warn!("scheduled collateral refresh: {e}");
        }
        // Pools even when collateral failed: a CRL or identity outage has
        // nothing to do with a raised platform TCB.
        self.refresh_platform_pools().await;
        collateral
    }

    /// Re-fetch the pool of every known platform with a stored credential,
    /// across all FMSPCs. Unlike the admin path this never aborts: one platform
    /// with a rejected credential, a broken TCB document or an upstream error is
    /// logged and skipped so the rest of the run still lands.
    pub async fn refresh_platform_pools(self: &Arc<Self>) {
        if !self.scheduled_pool_refresh
            || self.mode != CacheMode::Lazy
            || !self.is_intel
            || !self.pcs.enabled()
            || self.pcs_version == 3
        {
            return;
        }
        let pools = match self.blocking(|c| c.store.list_platform_pools()).await {
            Ok(pools) => pools,
            Err(e) => {
                tracing::error!("scheduled pool refresh: {e}");
                return;
            }
        };
        // A request already re-fetched these inside the throttle interval; a
        // second upstream round trip would only add load.
        let recently: Vec<String> = {
            let interval = self.pool_refetch_interval;
            let marks = self.refetch_marks.lock().await;
            marks
                .iter()
                .filter(|(_, at)| !interval.is_zero() && at.elapsed() < interval)
                .map(|(key, _)| key.clone())
                .collect()
        };
        let queue: Vec<PlatformPool> = pools
            .into_iter()
            .filter(|p| Self::has_stored_credential(p))
            .filter(|p| !recently.contains(&platform_key(&p.qe_id, &p.pce_id)))
            .collect();
        let mut pending = queue.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            while tasks.len() < self.refresh_concurrency.max(1) {
                let Some(pool) = pending.next() else { break };
                let me = self.clone();
                tasks.spawn(async move {
                    let key = platform_key(&pool.qe_id, &pool.pce_id);
                    (key, me.refresh_platform_pool(&pool).await)
                });
            }
            match tasks.join_next().await {
                Some(Ok((key, Ok(())))) => tracing::debug!("refreshed PCK cert pool {key}"),
                Some(Ok((key, Err(e)))) => {
                    tracing::warn!("scheduled pool refresh skipped {key}: {e}");
                }
                Some(Err(e)) => tracing::error!("scheduled pool refresh task failed: {e}"),
                None => break,
            }
        }
    }

    /// Run a full-prefix RocksDB scan off the async runtime.
    async fn blocking<T, F>(self: &Arc<Self>, f: F) -> Result<T, PccsError>
    where
        T: Send + 'static,
        F: FnOnce(&Cache) -> T + Send + 'static,
    {
        let me = self.clone();
        tokio::task::spawn_blocking(move || f(&me)).await.map_err(|_| error::INTERNAL_ERROR)
    }
}

fn log_sweep(prefix: &str, result: Result<usize, PccsError>) {
    match result {
        Ok(0) => {}
        Ok(n) => tracing::info!("swept {n} expired {prefix} records"),
        Err(e) => tracing::warn!("{prefix} sweep: {e}"),
    }
}

/// Upper-cased `qe_id:pce_id`: the key for both the per-platform re-fetch lock
/// and the in-memory throttle marks.
fn platform_key(qeid: &str, pceid: &str) -> String {
    format!("{}:{}", qeid.to_ascii_uppercase(), pceid.to_ascii_uppercase())
}

/// Node `cachingMode.getRawCpuSvnFromTcb`: the 16 `sgxtcbcompNNsvn` fields
/// concatenated as two-digit hex.
fn raw_cpusvn_from_tcb(tcb: &serde_json::Value) -> Option<String> {
    let mut out = String::with_capacity(32);
    for i in 1..=16u32 {
        let svn = tcb.get(format!("sgxtcbcomp{i:02}svn"))?.as_u64()?;
        if svn > 255 {
            return None;
        }
        out.push_str(&format!("{svn:02X}"));
    }
    Some(out)
}

pub fn build_cache(cfg: &Config) -> Result<Arc<Cache>, String> {
    std::fs::create_dir_all(&cfg.db_path)
        .map_err(|e| format!("create db path {}: {e}", cfg.db_path.display()))?;
    let store = Store::open(&cfg.db_path, cfg.cache_mode, &cfg.rocksdb_opts())?;
    if !cfg.no_seed {
        if let Some(p) = crate::store::find_seed_path(cfg.seed.as_deref()) {
            store.load_seed_file(&p)?;
            tracing::info!("seeded cache from {}", p.display());
        }
    }
    let pcs = PcsClient::new(cfg)?;
    Ok(Arc::new(Cache::new(store, pcs, cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amd_kds_host_strips_legacy_vcek_and_vlek_suffixes() {
        assert_eq!(
            normalize_amd_kds_host("https://kdsintf.amd.com/vcek/v1"),
            "https://kdsintf.amd.com"
        );
        assert_eq!(
            normalize_amd_kds_host("https://kdsintf.amd.com/vlek/v1/"),
            "https://kdsintf.amd.com"
        );
        assert_eq!(normalize_amd_kds_host(" https://kdsintf.amd.com "), "https://kdsintf.amd.com");
        assert_eq!(
            normalize_amd_kds_host("https://mirror.example/amd-kds/vcek/v1"),
            "https://mirror.example/amd-kds"
        );
    }

    #[test]
    fn nvidia_rim_host_strips_legacy_v1_rim_suffix() {
        assert_eq!(
            normalize_nvidia_rim_host("https://rim.attestation.nvidia.com/v1/rim"),
            "https://rim.attestation.nvidia.com"
        );
        assert_eq!(
            normalize_nvidia_rim_host(" https://rim.attestation.nvidia.com/v1/rim/ "),
            "https://rim.attestation.nvidia.com"
        );
        assert_eq!(
            normalize_nvidia_rim_host("https://rim.attestation.nvidia.com"),
            "https://rim.attestation.nvidia.com"
        );
    }

    #[test]
    fn amd_kds_path_is_whitelisted_and_query_is_sorted() {
        assert_eq!(
            canonicalize_amd_kds("/vcek/v1/Genoa/cert_chain").unwrap(),
            "/vcek/v1/Genoa/cert_chain"
        );
        assert_eq!(
            canonicalize_amd_kds("/vcek/v1/Genoa/abcd?teeSPL=2&blSPL=1").unwrap(),
            "/vcek/v1/Genoa/abcd?blSPL=1&teeSPL=2"
        );
        assert_err(
            &canonicalize_amd_kds("/vcek/v1/Genoa/cert_chain?junk=1").unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_err(&canonicalize_amd_kds("/vcek/v1/../../x").unwrap_err(), &error::INVALID_REQ);
        assert_err(
            &canonicalize_amd_kds("/vcek/v3/Genoa/cert_chain").unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_eq!(
            canonicalize_amd_kds("/vcek/v1/Genoa/abcd?blSPL=255").unwrap(),
            "/vcek/v1/Genoa/abcd?blSPL=255"
        );
        assert_err(
            &canonicalize_amd_kds("/vcek/v1/Genoa/abcd?blSPL=256").unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_err(
            &canonicalize_amd_kds("/vcek/v1/Genoa/abcd?blSPL=Nzzz").unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_err(
            &canonicalize_amd_kds("/vcek/v1/Genoa/abcd?blSPL=1&blSPL=2").unwrap_err(),
            &error::INVALID_REQ,
        );
    }

    #[test]
    fn amd_kds_turin_kms_query_with_fmc_spl_is_sorted() {
        // sev-snp-qvl: Turin uses chip_id[..8] (16 hex) and adds fmcSPL.
        let turin = "0123456789abcdef";
        assert_eq!(
            canonicalize_amd_kds(&format!(
                "/vcek/v1/Turin/{turin}?fmcSPL=1&blSPL=2&teeSPL=3&snpSPL=4&ucodeSPL=5"
            ))
            .unwrap(),
            format!("/vcek/v1/Turin/{turin}?blSPL=2&fmcSPL=1&snpSPL=4&teeSPL=3&ucodeSPL=5")
        );
        assert_err(
            &canonicalize_amd_kds(&format!("/vcek/v1/Turin/{turin}?fmcSPL=256")).unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_err(
            &canonicalize_amd_kds(&format!("/vcek/v1/Turin/{turin}?fmcSPL=1&fmcSPL=1"))
                .unwrap_err(),
            &error::INVALID_REQ,
        );
        // Milan/Genoa: full 64-byte chip_id (128 hex), no fmcSPL.
        let genoa = "ab".repeat(64);
        assert_eq!(
            canonicalize_amd_kds(&format!(
                "/vcek/v1/Genoa/{genoa}?blSPL=2&teeSPL=3&snpSPL=4&ucodeSPL=5"
            ))
            .unwrap(),
            format!("/vcek/v1/Genoa/{genoa}?blSPL=2&snpSPL=4&teeSPL=3&ucodeSPL=5")
        );
    }

    #[test]
    fn empty_query_pairs_and_keys_are_rejected() {
        for path in [
            "/vcek/v1/Milan/cert_chain?&",
            "/vcek/v1/Milan/ABCD?blSPL=1&&snpSPL=2",
            "/vcek/v1/Milan/ABCD?blSPL=1&",
            "/vcek/v1/Milan/ABCD?=3",
            "/vlek/v1/Genoa/crl?=",
        ] {
            assert_err(&canonicalize_amd_kds(path).unwrap_err(), &error::INVALID_REQ);
        }
        assert_err(&canonicalize_nvidia_rim("/v1/rim/some-id?&").unwrap_err(), &error::INVALID_REQ);
    }

    #[test]
    fn nvidia_rim_path_is_whitelisted() {
        assert_eq!(canonicalize_nvidia_rim("/v1/rim/some-id").unwrap(), "/v1/rim/some-id");
        assert_eq!(
            canonicalize_nvidia_rim("/v1/rim/NV_GPU_DRIVER_GH100_535.129.03").unwrap(),
            "/v1/rim/NV_GPU_DRIVER_GH100_535.129.03"
        );
        assert_eq!(canonicalize_nvidia_rim("/v1/rim/ids").unwrap(), "/v1/rim/ids");
        assert_err(
            &canonicalize_nvidia_rim("/v1/rim/some-id?junk=1").unwrap_err(),
            &error::INVALID_REQ,
        );
        assert_err(&canonicalize_nvidia_rim("/v1/rim/../x").unwrap_err(), &error::INVALID_REQ);
    }

    #[test]
    fn raw_cpusvn_matches_node_int_to_hex() {
        let mut tcb = serde_json::Map::new();
        for i in 1..=16u32 {
            tcb.insert(format!("sgxtcbcomp{i:02}svn"), serde_json::json!(i));
        }
        assert_eq!(
            raw_cpusvn_from_tcb(&serde_json::Value::Object(tcb)).as_deref(),
            Some("0102030405060708090A0B0C0D0E0F10")
        );
        assert_eq!(raw_cpusvn_from_tcb(&serde_json::json!({})), None);
    }

    #[test]
    fn raw_cpusvn_rejects_out_of_range_and_partial_levels() {
        // A component above 255 is not a byte.
        let mut tcb = serde_json::Map::new();
        for i in 1..=16u32 {
            tcb.insert(format!("sgxtcbcomp{i:02}svn"), serde_json::json!(300));
        }
        assert_eq!(raw_cpusvn_from_tcb(&serde_json::Value::Object(tcb)), None);
        // Missing component 16.
        let mut tcb = serde_json::Map::new();
        for i in 1..=15u32 {
            tcb.insert(format!("sgxtcbcomp{i:02}svn"), serde_json::json!(1));
        }
        assert_eq!(raw_cpusvn_from_tcb(&serde_json::Value::Object(tcb)), None);
    }

    #[test]
    fn miss_v3_is_eol_only_in_lazy_mode() {
        for (mode, version, want) in [
            (CacheMode::Lazy, 3, error::PCS_V3_REACHED_EOL),
            (CacheMode::Lazy, 4, error::NO_CACHE_DATA),
            (CacheMode::Offline, 3, error::NO_CACHE_DATA),
        ] {
            let (_dir, cache) = cache_with("", mode);
            assert_err(&cache.miss_v3(version), &want);
        }
    }

    #[test]
    fn cacheable_requires_a_chain() {
        assert!(!Cache::cacheable("X-Chain", ""));
        assert!(!Cache::cacheable("X-Chain", "   "));
        assert!(Cache::cacheable("X-Chain", "chain"));
    }

    // ---- Cache against a loopback mock PCS (never Intel) ----

    use crate::store::RawTcb;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// PccsError has no PartialEq; compare what the wire sees.
    fn assert_err(got: &PccsError, want: &PccsError) {
        assert_eq!((got.status, got.message), (want.status, want.message));
    }

    /// Removes the RocksDB directory once the cache is dropped.
    struct TestDir(std::path::PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Bind as `let (_dir, cache) = cache_with(..);` — locals drop in reverse
    /// declaration order, so the cache closes before the directory is removed.
    fn cache_with(base: &str, mode: CacheMode) -> (TestDir, Arc<Cache>) {
        let dir = std::env::temp_dir().join(format!("pccs-rs-cache-{}", uuid::Uuid::new_v4()));
        let cfg = Config {
            uri: base.into(),
            cache_mode: mode,
            db_path: dir.clone(),
            upstream_max_attempts: 1,
            ..Config::default()
        };
        let store = Store::open(&dir, mode, &crate::config::RocksDbOpts::default()).unwrap();
        let pcs = PcsClient::new(&cfg).unwrap();
        (TestDir(dir), Arc::new(Cache::new(store, pcs, &cfg)))
    }

    fn amd_cache(amd_kds_uri: &str, mode: CacheMode) -> (TestDir, Arc<Cache>) {
        let dir = std::env::temp_dir().join(format!("pccs-rs-cache-{}", uuid::Uuid::new_v4()));
        let cfg = Config {
            uri: String::new(),
            amd_kds_uri: amd_kds_uri.into(),
            cache_mode: mode,
            db_path: dir.clone(),
            upstream_max_attempts: 1,
            ..Config::default()
        };
        let store = Store::open(&dir, mode, &crate::config::RocksDbOpts::default()).unwrap();
        let pcs = PcsClient::new(&cfg).unwrap();
        (TestDir(dir), Arc::new(Cache::new(store, pcs, &cfg)))
    }

    fn amd_record(url: &str, fetched_at: u64) -> AmdKdsRecord {
        AmdKdsRecord {
            url: url.into(),
            body: b"cert".to_vec(),
            content_type: None,
            content_disposition: None,
            fetched_at,
        }
    }

    #[tokio::test]
    async fn expired_amd_kds_record_is_deleted_when_a_lookup_finds_it() {
        let host = "http://127.0.0.1:0";
        let url = format!("{host}/vcek/v1/Milan/cert_chain");
        for mode in [CacheMode::Offline, CacheMode::Req, CacheMode::Lazy] {
            let (_dir, cache) = amd_cache(host, mode);
            cache.store.put_amd_kds(&amd_record(&url, 0)).unwrap();
            assert!(cache.get_amd_kds("/vcek/v1/Milan/cert_chain").await.is_err());
            assert!(cache.store.get_amd_kds(&url).is_none(), "{mode:?} kept an expired record");
        }
    }

    #[tokio::test]
    async fn scheduled_refresh_sweeps_expired_amd_kds_records() {
        let host = "http://127.0.0.1:0";
        let stale = format!("{host}/vcek/v1/Milan/cert_chain");
        let fresh = format!("{host}/vcek/v1/Genoa/cert_chain");
        for mode in [CacheMode::Lazy, CacheMode::Offline] {
            let (_dir, cache) = amd_cache(host, mode);
            cache.store.put_amd_kds(&amd_record(&stale, 0)).unwrap();
            cache.store.put_amd_kds(&amd_record(&fresh, unix_time())).unwrap();
            let _ = cache.scheduled_refresh().await;
            assert!(cache.store.get_amd_kds(&stale).is_none(), "{mode:?} kept an expired record");
            assert!(cache.store.get_amd_kds(&fresh).is_some(), "{mode:?} swept a fresh record");
        }
    }

    fn rim_cache(nvidia_rim_uri: &str, mode: CacheMode) -> (TestDir, Arc<Cache>) {
        let dir = std::env::temp_dir().join(format!("pccs-rs-cache-{}", uuid::Uuid::new_v4()));
        let cfg = Config {
            uri: String::new(),
            nvidia_rim_uri: nvidia_rim_uri.into(),
            cache_mode: mode,
            db_path: dir.clone(),
            upstream_max_attempts: 1,
            ..Config::default()
        };
        let store = Store::open(&dir, mode, &crate::config::RocksDbOpts::default()).unwrap();
        let pcs = PcsClient::new(&cfg).unwrap();
        (TestDir(dir), Arc::new(Cache::new(store, pcs, &cfg)))
    }

    #[tokio::test]
    async fn expired_nvidia_rim_records_are_deleted_on_lookup_and_swept() {
        let host = "http://127.0.0.1:0";
        let looked_up = format!("{host}/v1/rim/looked-up");
        let stale = format!("{host}/v1/rim/stale");
        let fresh = format!("{host}/v1/rim/fresh");
        for mode in [CacheMode::Offline, CacheMode::Lazy] {
            let (_dir, cache) = rim_cache(host, mode);
            for (url, at) in [(&looked_up, 0), (&stale, 0), (&fresh, unix_time())] {
                cache.store.put_nvidia_rim(&amd_record(url, at)).unwrap();
            }
            assert!(cache.get_nvidia_rim("/v1/rim/looked-up").await.is_err());
            assert!(cache.store.get_nvidia_rim(&looked_up).is_none(), "{mode:?} lookup kept it");
            let _ = cache.scheduled_refresh().await;
            assert!(cache.store.get_nvidia_rim(&stale).is_none(), "{mode:?} sweep kept it");
            assert!(cache.store.get_nvidia_rim(&fresh).is_some(), "{mode:?} swept a fresh one");
        }
    }

    #[tokio::test]
    async fn recent_outcomes_are_bounded_in_count_and_body_size() {
        let (_dir, cache) = cache_with("", CacheMode::Lazy);
        let response = |len: usize| {
            RecentOutcome::Response(AmdKdsResponse {
                status: 429,
                body: vec![0; len],
                content_type: None,
                content_disposition: None,
                retry_after: None,
            })
        };
        for i in 0..RECENT_OUTCOMES_MAX + 16 {
            cache.remember(&format!("key-{i}"), response(1)).await;
        }
        assert!(cache.failures.lock().await.len() <= RECENT_OUTCOMES_MAX);

        let (_dir, cache) = cache_with("", CacheMode::Lazy);
        cache.remember("small", response(RECENT_BODY_MAX)).await;
        cache.remember("large", response(RECENT_BODY_MAX + 1)).await;
        assert!(cache.recent_non200("small").await.is_some());
        assert!(cache.recent_non200("large").await.is_none());
    }

    fn ocsp_cache(nvidia_ocsp_uri: &str, mode: CacheMode) -> (TestDir, Arc<Cache>) {
        let dir = std::env::temp_dir().join(format!("pccs-rs-cache-{}", uuid::Uuid::new_v4()));
        let cfg = Config {
            uri: String::new(),
            nvidia_ocsp_uri: nvidia_ocsp_uri.into(),
            cache_mode: mode,
            db_path: dir.clone(),
            upstream_max_attempts: 1,
            ..Config::default()
        };
        let store = Store::open(&dir, mode, &crate::config::RocksDbOpts::default()).unwrap();
        let pcs = PcsClient::new(&cfg).unwrap();
        (TestDir(dir), Arc::new(Cache::new(store, pcs, &cfg)))
    }

    /// Minimal DER OCSPRequest for one synthetic CertID.
    fn ocsp_request() -> Vec<u8> {
        fn der(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, value.len() as u8];
            out.extend_from_slice(value);
            out
        }
        let algorithm = der(0x30, &der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]));
        let cert_id = der(
            0x30,
            &[algorithm, der(0x04, &[1; 20]), der(0x04, &[2; 20]), der(0x02, &[3])].concat(),
        );
        let list = der(0x30, &der(0x30, &cert_id));
        der(0x30, &der(0x30, &list))
    }

    fn ocsp_record(cache_key: &str, expires_at: u64) -> NvidiaOcspRecord {
        NvidiaOcspRecord {
            cache_key: cache_key.into(),
            body: b"ocsp".to_vec(),
            content_type: None,
            fetched_at: 0,
            expires_at,
        }
    }

    #[tokio::test]
    async fn nvidia_ocsp_without_a_host_still_serves_the_cache() {
        let request = ocsp_request();
        let key = crate::ocsp::parse_request(&request).unwrap().cache_key;
        for mode in [CacheMode::Offline, CacheMode::Req, CacheMode::Lazy] {
            let (_dir, cache) = ocsp_cache("", mode);
            let miss = cache.get_nvidia_ocsp(&request).await.err().unwrap();
            let want = if mode == CacheMode::Lazy {
                error::NVIDIA_OCSP_ACCESS_FAILURE
            } else {
                error::NO_CACHE_DATA
            };
            assert_err(&miss, &want);
            cache.store.put_nvidia_ocsp(&ocsp_record(&key, unix_time() + 3600)).unwrap();
            let hit = cache.get_nvidia_ocsp(&request).await.unwrap();
            assert_eq!((hit.status, hit.body), (200, b"ocsp".to_vec()), "{mode:?}");
        }
    }

    #[tokio::test]
    async fn expired_nvidia_ocsp_records_are_deleted_on_lookup_and_swept() {
        let request = ocsp_request();
        let looked_up = crate::ocsp::parse_request(&request).unwrap().cache_key;
        for mode in [CacheMode::Offline, CacheMode::Lazy] {
            let (_dir, cache) = ocsp_cache("http://127.0.0.1:0", mode);
            for (key, at) in [(looked_up.as_str(), 1), ("stale", 1), ("fresh", unix_time() + 3600)]
            {
                cache.store.put_nvidia_ocsp(&ocsp_record(key, at)).unwrap();
            }
            assert!(cache.get_nvidia_ocsp(&request).await.is_err());
            assert!(cache.store.get_nvidia_ocsp(&looked_up).is_none(), "{mode:?} lookup kept it");
            let _ = cache.scheduled_refresh().await;
            assert!(cache.store.get_nvidia_ocsp("stale").is_none(), "{mode:?} sweep kept it");
            assert!(cache.store.get_nvidia_ocsp("fresh").is_some(), "{mode:?} swept a fresh one");
        }
    }

    async fn spawn(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}/sgx/certification/v4/")
    }

    /// A PCCS-shaped mock serving every collateral kind `fill_qv_collateral`
    /// and the LAZY miss paths ask for.
    async fn spawn_pccs(calls: Arc<AtomicU64>) -> String {
        use axum::routing::get;
        let count = move |calls: &Arc<AtomicU64>| calls.fetch_add(1, Ordering::Relaxed);
        let c1 = calls.clone();
        let c2 = calls.clone();
        let c3 = calls.clone();
        let c4 = calls.clone();
        let c5 = calls.clone();
        let c6 = calls.clone();
        let app = axum::Router::new()
            .route(
                "/sgx/certification/v4/pckcert",
                get(move || {
                    let c = c1.clone();
                    async move {
                        count(&c);
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
                        ));
                        let h = resp.headers_mut();
                        h.insert(
                            crate::headers::SGX_TCBM,
                            axum::http::HeaderValue::from_static("TM"),
                        );
                        h.insert(
                            crate::headers::SGX_FMSPC,
                            axum::http::HeaderValue::from_static("00A067110000"),
                        );
                        h.insert(
                            crate::headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                            axum::http::HeaderValue::from_static("PROCESSOR"),
                        );
                        h.insert(
                            crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("pck-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/pckcrl",
                get(move || {
                    let c = c2.clone();
                    async move {
                        count(&c);
                        let mut resp = axum::response::Response::new(axum::body::Body::from(vec![
                            0x30u8, 0x03,
                        ]));
                        resp.headers_mut().insert(
                            crate::headers::SGX_PCK_CRL_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("crl-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/qe/identity",
                get(move || {
                    let c = c3.clone();
                    async move {
                        count(&c);
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "{\"enclaveIdentity\":{\"id\":\"QE\"}}",
                        ));
                        resp.headers_mut().insert(
                            crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("id-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/qve/identity",
                get(move || {
                    let c = c4.clone();
                    async move {
                        count(&c);
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "{\"enclaveIdentity\":{\"id\":\"QVE\"}}",
                        ));
                        resp.headers_mut().insert(
                            crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("id-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/tdx/certification/v4/qe/identity",
                get(move || {
                    let c = c5.clone();
                    async move {
                        count(&c);
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "{\"enclaveIdentity\":{\"id\":\"TDQE\"}}",
                        ));
                        resp.headers_mut().insert(
                            crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("id-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/rootcacrl",
                get(move || {
                    let c = c6.clone();
                    async move {
                        count(&c);
                        axum::response::Response::new(axum::body::Body::from(vec![0x30u8, 0x82]))
                    }
                }),
            );
        spawn(app).await
    }

    fn platform(qe: &str) -> RegisteredPlatform {
        RegisteredPlatform {
            qe_id: qe.into(),
            pce_id: "0001".into(),
            cpu_svn: "AB".repeat(16),
            pce_svn: "00FF".into(),
            enc_ppid: "E".repeat(768),
            platform_manifest: String::new(),
            state: 0,
        }
    }

    #[tokio::test]
    async fn lazy_register_fills_cert_and_qv_collateral() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);

        cache.register_platform(platform("QE1"), UpdateType::All).await.unwrap();

        // The cert itself, plus one pool so later raw TCBs select locally.
        let rec = cache.store.get_pckcert("QE1", &"AB".repeat(16), "00FF", "0001").unwrap();
        assert_eq!(rec.ca, "PROCESSOR");
        assert!(cache.store.has_platform("QE1", "0001"));
        let pool = cache.store.get_platform_pool("QE1", "0001").unwrap();
        assert_eq!(pool.enc_ppid, "E".repeat(768));

        // QV collateral for both update types and both CAs.
        for ca in ["PROCESSOR", "PLATFORM"] {
            assert!(cache.store.get_pckcrl(ca).is_some(), "{ca}");
        }
        for id in [1u8, 2, 3] {
            for update in [UpdateType::Standard, UpdateType::Early] {
                assert!(cache.store.get_identity(id, 4, update).is_some());
            }
        }
        assert!(cache.store.get_rootcacrl().is_some());

        // A second registration of the same platform is a cache hit: no new
        // upstream calls at all. (The mock's counter, not `upstream_fetches`
        // — the direct QV-collateral fetches bypass that metric.)
        let before = calls.load(Ordering::Relaxed);
        cache.register_platform(platform("QE1"), UpdateType::Standard).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), before);
    }

    #[tokio::test]
    async fn req_register_failure_leaves_the_row_queued() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcert",
            get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Req);

        let err = cache.register_platform(platform("QE2"), UpdateType::Standard).await.unwrap_err();
        assert_err(&err, &error::NO_CACHE_DATA);
        // Node leaves the NEW row in the queue when the fill fails.
        let queued = cache.store.take_registered(0).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].qe_id, "QE2");
    }

    #[tokio::test]
    async fn lazy_intel_pckcert_without_ppid_or_manifest_is_a_400() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, mut cache) = cache_with(&base, CacheMode::Lazy);
        Arc::get_mut(&mut cache).unwrap().is_intel = true;
        let err =
            cache.get_pckcert("QE9", &"AB".repeat(16), "00FF", "0001", None, 4).await.unwrap_err();
        assert_err(&err, &error::INVALID_REQ);
        assert_eq!(calls.load(Ordering::Relaxed), 0, "rejected before upstream");
    }

    #[tokio::test]
    async fn offline_and_req_pckcert_miss_is_platform_unknown() {
        for mode in [CacheMode::Offline, CacheMode::Req] {
            let (_dir, cache) = cache_with("", mode);
            let err = cache
                .get_pckcert("QE9", &"AB".repeat(16), "00FF", "0001", None, 4)
                .await
                .unwrap_err();
            assert_err(&err, &error::platform_unknown());
        }
    }

    #[tokio::test]
    async fn chained_pckcert_is_cached_unchained_is_not() {
        use axum::routing::get;
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        // No issuer-chain header: the response is served but never persisted.
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcrl",
            get(move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    axum::response::Response::new(axum::body::Body::from(vec![0x30u8]))
                }
            }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);

        let rec = cache.get_pckcrl("PROCESSOR", 4).await.unwrap();
        assert_eq!(rec.pckcrl, vec![0x30]);
        assert!(cache.store.get_pckcrl("PROCESSOR").is_none(), "chain-less CRL is not cached");
        cache.get_pckcrl("PROCESSOR", 4).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2, "every request retries upstream");
    }

    #[tokio::test]
    async fn rootcacrl_and_crl_fill_through_cache() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);

        // PCCS upstream: {base}rootcacrl, cached after the first fetch.
        let crl_calls = calls.load(Ordering::Relaxed);
        let der = cache.get_rootcacrl(4).await.unwrap();
        assert_eq!(der, vec![0x30, 0x82]);
        cache.get_rootcacrl(4).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), crl_calls + 1, "second GET is a store hit");

        // A v3 *miss* is EOL, never a network call (a cached record is still
        // served — the store hit above comes first, as in Node).
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        let err = cache.get_rootcacrl(3).await.unwrap_err();
        assert_err(&err, &error::PCS_V3_REACHED_EOL);
    }

    #[tokio::test]
    async fn crl_fill_uses_the_given_uri() {
        use axum::routing::get;
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let app = axum::Router::new().route(
            "/IntelSGXRootCA.crl",
            get(move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    axum::response::Response::new(axum::body::Body::from(vec![0xAAu8]))
                }
            }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        // `get_crl` takes the URI verbatim; the handler layer is what
        // restricts it to Intel hosts.
        let host = base.trim_end_matches("/sgx/certification/v4/");
        let uri = format!("{host}/IntelSGXRootCA.crl");
        let der = cache.get_crl(&uri, 4).await.unwrap();
        assert_eq!(der, vec![0xAA]);
        cache.get_crl(&uri, 4).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_failed_fetch_is_reused_by_the_waiters_behind_it() {
        use axum::routing::get;
        let calls = Arc::new(AtomicU64::new(0));
        // The mock signals when the first fetch arrives and then blocks until
        // the test releases it, so the second request is deterministically
        // queued behind the first one's key lock when the failure lands.
        let received = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let c = calls.clone();
        let r = received.clone();
        let g = release.clone();
        let app = axum::Router::new().route(
            "/sgx/certification/v4/tcb",
            get(move || {
                let c = c.clone();
                let r = r.clone();
                let g = g.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    r.notify_one();
                    g.notified().await;
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);

        let first = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get_tcb(0, "00A067110000", 4, UpdateType::Standard).await }
        });
        // The first request has taken the key lock and reached the upstream.
        received.notified().await;
        let second = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get_tcb(0, "00A067110000", 4, UpdateType::Standard).await }
        });
        // Wait until the second request is deterministically queued on the
        // key lock: the first request holds the lock Arc plus its guard, so a
        // third strong reference is the second request inside `key_lock`.
        let key = keys::tcb(keys::prod_name(0), 4, "00A067110000", UpdateType::Standard.as_str());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let strong = {
                    let map = cache.inflight.lock().await;
                    map.get(&key)
                        .and_then(Weak::upgrade)
                        .map(|lock| Arc::strong_count(&lock))
                        .unwrap_or(0)
                };
                if strong >= 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second request never queued on the key lock");
        // The waiter is in place; let the first fetch fail.
        release.notify_one();
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert_err(&first.unwrap_err(), &error::NO_CACHE_DATA);
        // The waiter was queued behind the failing fetch and reuses its error
        // instead of issuing a second upstream call.
        assert_err(&second.unwrap_err(), &error::NO_CACHE_DATA);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refresh_certs_pccs_refetches_every_known_raw_tcb() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);

        let mut pool = crate::store::PlatformPool {
            qe_id: "QE3".into(),
            pce_id: "0001".into(),
            enc_ppid: "E".repeat(768),
            fmspc: "00A067110000".into(),
            ..Default::default()
        };
        pool.raw_tcbs.push(RawTcb {
            cpu_svn: "AB".repeat(16),
            pce_svn: "00FF".into(),
            tcbm: "TM".into(),
        });
        pool.raw_tcbs.push(RawTcb {
            cpu_svn: "CD".repeat(16),
            pce_svn: "00FE".into(),
            tcbm: "TM".into(),
        });
        cache.store.put_platform_pool(&pool).unwrap();

        let before = calls.load(Ordering::Relaxed);
        cache.refresh(Some("certs"), Some("00a067110000")).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), before + 2, "one re-fetch per raw TCB");

        // A non-matching fmspc is skipped entirely.
        cache.refresh(Some("certs"), Some("FFFFFFFFFFFF")).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), before + 2);
    }

    #[tokio::test]
    async fn refresh_pckcrl_failure_is_a_503() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcrl",
            get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        cache
            .store
            .put_pckcrl(&PckCrlRecord {
                ca: "PROCESSOR".into(),
                pckcrl: vec![1],
                issuer_chain: "c".into(),
            })
            .unwrap();
        let err = cache.refresh(None, None).await.unwrap_err();
        assert_err(&err, &error::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn refresh_rootcacrl_failure_is_a_500_when_cached() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/rootcacrl",
            get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        cache.store.put_rootcacrl(&[1]).unwrap();
        let err = cache.refresh(None, None).await.unwrap_err();
        assert_err(&err, &error::INTERNAL_ERROR);
    }

    #[tokio::test]
    async fn refresh_without_upstream_is_a_noop() {
        let (_dir, cache) = cache_with("", CacheMode::Lazy);
        cache.refresh(None, None).await.unwrap();
        cache.refresh(Some("certs"), Some("00A067110000")).await.unwrap();
    }

    #[tokio::test]
    async fn process_not_available_queues_na_rows_in_req_mode() {
        let (_dir, cache) = cache_with("", CacheMode::Req);
        let mut tcb = serde_json::Map::new();
        for i in 1..=16u32 {
            tcb.insert(format!("sgxtcbcomp{i:02}svn"), serde_json::json!(i));
        }
        tcb.insert("pcesvn".into(), serde_json::json!(7));
        let resp = PckCertsResponse {
            certs: Vec::new(),
            not_available: vec![
                serde_json::Value::Object(tcb),
                // Missing svn fields: skipped, not an error.
                serde_json::json!({ "pcesvn": 1 }),
                // Missing pcesvn: skipped.
                serde_json::json!({ "sgxtcbcomp01svn": 1 }),
            ],
            fmspc: "00A067110000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "chain".into(),
        };
        cache.process_not_available("QE4", "0001", "PP", "", &resp).unwrap();
        let queued = cache.store.take_registered(1).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].qe_id, "QE4");
        assert_eq!(queued[0].cpu_svn, "0102030405060708090A0B0C0D0E0F10");
        assert_eq!(queued[0].pce_svn, "7");
        assert_eq!(queued[0].state, PLATF_REG_NOT_AVAILABLE);

        // LAZY / OFFLINE never queue these rows.
        let (_dir, cache) = cache_with("", CacheMode::Lazy);
        cache.process_not_available("QE4", "0001", "PP", "", &resp).unwrap();
        assert!(cache.store.take_registered(1).unwrap().is_empty());
    }

    /// A synthetic PCK certificate (Platform CA): PPID 0x11*16, PCEID 4444,
    /// FMSPC 1234567890AB, CPUSVN 0x22*16, PCESVN 0x3333.
    const PCK_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICPDCCAjOgAwIBAgIBATAKBggqhkjOPQQDAjAkMSIwIAYDVQQDDBlJbnRlbCBT
R1ggUENLIFBsYXRmb3JtIENBMAAwJDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBD
ZXJ0aWZpY2F0ZTAAo4IByzCCAccwggHDBgkqhkiG+E0BDQEEggG0MIIBsDAeBgoq
hkiG+E0BDQEBBBARERERERERERERERERERERMBAGCiqGSIb4TQENAQMEAkREMBQG
CiqGSIb4TQENAQQEBhI0VniQqzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4
TQENAQIBAgEiMBAGCyqGSIb4TQENAQICAgEiMBAGCyqGSIb4TQENAQIDAgEiMBAG
CyqGSIb4TQENAQIEAgEiMBAGCyqGSIb4TQENAQIFAgEiMBAGCyqGSIb4TQENAQIG
AgEiMBAGCyqGSIb4TQENAQIHAgEiMBAGCyqGSIb4TQENAQIIAgEiMBAGCyqGSIb4
TQENAQIJAgEiMBAGCyqGSIb4TQENAQIKAgEiMBAGCyqGSIb4TQENAQILAgEiMBAG
CyqGSIb4TQENAQIMAgEiMBAGCyqGSIb4TQENAQINAgEiMBAGCyqGSIb4TQENAQIO
AgEiMBAGCyqGSIb4TQENAQIPAgEiMBAGCyqGSIb4TQENAQIQAgEiMBEGCyqGSIb4
TQENAQIRAgIzMzAfBgsqhkiG+E0BDQECEgQQIiIiIiIiIiIiIiIiIiIiIjAAAwEA
-----END CERTIFICATE-----
";

    fn pck_tcb_info() -> serde_json::Value {
        let comps: Vec<serde_json::Value> =
            (0..16).map(|_| serde_json::json!({ "svn": 0x22 })).collect();
        serde_json::json!({
            "id": "SGX", "fmspc": "1234567890AB", "pceId": "4444", "tcbType": 0,
            "tcbLevels": [{
                "tcb": { "sgxtcbcomponents": comps, "pcesvn": 0x3333 },
                "tcbStatus": "UpToDate"
            }]
        })
    }

    /// Mock serving the manifest `pckcerts` POST plus the SGX TCB info the
    /// fill then requires. The response also carries one `"Not available"`
    /// level, so LAZY mode drops the raw TCB again (Node `needUpdatePlatformTcbs`).
    async fn spawn_intel_pckcerts_mock(not_available: bool) -> String {
        use axum::routing::{get, post};
        let cert = PCK_PEM.replace('\n', "%0A").replace('-', "%2D");
        let mut entries = format!("{{\"tcbm\":\"{}3333\",\"cert\":\"{cert}\"}}", "22".repeat(16));
        if not_available {
            entries.push_str(
                ", {\"tcbm\":\"00\",\"cert\":\"Not%20available\",\"tcb\":{\"pcesvn\":1}}",
            );
        }
        let body = format!("[{entries}]");
        let app = axum::Router::new()
            .route(
                "/sgx/certification/v4/pckcerts",
                post(move || {
                    let body = body.clone();
                    async move {
                        let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                        let h = resp.headers_mut();
                        h.insert(
                            crate::headers::SGX_FMSPC,
                            axum::http::HeaderValue::from_static("1234567890ab"),
                        );
                        h.insert(
                            crate::headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                            axum::http::HeaderValue::from_static("platform"),
                        );
                        h.insert(
                            crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                            axum::http::HeaderValue::from_static("pck-chain"),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/tcb",
                get(|| async {
                    let mut resp = axum::response::Response::new(axum::body::Body::from(
                        serde_json::json!({ "tcbInfo": pck_tcb_info(), "signature": "s" })
                            .to_string(),
                    ));
                    resp.headers_mut().insert(
                        crate::headers::TCB_INFO_ISSUER_CHAIN,
                        axum::http::HeaderValue::from_static("tcb-chain"),
                    );
                    resp
                }),
            );
        spawn(app).await
    }

    #[tokio::test]
    async fn lazy_manifest_registration_fills_via_pckcerts_post_then_local_get() {
        let base = spawn_intel_pckcerts_mock(false).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        // Only authenticated registration fetches a Manifest pool. The
        // following PPID-less known-platform GET must select locally.
        cache
            .register_platform(
                RegisteredPlatform {
                    qe_id: "QEM".into(),
                    pce_id: "4444".into(),
                    cpu_svn: String::new(),
                    pce_svn: String::new(),
                    enc_ppid: String::new(),
                    platform_manifest: "MANIFEST".into(),
                    state: PLATF_REG_NEW,
                },
                UpdateType::Standard,
            )
            .await
            .unwrap();
        assert!(cache.store.get_platform_pool("QEM", "4444").unwrap().raw_tcbs.is_empty());

        let rec =
            cache.get_pckcert("QEM", &"22".repeat(16), "3333", "4444", None, 4).await.unwrap();
        assert_eq!(rec.cert, PCK_PEM);
        assert_eq!(rec.fmspc, "1234567890AB");
        assert_eq!(rec.ca, "PLATFORM");
        assert_eq!(rec.issuer_chain, "pck-chain");
        // The pool now holds the fetched certs, and the raw TCB is known.
        let pool = cache.store.get_platform_pool("QEM", "4444").unwrap();
        assert_eq!(pool.certs.len(), 1);
        assert_eq!(pool.raw_tcbs.len(), 1);
        // The SGX standard TCB info was fetched as part of the fill.
        assert!(cache.store.get_tcb(0, "1234567890AB", 4, UpdateType::Standard).is_some());
    }

    #[tokio::test]
    async fn lazy_fill_with_not_available_levels_skips_raw_and_get_persistence() {
        let base = spawn_intel_pckcerts_mock(true).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        // Exercise the shared fill action directly, not an invented
        // known-platform GET fallback. It can return a selection without
        // persisting a new raw/GET when Intel reports unavailable levels.
        let rec = cache
            .fill_pckcert(
                "QEN",
                &"22".repeat(16),
                "3333",
                "4444",
                PckFetchContext {
                    enc_ppid: "",
                    platform_manifest: "MANIFEST",
                    expected: None,
                    unknown_get: false,
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(cache.store.get_pckcert("QEN", &"22".repeat(16), "3333", "4444").is_none());
        assert_eq!(rec.cert, PCK_PEM);
        let pool = cache.store.get_platform_pool("QEN", "4444").unwrap();
        assert!(
            pool.raw_tcbs.is_empty(),
            "LAZY does not record the raw TCB when levels were Not available"
        );
    }

    #[tokio::test]
    async fn req_register_success_clears_the_queue_row() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Req);
        cache.register_platform(platform("QER"), UpdateType::Standard).await.unwrap();
        // Filled, and the registration row is gone (Node PLATF_REG_DELETED).
        assert!(cache.store.get_pckcert("QER", &"AB".repeat(16), "00FF", "0001").is_some());
        assert!(cache.store.take_registered(0).unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_pckcerts_fails_without_sgx_standard_tcb() {
        use axum::routing::get;
        // Every TCB fetch 404s: the mandatory SGX standard info is missing.
        let app = axum::Router::new().route(
            "/sgx/certification/v4/tcb",
            get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Req);
        let resp = PckCertsResponse {
            certs: vec![("TM".into(), "cert-pem".into())],
            not_available: Vec::new(),
            fmspc: "00A067110000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "pck-chain".into(),
        };
        let err = cache
            .store_pckcerts(
                "QET",
                "0001",
                &PckFetchContext {
                    enc_ppid: "PP",
                    platform_manifest: "",
                    expected: None,
                    unknown_get: false,
                },
                &resp,
                None,
            )
            .await
            .unwrap_err();
        assert_err(&err, &error::NO_CACHE_DATA);
        assert!(cache.store.get_platform_pool("QET", "0001").is_none());
    }

    #[tokio::test]
    async fn refresh_tolerates_identity_errors_and_skips_bad_crl_uris() {
        use axum::routing::get;
        let app = axum::Router::new()
            // Identity refresh 404s: tolerated, refresh continues.
            .route(
                "/sgx/certification/v4/qe/identity",
                get(|| async { axum::http::StatusCode::NOT_FOUND }),
            )
            .route(
                "/sgx/certification/v4/rootcacrl",
                get(|| async {
                    axum::response::Response::new(axum::body::Body::from(vec![0x0Au8]))
                }),
            );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        cache
            .store
            .put_identity(&IdentityRecord {
                enclave_id: 1,
                version: 4,
                update_type: "STANDARD".into(),
                identity: serde_json::json!({"id": "QE"}),
                raw_body: String::new(),
                issuer_chain: "c".into(),
            })
            .unwrap();
        cache.store.put_rootcacrl(&[1]).unwrap();
        // Not an Intel CRL URI: skipped, never fetched.
        cache.store.put_crl("https://evil.test/x.crl", &[2]).unwrap();

        cache.refresh(None, None).await.unwrap();
        assert_eq!(cache.store.get_rootcacrl().unwrap(), vec![0x0A]);
        assert_eq!(cache.store.get_crl("https://evil.test/x.crl").unwrap(), vec![2]);
    }

    #[tokio::test]
    async fn v3_and_non_lazy_short_circuits() {
        let (_dir, cache) = cache_with("", CacheMode::Req);
        let err = cache.get_identity(1, 4, UpdateType::Standard).await.unwrap_err();
        assert_err(&err, &error::NO_CACHE_DATA);
        let err = cache.get_pckcrl("PROCESSOR", 4).await.unwrap_err();
        assert_err(&err, &error::NO_CACHE_DATA);
        let err = cache.get_crl("https://x/y.crl", 4).await.unwrap_err();
        assert_err(&err, &error::NO_CACHE_DATA);

        let (_dir, cache) = cache_with("", CacheMode::Lazy);
        let err = cache.get_identity(1, 3, UpdateType::Standard).await.unwrap_err();
        assert_err(&err, &error::PCS_V3_REACHED_EOL);
        let err = cache.get_pckcrl("PROCESSOR", 3).await.unwrap_err();
        assert_err(&err, &error::PCS_V3_REACHED_EOL);
    }

    #[tokio::test]
    async fn store_pckcerts_writes_pool_and_fetches_tcb_infos() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/tcb",
            get(|| async {
                let mut resp = axum::response::Response::new(axum::body::Body::from(
                    serde_json::json!({"tcbInfo": pck_tcb_info(), "signature": "synthetic"})
                        .to_string(),
                ));
                resp.headers_mut().insert(
                    crate::headers::TCB_INFO_ISSUER_CHAIN,
                    axum::http::HeaderValue::from_static("tcb-chain"),
                );
                resp
            }),
        );
        let base = spawn(app).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Req);
        let resp = PckCertsResponse {
            certs: vec![("TM".into(), PCK_PEM.into())],
            not_available: Vec::new(),
            fmspc: "1234567890AB".into(),
            ca: "PLATFORM".into(),
            issuer_chain: "pck-chain".into(),
        };
        cache
            .store_pckcerts(
                "QE5",
                "4444",
                &PckFetchContext {
                    enc_ppid: "PP",
                    platform_manifest: "",
                    expected: None,
                    unknown_get: false,
                },
                &resp,
                None,
            )
            .await
            .unwrap();
        let pool = cache.store.get_platform_pool("QE5", "4444").unwrap();
        assert_eq!(pool.certs.len(), 1);
        assert_eq!(pool.issuer_chain, "pck-chain");
        // SGX standard TCB info is mandatory and was stored.
        assert!(cache.store.get_tcb(0, "1234567890AB", 4, UpdateType::Standard).is_some());

        // No certs at all is an error.
        let empty = PckCertsResponse {
            certs: Vec::new(),
            not_available: Vec::new(),
            fmspc: "00A067110000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "pck-chain".into(),
        };
        assert!(cache
            .store_pckcerts(
                "QE5",
                "0001",
                &PckFetchContext {
                    enc_ppid: "PP",
                    platform_manifest: "",
                    expected: None,
                    unknown_get: false
                },
                &empty,
                None
            )
            .await
            .is_err());

        // A chain-less response is not persisted.
        let chainless = PckCertsResponse { issuer_chain: String::new(), ..resp.clone() };
        assert!(cache
            .store_pckcerts(
                "QE6",
                "0001",
                &PckFetchContext {
                    enc_ppid: "PP",
                    platform_manifest: "",
                    expected: None,
                    unknown_get: false
                },
                &chainless,
                None
            )
            .await
            .is_err());
    }
}
