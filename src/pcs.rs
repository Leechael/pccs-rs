//! Upstream Intel PCS / PCCS HTTP client (hyper + rustls).
//! `Ocp-Apim-Subscription-Key` follows Node `pcs_client.js`: only on `pckcerts`
//! requests, plus every request to the early-access portal.
//! Any URL containing `/v3/` → 410 without a network call.

use crate::config::Config;
use crate::error::{self, PccsError};
use crate::headers;
use crate::store::{IdentityRecord, PckCertRecord, PckCrlRecord, TcbRecord};
use crate::validate::UpdateType;
use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Node `pcs_client.js` HTTP_TIMEOUT.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP keepalive probes on upstream sockets: they keep NAT / load-balancer
/// mappings alive across a quiet period and surface a peer that went away
/// without a FIN, instead of letting a pooled connection look healthy.
const UPSTREAM_TCP_KEEPALIVE: Duration = Duration::from_secs(60);
/// Largest upstream body we will buffer. Intel collateral is far below this.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// A 429/503 storm must not be amplified by the full retry budget.
const MAX_THROTTLED_ATTEMPTS: u32 = 3;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Root CA CRL fallback when the CRL Distribution Point cannot be read off the
/// cached Intel root CA certificate (Intel PCS has no `{base}rootcacrl` route).
pub const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

const EARLY_ACCESS_PREFIX: &str = "https://validation.api.trustedservices.intel.com/";

/// Everything outside the RFC 3986 unreserved set is escaped.
const QUERY_VALUE: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

fn q(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

type HttpClient = Client<HttpConnector, Full<Bytes>>;
type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

enum AnyClient {
    Http(HttpClient),
    Https(HttpsClient),
}

impl AnyClient {
    async fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, PccsError> {
        match self {
            AnyClient::Http(c) => c.request(req).await.map_err(|e| {
                tracing::warn!("upstream http: {e}");
                error::PCS_ACCESS_FAILURE
            }),
            AnyClient::Https(c) => c.request(req).await.map_err(|e| {
                tracing::warn!("upstream https: {e}");
                error::PCS_ACCESS_FAILURE
            }),
        }
    }
}

/// Parsed Intel `pckcerts` response: the whole cert pool for a platform.
#[derive(Debug, Clone)]
pub struct PckCertsResponse {
    /// `(tcbm, PEM)` for every usable certificate.
    pub certs: Vec<(String, String)>,
    /// `tcb` objects of the levels Intel reported as `"Not available"`.
    pub not_available: Vec<serde_json::Value>,
    pub fmspc: String,
    pub ca: String,
    pub issuer_chain: String,
}

pub struct PcsClient {
    base: String,
    api_key: String,
    is_intel: bool,
    max_attempts: u32,
    client: AnyClient,
    /// Bounds how many upstream requests are in flight at once.
    permits: Arc<Semaphore>,
    pub calls: Arc<AtomicU64>,
}

impl PcsClient {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if !cfg.proxy.trim().is_empty() {
            return Err(
                "proxy is not supported by pccs-rs; remove it from the configuration".to_string()
            );
        }
        let mut http_conn = HttpConnector::new();
        http_conn.set_connect_timeout(Some(CONNECT_TIMEOUT));
        // Collateral requests are small and latency-bound; Nagle would add up to
        // 40ms to every request head that does not fill a segment.
        http_conn.set_nodelay(true);
        http_conn.set_keepalive(Some(UPSTREAM_TCP_KEEPALIVE));
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            // Without a pool timer hyper-util never spawns the reaper task, so
            // idle connections are only ever evicted when a checkout happens to
            // look at them. With it, `pool_idle_timeout` is enforced in the
            // background too.
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(cfg.upstream_pool_idle_secs))
            // One idle connection per in-flight slot: the semaphore already caps
            // concurrency, so this is the most we can ever have open at once.
            .pool_max_idle_per_host(cfg.upstream_max_concurrent.max(1))
            // Default, kept explicit: a pooled connection the peer closed while
            // it sat idle fails before any byte of the request was written, so
            // replaying it is safe. Our GETs are idempotent (same request, same
            // result); the one POST (`pckcerts` with a platform manifest) is
            // already replayed by the retry loop in `send`.
            .retry_canceled_requests(true);
        let https = cfg.uri.starts_with("https://") || cfg.uri.is_empty();
        let client = if https {
            http_conn.enforce_http(false);
            let https_conn = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("native TLS roots: {e}"))?
                .https_or_http()
                .enable_http1()
                .wrap_connector(http_conn);
            AnyClient::Https(builder.build(https_conn))
        } else {
            AnyClient::Http(builder.build(http_conn))
        };
        Ok(Self {
            base: normalize_base(&cfg.uri),
            api_key: cfg.api_key.clone(),
            is_intel: cfg.is_intel_upstream(),
            max_attempts: cfg.upstream_max_attempts.max(1),
            client,
            permits: Arc::new(Semaphore::new(cfg.upstream_max_concurrent.max(1))),
            calls: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn enabled(&self) -> bool {
        !self.base.is_empty()
    }

    pub fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    fn check_v3(url: &str) -> Result<(), PccsError> {
        if url.contains("/v3/") {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        Ok(())
    }

    /// Node sends the subscription key on `pckcerts` (GET and POST) and on every
    /// early-access-portal request; never on CRL downloads.
    fn wants_api_key(url: &str) -> bool {
        if url.starts_with(EARLY_ACCESS_PREFIX) {
            return true;
        }
        let path = url.split(['?', '#']).next().unwrap_or(url);
        path.trim_end_matches('/').ends_with("/pckcerts")
    }

    /// Retry policy: up to `max_attempts` tries for transport errors (Node's
    /// `MAX_RETRY_COUNT`), but a throttled upstream (429/503) is retried at most
    /// twice so a PCS-side storm is not amplified by every cache miss. A
    /// `Retry-After` header wins over the exponential backoff, capped at 30s.
    async fn get(&self, url: &str) -> Result<(u16, HeaderMap, Vec<u8>), PccsError> {
        self.send(url, None).await
    }

    /// `body = Some(json)` issues a POST with `Content-Type: application/json`
    /// (Node `pcs_client.getCertsWithManifest`); `None` issues a GET.
    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, HeaderMap, Vec<u8>), PccsError> {
        Self::check_v3(url)?;
        if !self.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let send_key = Self::wants_api_key(url) && !self.api_key.is_empty();
        let mut last = error::PCS_ACCESS_FAILURE;
        let mut throttled = 0u32;
        let mut delay: Option<Duration> = None;
        for attempt in 0..self.max_attempts {
            if attempt > 0 {
                let backoff =
                    delay.take().unwrap_or(Duration::from_millis(50u64 << attempt.min(5)));
                tokio::time::sleep(backoff).await;
            }
            let uri: Uri = url.parse().map_err(|_| error::INTERNAL_ERROR)?;
            let payload = body.clone().unwrap_or_default();
            let builder = match &body {
                Some(_) => {
                    Request::post(uri).header(hyper::header::CONTENT_TYPE, "application/json")
                }
                None => Request::get(uri),
            };
            let mut req =
                builder.body(Full::new(Bytes::from(payload))).map_err(|_| error::INTERNAL_ERROR)?;
            if send_key {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(b"Ocp-Apim-Subscription-Key"),
                    HeaderValue::from_str(&self.api_key),
                ) {
                    req.headers_mut().insert(n, v);
                }
            }
            let _permit = match self.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return Err(error::INTERNAL_ERROR),
            };
            let attempt_result = tokio::time::timeout(REQUEST_TIMEOUT, self.attempt(req)).await;
            match attempt_result {
                Err(_) => {
                    tracing::warn!("upstream request {} timed out", redact_url(url));
                    last = error::PCS_ACCESS_FAILURE;
                }
                Ok(Err(e)) => {
                    last = e;
                }
                Ok(Ok((status, hdrs, body))) => {
                    if status == 429 || status == 503 {
                        throttled += 1;
                        if throttled < MAX_THROTTLED_ATTEMPTS && attempt + 1 < self.max_attempts {
                            delay = retry_after(&hdrs);
                            last = error::PCS_ACCESS_FAILURE;
                            continue;
                        }
                    }
                    tracing::info!("upstream request {} -> {status}", redact_url(url));
                    return Ok((status, hdrs, body));
                }
            }
        }
        Err(last)
    }

    /// One request plus a size-capped body read.
    async fn attempt(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<(u16, HeaderMap, Vec<u8>), PccsError> {
        let resp = self.client.request(req).await?;
        let status = resp.status().as_u16();
        let hdrs = resp.headers().clone();
        if let Some(len) = hdrs
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
        {
            if len > MAX_RESPONSE_BYTES {
                tracing::warn!("upstream response too large: {len} bytes");
                return Err(error::PCS_ACCESS_FAILURE);
            }
        }
        let body = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| {
                tracing::warn!("upstream body: {e}");
                error::PCS_ACCESS_FAILURE
            })?
            .to_bytes();
        Ok((status, hdrs, body.to_vec()))
    }

    fn hdr(h: &HeaderMap, name: &str) -> String {
        h.get(name)
            .or_else(|| h.get(name.to_ascii_lowercase()))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    pub async fn fetch_pckcert_pccs(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        enc_ppid: Option<&str>,
    ) -> Result<PckCertRecord, PccsError> {
        let mut url = format!(
            "{}pckcert?qeid={}&cpusvn={}&pcesvn={}&pceid={}",
            self.base,
            q(qeid),
            q(cpusvn),
            q(pcesvn),
            q(pceid)
        );
        if let Some(e) = enc_ppid {
            if !e.is_empty() {
                url.push_str("&encrypted_ppid=");
                url.push_str(&q(e));
            }
        }
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        Ok(PckCertRecord {
            qeid: qeid.to_ascii_uppercase(),
            pceid: pceid.to_ascii_uppercase(),
            cpusvn: cpusvn.to_ascii_uppercase(),
            pcesvn: pcesvn.to_ascii_uppercase(),
            cert: String::from_utf8_lossy(&body).into_owned(),
            tcbm: Self::hdr(&h, headers::SGX_TCBM).to_ascii_uppercase(),
            fmspc: Self::hdr(&h, headers::SGX_FMSPC).to_ascii_uppercase(),
            // Normalised like every other CA value we store, so the served
            // `SGX-PCK-Certificate-CA-Type` header is always `PROCESSOR` /
            // `PLATFORM` regardless of the upstream's casing.
            ca: Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_CA_TYPE).to_ascii_uppercase(),
            issuer_chain: Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN),
            encrypted_ppid: enc_ppid.map(|s| s.to_ascii_uppercase()),
            platform_manifest: String::new(),
        })
    }

    /// Everything Intel's `pckcerts` response carries. Selection happens in
    /// `Cache`, which needs the fmspc's TCB info first — the same order as
    /// Node `commonCacheLogic.getPckCertFromPCS`.
    pub async fn fetch_pckcerts_intel(
        &self,
        enc_ppid: &str,
        pceid: &str,
    ) -> Result<PckCertsResponse, PccsError> {
        // Node `getPckServerResponse`: an all-zero encrypted PPID is refused.
        if enc_ppid.is_empty() || enc_ppid.chars().all(|c| c == '0') {
            tracing::error!("Encrypted ppid is all zeros.");
            return Err(error::NO_CACHE_DATA);
        }
        let url =
            format!("{}pckcerts?encrypted_ppid={}&pceid={}", self.base, q(enc_ppid), q(pceid));
        let (status, h, body) = self.get(&url).await?;
        Self::parse_pckcerts(status, &h, &body)
    }

    /// Node `pcs_client.getCertsWithManifest`: POST `{platformManifest, pceid}`
    /// to `{base}pckcerts`. Node uses the same call whether the upstream is
    /// Intel PCS or another PCCS, so this path is not gated on `is_intel`.
    pub async fn fetch_pckcerts_intel_manifest(
        &self,
        platform_manifest: &str,
        pceid: &str,
    ) -> Result<PckCertsResponse, PccsError> {
        let url = format!("{}pckcerts", self.base);
        let payload = serde_json::json!({
            "platformManifest": platform_manifest,
            "pceid": pceid,
        })
        .to_string();
        let (status, h, body) = self.send(&url, Some(payload.into_bytes())).await?;
        Self::parse_pckcerts(status, &h, &body)
    }

    fn parse_pckcerts(
        status: u16,
        h: &HeaderMap,
        body: &[u8],
    ) -> Result<PckCertsResponse, PccsError> {
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let fmspc = Self::hdr(h, headers::SGX_FMSPC).to_ascii_uppercase();
        let ca = Self::hdr(h, headers::SGX_PCK_CERTIFICATE_CA_TYPE).to_ascii_uppercase();
        if fmspc.is_empty() || ca.is_empty() {
            // Node `getFmspcAndCaType` → PCCS_STATUS_INTERNAL_ERROR.
            tracing::error!("The server response doesn't include fmspc or ca.");
            return Err(error::INTERNAL_ERROR);
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| error::INTERNAL_ERROR)?;
        let arr = parsed.as_array().ok_or(error::NO_CACHE_DATA)?;
        let mut certs = Vec::new();
        let mut not_available = Vec::new();
        for c in arr {
            let tcbm = c.get("tcbm").and_then(|x| x.as_str()).unwrap_or("").to_ascii_uppercase();
            let cert = crate::validate::percent_decode(
                c.get("cert").and_then(|x| x.as_str()).unwrap_or(""),
            );
            // Node `filterPckCerts`
            if cert == "Not available" {
                not_available.push(c.get("tcb").cloned().unwrap_or(serde_json::Value::Null));
                continue;
            }
            if !tcbm.is_empty() && !cert.is_empty() {
                certs.push((tcbm, cert));
            }
        }
        Ok(PckCertsResponse {
            certs,
            not_available,
            fmspc,
            ca,
            issuer_chain: Self::hdr(h, headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN),
        })
    }

    pub async fn fetch_tcb(
        &self,
        prod_type: u8,
        fmspc: &str,
        version: u32,
        update: UpdateType,
    ) -> Result<TcbRecord, PccsError> {
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        let upd = match update {
            UpdateType::Early => "early",
            _ => "standard",
        };
        let url = format!(
            "{}tcb?fmspc={}&update={}",
            tdx_if(self.base.as_str(), prod_type == 1),
            q(fmspc),
            q(upd)
        );
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let raw_body = String::from_utf8(body).map_err(|_| error::NO_CACHE_DATA)?;
        let tcbinfo: serde_json::Value =
            serde_json::from_str(&raw_body).map_err(|_| error::NO_CACHE_DATA)?;
        let issuer = {
            let v4 = Self::hdr(&h, headers::TCB_INFO_ISSUER_CHAIN);
            if v4.is_empty() {
                Self::hdr(&h, headers::SGX_TCB_INFO_ISSUER_CHAIN)
            } else {
                v4
            }
        };
        Ok(TcbRecord {
            prod_type,
            fmspc: fmspc.to_ascii_uppercase(),
            version,
            update_type: update.as_str().to_string(),
            tcbinfo,
            raw_body,
            issuer_chain: issuer,
        })
    }

    pub async fn fetch_identity(
        &self,
        enclave_id: u8,
        version: u32,
        update: UpdateType,
    ) -> Result<IdentityRecord, PccsError> {
        if version == 3 {
            return Err(error::PCS_V3_REACHED_EOL);
        }
        let upd = match update {
            UpdateType::Early => "early",
            _ => "standard",
        };
        let upd = q(upd);
        let url = match enclave_id {
            2 => format!("{}qve/identity?update={upd}", self.base),
            3 => format!("{}qe/identity?update={upd}", tdx_if(&self.base, true)),
            _ => format!("{}qe/identity?update={upd}", self.base),
        };
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let raw_body = String::from_utf8(body).map_err(|_| error::NO_CACHE_DATA)?;
        let identity: serde_json::Value =
            serde_json::from_str(&raw_body).map_err(|_| error::NO_CACHE_DATA)?;
        Ok(IdentityRecord {
            enclave_id,
            version,
            update_type: update.as_str().to_string(),
            identity,
            raw_body,
            issuer_chain: Self::hdr(&h, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN),
        })
    }

    pub async fn fetch_pckcrl(&self, ca: &str) -> Result<PckCrlRecord, PccsError> {
        let url = format!("{}pckcrl?ca={}&encoding=der", self.base, q(&ca.to_ascii_lowercase()));
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        Ok(PckCrlRecord {
            ca: ca.to_ascii_uppercase(),
            pckcrl: body,
            issuer_chain: Self::hdr(&h, headers::SGX_PCK_CRL_ISSUER_CHAIN),
        })
    }

    /// Intel PCS has no `{base}rootcacrl` route. Node derives the URL from the
    /// CRL Distribution Point of the cached root CA certificate
    /// (`commonCacheLogic.getRootCACrlFromPCS`); the root CA is the last element
    /// of an issuer chain, so we take it from a fresh `qe/identity` response —
    /// the same call Node makes when the root cert is not cached yet. If the CDP
    /// cannot be read, fall back to Intel's documented root CA CRL URL.
    /// A PCCS upstream keeps serving `{base}rootcacrl`.
    async fn rootcacrl_url(&self) -> String {
        if !self.is_intel {
            return format!("{}rootcacrl", self.base);
        }
        match self.intel_root_ca_cdp().await {
            Some(u) => u,
            None => {
                tracing::info!(
                    "root CA CRL distribution point unavailable; using {INTEL_ROOT_CA_CRL_URL}"
                );
                INTEL_ROOT_CA_CRL_URL.to_string()
            }
        }
    }

    async fn intel_root_ca_cdp(&self) -> Option<String> {
        let url = format!("{}qe/identity?update=standard", self.base);
        let (status, h, _) = self.get(&url).await.ok()?;
        if status != 200 {
            return None;
        }
        let chain = Self::hdr(&h, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN);
        let chain = percent_decode(&chain);
        let root = last_pem_der(&chain)?;
        let cdp = crl_distribution_point(&root)?;
        if crate::validate::is_valid_crl_uri(&cdp) {
            Some(cdp)
        } else {
            tracing::warn!("root CA CRL distribution point {cdp} is not an Intel CRL URI");
            None
        }
    }

    pub async fn fetch_rootcacrl(&self) -> Result<Vec<u8>, PccsError> {
        let url = self.rootcacrl_url().await;
        let (status, _, body) = self.get(&url).await?;
        if status != 200 {
            // Node `getFileFromUrl` lets the HTTP error bubble up as a 500.
            tracing::error!("Failed to download file for the given uri.");
            return Err(error::INTERNAL_ERROR);
        }
        if body.iter().all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace()) {
            let s = String::from_utf8_lossy(&body);
            let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if let Ok(bytes) = hex::decode(&cleaned) {
                if !bytes.is_empty() {
                    return Ok(bytes);
                }
            }
        }
        Ok(body)
    }

    pub async fn fetch_crl(&self, uri: &str) -> Result<Vec<u8>, PccsError> {
        Self::check_v3(uri)?;
        if !self.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        let (status, _, body) = self.get(uri).await?;
        if status != 200 {
            // Node `getFileFromUrl` lets the HTTP error bubble up as a 500.
            tracing::error!("Failed to download file for the given uri.");
            return Err(error::INTERNAL_ERROR);
        }
        Ok(body)
    }
}

/// `Retry-After: <seconds>`, capped. HTTP-date form is ignored (Intel sends seconds).
fn retry_after(h: &HeaderMap) -> Option<Duration> {
    let secs: u64 = h.get(hyper::header::RETRY_AFTER)?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Node `parseAndModifyUrl`: query values longer than 50 characters are logged
/// as `first4...last4` so encrypted PPIDs never reach the log.
fn redact_url(url: &str) -> String {
    let Some((path, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let redacted: Vec<String> = query
        .split('&')
        .map(|param| match param.split_once('=') {
            Some((k, v)) if v.chars().count() > 50 => {
                let head: String = v.chars().take(4).collect();
                let tail: String = v.chars().skip(v.chars().count() - 4).collect();
                format!("{k}={head}...{tail}")
            }
            _ => param.to_string(),
        })
        .collect();
    format!("{path}?{}", redacted.join("&"))
}

/// DER of the last certificate in a PEM issuer chain (the root CA).
fn last_pem_der(pem: &str) -> Option<Vec<u8>> {
    let block = pem.rsplit("-----BEGIN CERTIFICATE-----").next()?;
    let b64: String = block
        .split("-----END CERTIFICATE-----")
        .next()?
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// URI of the first CRL Distribution Point in a DER certificate.
/// Locates the `2.5.29.31` extension OID, then the first
/// `[6] IMPLICIT IA5String` (`uniformResourceIdentifier`) after it.
fn crl_distribution_point(der: &[u8]) -> Option<String> {
    const CDP_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x1f];
    let start = der.windows(CDP_OID.len()).position(|w| w == CDP_OID)? + CDP_OID.len();
    let mut i = start;
    let end = der.len().min(start + 512);
    while i + 1 < end {
        if der[i] == 0x86 {
            let len = usize::from(der[i + 1]);
            // A short-form length; every Intel CDP URI is far below 128 bytes.
            if len < 0x80 && i + 2 + len <= der.len() {
                // A candidate that is not UTF-8 is simply not the URI we want;
                // `?` here would abandon the whole scan on the first such
                // false positive and lose a CDP that appears later.
                if let Ok(uri) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                    if uri.starts_with("http") {
                        return Some(uri.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn normalize_base(uri: &str) -> String {
    let u = uri.trim();
    if u.is_empty() {
        return String::new();
    }
    if u.ends_with('/') {
        u.to_string()
    } else {
        format!("{u}/")
    }
}

fn tdx_if(sgx_base: &str, tdx: bool) -> String {
    if tdx {
        sgx_base.replace("/sgx/", "/tdx/")
    } else {
        sgx_base.to_string()
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_scope_matches_node() {
        assert!(PcsClient::wants_api_key(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts?encrypted_ppid=aa&pceid=0000"
        ));
        assert!(PcsClient::wants_api_key(
            "https://pccs.example.test/sgx/certification/v4/pckcerts"
        ));
        // Early access portal: every request carries the key.
        assert!(PcsClient::wants_api_key(
            "https://validation.api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00"
        ));
        // Never on plain collateral or CRL downloads.
        assert!(!PcsClient::wants_api_key(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?qeid=aa"
        ));
        assert!(!PcsClient::wants_api_key(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00A067110000"
        ));
        assert!(!PcsClient::wants_api_key(INTEL_ROOT_CA_CRL_URL));
    }

    #[test]
    fn long_query_values_are_redacted_in_logs() {
        let long = "A".repeat(64);
        let url = format!("https://pcs.test/v4/pckcerts?encrypted_ppid={long}&pceid=0000");
        assert_eq!(
            redact_url(&url),
            "https://pcs.test/v4/pckcerts?encrypted_ppid=AAAA...AAAA&pceid=0000"
        );
        assert_eq!(
            redact_url("https://pcs.test/v4/qe/identity"),
            "https://pcs.test/v4/qe/identity"
        );
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(q("00A067110000"), "00A067110000");
        assert_eq!(q("a&b=c d"), "a%26b%3Dc%20d");
        assert_eq!(q("../../etc"), "..%2F..%2Fetc");
    }

    #[test]
    fn retry_after_seconds_is_capped() {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(retry_after(&h), Some(Duration::from_secs(5)));
        h.insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("99999"));
        assert_eq!(retry_after(&h), Some(MAX_RETRY_AFTER));
        h.insert(
            hyper::header::RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(retry_after(&h), None);
    }

    #[test]
    fn crl_distribution_point_is_read_from_der() {
        // 2.5.29.31 OID, then a [6] IA5String holding the CDP URI.
        let uri = b"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
        let mut der = vec![0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x03];
        der.push(0x86);
        der.push(uri.len() as u8);
        der.extend_from_slice(uri);
        assert_eq!(
            crl_distribution_point(&der).as_deref(),
            Some(std::str::from_utf8(uri).unwrap())
        );
        assert_eq!(crl_distribution_point(b"no extensions here"), None);
    }

    #[test]
    fn last_pem_returns_the_last_certificate() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nd29ybGQ=\n-----END CERTIFICATE-----\n";
        assert_eq!(last_pem_der(pem).unwrap(), b"world");
    }

    #[test]
    fn normalize_base_appends_a_slash() {
        assert_eq!(normalize_base(""), "");
        assert_eq!(normalize_base("https://x/v4/"), "https://x/v4/");
        assert_eq!(normalize_base("https://x/v4"), "https://x/v4/");
        assert_eq!(normalize_base("  https://x/v4  "), "https://x/v4/");
    }

    #[test]
    fn tdx_if_swaps_the_product_segment() {
        assert_eq!(tdx_if("https://x/sgx/v4/", false), "https://x/sgx/v4/");
        assert_eq!(tdx_if("https://x/sgx/v4/", true), "https://x/tdx/v4/");
    }

    #[test]
    fn percent_decode_edge_cases() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%2"), "%2");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn redact_url_only_shortens_values_over_50_chars() {
        let exact = "A".repeat(50);
        let url = format!("https://x/pckcerts?encrypted_ppid={exact}");
        assert_eq!(redact_url(&url), url, "50 chars is not redacted");
        let over = "B".repeat(51);
        let url = format!("https://x/pckcerts?encrypted_ppid={over}");
        assert_eq!(redact_url(&url), "https://x/pckcerts?encrypted_ppid=BBBB...BBBB");
    }

    #[test]
    fn parse_pckcerts_status_and_shape_checks() {
        let mut h = HeaderMap::new();
        h.insert(headers::SGX_FMSPC, HeaderValue::from_static("00a067110000"));
        h.insert(headers::SGX_PCK_CERTIFICATE_CA_TYPE, HeaderValue::from_static("processor"));
        h.insert(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, HeaderValue::from_static("chain"));

        // Non-200 is a cache miss.
        assert!(PcsClient::parse_pckcerts(404, &h, b"[]").is_err());
        // Missing fmspc / ca headers is a 500, as in Node.
        assert!(PcsClient::parse_pckcerts(200, &HeaderMap::new(), b"[]").is_err());
        // Unparseable / non-array bodies.
        assert!(PcsClient::parse_pckcerts(200, &h, b"not json").is_err());
        assert!(PcsClient::parse_pckcerts(200, &h, b"{}").is_err());

        let body = serde_json::json!([
            { "tcbm": "aa", "cert": "cert-pem" },
            // "Not available" goes to the registration queue, not the pool.
            { "tcbm": "bb", "cert": "Not%20available", "tcb": { "pcesvn": 7 } },
            // Entries without both tcbm and cert are dropped.
            { "tcbm": "", "cert": "x" },
            { "tcbm": "cc" }
        ])
        .to_string();
        let resp = PcsClient::parse_pckcerts(200, &h, body.as_bytes()).unwrap();
        assert_eq!(resp.certs, vec![("AA".to_string(), "cert-pem".to_string())]);
        assert_eq!(resp.not_available.len(), 1);
        assert_eq!(resp.not_available[0]["pcesvn"], 7);
        assert_eq!(resp.fmspc, "00A067110000");
        assert_eq!(resp.ca, "PROCESSOR");
        assert_eq!(resp.issuer_chain, "chain");
    }

    // ---- mock-upstream integration tests (loopback only, never Intel) ----

    use axum::http::StatusCode;
    use std::sync::Mutex as StdMutex;

    fn client_for(base: &str) -> PcsClient {
        let cfg = Config {
            uri: base.into(),
            api_key: "secret-key".into(),
            upstream_max_attempts: 1,
            ..Config::default()
        };
        PcsClient::new(&cfg).unwrap()
    }

    async fn spawn(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}/sgx/certification/v4/")
    }

    type Seen = Arc<StdMutex<Vec<(String, String, String)>>>;

    /// Records `(method, path?query, subscription-key)` for every request.
    fn recorder() -> (Seen, axum::Router) {
        use axum::routing::any;
        let seen: Seen = Arc::new(StdMutex::new(Vec::new()));
        let seen2 = seen.clone();
        let app = axum::Router::new().fallback(any(move |req: Request<axum::body::Body>| {
            let seen = seen2.clone();
            async move {
                let method = req.method().to_string();
                let pq = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("").to_string();
                let key = req
                    .headers()
                    .get("Ocp-Apim-Subscription-Key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                seen.lock().unwrap().push((method, pq, key));
                hyper::Response::builder().status(404).body(axum::body::Body::empty()).unwrap()
            }
        }));
        (seen, app)
    }

    #[tokio::test]
    async fn pckcert_pccs_normalises_and_encodes() {
        let (seen, app) = recorder();
        let base = spawn(app).await;
        let client = client_for(&base);

        // 404 upstream → NO_CACHE_DATA.
        assert!(client.fetch_pckcert_pccs("qe", "aa", "bb", "cc", None).await.is_err());
        let req = seen.lock().unwrap()[0].clone();
        assert_eq!(req.0, "GET");
        assert!(req.1.starts_with("/sgx/certification/v4/pckcert?"), "{}", req.1);
        // No enc_ppid param when None; the key is not sent on plain collateral.
        assert!(!req.1.contains("encrypted_ppid"), "{}", req.1);
        assert_eq!(req.2, "");

        // Serve a cert and check record normalisation + query encoding.
        let (seen2, app2) = {
            use axum::routing::get;
            let seen: Seen = Arc::new(StdMutex::new(Vec::new()));
            let seen2 = seen.clone();
            let app = axum::Router::new().route(
                "/sgx/certification/v4/pckcert",
                get(move |req: Request<axum::body::Body>| {
                    let seen = seen2.clone();
                    async move {
                        let pq = req.uri().query().unwrap_or("").to_string();
                        seen.lock().unwrap().push(("GET".into(), pq, String::new()));
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "-----BEGIN CERTIFICATE-----\nPEM\n-----END CERTIFICATE-----\n",
                        ));
                        let h = resp.headers_mut();
                        h.insert(headers::SGX_TCBM, HeaderValue::from_static("aabb"));
                        h.insert(headers::SGX_FMSPC, HeaderValue::from_static("00a067110000"));
                        h.insert(
                            headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                            HeaderValue::from_static("processor"),
                        );
                        h.insert(
                            headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                            HeaderValue::from_static("the-chain"),
                        );
                        resp
                    }
                }),
            );
            (seen, app)
        };
        let base = spawn(app2).await;
        let client = client_for(&base);
        let rec =
            client.fetch_pckcert_pccs("qeid", "ab", "cd", "ef", Some("p p&id")).await.unwrap();
        assert_eq!(rec.qeid, "QEID");
        assert_eq!(rec.pceid, "EF");
        assert_eq!(rec.cpusvn, "AB");
        assert_eq!(rec.pcesvn, "CD");
        assert_eq!(rec.tcbm, "AABB");
        assert_eq!(rec.fmspc, "00A067110000");
        assert_eq!(rec.ca, "PROCESSOR");
        assert_eq!(rec.issuer_chain, "the-chain");
        assert_eq!(rec.encrypted_ppid.as_deref(), Some("P P&ID"));
        assert!(rec.cert.contains("BEGIN CERTIFICATE"));
        let query = &seen2.lock().unwrap()[0].1;
        assert!(query.contains("encrypted_ppid=p%20p%26id"), "{query}");
    }

    #[tokio::test]
    async fn pckcerts_intel_rejects_all_zero_ppid_without_network() {
        let client = client_for("");
        assert!(!client.enabled());
        assert!(client.fetch_pckcerts_intel("", "0000").await.is_err());
        assert!(client.fetch_pckcerts_intel("00000000", "0000").await.is_err());
        assert_eq!(client.call_count(), 0, "no network call may happen");
    }

    #[tokio::test]
    async fn pckcerts_endpoints_send_the_api_key() {
        use axum::routing::get;
        let seen: Seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_g = seen.clone();
        let seen_p = seen.clone();
        let responder = |seen: Seen| {
            move |req: Request<axum::body::Body>| {
                let seen = seen.clone();
                async move {
                    let key = req
                        .headers()
                        .get("Ocp-Apim-Subscription-Key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    seen.lock().unwrap().push((req.method().to_string(), String::new(), key));
                    let mut resp = axum::response::Response::new(axum::body::Body::from("[]"));
                    let h = resp.headers_mut();
                    h.insert(headers::SGX_FMSPC, HeaderValue::from_static("00A067110000"));
                    h.insert(
                        headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                        HeaderValue::from_static("PLATFORM"),
                    );
                    resp
                }
            }
        };
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcerts",
            get(responder(seen_g)).post(responder(seen_p)),
        );
        let base = spawn(app).await;
        let client = client_for(&base);

        let resp = client.fetch_pckcerts_intel("AA", "0000").await.unwrap();
        assert!(resp.certs.is_empty());
        let resp = client.fetch_pckcerts_intel_manifest("{}", "0000").await.unwrap();
        assert!(resp.certs.is_empty());

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "GET");
        assert_eq!(seen[0].2, "secret-key", "GET pckcerts carries the key");
        assert_eq!(seen[1].0, "POST");
        assert_eq!(seen[1].2, "secret-key", "POST pckcerts carries the key");
    }

    #[tokio::test]
    async fn fetch_tcb_paths_headers_and_errors() {
        use axum::routing::get;
        let seen: Seen = Arc::new(StdMutex::new(Vec::new()));
        let seen2 = seen.clone();
        let ok = move |req: Request<axum::body::Body>, legacy_chain: bool| {
            let seen = seen2.clone();
            async move {
                seen.lock().unwrap().push((
                    String::new(),
                    req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("").to_string(),
                    String::new(),
                ));
                let mut resp = axum::response::Response::new(axum::body::Body::from(
                    "{\"tcbInfo\":{\"id\":\"SGX\"}}",
                ));
                let name = if legacy_chain {
                    headers::SGX_TCB_INFO_ISSUER_CHAIN
                } else {
                    headers::TCB_INFO_ISSUER_CHAIN
                };
                resp.headers_mut().insert(name, HeaderValue::from_static("tcb-chain"));
                resp
            }
        };
        let seen3 = seen.clone();
        let app = axum::Router::new()
            .route("/sgx/certification/v4/tcb", get(move |req| ok(req, false)))
            .route(
                "/tdx/certification/v4/tcb",
                get(move |req: Request<axum::body::Body>| {
                    let seen = seen3.clone();
                    async move {
                        seen.lock().unwrap().push((
                            String::new(),
                            req.uri()
                                .path_and_query()
                                .map(|x| x.as_str())
                                .unwrap_or("")
                                .to_string(),
                            String::new(),
                        ));
                        let mut resp = axum::response::Response::new(axum::body::Body::from(
                            "{\"tcbInfo\":{\"id\":\"TDX\"}}",
                        ));
                        resp.headers_mut().insert(
                            headers::SGX_TCB_INFO_ISSUER_CHAIN,
                            HeaderValue::from_static("legacy-chain"),
                        );
                        resp
                    }
                }),
            );
        let base = spawn(app).await;
        let client = client_for(&base);

        // v3 is refused before any network call.
        assert!(client.fetch_tcb(0, "00A067110000", 3, UpdateType::Standard).await.is_err());
        assert_eq!(client.call_count(), 0);

        let rec = client.fetch_tcb(0, "00a067110000", 4, UpdateType::Early).await.unwrap();
        assert_eq!(rec.fmspc, "00A067110000");
        assert_eq!(rec.update_type, "EARLY");
        assert_eq!(rec.issuer_chain, "tcb-chain");
        assert!(rec.raw_body.contains("SGX"));

        // TDX swaps /sgx/ for /tdx/ and falls back to the legacy header name.
        let rec = client.fetch_tcb(1, "00A067110000", 4, UpdateType::Standard).await.unwrap();
        assert_eq!(rec.issuer_chain, "legacy-chain");

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].1, "/sgx/certification/v4/tcb?fmspc=00a067110000&update=early");
        assert_eq!(seen[1].1, "/tdx/certification/v4/tcb?fmspc=00A067110000&update=standard");
    }

    #[tokio::test]
    async fn fetch_tcb_bad_responses_are_cache_misses() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/tcb",
            get(|| async { axum::response::Response::new(axum::body::Body::from("not json")) }),
        );
        let base = spawn(app).await;
        let client = client_for(&base);
        assert!(client.fetch_tcb(0, "00A067110000", 4, UpdateType::Standard).await.is_err());
    }

    #[tokio::test]
    async fn fetch_identity_url_per_enclave_id() {
        let (seen, app) = recorder();
        let base = spawn(app).await;
        let client = client_for(&base);

        // 404s are cache misses, but the URLs are still observable.
        assert!(client.fetch_identity(1, 4, UpdateType::Standard).await.is_err());
        assert!(client.fetch_identity(2, 4, UpdateType::Early).await.is_err());
        assert!(client.fetch_identity(3, 4, UpdateType::Standard).await.is_err());
        assert!(client.fetch_identity(1, 3, UpdateType::Standard).await.is_err());
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].1, "/sgx/certification/v4/qe/identity?update=standard");
        assert_eq!(seen[1].1, "/sgx/certification/v4/qve/identity?update=early");
        assert_eq!(seen[2].1, "/tdx/certification/v4/qe/identity?update=standard");
        assert_eq!(seen.len(), 3, "v3 never reaches the network");
    }

    #[tokio::test]
    async fn fetch_identity_success() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/qve/identity",
            get(|| async {
                let mut resp = axum::response::Response::new(axum::body::Body::from(
                    "{\"enclaveIdentity\":{\"id\":\"QvE\"}}",
                ));
                resp.headers_mut().insert(
                    headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                    HeaderValue::from_static("id-chain"),
                );
                resp
            }),
        );
        let base = spawn(app).await;
        let client = client_for(&base);
        let rec = client.fetch_identity(2, 4, UpdateType::Standard).await.unwrap();
        assert_eq!(rec.enclave_id, 2);
        assert_eq!(rec.issuer_chain, "id-chain");
        assert!(rec.raw_body.contains("QvE"));
    }

    #[tokio::test]
    async fn fetch_pckcrl_lowercases_ca() {
        let (seen, app) = recorder();
        let base = spawn(app).await;
        let client = client_for(&base);
        assert!(client.fetch_pckcrl("PROCESSOR").await.is_err());
        assert_eq!(
            seen.lock().unwrap()[0].1,
            "/sgx/certification/v4/pckcrl?ca=processor&encoding=der"
        );

        use axum::routing::get;
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcrl",
            get(|| async {
                let mut resp = axum::response::Response::new(axum::body::Body::from(vec![1u8, 2]));
                resp.headers_mut().insert(
                    headers::SGX_PCK_CRL_ISSUER_CHAIN,
                    HeaderValue::from_static("crl-chain"),
                );
                resp
            }),
        );
        let base = spawn(app).await;
        let client = client_for(&base);
        let rec = client.fetch_pckcrl("platform").await.unwrap();
        assert_eq!(rec.ca, "PLATFORM");
        assert_eq!(rec.pckcrl, vec![1, 2]);
        assert_eq!(rec.issuer_chain, "crl-chain");
    }

    #[tokio::test]
    async fn fetch_rootcacrl_hex_decodes_and_pccs_url() {
        use axum::routing::get;
        // Hex-text body is decoded to DER.
        let app = axum::Router::new().route(
            "/sgx/certification/v4/rootcacrl",
            get(|| async { axum::response::Response::new(axum::body::Body::from("30 03\n0a0b")) }),
        );
        let base = spawn(app).await;
        let client = client_for(&base);
        let der = client.fetch_rootcacrl().await.unwrap();
        assert_eq!(der, vec![0x30, 0x03, 0x0a, 0x0b]);

        // Binary body passes through untouched.
        let app = axum::Router::new().route(
            "/sgx/certification/v4/rootcacrl",
            get(|| async {
                axum::response::Response::new(axum::body::Body::from(vec![0x30u8, 0x82]))
            }),
        );
        let base = spawn(app).await;
        let client = client_for(&base);
        assert_eq!(client.fetch_rootcacrl().await.unwrap(), vec![0x30, 0x82]);

        // Non-200 bubbles up as a 500.
        let (seen, app) = recorder();
        let base = spawn(app).await;
        let client = client_for(&base);
        assert!(client.fetch_rootcacrl().await.is_err());
        assert_eq!(seen.lock().unwrap()[0].1, "/sgx/certification/v4/rootcacrl");
    }

    #[tokio::test]
    async fn fetch_crl_errors_and_v3_guard() {
        let (seen, app) = recorder();
        let base = spawn(app).await;
        let client = client_for(&base);
        assert!(client
            .fetch_crl("https://certificates.trustedservices.intel.com/x.crl")
            .await
            .is_err());
        // v3 CRL URLs are refused before the network.
        assert!(client.fetch_crl("https://x/v3/pckcrl?ca=processor").await.is_err());
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn throttled_upstream_is_retried_at_most_twice() {
        use axum::routing::get;
        let calls = Arc::new(AtomicU64::new(0));
        let calls2 = calls.clone();
        let app = axum::Router::new().route(
            "/sgx/certification/v4/pckcrl",
            get(move || {
                let calls = calls2.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    hyper::Response::builder()
                        .status(503)
                        .header(hyper::header::RETRY_AFTER, "0")
                        .body(axum::body::Body::empty())
                        .unwrap()
                }
            }),
        );
        let base = spawn(app).await;
        let cfg = Config { uri: base, upstream_max_attempts: 6, ..Config::default() };
        let client = PcsClient::new(&cfg).unwrap();
        let err = client.fetch_pckcrl("processor").await.unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND, "final 503 surfaces as a miss");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            u64::from(MAX_THROTTLED_ATTEMPTS),
            "a 429/503 storm is not amplified by the full retry budget"
        );
    }

    #[tokio::test]
    async fn transport_errors_use_the_full_retry_budget() {
        // A listener that accepts and instantly drops every connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let calls2 = calls.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => {
                        calls2.fetch_add(1, Ordering::Relaxed);
                        drop(sock);
                    }
                    Err(_) => break,
                }
            }
        });
        let cfg = Config {
            uri: format!("http://{addr}/sgx/certification/v4/"),
            upstream_max_attempts: 2,
            ..Config::default()
        };
        let client = PcsClient::new(&cfg).unwrap();
        assert!(client.fetch_pckcrl("processor").await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn oversized_content_length_is_refused() {
        // Raw TCP: axum rewrites a bogus Content-Length, so the lie must be
        // written straight onto the wire.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                        MAX_RESPONSE_BYTES + 1
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                });
            }
        });
        let client = client_for(&format!("http://{addr}/sgx/certification/v4/"));
        assert!(client.fetch_pckcrl("processor").await.is_err());
    }

    #[tokio::test]
    async fn send_rejects_v3_and_disabled_clients() {
        let client = client_for("");
        assert!(client.fetch_pckcrl("processor").await.is_err(), "disabled");

        let client = client_for("http://127.0.0.1:1/sgx/certification/v4/");
        let err = client
            .get("http://127.0.0.1:1/sgx/certification/v3/pckcrl?ca=processor")
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::GONE);
    }
}
