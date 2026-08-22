//! Upstream Intel PCS / PCCS HTTP client (hyper + rustls).
//! `Ocp-Apim-Subscription-Key` follows Node `pcs_client.js`: only on `pckcerts`
//! requests, plus every request to the early-access portal.
//! Any URL containing `/v3/` → 410 without a network call.

use crate::config::Config;
use crate::error::{self, PccsError};
use crate::headers;
use crate::store::{IdentityRecord, PckCertRecord, PckCrlRecord, TcbRecord};
use crate::validate::UpdateType;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Node `pcs_client.js` HTTP_TIMEOUT.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

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
                "proxy is not supported by pccs-rs; remove it from the configuration".to_string(),
            );
        }
        let mut http_conn = HttpConnector::new();
        http_conn.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let https = cfg.uri.starts_with("https://") || cfg.uri.is_empty();
        let client = if https {
            http_conn.enforce_http(false);
            let https_conn = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("native TLS roots: {e}"))?
                .https_or_http()
                .enable_http1()
                .wrap_connector(http_conn);
            AnyClient::Https(Client::builder(TokioExecutor::new()).build(https_conn))
        } else {
            AnyClient::Http(Client::builder(TokioExecutor::new()).build(http_conn))
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
                let backoff = delay
                    .take()
                    .unwrap_or(Duration::from_millis(50u64 << attempt.min(5)));
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
            let mut req = builder
                .body(Full::new(Bytes::from(payload)))
                .map_err(|_| error::INTERNAL_ERROR)?;
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
        let url = format!(
            "{}pckcerts?encrypted_ppid={}&pceid={}",
            self.base,
            q(enc_ppid),
            q(pceid)
        );
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
            let tcbm = c
                .get("tcbm")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_ascii_uppercase();
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
        let url = format!(
            "{}pckcrl?ca={}&encoding=der",
            self.base,
            q(&ca.to_ascii_lowercase())
        );
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
        if body
            .iter()
            .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
        {
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
    let secs: u64 = h
        .get(hyper::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
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
    base64_decode(&b64)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
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
        h.insert(
            hyper::header::RETRY_AFTER,
            HeaderValue::from_static("99999"),
        );
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
    fn base64_and_last_pem_roundtrip() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nd29ybGQ=\n-----END CERTIFICATE-----\n";
        assert_eq!(last_pem_der(pem).unwrap(), b"world");
    }
}
