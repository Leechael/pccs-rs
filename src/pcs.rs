//! Upstream Intel PCS / PCCS HTTP client (hyper + rustls).
//! Intel host: send `Ocp-Apim-Subscription-Key`. PCCS (incl. Phala): omit.
//! Any URL containing `/v3/` → 410 without a network call.

use crate::config::Config;
use crate::error::{self, PccsError};
use crate::headers;
use crate::store::{IdentityRecord, PckCertRecord, PckCrlRecord, TcbRecord};
use crate::validate::UpdateType;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

type HttpClient = Client<HttpConnector, Empty<Bytes>>;
type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

enum AnyClient {
    Http(HttpClient),
    Https(HttpsClient),
}

impl AnyClient {
    async fn request(&self, req: Request<Empty<Bytes>>) -> Result<hyper::Response<hyper::body::Incoming>, PccsError> {
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

pub struct PcsClient {
    base: String,
    api_key: String,
    is_intel: bool,
    client: AnyClient,
    pub calls: Arc<AtomicU64>,
}

impl PcsClient {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let https = cfg.uri.starts_with("https://") || cfg.uri.is_empty();
        let client = if https {
            let https_conn = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("native TLS roots: {e}"))?
                .https_or_http()
                .enable_http1()
                .build();
            AnyClient::Https(Client::builder(TokioExecutor::new()).build(https_conn))
        } else {
            AnyClient::Http(Client::builder(TokioExecutor::new()).build_http())
        };
        if !cfg.proxy.trim().is_empty() {
            tracing::warn!("proxy={} is set; use HTTPS_PROXY/HTTP_PROXY in the environment for outbound PCS", cfg.proxy);
        }
        Ok(Self {
            base: normalize_base(&cfg.uri),
            api_key: cfg.api_key.clone(),
            is_intel: cfg.is_intel_upstream(),
            client,
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

    async fn get(&self, url: &str) -> Result<(u16, HeaderMap, Vec<u8>), PccsError> {
        Self::check_v3(url)?;
        if !self.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut last = error::PCS_ACCESS_FAILURE;
        for attempt in 0..6u32 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(50 * (1 << attempt.min(5)))).await;
            }
            let uri: Uri = url.parse().map_err(|_| error::INTERNAL_ERROR)?;
            let mut req = Request::get(uri).body(Empty::<Bytes>::new()).map_err(|_| error::INTERNAL_ERROR)?;
            if self.is_intel && !self.api_key.is_empty() {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(b"Ocp-Apim-Subscription-Key"),
                    HeaderValue::from_str(&self.api_key),
                ) {
                    req.headers_mut().insert(n, v);
                }
            }
            match self.client.request(req).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if (status == 429 || status == 503) && attempt + 1 < 6 {
                        last = error::PCS_ACCESS_FAILURE;
                        continue;
                    }
                    let hdrs = resp.headers().clone();
                    let body = resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|_| error::PCS_ACCESS_FAILURE)?
                        .to_bytes();
                    tracing::info!("upstream GET {url} -> {status}");
                    return Ok((status, hdrs, body.to_vec()));
                }
                Err(_) => {
                    last = error::PCS_ACCESS_FAILURE;
                }
            }
        }
        Err(last)
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
            self.base, qeid, cpusvn, pcesvn, pceid
        );
        if let Some(e) = enc_ppid {
            if !e.is_empty() {
                url.push_str("&encrypted_ppid=");
                url.push_str(e);
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
            ca: Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_CA_TYPE),
            issuer_chain: Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN),
            encrypted_ppid: enc_ppid.map(|s| s.to_ascii_uppercase()),
            platform_manifest: String::new(),
        })
    }

    pub async fn fetch_pckcerts_intel(
        &self,
        enc_ppid: &str,
        pceid: &str,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
    ) -> Result<PckCertRecord, PccsError> {
        if enc_ppid.is_empty() || enc_ppid.chars().all(|c| c == '0') {
            return Err(error::NO_CACHE_DATA);
        }
        let url = format!("{}pckcerts?encrypted_ppid={}&pceid={}", self.base, enc_ppid, pceid);
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let issuer = Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN);
        let fmspc = Self::hdr(&h, headers::SGX_FMSPC).to_ascii_uppercase();
        let ca = Self::hdr(&h, headers::SGX_PCK_CERTIFICATE_CA_TYPE);
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| error::INTERNAL_ERROR)?;
        let arr = parsed.as_array().ok_or(error::NO_CACHE_DATA)?;
        let mut certs = Vec::new();
        for c in arr {
            let tcbm = c
                .get("tcbm")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_ascii_uppercase();
            let mut cert = c.get("cert").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if cert == "Not available" {
                continue;
            }
            if cert.contains('%') {
                cert = percent_decode(&cert);
            }
            if !tcbm.is_empty() && !cert.is_empty() {
                certs.push((tcbm, cert));
            }
        }
        let (tcbm, cert) = crate::selection::select_for_raw_tcb(cpusvn, pcesvn, &certs)
            .ok_or(error::NO_CACHE_DATA)?;
        Ok(PckCertRecord {
            qeid: qeid.to_ascii_uppercase(),
            pceid: pceid.to_ascii_uppercase(),
            cpusvn: cpusvn.to_ascii_uppercase(),
            pcesvn: pcesvn.to_ascii_uppercase(),
            cert,
            tcbm,
            fmspc,
            ca,
            issuer_chain: issuer,
            encrypted_ppid: Some(enc_ppid.to_ascii_uppercase()),
            platform_manifest: String::new(),
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
            fmspc,
            upd
        );
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let tcbinfo: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| error::NO_CACHE_DATA)?;
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
        let url = match enclave_id {
            2 => format!("{}qve/identity?update={upd}", self.base),
            3 => format!("{}qe/identity?update={upd}", tdx_if(&self.base, true)),
            _ => format!("{}qe/identity?update={upd}", self.base),
        };
        let (status, h, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
        }
        let identity: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| error::NO_CACHE_DATA)?;
        Ok(IdentityRecord {
            enclave_id,
            version,
            update_type: update.as_str().to_string(),
            identity,
            issuer_chain: Self::hdr(&h, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN),
        })
    }

    pub async fn fetch_pckcrl(&self, ca: &str) -> Result<PckCrlRecord, PccsError> {
        let url = format!(
            "{}pckcrl?ca={}&encoding=der",
            self.base,
            ca.to_ascii_lowercase()
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

    pub async fn fetch_rootcacrl(&self) -> Result<Vec<u8>, PccsError> {
        let url = format!("{}rootcacrl", self.base);
        let (status, _, body) = self.get(&url).await?;
        if status != 200 {
            return Err(error::NO_CACHE_DATA);
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
            return Err(error::NO_CACHE_DATA);
        }
        Ok(body)
    }
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
