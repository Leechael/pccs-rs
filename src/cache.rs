//! CachingFillMode: LAZY / REQ / OFFLINE. Miss path talks to `PcsClient`.

use crate::config::{CacheMode, Config};
use crate::error::{self, PccsError};
use crate::keys;
use crate::pcs::{PckCertsResponse, PcsClient};
use crate::store::{
    IdentityRecord, PckCertRecord, PckCrlRecord, PlatformCert, PlatformPool, RegisteredPlatform,
    Store, TcbRecord,
};
use crate::validate::UpdateType;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Node `Constants.PLATF_REG_NEW` / `PLATF_REG_NOT_AVAILABLE`.
const PLATF_REG_NEW: u8 = 0;
const PLATF_REG_NOT_AVAILABLE: u8 = 1;

pub struct Cache {
    pub store: Store,
    pub pcs: PcsClient,
    pub mode: CacheMode,
    pub pcs_version: u32,
    pub is_intel: bool,
    /// Per-key locks so N concurrent misses on the same key produce one
    /// upstream request; the losers re-read the store after acquiring.
    inflight: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    /// Only one refresh at a time; a second admin call waits for the first.
    refresh_lock: Mutex<()>,
    /// Recent upstream failures per key; see `key_lock`.
    failures: Mutex<HashMap<String, (std::time::Instant, PccsError)>>,
}

/// How long a failed upstream fetch suppresses a retry by the requests already
/// queued behind it. Short on purpose — this is stampede control, not caching.
const FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

impl Cache {
    pub fn new(store: Store, pcs: PcsClient, cfg: &Config) -> Self {
        Self {
            mode: cfg.cache_mode,
            pcs_version: cfg.pcs_version(),
            is_intel: cfg.is_intel_upstream(),
            store,
            pcs,
            inflight: Mutex::new(HashMap::new()),
            refresh_lock: Mutex::new(()),
            failures: Mutex::new(HashMap::new()),
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
        let mut map = self.failures.lock().await;
        match map.get(key) {
            Some((at, e)) if at.elapsed() < FAILURE_TTL => Some(e.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Pass a fetch result through, remembering an upstream failure briefly so
    /// the waiters behind us do not each repeat it. Used as
    /// `self.note(&key, fetch().await)?`.
    async fn note<T>(&self, key: &str, result: Result<T, PccsError>) -> Result<T, PccsError> {
        if let Err(e) = &result {
            let mut map = self.failures.lock().await;
            if map.len() > 1024 {
                map.retain(|_, (at, _)| at.elapsed() < FAILURE_TTL);
            }
            map.insert(key.to_string(), (std::time::Instant::now(), e.clone()));
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

    // ---------------- pckcert ----------------

    /// Node `pckcertService.getPckCert`: platform row → per-raw-TCB cert →
    /// otherwise local PCK cert selection, and only then the upstream.
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

        let key = keys::pckcert(qeid, pceid, cpusvn, pcesvn);
        let _guard = self.key_lock(&key).await?;
        if let Some(rec) = self.store.get_pckcert(qeid, cpusvn, pcesvn, pceid) {
            return Ok(rec);
        }
        let platform =
            if known_platform { self.store.get_platform_pool(qeid, pceid) } else { None };

        // Node `pckCertSelection`: a cached platform is treated as cached
        // collateral — select the best cert for this new raw TCB locally.
        if let Some(pool) = &platform {
            match self.select_from_pool(pool, cpusvn, pcesvn, pceid) {
                Ok(rec) => return Ok(rec),
                Err(e) => {
                    if self.mode != CacheMode::Lazy || version == 3 || !self.pcs.enabled() {
                        return Err(e);
                    }
                    tracing::info!("local PCK cert selection failed; falling back to upstream");
                }
            }
        }

        match self.mode {
            CacheMode::Offline | CacheMode::Req => Err(error::platform_unknown()),
            CacheMode::Lazy => {
                if version == 3 {
                    return Err(error::PCS_V3_REACHED_EOL);
                }
                let manifest =
                    platform.as_ref().map(|p| p.platform_manifest.clone()).unwrap_or_default();
                self.note(
                    &key,
                    self.fill_pckcert(
                        qeid,
                        cpusvn,
                        pcesvn,
                        pceid,
                        enc_ppid.unwrap_or(""),
                        &manifest,
                    )
                    .await,
                )
                .await
            }
        }
    }

    /// Node `pckcertService.pckCertSelection`, run against the cached pool.
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
        self.store.put_pckcert(&rec)?;
        self.store.upsert_raw_tcb(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn, &rec.tcbm)?;
        Ok(rec)
    }

    /// Node `commonCacheLogic.getPckCertFromPCS`.
    async fn fill_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        enc_ppid: &str,
        platform_manifest: &str,
    ) -> Result<PckCertRecord, PccsError> {
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        if enc_ppid.is_empty() && platform_manifest.is_empty() {
            tracing::error!("Missing encrypted ppid or platform manifest.");
            return Err(error::INVALID_REQ);
        }
        self.store.record_upstream();

        // A PCCS upstream without a platform manifest serves a single cert.
        if !self.is_intel && platform_manifest.is_empty() {
            let rec =
                self.pcs.fetch_pckcert_pccs(qeid, cpusvn, pcesvn, pceid, Some(enc_ppid)).await?;
            if !Self::cacheable(crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, &rec.issuer_chain)
            {
                return Ok(rec);
            }
            // Keep the single cert in the pool as well, so `has_platform` is a
            // single get and later raw TCBs can be selected locally.
            let pool = PlatformPool {
                qe_id: rec.qeid.clone(),
                pce_id: rec.pceid.clone(),
                enc_ppid: enc_ppid.to_ascii_uppercase(),
                platform_manifest: platform_manifest.to_string(),
                fmspc: rec.fmspc.clone(),
                ca: rec.ca.to_ascii_uppercase(),
                issuer_chain: rec.issuer_chain.clone(),
                certs: vec![PlatformCert { tcbm: rec.tcbm.clone(), cert: rec.cert.clone() }],
                raw_tcbs: Vec::new(),
            };
            self.store.put_platform_pool(&pool)?;
            self.store.put_pckcert(&rec)?;
            self.store.upsert_raw_tcb(
                &rec.qeid,
                &rec.pceid,
                &rec.cpusvn,
                &rec.pcesvn,
                &rec.tcbm,
            )?;
            return Ok(rec);
        }

        let resp = if platform_manifest.is_empty() {
            self.pcs.fetch_pckcerts_intel(enc_ppid, pceid).await?
        } else {
            self.pcs.fetch_pckcerts_intel_manifest(platform_manifest, pceid).await?
        };
        self.store_pckcerts(qeid, pceid, enc_ppid, platform_manifest, &resp).await?;

        if cpusvn.is_empty() || pcesvn.is_empty() {
            // Node returns `{}` when no raw TCB was supplied.
            return Err(error::NO_CACHE_DATA);
        }
        let pool = self.store.get_platform_pool(qeid, pceid).ok_or(error::NO_CACHE_DATA)?;
        let rec = self.select_from_pool(&pool, cpusvn, pcesvn, pceid)?;
        // Node `needUpdatePlatformTcbs`: LAZY does not record the raw TCB when
        // some levels came back "Not available" — a later refresh must redo it.
        if self.mode == CacheMode::Lazy && !resp.not_available.is_empty() {
            self.store.remove_raw_tcb(qeid, pceid, cpusvn, pcesvn)?;
        }
        Ok(rec)
    }

    /// Flush and rewrite the platform's cert pool, its TCB infos, and every
    /// already-known raw TCB (Node re-runs selection for all of them).
    async fn store_pckcerts(
        &self,
        qeid: &str,
        pceid: &str,
        enc_ppid: &str,
        platform_manifest: &str,
        resp: &PckCertsResponse,
    ) -> Result<(), PccsError> {
        self.process_not_available(qeid, pceid, enc_ppid, platform_manifest, resp)?;
        if resp.certs.is_empty() {
            tracing::error!("No valid PCK certificates in the response.");
            return Err(error::NO_CACHE_DATA);
        }
        if !Self::cacheable(crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, &resp.issuer_chain) {
            return Err(error::PCS_ACCESS_FAILURE);
        }
        // Node `fetchTcbInfo`: SGX standard is mandatory.
        self.fill_tcb_infos(&resp.fmspc).await?;

        let pool = PlatformPool {
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
            // Filled in by `replace_platform_certs` from the existing record;
            // the pool must never be written with these dropped.
            raw_tcbs: Vec::new(),
        };
        // One atomic write: the new certs and the already-known raw TCB levels
        // land together, so a cancelled task cannot leave the platform with an
        // empty `raw_tcbs`.
        let previous = self.store.replace_platform_certs(&pool)?;

        // Re-run selection so each cached raw TCB level picks up the best cert
        // from the refreshed pool. Purely an update of existing entries now.
        for raw in previous {
            if let Err(e) = self.select_from_pool(&pool, &raw.cpu_svn, &raw.pce_svn, pceid) {
                tracing::warn!(
                    "re-selection for cached raw TCB {}/{} failed: {}",
                    raw.cpu_svn,
                    raw.pce_svn,
                    e
                );
            }
        }
        Ok(())
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

    /// Node `fetchTcbInfo` + `upsertTcbInfos`.
    async fn fill_tcb_infos(&self, fmspc: &str) -> Result<(), PccsError> {
        let mut wanted: Vec<(u8, UpdateType)> =
            vec![(0, UpdateType::Early), (0, UpdateType::Standard)];
        if self.pcs_version >= 4 {
            wanted.push((1, UpdateType::Early));
            wanted.push((1, UpdateType::Standard));
        }
        let mut sgx_standard = false;
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
                        self.store.put_tcb(&rec)?;
                    }
                }
                Err(e) => tracing::debug!("no tcb info for {fmspc} ({prod}, {update:?}): {e}"),
            }
        }
        if !sgx_standard {
            tracing::error!("The TCB info doesn't include standard update type.");
            return Err(error::NO_CACHE_DATA);
        }
        Ok(())
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
                        &p.enc_ppid,
                        &p.platform_manifest,
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
                        &p.enc_ppid,
                        &p.platform_manifest,
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

        // Node `refreshEnclaveIdentities` tolerates a missing identity.
        for rec in self.blocking(|c| c.store.list_identities()).await? {
            if rec.version == 3 {
                continue;
            }
            let upd = if rec.update_type.eq_ignore_ascii_case("EARLY") {
                UpdateType::Early
            } else {
                UpdateType::Standard
            };
            match self.pcs.fetch_identity(rec.enclave_id, rec.version, upd).await {
                Ok(fresh) => {
                    if Self::cacheable(
                        crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                        &fresh.issuer_chain,
                    ) {
                        self.store.put_identity(&fresh)?;
                    }
                }
                Err(e) => tracing::debug!(
                    "Couldn't get enclave identity for (id:{},version:{}): {e}",
                    rec.enclave_id,
                    rec.version
                ),
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
    /// re-selection for every raw TCB that platform has.
    async fn refresh_certs(self: &Arc<Self>, fmspc: &str) -> Result<(), PccsError> {
        if !self.pcs.enabled() || self.pcs_version == 3 {
            return Ok(());
        }
        for pool in self.blocking(|c| c.store.list_platform_pools()).await? {
            if !pool.fmspc.eq_ignore_ascii_case(fmspc) {
                continue;
            }
            let resp = if !pool.platform_manifest.is_empty() {
                self.pcs.fetch_pckcerts_intel_manifest(&pool.platform_manifest, &pool.pce_id).await
            } else if self.is_intel {
                self.pcs.fetch_pckcerts_intel(&pool.enc_ppid, &pool.pce_id).await
            } else {
                // A PCCS upstream has no cert-pool endpoint; re-fetch the
                // selected cert for every known raw TCB instead.
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
                        self.store.put_pckcert(&fresh)?;
                    }
                }
                continue;
            };
            let resp = resp.map_err(|e| {
                tracing::error!("Failed to refresh PCK certs for {}: {e}", pool.qe_id);
                error::NO_CACHE_DATA
            })?;
            self.store_pckcerts(
                &pool.qe_id,
                &pool.pce_id,
                &pool.enc_ppid,
                &pool.platform_manifest,
                &resp,
            )
            .await?;
        }
        Ok(())
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
            match store.load_seed_file(&p) {
                Ok(()) => tracing::info!("seeded cache from {}", p.display()),
                Err(e) => tracing::warn!("seed load failed: {e}"),
            }
        }
    }
    let pcs = PcsClient::new(cfg)?;
    Ok(Arc::new(Cache::new(store, pcs, cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn lazy_pckcert_without_ppid_or_manifest_is_a_400() {
        let calls = Arc::new(AtomicU64::new(0));
        let base = spawn_pccs(calls.clone()).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
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
    async fn lazy_pckcert_with_manifest_fills_via_pckcerts_post() {
        let base = spawn_intel_pckcerts_mock(false).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        // A platform known only by its manifest; the local pool has no certs,
        // so selection fails and LAZY falls back to the upstream.
        cache
            .store
            .put_platform_pool(&crate::store::PlatformPool {
                qe_id: "QEM".into(),
                pce_id: "4444".into(),
                platform_manifest: "MANIFEST".into(),
                ..Default::default()
            })
            .unwrap();

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
    async fn lazy_fill_with_not_available_levels_forgets_the_raw_tcb() {
        let base = spawn_intel_pckcerts_mock(true).await;
        let (_dir, cache) = cache_with(&base, CacheMode::Lazy);
        cache
            .store
            .put_platform_pool(&crate::store::PlatformPool {
                qe_id: "QEN".into(),
                pce_id: "4444".into(),
                platform_manifest: "MANIFEST".into(),
                ..Default::default()
            })
            .unwrap();
        let rec =
            cache.get_pckcert("QEN", &"22".repeat(16), "3333", "4444", None, 4).await.unwrap();
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
        let err = cache.store_pckcerts("QET", "0001", "PP", "", &resp).await.unwrap_err();
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
                    "{\"tcbInfo\":{\"id\":\"SGX\"}}",
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
            certs: vec![("TM".into(), "cert-pem".into())],
            not_available: Vec::new(),
            fmspc: "00A067110000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "pck-chain".into(),
        };
        cache.store_pckcerts("QE5", "0001", "PP", "", &resp).await.unwrap();
        let pool = cache.store.get_platform_pool("QE5", "0001").unwrap();
        assert_eq!(pool.certs.len(), 1);
        assert_eq!(pool.issuer_chain, "pck-chain");
        // SGX standard TCB info is mandatory and was stored.
        assert!(cache.store.get_tcb(0, "00A067110000", 4, UpdateType::Standard).is_some());

        // No certs at all is an error.
        let empty = PckCertsResponse {
            certs: Vec::new(),
            not_available: Vec::new(),
            fmspc: "00A067110000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "pck-chain".into(),
        };
        assert!(cache.store_pckcerts("QE5", "0001", "PP", "", &empty).await.is_err());

        // A chain-less response is not persisted.
        let chainless = PckCertsResponse { issuer_chain: String::new(), ..resp.clone() };
        assert!(cache.store_pckcerts("QE6", "0001", "PP", "", &chainless).await.is_err());
    }
}
