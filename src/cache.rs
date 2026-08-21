//! CachingFillMode: LAZY / REQ / OFFLINE. Miss path talks to `PcsClient`.

use crate::config::{CacheMode, Config};
use crate::error::{self, PccsError};
use crate::pcs::PcsClient;
use crate::store::{
    IdentityRecord, PckCertRecord, PckCrlRecord, RegisteredPlatform, Store, TcbRecord,
};
use crate::validate::UpdateType;
use std::sync::Arc;

pub struct Cache {
    pub store: Store,
    pub pcs: PcsClient,
    pub mode: CacheMode,
    pub pcs_version: u32,
    pub is_intel: bool,
}

impl Cache {
    pub fn new(store: Store, pcs: PcsClient, cfg: &Config) -> Self {
        Self {
            mode: cfg.cache_mode,
            pcs_version: cfg.pcs_version(),
            is_intel: cfg.is_intel_upstream(),
            store,
            pcs,
        }
    }

    fn miss_v3(&self, version: u32) -> PccsError {
        if version == 3 && self.mode == CacheMode::Lazy {
            error::PCS_V3_REACHED_EOL
        } else {
            error::NO_CACHE_DATA
        }
    }

    pub async fn get_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        enc_ppid: Option<&str>,
        version: u32,
    ) -> Result<PckCertRecord, PccsError> {
        if let Some(rec) = self.store.get_pckcert(qeid, cpusvn, pcesvn, pceid) {
            self.store.record_hit();
            tracing::debug!("cache hit pckcert");
            return Ok(rec);
        }
        self.store.record_miss();
        tracing::info!("cache miss pckcert qeid={qeid} pceid={pceid}");
        match self.mode {
            CacheMode::Offline | CacheMode::Req => {
                if !self.store.has_platform(qeid, pceid) {
                    return Err(error::platform_unknown());
                }
                Err(error::NO_CACHE_DATA)
            }
            CacheMode::Lazy => {
                if version == 3 {
                    return Err(error::PCS_V3_REACHED_EOL);
                }
                self.fill_pckcert(qeid, cpusvn, pcesvn, pceid, enc_ppid).await
            }
        }
    }

    async fn fill_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        enc_ppid: Option<&str>,
    ) -> Result<PckCertRecord, PccsError> {
        if !self.pcs.enabled() {
            return Err(error::NO_CACHE_DATA);
        }
        self.store.record_upstream();
        let rec = if self.is_intel {
            self.pcs
                .fetch_pckcerts_intel(enc_ppid.unwrap_or(""), pceid, qeid, cpusvn, pcesvn)
                .await?
        } else {
            self.pcs
                .fetch_pckcert_pccs(qeid, cpusvn, pcesvn, pceid, enc_ppid)
                .await?
        };
        self.store.put_pckcert(&rec)?;
        Ok(rec)
    }

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
        self.store.record_upstream();
        let rec = self.pcs.fetch_tcb(prod_type, fmspc, version, update).await?;
        self.store.put_tcb(&rec)?;
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
        self.store.record_upstream();
        let rec = self.pcs.fetch_identity(enclave_id, version, update).await?;
        self.store.put_identity(&rec)?;
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
        self.store.record_upstream();
        let rec = self.pcs.fetch_pckcrl(ca).await?;
        self.store.put_pckcrl(&rec)?;
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
        self.store.record_upstream();
        let rec = self.pcs.fetch_rootcacrl().await?;
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
        self.store.record_upstream();
        let rec = self.pcs.fetch_crl(uri).await?;
        self.store.put_crl(uri, &rec)?;
        Ok(rec)
    }

    pub async fn register_platform(
        &self,
        p: RegisteredPlatform,
        update: UpdateType,
    ) -> Result<(), PccsError> {
        let cached = self.store.has_platform(&p.qe_id, &p.pce_id)
            && (p.platform_manifest.is_empty()
                && self
                    .store
                    .get_pckcert(&p.qe_id, &p.cpu_svn, &p.pce_svn, &p.pce_id)
                    .is_some()
                || !p.platform_manifest.is_empty());
        match self.mode {
            CacheMode::Offline => {
                if !cached {
                    self.store.register_platform(p);
                }
                Ok(())
            }
            CacheMode::Req => {
                if !cached {
                    self.store.register_platform(RegisteredPlatform {
                        state: 0,
                        ..p.clone()
                    });
                    let _ = self
                        .fill_pckcert(
                            &p.qe_id,
                            &p.cpu_svn,
                            &p.pce_svn,
                            &p.pce_id,
                            Some(p.enc_ppid.as_str()),
                        )
                        .await;
                    // drain this NEW row (Node marks deleted after fill)
                    let _ = self.store.take_registered(0);
                }
                self.fill_qv_collateral(update).await;
                Ok(())
            }
            CacheMode::Lazy => {
                if !cached {
                    if self.pcs.enabled() {
                        self.fill_pckcert(
                            &p.qe_id,
                            &p.cpu_svn,
                            &p.pce_svn,
                            &p.pce_id,
                            Some(p.enc_ppid.as_str()),
                        )
                        .await?;
                    } else {
                        // no upstream: keep registration so GET /platforms?source=reg works in tests
                        self.store.register_platform(p);
                        return Ok(());
                    }
                }
                self.fill_qv_collateral(update).await;
                Ok(())
            }
        }
    }

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
                    let _ = self.store.put_pckcrl(&r);
                }
            }
        }
        for id in [1u8, 2, 3] {
            for u in &updates {
                if self.store.get_identity(id, self.pcs_version, *u).is_none() {
                    if let Ok(r) = self.pcs.fetch_identity(id, self.pcs_version, *u).await {
                        let _ = self.store.put_identity(&r);
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

    pub async fn refresh(&self, typ: Option<&str>, fmspc: Option<&str>) -> Result<(), PccsError> {
        if self.mode == CacheMode::Offline {
            return Err(error::SERVICE_UNAVAILABLE);
        }
        if let Some(t) = typ {
            if t != "certs" {
                return Err(error::INVALID_REQ);
            }
            let fmspc = crate::validate::fmspc(fmspc)?;
            return self.refresh_certs(&fmspc).await;
        }
        self.refresh_collateral().await
    }

    async fn refresh_collateral(&self) -> Result<(), PccsError> {
        if !self.pcs.enabled() {
            return Ok(());
        }
        for rec in self.store.list_tcbs() {
            if rec.version == 3 {
                continue;
            }
            let upd = if rec.update_type == "EARLY" {
                UpdateType::Early
            } else {
                UpdateType::Standard
            };
            if let Ok(fresh) = self
                .pcs
                .fetch_tcb(rec.prod_type, &rec.fmspc, rec.version, upd)
                .await
            {
                let _ = self.store.put_tcb(&fresh);
            }
        }
        for rec in self.store.list_identities() {
            if rec.version == 3 {
                continue;
            }
            let upd = if rec.update_type == "EARLY" {
                UpdateType::Early
            } else {
                UpdateType::Standard
            };
            if let Ok(fresh) = self
                .pcs
                .fetch_identity(rec.enclave_id, rec.version, upd)
                .await
            {
                let _ = self.store.put_identity(&fresh);
            }
        }
        for rec in self.store.list_pckcrls() {
            if let Ok(fresh) = self.pcs.fetch_pckcrl(&rec.ca).await {
                let _ = self.store.put_pckcrl(&fresh);
            }
        }
        if let Ok(fresh) = self.pcs.fetch_rootcacrl().await {
            let _ = self.store.put_rootcacrl(&fresh);
        }
        for rec in self.store.list_crls() {
            if let Ok(fresh) = self.pcs.fetch_crl(&rec.uri).await {
                let _ = self.store.put_crl(&rec.uri, &fresh);
            }
        }
        Ok(())
    }

    async fn refresh_certs(&self, fmspc: &str) -> Result<(), PccsError> {
        if !self.pcs.enabled() || self.pcs_version == 3 {
            return Ok(());
        }
        for rec in self.store.list_pckcerts() {
            if rec.fmspc != fmspc {
                continue;
            }
            let enc = rec.encrypted_ppid.as_deref();
            if let Ok(fresh) = if self.is_intel {
                self.pcs
                    .fetch_pckcerts_intel(
                        enc.unwrap_or(""),
                        &rec.pceid,
                        &rec.qeid,
                        &rec.cpusvn,
                        &rec.pcesvn,
                    )
                    .await
            } else {
                self.pcs
                    .fetch_pckcert_pccs(&rec.qeid, &rec.cpusvn, &rec.pcesvn, &rec.pceid, enc)
                    .await
            } {
                let _ = self.store.put_pckcert(&fresh);
            }
        }
        Ok(())
    }
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
