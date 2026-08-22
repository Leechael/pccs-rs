//! RocksDB store: one key per cacheable GET. Value = response body + Intel headers.
//! No Intel/Sequelize tables. Writes use WriteBatch.

use crate::config::{CacheMode, RocksDbOpts};
use crate::error::{self, PccsError};
use crate::keys;
use crate::validate::UpdateType;
use rocksdb::{BlockBasedOptions, Cache, Direction, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PckCertRecord {
    pub qeid: String,
    pub pceid: String,
    pub cpusvn: String,
    pub pcesvn: String,
    pub cert: String,
    pub tcbm: String,
    pub fmspc: String,
    pub ca: String,
    pub issuer_chain: String,
    #[serde(default)]
    pub encrypted_ppid: Option<String>,
    #[serde(default)]
    pub platform_manifest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbRecord {
    pub prod_type: u8,
    pub fmspc: String,
    pub version: u32,
    pub update_type: String,
    pub tcbinfo: Value,
    #[serde(default)]
    pub raw_body: String,
    pub issuer_chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub enclave_id: u8,
    pub version: u32,
    pub update_type: String,
    pub identity: Value,
    #[serde(default)]
    pub raw_body: String,
    pub issuer_chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PckCrlRecord {
    pub ca: String,
    pub pckcrl: Vec<u8>,
    pub issuer_chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlRecord {
    pub uri: String,
    pub crl: Vec<u8>,
}

/// `GET /platforms?source=[fmspc]` row. Node's SQL selects exactly these six
/// columns — `fmspc` and `ca` are filter/join columns and are not returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformRecord {
    pub qe_id: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub pce_svn: String,
    pub enc_ppid: String,
    pub platform_manifest: String,
}

/// One cert of a platform's PCK cert pool (Intel `pck_cert` row).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformCert {
    pub tcbm: String,
    pub cert: String,
}

/// One raw TCB level known for a platform (Intel `platform_tcbs` row).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawTcb {
    pub cpu_svn: String,
    pub pce_svn: String,
    pub tcbm: String,
}

/// Intel `platforms` + `pck_cert` + `platform_tcbs` for one (qe_id, pce_id),
/// stored under a single `platform/` key so `has_platform` is one `DB::get`
/// and PCK cert selection can run locally on a `/pckcert` miss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformPool {
    pub qe_id: String,
    pub pce_id: String,
    #[serde(default)]
    pub enc_ppid: String,
    #[serde(default)]
    pub platform_manifest: String,
    #[serde(default)]
    pub fmspc: String,
    #[serde(default)]
    pub ca: String,
    #[serde(default)]
    pub issuer_chain: String,
    #[serde(default)]
    pub certs: Vec<PlatformCert>,
    #[serde(default)]
    pub raw_tcbs: Vec<RawTcb>,
}

impl PlatformPool {
    pub fn cert_pairs(&self) -> Vec<(String, String)> {
        self.certs
            .iter()
            .map(|c| (c.tcbm.clone(), c.cert.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredPlatform {
    pub qe_id: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub pce_svn: String,
    pub enc_ppid: String,
    #[serde(default)]
    pub platform_manifest: String,
    #[serde(default)]
    pub state: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    pub id: String,
    pub fmspc: String,
    pub is_default: bool,
    pub policy: String,
    /// Node `appraisal_policies.type` (0 SGX / 1 TDX 1.0 / 2 TDX 1.5).
    #[serde(default)]
    pub policy_type: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AppraisalList {
    policies: Vec<AppraisalPolicy>,
}

pub struct Store {
    db: DB,
    pub cache_mode: CacheMode,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub upstream_fetches: AtomicU64,
    /// Serialises read-modify-write sequences that a scan could otherwise
    /// interleave with: the registration-queue drain, the per-platform pool
    /// upsert, and the appraisal-policy list upsert.
    reg_lock: Mutex<()>,
    platform_lock: Mutex<()>,
    appraisal_lock: Mutex<()>,
}

impl Store {
    pub fn open(path: &Path, cache_mode: CacheMode, rocks: &RocksDbOpts) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        apply_rocksdb_opts(&mut opts, rocks);
        tracing::info!(
            block_cache_mb = rocks.block_cache_mb,
            write_buffer_mb = rocks.write_buffer_mb,
            max_write_buffers = rocks.max_write_buffers,
            max_open_files = rocks.max_open_files,
            "rocksdb memory knobs"
        );
        let db =
            DB::open(&opts, path).map_err(|e| format!("rocksdb open {}: {e}", path.display()))?;
        Ok(Self {
            db,
            cache_mode,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            upstream_fetches: AtomicU64::new(0),
            reg_lock: Mutex::new(()),
            platform_lock: Mutex::new(()),
            appraisal_lock: Mutex::new(()),
        })
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_upstream(&self) {
        self.upstream_fetches.fetch_add(1, Ordering::Relaxed);
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        // `get_pinned` reads straight out of the block cache instead of
        // allocating a `Vec<u8>` copy per lookup.
        let v = self.db.get_pinned(key.as_bytes()).ok().flatten()?;
        serde_json::from_slice(&v).ok()
    }

    fn put_json<T: Serialize>(&self, key: &str, val: &T) -> Result<(), PccsError> {
        let bytes = serde_json::to_vec(val).map_err(|_| error::INTERNAL_ERROR)?;
        self.db
            .put(key.as_bytes(), bytes)
            .map_err(|_| error::INTERNAL_ERROR)
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), PccsError> {
        self.db.write(batch).map_err(|_| error::INTERNAL_ERROR)
    }

    fn scan_prefix(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let iter = self
            .db
            .iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        for item in iter {
            let Ok((k, v)) = item else { break };
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            out.push((String::from_utf8_lossy(&k).into_owned(), v.to_vec()));
        }
        out
    }

    // ---------- pckcert ----------

    /// Hot path. The stored record is re-checked against the request so a hash
    /// collision or a key-construction bug reads as a miss, never as another
    /// platform's certificate.
    pub fn get_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
    ) -> Option<PckCertRecord> {
        let rec: PckCertRecord = self.get_json(&keys::pckcert(qeid, pceid, cpusvn, pcesvn))?;
        let matches = rec.qeid.eq_ignore_ascii_case(qeid)
            && rec.pceid.eq_ignore_ascii_case(pceid)
            && rec.cpusvn.eq_ignore_ascii_case(cpusvn)
            && rec.pcesvn.eq_ignore_ascii_case(pcesvn);
        if !matches {
            tracing::warn!("pckcert record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_pckcert(&self, rec: &PckCertRecord) -> Result<(), PccsError> {
        self.put_json(
            &keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn),
            rec,
        )
    }

    // ---------- platform pool ----------

    /// Node `platformsDao.getPlatform` — one row, one `DB::get`.
    pub fn get_platform_pool(&self, qeid: &str, pceid: &str) -> Option<PlatformPool> {
        let pool: PlatformPool = self.get_json(&keys::platform(qeid, pceid))?;
        if !pool.qe_id.eq_ignore_ascii_case(qeid) || !pool.pce_id.eq_ignore_ascii_case(pceid) {
            tracing::warn!("platform record does not match its key; treating as a miss");
            return None;
        }
        Some(pool)
    }

    pub fn put_platform_pool(&self, pool: &PlatformPool) -> Result<(), PccsError> {
        self.put_json(&keys::platform(&pool.qe_id, &pool.pce_id), pool)
    }

    /// Replace a platform's cert pool while *carrying its known raw TCB levels
    /// forward*, as one read-modify-write under `platform_lock`.
    ///
    /// The naive version — write the pool with `raw_tcbs: []`, then re-add each
    /// level in a second step — leaves a window in which the platform exists
    /// with no known TCB levels. A task cancelled in that window (or a
    /// concurrent `upsert_raw_tcb`) permanently loses them, which empties
    /// `GET /platforms?source=[fmspc]`. Writing once closes the window.
    ///
    /// Returns the raw TCB levels that were already cached, for re-selection.
    pub fn replace_platform_certs(&self, fresh: &PlatformPool) -> Result<Vec<RawTcb>, PccsError> {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let previous = self
            .get_platform_pool(&fresh.qe_id, &fresh.pce_id)
            .map(|p| p.raw_tcbs)
            .unwrap_or_default();
        let mut merged = fresh.clone();
        merged.raw_tcbs = previous.clone();
        self.put_platform_pool(&merged)?;
        Ok(previous)
    }

    /// Hot path: existence only. Deserialising the whole pool (every cert of
    /// the platform) just to answer "is this platform known?" is pure waste on
    /// a `/pckcert` cache hit, so this stops at the raw `DB::get`.
    pub fn has_platform(&self, qeid: &str, pceid: &str) -> bool {
        self.db
            .get_pinned(keys::platform(qeid, pceid).as_bytes())
            .ok()
            .flatten()
            .is_some()
    }

    pub fn list_platform_pools(&self) -> Vec<PlatformPool> {
        self.scan_prefix(keys::PLATFORM)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    /// Node `platformTcbsDao.upsertPlatformTcbs`. Read-modify-write of one
    /// platform record, serialised against concurrent writers.
    pub fn upsert_raw_tcb(
        &self,
        qeid: &str,
        pceid: &str,
        cpusvn: &str,
        pcesvn: &str,
        tcbm: &str,
    ) -> Result<(), PccsError> {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut pool) = self.get_platform_pool(qeid, pceid) else {
            return Ok(());
        };
        let entry = RawTcb {
            cpu_svn: cpusvn.to_ascii_uppercase(),
            pce_svn: pcesvn.to_ascii_uppercase(),
            tcbm: tcbm.to_ascii_uppercase(),
        };
        match pool
            .raw_tcbs
            .iter_mut()
            .find(|r| r.cpu_svn == entry.cpu_svn && r.pce_svn == entry.pce_svn)
        {
            Some(existing) => existing.tcbm = entry.tcbm,
            None => pool.raw_tcbs.push(entry),
        }
        self.put_platform_pool(&pool)
    }

    /// Undo an `upsert_raw_tcb`. Node's LAZY mode simply skips the
    /// `platform_tcbs` insert when some TCB levels had no certificate.
    pub fn remove_raw_tcb(
        &self,
        qeid: &str,
        pceid: &str,
        cpusvn: &str,
        pcesvn: &str,
    ) -> Result<(), PccsError> {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut pool) = self.get_platform_pool(qeid, pceid) else {
            return Ok(());
        };
        pool.raw_tcbs.retain(|r| {
            !(r.cpu_svn.eq_ignore_ascii_case(cpusvn) && r.pce_svn.eq_ignore_ascii_case(pcesvn))
        });
        self.put_platform_pool(&pool)
    }

    /// Node `platformsDao.getCachedPlatformsByFmspc`: a join of `platforms`
    /// with `platform_tcbs`, i.e. one row per known raw TCB.
    pub fn cached_platforms_by_fmspc(&self, fmspcs: &[String]) -> Vec<PlatformRecord> {
        let mut out = Vec::new();
        for pool in self.list_platform_pools() {
            if !fmspcs.is_empty() && !fmspcs.iter().any(|f| f.eq_ignore_ascii_case(&pool.fmspc)) {
                continue;
            }
            for raw in &pool.raw_tcbs {
                out.push(PlatformRecord {
                    qe_id: pool.qe_id.clone(),
                    pce_id: pool.pce_id.clone(),
                    cpu_svn: raw.cpu_svn.clone(),
                    pce_svn: raw.pce_svn.clone(),
                    enc_ppid: pool.enc_ppid.clone(),
                    platform_manifest: pool.platform_manifest.clone(),
                });
            }
        }
        out
    }

    // ---------- tcb / identity / crl ----------

    pub fn get_tcb(
        &self,
        prod_type: u8,
        fmspc: &str,
        version: u32,
        update: UpdateType,
    ) -> Option<TcbRecord> {
        let rec: TcbRecord = self.get_json(&keys::tcb(
            keys::prod_name(prod_type),
            version,
            fmspc,
            update.as_str(),
        ))?;
        if rec.prod_type != prod_type
            || rec.version != version
            || !rec.fmspc.eq_ignore_ascii_case(fmspc)
            || !rec.update_type.eq_ignore_ascii_case(update.as_str())
        {
            tracing::warn!("tcb record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_tcb(&self, rec: &TcbRecord) -> Result<(), PccsError> {
        self.put_json(
            &keys::tcb(
                keys::prod_name(rec.prod_type),
                rec.version,
                &rec.fmspc,
                &rec.update_type,
            ),
            rec,
        )
    }

    pub fn list_tcbs(&self) -> Vec<TcbRecord> {
        self.scan_prefix(keys::TCB)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn get_identity(
        &self,
        enclave_id: u8,
        version: u32,
        update: UpdateType,
    ) -> Option<IdentityRecord> {
        let rec: IdentityRecord = self.get_json(&keys::identity(
            keys::identity_name(enclave_id),
            version,
            update.as_str(),
        ))?;
        if rec.enclave_id != enclave_id
            || rec.version != version
            || !rec.update_type.eq_ignore_ascii_case(update.as_str())
        {
            tracing::warn!("identity record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_identity(&self, rec: &IdentityRecord) -> Result<(), PccsError> {
        self.put_json(
            &keys::identity(
                keys::identity_name(rec.enclave_id),
                rec.version,
                &rec.update_type,
            ),
            rec,
        )
    }

    pub fn list_identities(&self) -> Vec<IdentityRecord> {
        self.scan_prefix(keys::IDENTITY)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn get_pckcrl(&self, ca: &str) -> Option<PckCrlRecord> {
        let rec: PckCrlRecord = self.get_json(&keys::pckcrl(ca))?;
        if !rec.ca.eq_ignore_ascii_case(ca) {
            tracing::warn!("pckcrl record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_pckcrl(&self, rec: &PckCrlRecord) -> Result<(), PccsError> {
        self.put_json(&keys::pckcrl(&rec.ca), rec)
    }

    pub fn list_pckcrls(&self) -> Vec<PckCrlRecord> {
        self.scan_prefix(keys::PCKCRL)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn get_rootcacrl(&self) -> Option<Vec<u8>> {
        self.get_json::<Vec<u8>>(&keys::rootcacrl())
    }

    pub fn put_rootcacrl(&self, crl: &[u8]) -> Result<(), PccsError> {
        self.put_json(&keys::rootcacrl(), &crl.to_vec())
    }

    pub fn get_crl(&self, uri: &str) -> Option<Vec<u8>> {
        self.get_json::<CrlRecord>(&keys::crl(uri)).map(|r| r.crl)
    }

    pub fn put_crl(&self, uri: &str, crl: &[u8]) -> Result<(), PccsError> {
        self.put_json(
            &keys::crl(uri),
            &CrlRecord {
                uri: uri.to_string(),
                crl: crl.to_vec(),
            },
        )
    }

    pub fn list_crls(&self) -> Vec<CrlRecord> {
        self.scan_prefix(keys::CRL)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    // ---------- registration queue ----------

    fn normalize_reg(p: &mut RegisteredPlatform) {
        p.qe_id = p.qe_id.to_ascii_uppercase();
        p.pce_id = p.pce_id.to_ascii_uppercase();
        p.cpu_svn = p.cpu_svn.to_ascii_uppercase();
        p.pce_svn = p.pce_svn.to_ascii_uppercase();
        p.enc_ppid = p.enc_ppid.to_ascii_uppercase();
    }

    /// Node `platformsRegDao.registerPlatform` — upsert keyed by
    /// (qe_id, pce_id, cpu_svn, pce_svn).
    pub fn register_platform(&self, mut p: RegisteredPlatform) -> Result<(), PccsError> {
        let _guard = self.reg_lock.lock().unwrap_or_else(|e| e.into_inner());
        Self::normalize_reg(&mut p);
        let key = keys::preg(&p.qe_id, &p.pce_id, &p.cpu_svn, &p.pce_svn);
        self.put_json(&key, &p)
    }

    /// Node `ReqCachingMode.registerPlatforms` marks *this* row deleted after a
    /// successful fill (`registerPlatform(regDataJson, PLATF_REG_DELETED)`).
    /// A `PLATF_REG_DELETED` row is never returned by any query, so removing
    /// the key is observably the same and keeps the queue from growing.
    pub fn delete_registered(&self, p: &RegisteredPlatform) -> Result<(), PccsError> {
        let _guard = self.reg_lock.lock().unwrap_or_else(|e| e.into_inner());
        let key = keys::preg(
            &p.qe_id.to_ascii_uppercase(),
            &p.pce_id.to_ascii_uppercase(),
            &p.cpu_svn.to_ascii_uppercase(),
            &p.pce_svn.to_ascii_uppercase(),
        );
        self.db
            .delete(key.as_bytes())
            .map_err(|_| error::INTERNAL_ERROR)
    }

    /// Node `getRegisteredPlatforms` + `deleteRegisteredPlatforms(state)` inside
    /// one transaction. The scan and the batch delete are serialised against
    /// concurrent registrations, so a row written between the two cannot be
    /// dropped without ever being returned.
    pub fn take_registered(&self, state: u8) -> Result<Vec<RegisteredPlatform>, PccsError> {
        let _guard = self.reg_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut take = Vec::new();
        let mut batch = WriteBatch::default();
        for (k, v) in self.scan_prefix(keys::PREG) {
            if let Ok(p) = serde_json::from_slice::<RegisteredPlatform>(&v) {
                if p.state == state {
                    take.push(p);
                    batch.delete(k.as_bytes());
                }
            }
        }
        self.write_batch(batch)?;
        Ok(take)
    }

    // ---------- appraisal ----------

    /// Node `appraisalPolicyService.putAppraisalPolicy` +
    /// `appraisalPolicyDao.upsertAppraisalPolicy`: validate, hash the policy to
    /// get the primary key, clear `is_default` on the other policies of this
    /// fmspc, then upsert by id.
    pub fn put_appraisal_policy(&self, body: &Value) -> Result<String, PccsError> {
        let reg = crate::validate::appraisal_policy(body)?;
        let id = sha384_hex(&reg.policy);
        let key = keys::appraisal(&reg.fmspc);

        let _guard = self
            .appraisal_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut list: AppraisalList = self.get_json(&key).unwrap_or_default();
        if reg.is_default {
            for p in list.policies.iter_mut() {
                p.is_default = false;
            }
        }
        let entry = AppraisalPolicy {
            id: id.clone(),
            fmspc: reg.fmspc,
            is_default: reg.is_default,
            policy: reg.policy,
            policy_type: reg.policy_type,
        };
        match list.policies.iter_mut().find(|p| p.id == id) {
            Some(existing) => *existing = entry,
            None => list.policies.push(entry),
        }
        self.put_json(&key, &list)?;
        Ok(id)
    }

    /// Seed-file path: the fixture is operator-supplied, not an API request, so
    /// it skips the JWS payload checks that `PUT /appraisalpolicy` applies.
    fn upsert_appraisal_policy_raw(&self, fmspc: &str, policy: &str, is_default: bool) {
        let fmspc = fmspc.to_ascii_uppercase();
        let id = sha384_hex(policy);
        let key = keys::appraisal(&fmspc);
        let _guard = self
            .appraisal_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut list: AppraisalList = self.get_json(&key).unwrap_or_default();
        if is_default {
            for p in list.policies.iter_mut() {
                p.is_default = false;
            }
        }
        let entry = AppraisalPolicy {
            id: id.clone(),
            fmspc,
            is_default,
            policy: policy.to_string(),
            policy_type: 0,
        };
        match list.policies.iter_mut().find(|p| p.id == id) {
            Some(existing) => *existing = entry,
            None => list.policies.push(entry),
        }
        let _ = self.put_json(&key, &list);
    }

    pub fn get_default_policies(&self, fmspc: &str) -> Result<String, PccsError> {
        let list: AppraisalList = self
            .get_json(&keys::appraisal(fmspc))
            .ok_or(error::NO_CACHE_DATA)?;
        let defaults: Vec<&str> = list
            .policies
            .iter()
            .filter(|p| p.is_default)
            .map(|p| p.policy.as_str())
            .collect();
        if defaults.is_empty() {
            return Err(error::NO_CACHE_DATA);
        }
        Ok(defaults.join(","))
    }

    // ---------- seed ----------

    pub fn load_seed_file(&self, path: &Path) -> Result<(), String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("read seed {}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(&data).map_err(|e| format!("parse seed: {e}"))?;
        self.load_seed_value(&v);
        Ok(())
    }

    pub fn load_seed_value(&self, v: &Value) {
        if let Some(arr) = v.get("pckcerts").and_then(|x| x.as_array()) {
            for item in arr {
                self.upsert_pckcert_from_json(item);
            }
        }
        // After `pckcerts`, so a platform that also has a seeded certificate
        // keeps that cert and only gains the registration fields.
        if let Some(arr) = v.get("platforms").and_then(|x| x.as_array()) {
            for item in arr {
                self.upsert_seed_platform(item);
            }
        }
        if let Some(arr) = v.get("tcbinfo").and_then(|x| x.as_array()) {
            for item in arr {
                self.upsert_tcb_from_json(item);
            }
        }
        if let Some(arr) = v.get("identities").and_then(|x| x.as_array()) {
            for item in arr {
                self.upsert_identity_from_json(item);
            }
        }
        if let Some(arr) = v.get("pckcrls").and_then(|x| x.as_array()) {
            for item in arr {
                let ca = item
                    .get("ca")
                    .and_then(|x| x.as_str())
                    .unwrap_or("PROCESSOR")
                    .to_ascii_uppercase();
                let issuer = item
                    .get("issuer_chain")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let hexv = item
                    .get("pckcrl_hex")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                if let Ok(bytes) = hex::decode(hexv) {
                    let _ = self.put_pckcrl(&PckCrlRecord {
                        ca,
                        pckcrl: bytes,
                        issuer_chain: issuer,
                    });
                }
            }
        }
        if let Some(hexv) = v.get("rootcacrl_hex").and_then(|x| x.as_str()) {
            if let Ok(bytes) = hex::decode(hexv) {
                let _ = self.put_rootcacrl(&bytes);
            }
        }
        if let Some(arr) = v.get("crls").and_then(|x| x.as_array()) {
            for item in arr {
                let uri = item.get("uri").and_then(|x| x.as_str()).unwrap_or("");
                let hexv = item.get("crl_hex").and_then(|x| x.as_str()).unwrap_or("");
                if !uri.is_empty() {
                    if let Ok(bytes) = hex::decode(hexv) {
                        let _ = self.put_crl(uri, &bytes);
                    }
                }
            }
        }
        if let Some(arr) = v.get("appraisal_policies").and_then(|x| x.as_array()) {
            for item in arr {
                let fmspc = item
                    .get("fmspc")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_ascii_uppercase();
                let policy = item
                    .get("policy")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let is_default = item
                    .get("is_default")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(true);
                if !fmspc.is_empty() && !policy.is_empty() {
                    self.upsert_appraisal_policy_raw(&fmspc, &policy, is_default);
                }
            }
        }
    }

    fn upsert_pckcert_from_json(&self, item: &Value) {
        let qeid = first_upper(item, &["qeid", "qe_id"]);
        let cpusvn = first_upper(item, &["cpusvn", "cpu_svn"]);
        let pcesvn = first_upper(item, &["pcesvn", "pce_svn"]);
        let pceid = first_upper(item, &["pceid", "pce_id"]);
        if qeid.is_empty() || cpusvn.is_empty() || pcesvn.is_empty() || pceid.is_empty() {
            return;
        }
        let rec = PckCertRecord {
            qeid,
            pceid,
            cpusvn,
            pcesvn,
            cert: item
                .get("cert")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            tcbm: upper(item, "tcbm"),
            fmspc: upper(item, "fmspc"),
            // Uppercase like every other writer, so the served
            // `SGX-PCK-Certificate-CA-Type` header is `PROCESSOR` / `PLATFORM`
            // whatever casing the seed file used.
            ca: item
                .get("ca")
                .and_then(|x| x.as_str())
                .unwrap_or("PROCESSOR")
                .to_ascii_uppercase(),
            issuer_chain: item
                .get("issuer_chain")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            encrypted_ppid: item
                .get("encrypted_ppid")
                .or_else(|| item.get("enc_ppid"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_ascii_uppercase()),
            platform_manifest: item
                .get("platform_manifest")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        };
        // A seeded raw-TCB record also establishes the platform, so
        // `has_platform` and the local-selection miss path work offline.
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut pool = self
            .get_platform_pool(&rec.qeid, &rec.pceid)
            .unwrap_or_else(|| PlatformPool {
                qe_id: rec.qeid.clone(),
                pce_id: rec.pceid.clone(),
                enc_ppid: rec.encrypted_ppid.clone().unwrap_or_default(),
                platform_manifest: rec.platform_manifest.clone(),
                fmspc: rec.fmspc.clone(),
                ca: rec.ca.clone(),
                issuer_chain: rec.issuer_chain.clone(),
                certs: Vec::new(),
                raw_tcbs: Vec::new(),
            });
        if !rec.tcbm.is_empty() && !pool.certs.iter().any(|c| c.tcbm == rec.tcbm) {
            pool.certs.push(PlatformCert {
                tcbm: rec.tcbm.clone(),
                cert: rec.cert.clone(),
            });
        }
        let raw = RawTcb {
            cpu_svn: rec.cpusvn.clone(),
            pce_svn: rec.pcesvn.clone(),
            tcbm: rec.tcbm.clone(),
        };
        if !pool
            .raw_tcbs
            .iter()
            .any(|r| r.cpu_svn == raw.cpu_svn && r.pce_svn == raw.pce_svn)
        {
            pool.raw_tcbs.push(raw);
        }
        let _ = self.put_platform_pool(&pool);
        drop(_guard);
        let _ = self.put_pckcert(&rec);
    }

    /// Seed `platforms[]` — the Intel `platforms` table row, with no
    /// certificate attached. Creates or merges the `platform/` pool so a seeded
    /// platform counts as known (`has_platform`) and shows up in
    /// `GET /platforms?source=[fmspc]` even before any cert is cached.
    ///
    /// Merges rather than overwrites: `pckcerts` is seeded first, and its certs
    /// and raw TCB levels must survive.
    fn upsert_seed_platform(&self, item: &Value) {
        let qe_id = first_upper(item, &["qe_id", "qeid"]);
        let pce_id = first_upper(item, &["pce_id", "pceid"]);
        if qe_id.is_empty() || pce_id.is_empty() {
            return;
        }
        let enc_ppid = first_upper(item, &["enc_ppid", "encrypted_ppid"]);
        let manifest = item
            .get("platform_manifest")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        let fmspc = upper(item, "fmspc");
        let cpu_svn = first_upper(item, &["cpu_svn", "cpusvn"]);
        let pce_svn = first_upper(item, &["pce_svn", "pcesvn"]);

        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut pool = self
            .get_platform_pool(&qe_id, &pce_id)
            .unwrap_or_else(|| PlatformPool {
                qe_id: qe_id.clone(),
                pce_id: pce_id.clone(),
                ..Default::default()
            });
        // Only fill blanks; a value already established by a seeded cert wins.
        if pool.enc_ppid.is_empty() {
            pool.enc_ppid = enc_ppid;
        }
        if pool.platform_manifest.is_empty() {
            pool.platform_manifest = manifest;
        }
        if pool.fmspc.is_empty() {
            pool.fmspc = fmspc;
        }
        // A (cpu_svn, pce_svn) with no cert still makes the level *known*, so
        // `GET /platforms?source=[fmspc]` lists it. `tcbm` stays empty until a
        // certificate is selected for it.
        if !cpu_svn.is_empty()
            && !pce_svn.is_empty()
            && !pool
                .raw_tcbs
                .iter()
                .any(|r| r.cpu_svn == cpu_svn && r.pce_svn == pce_svn)
        {
            pool.raw_tcbs.push(RawTcb {
                cpu_svn,
                pce_svn,
                tcbm: String::new(),
            });
        }
        let _ = self.put_platform_pool(&pool);
    }

    fn upsert_tcb_from_json(&self, item: &Value) {
        let prod = match item
            .get("prod_type")
            .and_then(|x| x.as_str())
            .unwrap_or("sgx")
        {
            "tdx" | "TDX" => 1u8,
            _ => 0,
        };
        let fmspc = upper(item, "fmspc");
        if fmspc.is_empty() {
            return;
        }
        let rec = TcbRecord {
            prod_type: prod,
            fmspc,
            version: item.get("version").and_then(|x| x.as_u64()).unwrap_or(4) as u32,
            update_type: item
                .get("update_type")
                .and_then(|x| x.as_str())
                .unwrap_or("STANDARD")
                .to_ascii_uppercase(),
            issuer_chain: item
                .get("issuer_chain")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            raw_body: item.get("tcbinfo").map(raw_json).unwrap_or_default(),
            tcbinfo: item.get("tcbinfo").cloned().unwrap_or(Value::Null),
        };
        let _ = self.put_tcb(&rec);
    }

    fn upsert_identity_from_json(&self, item: &Value) {
        let rec = IdentityRecord {
            enclave_id: item.get("enclave_id").and_then(|x| x.as_u64()).unwrap_or(1) as u8,
            version: item.get("version").and_then(|x| x.as_u64()).unwrap_or(4) as u32,
            update_type: item
                .get("update_type")
                .and_then(|x| x.as_str())
                .unwrap_or("STANDARD")
                .to_ascii_uppercase(),
            issuer_chain: item
                .get("issuer_chain")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            raw_body: item.get("identity").map(raw_json).unwrap_or_default(),
            identity: item.get("identity").cloned().unwrap_or(Value::Null),
        };
        let _ = self.put_identity(&rec);
    }

    /// `PUT /platformcollateral` — Node `platformCollateralService.addPlatformCollateral`.
    /// Validated against `PLATFORM_COLLATERAL_SCHEMA_V3/V4` first, then written
    /// as GET-shaped records plus one platform pool per (qe_id, pce_id).
    pub fn put_platform_collateral(&self, body: &Value, version: u32) -> Result<(), PccsError> {
        crate::validate::platform_collateral(body, version)?;
        let platforms = body
            .get("platforms")
            .and_then(|x| x.as_array())
            .ok_or(error::INVALID_REQ)?;
        let collaterals = body.get("collaterals").cloned().unwrap_or(Value::Null);
        let certificates = collaterals
            .get("certificates")
            .cloned()
            .unwrap_or(Value::Null);

        // ---- TCB infos ----
        let tcb_issuer = first_str(
            &certificates,
            &[
                crate::headers::tcb_issuer_chain_name(version),
                crate::headers::TCB_INFO_ISSUER_CHAIN,
                crate::headers::SGX_TCB_INFO_ISSUER_CHAIN,
            ],
        )
        .unwrap_or_default();
        let tcb_fields: &[(&str, u8, bool)] = if version < 4 {
            &[("tcbinfo", 0, false), ("tcbinfo_early", 0, true)]
        } else {
            &[
                ("sgx_tcbinfo", 0, false),
                ("sgx_tcbinfo_early", 0, true),
                ("tdx_tcbinfo", 1, false),
                ("tdx_tcbinfo_early", 1, true),
            ]
        };
        if let Some(tcbs) = collaterals.get("tcbinfos").and_then(|x| x.as_array()) {
            for t in tcbs {
                let fmspc = upper(t, "fmspc");
                if fmspc.is_empty() {
                    continue;
                }
                for (field, prod, early) in tcb_fields {
                    let Some(info) = t.get(*field) else { continue };
                    self.put_tcb(&TcbRecord {
                        prod_type: *prod,
                        fmspc: fmspc.clone(),
                        version,
                        update_type: if *early { "EARLY" } else { "STANDARD" }.into(),
                        // Node: `Buffer.from(JSON.stringify(tcbinfo[type]))`.
                        // serde_json keeps document order (`preserve_order`), so
                        // the signed body is byte-identical to what was PUT.
                        raw_body: raw_json(info),
                        tcbinfo: info.clone(),
                        issuer_chain: tcb_issuer.clone(),
                    })?;
                }
            }
        }

        // ---- enclave identities ----
        let identity_issuer = certificates
            .get(crate::headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        for (field, id, early) in [
            ("qeidentity", 1u8, false),
            ("qeidentity_early", 1, true),
            ("qveidentity", 2, false),
            ("qveidentity_early", 2, true),
            ("tdqeidentity", 3, false),
            ("tdqeidentity_early", 3, true),
        ] {
            let Some(ident) = collaterals.get(field) else {
                continue;
            };
            // The schema declares these as strings; a JSON object is also
            // accepted. Either way the stored body is what was sent.
            let (identity, raw_body) = if let Some(s) = ident.as_str() {
                (
                    serde_json::from_str(s).unwrap_or_else(|_| ident.clone()),
                    s.to_string(),
                )
            } else {
                (ident.clone(), raw_json(ident))
            };
            self.put_identity(&IdentityRecord {
                enclave_id: id,
                version,
                update_type: if early { "EARLY" } else { "STANDARD" }.into(),
                identity,
                raw_body,
                issuer_chain: identity_issuer.clone(),
            })?;
        }

        // ---- CRLs ----
        let pck_chain = |ca: &str| -> String {
            certificates
                .pointer(&format!(
                    "/{}/{ca}",
                    crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN
                ))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        if let Some(crl) = collaterals.get("pckcacrl") {
            for (field, ca) in [("processorCrl", "PROCESSOR"), ("platformCrl", "PLATFORM")] {
                if let Some(hexv) = crl.get(field).and_then(|x| x.as_str()) {
                    if let Ok(bytes) = hex::decode(hexv) {
                        self.put_pckcrl(&PckCrlRecord {
                            ca: ca.into(),
                            pckcrl: bytes,
                            issuer_chain: pck_chain(ca),
                        })?;
                    }
                }
            }
        }
        if let Some(hexv) = collaterals.get("rootcacrl").and_then(|x| x.as_str()) {
            if let Ok(bytes) = hex::decode(hexv) {
                self.put_rootcacrl(&bytes)?;
                if let Some(cdp) = collaterals.get("rootcacrl_cdp").and_then(|x| x.as_str()) {
                    self.put_crl(cdp, &bytes)?;
                }
            }
        }

        // ---- PCK certs: one pool per platform, selection per raw TCB ----
        let empty = Vec::new();
        let pck_certs = collaterals
            .get("pck_certs")
            .and_then(|x| x.as_array())
            .unwrap_or(&empty);
        let tcbinfos = collaterals
            .get("tcbinfos")
            .and_then(|x| x.as_array())
            .unwrap_or(&empty);

        let mut batch = WriteBatch::default();
        // Held across every read-modify-write below *and* the final
        // `write_batch`, so a concurrent `upsert_raw_tcb` can neither observe a
        // half-built pool nor have its own write silently overwritten.
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        for pc in pck_certs {
            let qe_id = first_upper(pc, &["qe_id", "qeid"]);
            let pce_id = first_upper(pc, &["pce_id", "pceid"]);
            let certs: Vec<(String, String)> = pc
                .get("certs")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|c| {
                            (
                                upper(c, "tcbm"),
                                crate::validate::percent_decode(
                                    c.get("cert").and_then(|x| x.as_str()).unwrap_or(""),
                                ),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            if certs.is_empty() {
                tracing::error!("PCK certificates not found in the collateral file.");
                return Err(error::INVALID_REQ);
            }

            // Node parses an arbitrary cert for fmspc + ca; an unparsable cert
            // is a 400, never a fallback to the request's own fields.
            let info = crate::selection::parse_pck_cert(&certs[0].1).map_err(|e| {
                tracing::error!("Invalid certificate format: {e}");
                error::INVALID_REQ
            })?;
            if info.fmspc.is_empty() || info.ca.is_empty() {
                tracing::error!("Invalid certificate format.");
                return Err(error::INVALID_REQ);
            }

            let tcb_info_obj = tcbinfos
                .iter()
                .find(|t| upper(t, "fmspc") == info.fmspc)
                .and_then(|t| collateral_tcb_info(t, version))
                .ok_or_else(|| {
                    tracing::error!("Can't find TCB info.");
                    error::INVALID_REQ
                })?;

            let new_platforms: Vec<&Value> = platforms
                .iter()
                .filter(|p| {
                    first_upper(p, &["qe_id", "qeid"]) == qe_id
                        && first_upper(p, &["pce_id", "pceid"]) == pce_id
                })
                .collect();

            let mut pool =
                self.get_platform_pool(&qe_id, &pce_id)
                    .unwrap_or_else(|| PlatformPool {
                        qe_id: qe_id.clone(),
                        pce_id: pce_id.clone(),
                        ..Default::default()
                    });
            pool.fmspc = info.fmspc.clone();
            pool.ca = info.ca.clone();
            pool.certs = certs
                .iter()
                .map(|(tcbm, cert)| PlatformCert {
                    tcbm: tcbm.clone(),
                    cert: cert.clone(),
                })
                .collect();
            let issuer = if pck_chain(&info.ca).is_empty() {
                new_platforms
                    .first()
                    .and_then(|p| p.get("issuer_chain"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                pck_chain(&info.ca)
            };
            pool.issuer_chain = issuer.clone();
            if let Some(p) = new_platforms.first() {
                pool.enc_ppid = first_upper(p, &["enc_ppid", "encrypted_ppid"]);
                pool.platform_manifest = p
                    .get("platform_manifest")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_ascii_uppercase();
            }

            // Node: cached platform_tcbs plus the raw TCBs in this request.
            let mut raw_tcbs: Vec<(String, String)> = pool
                .raw_tcbs
                .iter()
                .map(|r| (r.cpu_svn.clone(), r.pce_svn.clone()))
                .collect();
            for p in &new_platforms {
                let cpu = first_upper(p, &["cpu_svn", "cpusvn"]);
                let pce = first_upper(p, &["pce_svn", "pcesvn"]);
                if !cpu.is_empty()
                    && !pce.is_empty()
                    && !raw_tcbs.contains(&(cpu.clone(), pce.clone()))
                {
                    raw_tcbs.push((cpu, pce));
                }
            }

            pool.raw_tcbs.clear();
            for (cpu_svn, pce_svn) in raw_tcbs {
                let (tcbm, cert) = crate::selection::select_best_pck_cert(
                    &cpu_svn,
                    &pce_svn,
                    &pce_id,
                    &certs,
                    &tcb_info_obj,
                )
                .map_err(|e| {
                    tracing::error!("Failed to select the best certificate: {e}");
                    error::INVALID_REQ
                })?;
                pool.raw_tcbs.push(RawTcb {
                    cpu_svn: cpu_svn.clone(),
                    pce_svn: pce_svn.clone(),
                    tcbm: tcbm.clone(),
                });
                let rec = PckCertRecord {
                    qeid: qe_id.clone(),
                    pceid: pce_id.clone(),
                    cpusvn: cpu_svn,
                    pcesvn: pce_svn,
                    cert,
                    tcbm,
                    fmspc: info.fmspc.clone(),
                    ca: info.ca.clone(),
                    issuer_chain: issuer.clone(),
                    encrypted_ppid: if pool.enc_ppid.is_empty() {
                        None
                    } else {
                        Some(pool.enc_ppid.clone())
                    },
                    platform_manifest: pool.platform_manifest.clone(),
                };
                let k = keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn);
                batch.put(
                    k.as_bytes(),
                    serde_json::to_vec(&rec).map_err(|_| error::INTERNAL_ERROR)?,
                );
            }
            let k = keys::platform(&pool.qe_id, &pool.pce_id);
            batch.put(
                k.as_bytes(),
                serde_json::to_vec(&pool).map_err(|_| error::INTERNAL_ERROR)?,
            );
        }

        self.write_batch(batch)
    }
}

impl Default for PlatformPool {
    fn default() -> Self {
        Self {
            qe_id: String::new(),
            pce_id: String::new(),
            enc_ppid: String::new(),
            platform_manifest: String::new(),
            fmspc: String::new(),
            ca: String::new(),
            issuer_chain: String::new(),
            certs: Vec::new(),
            raw_tcbs: Vec::new(),
        }
    }
}

/// Node `getTcbInfoObject`: EARLY wins over STANDARD, always the SGX one.
fn collateral_tcb_info(tcbinfo: &Value, version: u32) -> Option<Value> {
    let fields: &[&str] = if version < 4 {
        &["tcbinfo_early", "tcbinfo"]
    } else {
        &["sgx_tcbinfo_early", "sgx_tcbinfo"]
    };
    for f in fields {
        if let Some(inner) = tcbinfo.get(*f).and_then(|v| v.get("tcbInfo")) {
            return Some(inner.clone());
        }
    }
    None
}

/// Exact bytes of a JSON value. `serde_json` is built with `preserve_order`, so
/// this reproduces JavaScript's `JSON.stringify` key order for a parsed object.
fn raw_json(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn upper(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_uppercase()
}

fn first_upper(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return s.to_ascii_uppercase();
        }
    }
    String::new()
}

fn first_str(v: &Value, paths: &[&str]) -> Option<String> {
    for p in paths {
        if p.contains('.') {
            let pointer = format!("/{}", p.replace('.', "/"));
            if let Some(s) = v.pointer(&pointer).and_then(|x| x.as_str()) {
                return Some(s.to_string());
            }
        } else if let Some(s) = v.get(*p).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

pub fn sha384_hex(s: &str) -> String {
    use sha2::{Digest, Sha384};
    hex::encode(Sha384::digest(s.as_bytes()))
}

pub fn find_seed_path(explicit: Option<&Path>) -> Option<std::path::PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    let candidates = [
        std::path::PathBuf::from("fixtures/seed.json"),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/seed.json"),
        std::path::PathBuf::from("/workspace/pccs-rs/fixtures/seed.json"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Apply runtime RocksDB memory knobs. Keeps zstd block compression.
pub fn apply_rocksdb_opts(opts: &mut Options, rocks: &RocksDbOpts) {
    opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
    opts.set_write_buffer_size(rocks.write_buffer_bytes());
    opts.set_max_write_buffer_number(rocks.max_write_buffers);
    opts.set_max_open_files(rocks.max_open_files);
    let cache = Cache::new_lru_cache(rocks.block_cache_bytes());
    let mut table = BlockBasedOptions::default();
    table.set_block_cache(&cache);
    opts.set_block_based_table_factory(&table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CacheMode, RocksDbOpts};

    #[test]
    fn two_configs_produce_different_option_values() {
        let default = RocksDbOpts::default();
        let tiny = RocksDbOpts {
            block_cache_mb: 1,
            write_buffer_mb: 4,
            max_write_buffers: 1,
            max_open_files: 64,
        };
        assert_ne!(default.block_cache_bytes(), tiny.block_cache_bytes());
        assert_ne!(default.write_buffer_bytes(), tiny.write_buffer_bytes());
        assert_ne!(default.max_write_buffers, tiny.max_write_buffers);
        assert_ne!(default.max_open_files, tiny.max_open_files);
    }

    #[test]
    fn open_succeeds_with_1mib_block_cache() {
        let dir = std::env::temp_dir().join(format!("pccs-rs-rdb-{}", uuid::Uuid::new_v4()));
        let opts = RocksDbOpts {
            block_cache_mb: 1,
            write_buffer_mb: 4,
            max_write_buffers: 1,
            max_open_files: 64,
        };
        let store = Store::open(&dir, CacheMode::Offline, &opts).expect("open with 1 MiB cache");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
