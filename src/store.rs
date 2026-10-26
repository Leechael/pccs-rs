//! RocksDB store: one key per cacheable GET. Value = response body + Intel headers.
//! No Intel/Sequelize tables. Writes use WriteBatch.

use crate::config::{CacheMode, RocksDbOpts};
use crate::error::{self, PccsError};
use crate::keys;
use crate::metrics::{CacheResult, Kind, Metrics};
use crate::validate::UpdateType;
use rocksdb::{BlockBasedOptions, Cache, Direction, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmdKdsRecord {
    pub url: String,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub fetched_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaOcspRecord {
    pub cache_key: String,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub fetched_at: u64,
    pub expires_at: u64,
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

/// Opaque snapshot of only the fetch credentials. Deliberately no Debug or
/// serialization implementation: credentials must not leak through diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct PlatformCredentials {
    enc_ppid: String,
    platform_manifest: String,
}

/// Publication guard. Only an unknown GET may accept a platform created while
/// it was fetching, and only when that platform has the actual request creds.
/// Registration and refresh retain the strict observed-context comparison.
pub(crate) enum PlatformPublication<'a> {
    Observed(Option<&'a PlatformCredentials>),
    AbsentGet { enc_ppid: &'a str, platform_manifest: &'a str },
}

impl PlatformPool {
    pub fn credentials(&self) -> PlatformCredentials {
        PlatformCredentials {
            enc_ppid: self.enc_ppid.clone(),
            platform_manifest: self.platform_manifest.clone(),
        }
    }

    pub fn cert_pairs(&self) -> Vec<(String, String)> {
        self.certs.iter().map(|c| (c.tcbm.clone(), c.cert.clone())).collect()
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
    pub metrics: Arc<Metrics>,
    /// Serialises read-modify-write sequences that a scan could otherwise
    /// interleave with: the registration-queue drain, the per-platform pool
    /// upsert, and the appraisal-policy list upsert.
    reg_lock: Mutex<()>,
    platform_lock: Mutex<()>,
    appraisal_lock: Mutex<()>,
    /// Serialises the bound-and-evict step of the read-through kinds. Holds
    /// the last index timestamp handed out, so write times never repeat.
    fifo_lock: Mutex<u64>,
    readthrough_max_entries: usize,
}

/// Read-through kinds bounded by `readthrough_max_entries_per_kind`.
const BOUNDED_KINDS: [&str; 3] = [keys::AMD_KDS, keys::NVIDIA_RIM, keys::NVIDIA_OCSP];

fn fifo_order_prefix(kind: &str) -> Vec<u8> {
    format!("{}{kind}", keys::FIFO_ORDER).into_bytes()
}

fn fifo_order_key(kind: &str, written_at: u64, entry_key: &[u8]) -> Vec<u8> {
    let mut key = fifo_order_prefix(kind);
    key.extend_from_slice(&written_at.to_be_bytes());
    key.extend_from_slice(entry_key);
    key
}

fn fifo_pos_key(entry_key: &[u8]) -> Vec<u8> {
    [keys::FIFO_POS.as_bytes(), entry_key].concat()
}

fn fifo_count_key(kind: &str) -> String {
    format!("{}{kind}", keys::FIFO_COUNT)
}

fn be_u64(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

pub(crate) fn tcb_kind(prod_type: u8) -> Kind {
    if prod_type == 1 {
        Kind::TdxTcb
    } else {
        Kind::SgxTcb
    }
}

pub(crate) fn identity_kind(enclave_id: u8) -> Kind {
    match enclave_id {
        2 => Kind::QveIdentity,
        3 => Kind::TdqeIdentity,
        _ => Kind::QeIdentity,
    }
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
        let store = Self {
            db,
            cache_mode,
            metrics: Arc::new(Metrics::default()),
            reg_lock: Mutex::new(()),
            platform_lock: Mutex::new(()),
            appraisal_lock: Mutex::new(()),
            fifo_lock: Mutex::new(0),
            readthrough_max_entries: crate::config::DEFAULT_READTHROUGH_MAX_ENTRIES_PER_KIND
                as usize,
        };
        store.index_unindexed_entries()?;
        Ok(store)
    }

    /// Entries per read-through kind; below 1 is raised to 1.
    pub fn set_readthrough_max_entries(&mut self, max: usize) {
        self.readthrough_max_entries = max.max(1);
    }

    /// Number of indexed entries of one read-through kind.
    pub fn readthrough_count(&self, kind: &str) -> u64 {
        self.db
            .get_pinned(fifo_count_key(kind))
            .ok()
            .flatten()
            .and_then(|v| be_u64(&v))
            .unwrap_or(0)
    }

    fn lock_fifo(&self) -> MutexGuard<'_, u64> {
        self.fifo_lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A kind without a count row predates the index: index what is on disk,
    /// oldest `fetched_at` first. A kind with nothing on disk stays unwritten.
    fn index_unindexed_entries(&self) -> Result<(), String> {
        #[derive(Deserialize)]
        struct Stamp {
            #[serde(default)]
            fetched_at: u64,
        }
        for kind in BOUNDED_KINDS {
            let has_count = self.db.get_pinned(fifo_count_key(kind)).map_err(|e| e.to_string())?;
            if has_count.is_some() {
                continue;
            }
            let mut entries: Vec<(u64, Vec<u8>)> = Vec::new();
            for (key, value) in self.scan_prefix(kind) {
                let fetched_at =
                    serde_json::from_slice::<Stamp>(&value).map_or(0, |s| s.fetched_at);
                entries.push((fetched_at, key.into_bytes()));
            }
            if entries.is_empty() {
                continue;
            }
            entries.sort();
            let mut batch = WriteBatch::default();
            for (i, (fetched_at, key)) in entries.iter().enumerate() {
                let written_at = fetched_at.saturating_mul(1_000_000).saturating_add(i as u64);
                batch.put(fifo_order_key(kind, written_at, key), []);
                batch.put(fifo_pos_key(key), written_at.to_be_bytes());
            }
            batch.put(fifo_count_key(kind), (entries.len() as u64).to_be_bytes());
            self.db.write(batch).map_err(|e| format!("index {kind} entries: {e}"))?;
        }
        Ok(())
    }

    /// Write one read-through record and keep its kind within the cap. The
    /// insert, the index rows, the count and any evictions of the oldest-written
    /// entries are one atomic batch taken under `fifo_lock`, so concurrent
    /// inserts of different keys cannot make the count drift or evict an entry
    /// newer than the one being written. Rewriting a key replaces its index row.
    fn put_bounded<T: Serialize>(
        &self,
        kind: &'static str,
        entry_key: &str,
        val: &T,
    ) -> Result<(), PccsError> {
        let bytes = serde_json::to_vec(val).map_err(|_| error::INTERNAL_ERROR)?;
        let mut last = self.lock_fifo();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        let written_at = now.max(last.saturating_add(1));
        *last = written_at;

        let entry = entry_key.as_bytes();
        let pos_key = fifo_pos_key(entry);
        let mut count = self.readthrough_count(kind);
        let mut batch = WriteBatch::default();
        match self.db.get_pinned(&pos_key).map_err(|_| error::INTERNAL_ERROR)? {
            Some(old) => {
                if let Some(old) = be_u64(&old) {
                    batch.delete(fifo_order_key(kind, old, entry));
                }
            }
            None => count += 1,
        }
        batch.put(entry, bytes);
        batch.put(&pos_key, written_at.to_be_bytes());
        batch.put(fifo_order_key(kind, written_at, entry), []);

        let max = self.readthrough_max_entries as u64;
        if count > max {
            let mut excess = count - max;
            let prefix = fifo_order_prefix(kind);
            let iter = self.db.iterator(IteratorMode::From(&prefix, Direction::Forward));
            for item in iter {
                let (order_key, _) = item.map_err(|_| error::INTERNAL_ERROR)?;
                if excess == 0 || !order_key.starts_with(&prefix) {
                    break;
                }
                let Some(victim) = order_key.get(prefix.len() + 8..) else { continue };
                // The superseded row of the key being rewritten is already in
                // the batch; this write is the newest and never a victim.
                if victim == entry {
                    continue;
                }
                batch.delete(victim);
                batch.delete(fifo_pos_key(victim));
                batch.delete(&order_key);
                excess -= 1;
                count -= 1;
            }
        }
        batch.put(fifo_count_key(kind), count.to_be_bytes());
        self.write_batch(batch)
    }

    /// Queue the removal of `entry_key`'s index rows. Returns whether it had any.
    fn unindex(&self, batch: &mut WriteBatch, kind: &str, entry_key: &[u8]) -> bool {
        let pos_key = fifo_pos_key(entry_key);
        let Ok(Some(pos)) = self.db.get_pinned(&pos_key) else { return false };
        if let Some(written_at) = be_u64(&pos) {
            batch.delete(fifo_order_key(kind, written_at, entry_key));
        }
        batch.delete(pos_key);
        true
    }

    pub fn record_lookup(&self, kind: Kind, result: CacheResult) {
        self.metrics.cache_lookup(kind, result);
    }

    pub fn record_hit(&self, kind: Kind) {
        self.record_lookup(kind, CacheResult::Hit);
    }

    pub fn record_miss(&self, kind: Kind) {
        self.record_lookup(kind, CacheResult::Miss);
    }

    /// Lightweight health check: returns `true` if the DB is usable, `false`
    /// otherwise. Used by the `/healthz/ready` probe. Cheap enough to run on
    /// every readiness check (sub-millisecond on a healthy DB).
    pub fn is_healthy(&self) -> bool {
        self.db.property_value("rocksdb.estimate-num-keys").is_ok()
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        // `get_pinned` reads straight out of the block cache instead of
        // allocating a `Vec<u8>` copy per lookup.
        let v = self.db.get_pinned(key.as_bytes()).ok().flatten()?;
        serde_json::from_slice(&v).ok()
    }

    /// Time individual response reads, not scans or FIFO/index bookkeeping.
    fn read_json<T: for<'de> Deserialize<'de>>(&self, kind: Kind, key: &str) -> Option<T> {
        let start = Instant::now();
        let value = self.db.get_pinned(key.as_bytes());
        let elapsed = start.elapsed();
        self.metrics.store_read(kind, elapsed);
        serde_json::from_slice(&value.ok().flatten()?).ok()
    }

    fn put_json<T: Serialize>(&self, key: &str, val: &T) -> Result<(), PccsError> {
        let bytes = serde_json::to_vec(val).map_err(|_| error::INTERNAL_ERROR)?;
        self.db.put(key.as_bytes(), bytes).map_err(|_| error::INTERNAL_ERROR)
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), PccsError> {
        self.db.write(batch).map_err(|_| error::INTERNAL_ERROR)
    }

    fn scan_prefix(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let iter = self.db.iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward));
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
        let rec: PckCertRecord =
            self.read_json(Kind::Pckcert, &keys::pckcert(qeid, pceid, cpusvn, pcesvn))?;
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
        self.put_json(&keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn), rec)
    }

    // ---------- platform pool ----------

    /// Node `platformsDao.getPlatform` — one row, one `DB::get`.
    pub fn get_platform_pool(&self, qeid: &str, pceid: &str) -> Option<PlatformPool> {
        let pool: PlatformPool = self.read_json(Kind::Pckcert, &keys::platform(qeid, pceid))?;
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

    /// Re-read the current pool under `platform_lock`, compute a selection,
    /// and optionally publish its GET key and raw mapping in one atomic batch.
    /// The closure is computation only: it must not mutate the store or re-enter
    /// platform methods. `persist = false` returns an untracked response only.
    pub fn select_platform_cert<F>(
        &self,
        qeid: &str,
        pceid: &str,
        persist: bool,
        select: F,
    ) -> Result<PckCertRecord, PccsError>
    where
        F: FnOnce(&PlatformPool) -> Result<PckCertRecord, PccsError>,
    {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut pool = self.get_platform_pool(qeid, pceid).ok_or(error::NO_CACHE_DATA)?;
        let rec = select(&pool)?;
        if persist {
            let raw = RawTcb {
                cpu_svn: rec.cpusvn.to_ascii_uppercase(),
                pce_svn: rec.pcesvn.to_ascii_uppercase(),
                tcbm: rec.tcbm.to_ascii_uppercase(),
            };
            match pool.raw_tcbs.iter_mut().find(|r| {
                r.cpu_svn.eq_ignore_ascii_case(&raw.cpu_svn)
                    && r.pce_svn.eq_ignore_ascii_case(&raw.pce_svn)
            }) {
                Some(existing) => *existing = raw,
                None => pool.raw_tcbs.push(raw),
            }
            let mut batch = WriteBatch::default();
            Self::batch_pckcert(&mut batch, &rec)?;
            batch.put(
                keys::platform(qeid, pceid).as_bytes(),
                serde_json::to_vec(&pool).map_err(|_| error::INTERNAL_ERROR)?,
            );
            self.write_batch(batch)?;
        }
        Ok(rec)
    }

    /// Replace the pool, staged TCB collateral and tracked GET selections as
    /// one atomic batch, optionally adding a newly selected raw GET mapping.
    /// Read raw mappings only after locking; a concurrent local selection must
    /// either precede this replacement or select from the newly committed pool.
    /// All selection and serialization can fail before the batch is committed,
    /// leaving the old pool and success keys coherent. The closure must only
    /// compute a selection, never mutate/re-enter platform methods.
    pub fn replace_platform_certs_with_selection<F>(
        &self,
        fresh: &PlatformPool,
        expected: Option<&PlatformCredentials>,
        tcbs: &[TcbRecord],
        selected: Option<&PckCertRecord>,
        select: F,
    ) -> Result<(), PccsError>
    where
        F: FnMut(&PlatformPool, &RawTcb) -> Result<PckCertRecord, PccsError>,
    {
        self.replace_platform_certs_after_fetch(
            fresh,
            PlatformPublication::Observed(expected),
            tcbs,
            selected,
            select,
        )
    }

    pub(crate) fn replace_platform_certs_after_fetch<F>(
        &self,
        fresh: &PlatformPool,
        publication: PlatformPublication<'_>,
        tcbs: &[TcbRecord],
        selected: Option<&PckCertRecord>,
        mut select: F,
    ) -> Result<(), PccsError>
    where
        F: FnMut(&PlatformPool, &RawTcb) -> Result<PckCertRecord, PccsError>,
    {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.get_platform_pool(&fresh.qe_id, &fresh.pce_id);
        Self::check_platform_publication(current.as_ref(), publication)?;
        let mut merged = fresh.clone();
        merged.raw_tcbs = current.map(|p| p.raw_tcbs).unwrap_or_default();
        let mut batch = WriteBatch::default();
        for raw in &mut merged.raw_tcbs {
            let rec = select(fresh, raw)?;
            raw.tcbm = rec.tcbm.to_ascii_uppercase();
            Self::batch_pckcert(&mut batch, &rec)?;
        }
        if let Some(rec) = selected {
            let raw = RawTcb {
                cpu_svn: rec.cpusvn.to_ascii_uppercase(),
                pce_svn: rec.pcesvn.to_ascii_uppercase(),
                tcbm: rec.tcbm.to_ascii_uppercase(),
            };
            match merged.raw_tcbs.iter_mut().find(|r| {
                r.cpu_svn.eq_ignore_ascii_case(&raw.cpu_svn)
                    && r.pce_svn.eq_ignore_ascii_case(&raw.pce_svn)
            }) {
                Some(existing) => *existing = raw,
                None => merged.raw_tcbs.push(raw),
            }
            Self::batch_pckcert(&mut batch, rec)?;
        }
        for rec in tcbs {
            batch.put(
                keys::tcb(
                    keys::prod_name(rec.prod_type),
                    rec.version,
                    &rec.fmspc,
                    &rec.update_type,
                )
                .as_bytes(),
                serde_json::to_vec(rec).map_err(|_| error::INTERNAL_ERROR)?,
            );
        }
        batch.put(
            keys::platform(&merged.qe_id, &merged.pce_id).as_bytes(),
            serde_json::to_vec(&merged).map_err(|_| error::INTERNAL_ERROR)?,
        );
        self.write_batch(batch)
    }

    /// A PCCS single-cert response augments a pool; it never replaces the full
    /// inventory. Publish its cert, raw mapping and all affected GET records in
    /// one batch under the same lock as local selection and full replacement.
    pub fn merge_pckcert(
        &self,
        rec: &PckCertRecord,
        expected: Option<&PlatformCredentials>,
    ) -> Result<(), PccsError> {
        self.merge_pckcert_after_fetch(rec, PlatformPublication::Observed(expected))
    }

    pub(crate) fn merge_pckcert_after_fetch(
        &self,
        rec: &PckCertRecord,
        publication: PlatformPublication<'_>,
    ) -> Result<(), PccsError> {
        let _guard = self.platform_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.get_platform_pool(&rec.qeid, &rec.pceid);
        Self::check_platform_publication(current.as_ref(), publication)?;
        let new_platform = current.is_none();
        let mut pool = current.unwrap_or_else(|| PlatformPool {
            qe_id: rec.qeid.clone(),
            pce_id: rec.pceid.clone(),
            ..Default::default()
        });
        if (!pool.fmspc.is_empty() && !pool.fmspc.eq_ignore_ascii_case(&rec.fmspc))
            || (!pool.ca.is_empty() && !pool.ca.eq_ignore_ascii_case(&rec.ca))
        {
            tracing::warn!("PCCS single certificate conflicts with cached platform metadata");
            return Err(error::NO_CACHE_DATA);
        }
        let known_ppids: Vec<_> = pool
            .certs
            .iter()
            .filter_map(|c| crate::selection::parse_pck_cert(&c.cert).ok())
            .map(|c| c.ppid)
            .collect();
        match crate::selection::parse_pck_cert(&rec.cert) {
            Ok(cert) => {
                if known_ppids.iter().any(|ppid| !ppid.eq_ignore_ascii_case(&cert.ppid))
                    || !cert.pce_id.eq_ignore_ascii_case(&rec.pceid)
                    || !cert.fmspc.eq_ignore_ascii_case(&rec.fmspc)
                    || !cert.ca.eq_ignore_ascii_case(&rec.ca)
                {
                    tracing::warn!(
                        "PCCS single certificate conflicts with cached platform identity"
                    );
                    return Err(error::NO_CACHE_DATA);
                }
            }
            Err(_) if !known_ppids.is_empty() => {
                tracing::warn!("Unparseable PCCS certificate cannot augment a validated pool");
                return Err(error::NO_CACHE_DATA);
            }
            // Legacy opaque development seeds / unknown single-cert mirrors
            // retain their baseline transport behavior, not a trust guarantee.
            Err(_) => {}
        }
        pool.fmspc = rec.fmspc.clone();
        pool.ca = rec.ca.to_ascii_uppercase();
        pool.issuer_chain = rec.issuer_chain.clone();
        // A known PCCS upstream ignores the caller's PPID. Its response
        // therefore cannot authenticate a replacement for retained credentials.
        if new_platform {
            pool.enc_ppid = rec.encrypted_ppid.clone().unwrap_or_default();
            pool.platform_manifest = rec.platform_manifest.clone();
        }
        let cert = PlatformCert { tcbm: rec.tcbm.clone(), cert: rec.cert.clone() };
        match pool.certs.iter_mut().find(|c| c.tcbm.eq_ignore_ascii_case(&rec.tcbm)) {
            Some(existing) => *existing = cert,
            None => pool.certs.push(cert),
        }
        let mut batch = WriteBatch::default();
        for raw in &pool.raw_tcbs {
            if let Some(mut cached) =
                self.get_pckcert(&pool.qe_id, &raw.cpu_svn, &raw.pce_svn, &pool.pce_id)
            {
                cached.fmspc = pool.fmspc.clone();
                cached.ca = pool.ca.clone();
                cached.issuer_chain = pool.issuer_chain.clone();
                cached.encrypted_ppid =
                    if pool.enc_ppid.is_empty() { None } else { Some(pool.enc_ppid.clone()) };
                cached.platform_manifest = pool.platform_manifest.clone();
                if cached.tcbm.eq_ignore_ascii_case(&rec.tcbm) {
                    cached.cert = rec.cert.clone();
                }
                Self::batch_pckcert(&mut batch, &cached)?;
            }
        }
        let raw = RawTcb {
            cpu_svn: rec.cpusvn.to_ascii_uppercase(),
            pce_svn: rec.pcesvn.to_ascii_uppercase(),
            tcbm: rec.tcbm.to_ascii_uppercase(),
        };
        match pool.raw_tcbs.iter_mut().find(|r| {
            r.cpu_svn.eq_ignore_ascii_case(&raw.cpu_svn)
                && r.pce_svn.eq_ignore_ascii_case(&raw.pce_svn)
        }) {
            Some(existing) => *existing = raw,
            None => pool.raw_tcbs.push(raw),
        }
        let mut selected = rec.clone();
        selected.encrypted_ppid =
            if pool.enc_ppid.is_empty() { None } else { Some(pool.enc_ppid.clone()) };
        selected.platform_manifest = pool.platform_manifest.clone();
        Self::batch_pckcert(&mut batch, &selected)?;
        batch.put(
            keys::platform(&pool.qe_id, &pool.pce_id).as_bytes(),
            serde_json::to_vec(&pool).map_err(|_| error::INTERNAL_ERROR)?,
        );
        self.write_batch(batch)
    }

    /// Called only under platform_lock, before publication. Raw additions are
    /// not credential changes. Observed(None) remains strict for POST/refresh;
    /// AbsentGet additionally accepts a same-credential concurrent GET fill.
    fn check_platform_publication(
        current: Option<&PlatformPool>,
        publication: PlatformPublication<'_>,
    ) -> Result<(), PccsError> {
        let matches = match publication {
            PlatformPublication::Observed(expected) => {
                current.map(PlatformPool::credentials).as_ref() == expected
            }
            PlatformPublication::AbsentGet { enc_ppid, platform_manifest } => {
                current.is_none_or(|pool| {
                    pool.enc_ppid.eq_ignore_ascii_case(enc_ppid)
                        && pool.platform_manifest == platform_manifest
                })
            }
        };
        if !matches {
            tracing::warn!("Rejecting PCK response fetched under stale platform credentials");
            return Err(error::NO_CACHE_DATA);
        }
        Ok(())
    }

    fn batch_pckcert(batch: &mut WriteBatch, rec: &PckCertRecord) -> Result<(), PccsError> {
        batch.put(
            keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn).as_bytes(),
            serde_json::to_vec(rec).map_err(|_| error::INTERNAL_ERROR)?,
        );
        Ok(())
    }

    /// Hot path: existence only. Deserialising the whole pool (every cert of
    /// the platform) just to answer "is this platform known?" is pure waste on
    /// a `/pckcert` cache hit, so this stops at the raw `DB::get`.
    pub fn has_platform(&self, qeid: &str, pceid: &str) -> bool {
        let start = Instant::now();
        let value = self.db.get_pinned(keys::platform(qeid, pceid).as_bytes());
        self.metrics.store_read(Kind::Pckcert, start.elapsed());
        value.ok().flatten().is_some()
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
        let rec: TcbRecord = self.read_json(
            tcb_kind(prod_type),
            &keys::tcb(keys::prod_name(prod_type), version, fmspc, update.as_str()),
        )?;
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
            &keys::tcb(keys::prod_name(rec.prod_type), rec.version, &rec.fmspc, &rec.update_type),
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
        let rec: IdentityRecord = self.read_json(
            identity_kind(enclave_id),
            &keys::identity(keys::identity_name(enclave_id), version, update.as_str()),
        )?;
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
            &keys::identity(keys::identity_name(rec.enclave_id), rec.version, &rec.update_type),
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
        let rec: PckCrlRecord = self.read_json(Kind::Pckcrl, &keys::pckcrl(ca))?;
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
        self.read_json::<Vec<u8>>(Kind::Rootcacrl, &keys::rootcacrl())
    }

    pub fn put_rootcacrl(&self, crl: &[u8]) -> Result<(), PccsError> {
        self.put_json(&keys::rootcacrl(), &crl.to_vec())
    }

    pub fn get_crl(&self, uri: &str) -> Option<Vec<u8>> {
        self.read_json::<CrlRecord>(Kind::Crl, &keys::crl(uri)).map(|r| r.crl)
    }

    pub fn put_crl(&self, uri: &str, crl: &[u8]) -> Result<(), PccsError> {
        self.put_json(&keys::crl(uri), &CrlRecord { uri: uri.to_string(), crl: crl.to_vec() })
    }

    pub fn list_crls(&self) -> Vec<CrlRecord> {
        self.scan_prefix(keys::CRL)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn get_amd_kds(&self, url: &str) -> Option<AmdKdsRecord> {
        let rec: AmdKdsRecord = self.read_json(Kind::AmdKds, &keys::amd_kds(url))?;
        if rec.url != url {
            tracing::warn!("amd kds record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_amd_kds(&self, rec: &AmdKdsRecord) -> Result<(), PccsError> {
        self.put_bounded(keys::AMD_KDS, &keys::amd_kds(&rec.url), rec)
    }

    pub fn delete_key(&self, key: &str) -> Result<(), PccsError> {
        let Some(kind) = BOUNDED_KINDS.into_iter().find(|kind| key.starts_with(kind)) else {
            return self.db.delete(key.as_bytes()).map_err(|_| error::INTERNAL_ERROR);
        };
        let _guard = self.lock_fifo();
        let mut batch = WriteBatch::default();
        batch.delete(key.as_bytes());
        if self.unindex(&mut batch, kind, key.as_bytes()) {
            let count = self.readthrough_count(kind).saturating_sub(1);
            batch.put(fifo_count_key(kind), count.to_be_bytes());
        }
        self.write_batch(batch)
    }

    /// Delete every record under `prefix` that `expired` flags, in one batch.
    /// Only the expired keys are held in memory, never the scanned values.
    pub fn sweep_prefix<T: for<'de> Deserialize<'de>>(
        &self,
        prefix: &str,
        expired: impl Fn(&T) -> bool,
    ) -> Result<usize, PccsError> {
        // A bounded kind keeps its index and count in step with the deletes.
        let kind = BOUNDED_KINDS.into_iter().find(|kind| *kind == prefix);
        let _guard = kind.map(|_| self.lock_fifo());
        let mut batch = WriteBatch::default();
        let mut swept = 0;
        let mut unindexed = 0;
        let iter = self.db.iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        for item in iter {
            let (k, v) = item.map_err(|_| error::INTERNAL_ERROR)?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            if serde_json::from_slice::<T>(&v).is_ok_and(|rec| expired(&rec)) {
                batch.delete(&k);
                if kind.is_some_and(|kind| self.unindex(&mut batch, kind, &k)) {
                    unindexed += 1;
                }
                swept += 1;
            }
        }
        if swept > 0 {
            if let Some(kind) = kind.filter(|_| unindexed > 0) {
                let count = self.readthrough_count(kind).saturating_sub(unindexed);
                batch.put(fifo_count_key(kind), count.to_be_bytes());
            }
            self.write_batch(batch)?;
        }
        Ok(swept)
    }

    pub fn get_nvidia_rim(&self, url: &str) -> Option<AmdKdsRecord> {
        let rec: AmdKdsRecord = self.read_json(Kind::NvidiaRim, &keys::nvidia_rim(url))?;
        if rec.url != url {
            tracing::warn!("nvidia rim record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_nvidia_rim(&self, rec: &AmdKdsRecord) -> Result<(), PccsError> {
        self.put_bounded(keys::NVIDIA_RIM, &keys::nvidia_rim(&rec.url), rec)
    }

    pub fn get_nvidia_ocsp(&self, cache_key: &str) -> Option<NvidiaOcspRecord> {
        let rec: NvidiaOcspRecord =
            self.read_json(Kind::NvidiaOcsp, &keys::nvidia_ocsp(cache_key))?;
        if rec.cache_key != cache_key {
            tracing::warn!("nvidia ocsp record does not match its key; treating as a miss");
            return None;
        }
        Some(rec)
    }

    pub fn put_nvidia_ocsp(&self, rec: &NvidiaOcspRecord) -> Result<(), PccsError> {
        self.put_bounded(keys::NVIDIA_OCSP, &keys::nvidia_ocsp(&rec.cache_key), rec)
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
        self.db.delete(key.as_bytes()).map_err(|_| error::INTERNAL_ERROR)
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

        let _guard = self.appraisal_lock.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = self.appraisal_lock.lock().unwrap_or_else(|e| e.into_inner());
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
        let list: AppraisalList =
            self.get_json(&keys::appraisal(fmspc)).ok_or(error::NO_CACHE_DATA)?;
        let defaults: Vec<&str> =
            list.policies.iter().filter(|p| p.is_default).map(|p| p.policy.as_str()).collect();
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
                let issuer =
                    item.get("issuer_chain").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let hexv = item.get("pckcrl_hex").and_then(|x| x.as_str()).unwrap_or("");
                if let Ok(bytes) = hex::decode(hexv) {
                    let _ =
                        self.put_pckcrl(&PckCrlRecord { ca, pckcrl: bytes, issuer_chain: issuer });
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
                let fmspc =
                    item.get("fmspc").and_then(|x| x.as_str()).unwrap_or("").to_ascii_uppercase();
                let policy = item.get("policy").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let is_default = item.get("is_default").and_then(|x| x.as_bool()).unwrap_or(true);
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
            cert: item.get("cert").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            tcbm: upper(item, "tcbm"),
            fmspc: upper(item, "fmspc"),
            // Uppercase like every other writer, so the served
            // `SGX-PCK-Certificate-CA-Type` header is `PROCESSOR` / `PLATFORM`
            // whatever casing the seed file used.
            ca: item.get("ca").and_then(|x| x.as_str()).unwrap_or("PROCESSOR").to_ascii_uppercase(),
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
        let mut pool =
            self.get_platform_pool(&rec.qeid, &rec.pceid).unwrap_or_else(|| PlatformPool {
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
            pool.certs.push(PlatformCert { tcbm: rec.tcbm.clone(), cert: rec.cert.clone() });
        }
        let raw = RawTcb {
            cpu_svn: rec.cpusvn.clone(),
            pce_svn: rec.pcesvn.clone(),
            tcbm: rec.tcbm.clone(),
        };
        if !pool.raw_tcbs.iter().any(|r| r.cpu_svn == raw.cpu_svn && r.pce_svn == raw.pce_svn) {
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
        let mut pool = self.get_platform_pool(&qe_id, &pce_id).unwrap_or_else(|| PlatformPool {
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
            && !pool.raw_tcbs.iter().any(|r| r.cpu_svn == cpu_svn && r.pce_svn == pce_svn)
        {
            pool.raw_tcbs.push(RawTcb { cpu_svn, pce_svn, tcbm: String::new() });
        }
        let _ = self.put_platform_pool(&pool);
    }

    fn upsert_tcb_from_json(&self, item: &Value) {
        let prod = match item.get("prod_type").and_then(|x| x.as_str()).unwrap_or("sgx") {
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
        let platforms =
            body.get("platforms").and_then(|x| x.as_array()).ok_or(error::INVALID_REQ)?;
        let collaterals = body.get("collaterals").cloned().unwrap_or(Value::Null);
        let certificates = collaterals.get("certificates").cloned().unwrap_or(Value::Null);

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
                (serde_json::from_str(s).unwrap_or_else(|_| ident.clone()), s.to_string())
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
                .pointer(&format!("/{}/{ca}", crate::headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN))
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
        let pck_certs = collaterals.get("pck_certs").and_then(|x| x.as_array()).unwrap_or(&empty);
        let tcbinfos = collaterals.get("tcbinfos").and_then(|x| x.as_array()).unwrap_or(&empty);

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

            let mut pool = self.get_platform_pool(&qe_id, &pce_id).unwrap_or_else(|| {
                PlatformPool { qe_id: qe_id.clone(), pce_id: pce_id.clone(), ..Default::default() }
            });
            pool.fmspc = info.fmspc.clone();
            pool.ca = info.ca.clone();
            pool.certs = certs
                .iter()
                .map(|(tcbm, cert)| PlatformCert { tcbm: tcbm.clone(), cert: cert.clone() })
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
            let mut raw_tcbs: Vec<(String, String)> =
                pool.raw_tcbs.iter().map(|r| (r.cpu_svn.clone(), r.pce_svn.clone())).collect();
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
            batch.put(k.as_bytes(), serde_json::to_vec(&pool).map_err(|_| error::INTERNAL_ERROR)?);
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
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_ascii_uppercase()
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

/// Startup seeds are explicit only. Preserve a missing explicit path so the
/// caller reports its load failure rather than discovering another seed.
pub fn find_seed_path(explicit: Option<&Path>) -> Option<std::path::PathBuf> {
    explicit.map(Path::to_path_buf)
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

    fn kds_rec(url: &str, fetched_at: u64) -> AmdKdsRecord {
        AmdKdsRecord {
            url: url.into(),
            body: b"body".to_vec(),
            content_type: None,
            content_disposition: None,
            fetched_at,
        }
    }

    fn ocsp_rec(cache_key: &str) -> NvidiaOcspRecord {
        NvidiaOcspRecord {
            cache_key: cache_key.into(),
            body: b"ocsp".to_vec(),
            content_type: None,
            fetched_at: 1,
            expires_at: u64::MAX,
        }
    }

    fn bounded_store(max: usize) -> (TestDir, Store) {
        let (dir, mut store) = temp_store();
        store.set_readthrough_max_entries(max);
        (dir, store)
    }

    /// Entries, order-index rows and position rows of one kind, as stored.
    fn fifo_rows(store: &Store, kind: &str) -> (usize, usize, usize) {
        (
            store.scan_prefix(kind).len(),
            store.scan_prefix(&format!("fifo/{kind}")).len(),
            store.scan_prefix(&format!("fifo-pos/{kind}")).len(),
        )
    }

    #[test]
    fn readthrough_cap_evicts_the_oldest_written_entries() {
        let (_dir, store) = bounded_store(3);
        for i in 0..5 {
            store.put_amd_kds(&kds_rec(&format!("u{i}"), 1)).unwrap();
        }
        assert!(store.get_amd_kds("u0").is_none());
        assert!(store.get_amd_kds("u1").is_none());
        for i in 2..5 {
            assert!(store.get_amd_kds(&format!("u{i}")).is_some(), "u{i} must remain");
        }
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 3);
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (3, 3, 3));
    }

    #[test]
    fn readthrough_cap_applies_to_rim_and_ocsp_and_is_per_kind() {
        let (_dir, store) = bounded_store(2);
        for i in 0..3 {
            store.put_nvidia_rim(&kds_rec(&format!("r{i}"), 1)).unwrap();
            store.put_nvidia_ocsp(&ocsp_rec(&format!("o{i}"))).unwrap();
        }
        store.put_amd_kds(&kds_rec("a0", 1)).unwrap();
        assert!(store.get_nvidia_rim("r0").is_none());
        assert!(store.get_nvidia_rim("r2").is_some());
        assert!(store.get_nvidia_ocsp("o0").is_none());
        assert!(store.get_nvidia_ocsp("o2").is_some());
        // Another kind filling up never evicts this one.
        assert!(store.get_amd_kds("a0").is_some());
        for kind in [keys::NVIDIA_RIM, keys::NVIDIA_OCSP] {
            assert_eq!(store.readthrough_count(kind), 2);
            assert_eq!(fifo_rows(&store, kind), (2, 2, 2));
        }
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 1);
    }

    #[test]
    fn rewriting_a_key_does_not_add_an_index_entry_and_refreshes_its_age() {
        let (_dir, store) = bounded_store(3);
        store.put_amd_kds(&kds_rec("u0", 1)).unwrap();
        store.put_amd_kds(&kds_rec("u1", 1)).unwrap();
        store.put_amd_kds(&kds_rec("u0", 2)).unwrap();
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 2);
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (2, 2, 2));
        // u0 was rewritten after u1, so u1 is now the oldest.
        store.put_amd_kds(&kds_rec("u2", 1)).unwrap();
        store.put_amd_kds(&kds_rec("u3", 1)).unwrap();
        assert!(store.get_amd_kds("u1").is_none());
        assert!(store.get_amd_kds("u0").is_some());
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (3, 3, 3));
    }

    #[test]
    fn readthrough_count_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("pccs-rs-store-{}", uuid::Uuid::new_v4()));
        let _cleanup = TestDir(dir.clone());
        let open = || {
            let mut store =
                Store::open(&dir, CacheMode::Lazy, &RocksDbOpts::default()).expect("open");
            store.set_readthrough_max_entries(3);
            store
        };
        let store = open();
        store.put_amd_kds(&kds_rec("u0", 1)).unwrap();
        store.put_amd_kds(&kds_rec("u1", 1)).unwrap();
        drop(store);

        let store = open();
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 2);
        store.put_amd_kds(&kds_rec("u2", 1)).unwrap();
        store.put_amd_kds(&kds_rec("u3", 1)).unwrap();
        // The oldest entry was written before the restart.
        assert!(store.get_amd_kds("u0").is_none());
        assert!(store.get_amd_kds("u1").is_some());
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 3);
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (3, 3, 3));
    }

    #[test]
    fn expiry_delete_and_sweep_keep_the_count_consistent() {
        let (_dir, store) = bounded_store(3);
        for i in 0..3 {
            store.put_amd_kds(&kds_rec(&format!("u{i}"), i)).unwrap();
        }
        store.delete_key(&keys::amd_kds("u1")).unwrap();
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 2);
        // Deleting a key that is not there changes nothing.
        store.delete_key(&keys::amd_kds("missing")).unwrap();
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 2);
        let swept = store.sweep_prefix(keys::AMD_KDS, |r: &AmdKdsRecord| r.fetched_at == 0);
        assert_eq!(swept.unwrap(), 1);
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 1);
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (1, 1, 1));
        // No drift: the cap still admits exactly three entries.
        for i in 10..14 {
            store.put_amd_kds(&kds_rec(&format!("u{i}"), 1)).unwrap();
        }
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 3);
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (3, 3, 3));
    }

    #[test]
    fn concurrent_inserts_keep_the_cap_and_the_count_exact() {
        let (_dir, store) = bounded_store(10);
        let store = std::sync::Arc::new(store);
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        store.put_nvidia_ocsp(&ocsp_rec(&format!("t{t}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(store.readthrough_count(keys::NVIDIA_OCSP), 10);
        assert_eq!(fifo_rows(&store, keys::NVIDIA_OCSP), (10, 10, 10));
    }

    #[test]
    fn entries_written_before_the_index_existed_are_indexed_on_open() {
        let dir = std::env::temp_dir().join(format!("pccs-rs-store-{}", uuid::Uuid::new_v4()));
        let _cleanup = TestDir(dir.clone());
        let store = Store::open(&dir, CacheMode::Lazy, &RocksDbOpts::default()).unwrap();
        for (url, fetched_at) in [("u30", 30), ("u10", 10), ("u40", 40), ("u20", 20)] {
            store.put_json(&keys::amd_kds(url), &kds_rec(url, fetched_at)).unwrap();
        }
        drop(store);

        let mut store = Store::open(&dir, CacheMode::Lazy, &RocksDbOpts::default()).unwrap();
        store.set_readthrough_max_entries(3);
        assert_eq!(store.readthrough_count(keys::AMD_KDS), 4);
        store.put_amd_kds(&kds_rec("new", 50)).unwrap();
        // Oldest by fetched_at go first.
        assert!(store.get_amd_kds("u10").is_none());
        assert!(store.get_amd_kds("u20").is_none());
        for url in ["u30", "u40", "new"] {
            assert!(store.get_amd_kds(url).is_some(), "{url} must remain");
        }
        assert_eq!(fifo_rows(&store, keys::AMD_KDS), (3, 3, 3));
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

    /// Removes the RocksDB directory once the store is dropped.
    struct TestDir(std::path::PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Bind as `let (_dir, s) = temp_store();` — locals drop in reverse
    /// declaration order, so the store closes before the directory is removed.
    fn temp_store() -> (TestDir, Store) {
        let dir = std::env::temp_dir().join(format!("pccs-rs-store-{}", uuid::Uuid::new_v4()));
        let store =
            Store::open(&dir, CacheMode::Lazy, &RocksDbOpts::default()).expect("temp store");
        (TestDir(dir), store)
    }

    fn pckcert_rec(qeid: &str) -> PckCertRecord {
        PckCertRecord {
            qeid: qeid.into(),
            pceid: "0001".into(),
            cpusvn: "AB".repeat(16),
            pcesvn: "00FF".into(),
            cert: "pem".into(),
            tcbm: "tcbm".into(),
            fmspc: "00906EA10000".into(),
            ca: "PROCESSOR".into(),
            issuer_chain: "chain".into(),
            encrypted_ppid: None,
            platform_manifest: String::new(),
        }
    }

    #[test]
    fn hot_reads_record_store_duration_but_scans_do_not() {
        let (_dir, s) = temp_store();
        assert!(s.get_pckcrl("PROCESSOR").is_none());
        s.put_pckcrl(&PckCrlRecord {
            ca: "PROCESSOR".into(),
            pckcrl: vec![1, 2],
            issuer_chain: "chain".into(),
        })
        .unwrap();
        assert!(s.get_pckcrl("PROCESSOR").is_some());
        assert_eq!(s.list_pckcrls().len(), 1);
        let rendered = s.metrics.render();
        assert!(
            rendered.contains("pccs_store_read_duration_seconds_count{kind=\"pckcrl\"} 2"),
            "{rendered}"
        );
    }

    #[test]
    fn pckcert_round_trip_and_key_mismatch_is_a_miss() {
        let (_dir, s) = temp_store();
        let rec = pckcert_rec("QEID1");
        s.put_pckcert(&rec).unwrap();
        // Case-insensitive on every field, like Node's SQL.
        let got = s.get_pckcert("qeid1", &"ab".repeat(16), "00ff", "0001").unwrap();
        assert_eq!(got.qeid, "QEID1");
        // A different raw TCB is a different key.
        assert!(s.get_pckcert("QEID1", &"CD".repeat(16), "00FF", "0001").is_none());

        // A record stored under a key it does not match reads as a miss, never
        // as another platform's certificate.
        let other = pckcert_rec("QEID2");
        let key = keys::pckcert("QEID3", "0001", &"AB".repeat(16), "00FF");
        s.put_json(&key, &other).unwrap();
        assert!(s.get_pckcert("QEID3", &"AB".repeat(16), "00FF", "0001").is_none());
    }

    #[test]
    fn platform_pool_lifecycle() {
        let (_dir, s) = temp_store();
        assert!(!s.has_platform("QE", "0001"));
        assert!(s.get_platform_pool("QE", "0001").is_none());
        // upsert / remove on an unknown platform are no-ops, not errors.
        s.upsert_raw_tcb("QE", "0001", "AA", "BB", "TM").unwrap();
        s.remove_raw_tcb("QE", "0001", "AA", "BB").unwrap();

        let mut pool = PlatformPool {
            qe_id: "QE".into(),
            pce_id: "0001".into(),
            fmspc: "00906EA10000".into(),
            ..Default::default()
        };
        pool.raw_tcbs.push(RawTcb {
            cpu_svn: "AA".into(),
            pce_svn: "BB".into(),
            tcbm: "TM1".into(),
        });
        s.put_platform_pool(&pool).unwrap();
        assert!(s.has_platform("qe", "0001"));
        assert_eq!(s.list_platform_pools().len(), 1);

        // upsert appends a new level and updates an existing one in place.
        s.upsert_raw_tcb("QE", "0001", "cc", "dd", "tm2").unwrap();
        s.upsert_raw_tcb("QE", "0001", "AA", "BB", "TM3").unwrap();
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.raw_tcbs.len(), 2);
        assert_eq!(pool.raw_tcbs[0].tcbm, "TM3");
        assert_eq!(pool.raw_tcbs[1].tcbm, "TM2");
        assert_eq!(pool.cert_pairs(), Vec::<(String, String)>::new());

        // replace_platform_certs carries the known raw TCBs forward and
        // returns them for re-selection.
        let fresh = PlatformPool {
            qe_id: "QE".into(),
            pce_id: "0001".into(),
            certs: vec![PlatformCert { tcbm: "T".into(), cert: "C".into() }],
            ..Default::default()
        };
        let previous = s.replace_platform_certs(&fresh).unwrap();
        assert_eq!(previous.len(), 2);
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.raw_tcbs.len(), 2, "raw TCBs must survive a cert refresh");
        assert_eq!(pool.cert_pairs(), vec![("T".to_string(), "C".to_string())]);

        s.remove_raw_tcb("QE", "0001", "aa", "bb").unwrap();
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.raw_tcbs.len(), 1);
        assert_eq!(pool.raw_tcbs[0].cpu_svn, "CC");

        // A record stored under a key it does not match reads as a miss.
        let key = keys::platform("QEX", "0001");
        s.put_json(&key, &pool).unwrap();
        assert!(s.get_platform_pool("QEX", "0001").is_none());
    }

    #[test]
    fn cached_platforms_by_fmspc_filters_and_expands_raw_tcbs() {
        let (_dir, s) = temp_store();
        let pool = PlatformPool {
            qe_id: "QE".into(),
            pce_id: "0001".into(),
            enc_ppid: "PP".into(),
            fmspc: "00906EA10000".into(),
            raw_tcbs: vec![
                RawTcb { cpu_svn: "A".into(), pce_svn: "B".into(), tcbm: String::new() },
                RawTcb { cpu_svn: "C".into(), pce_svn: "D".into(), tcbm: String::new() },
            ],
            ..Default::default()
        };
        s.put_platform_pool(&pool).unwrap();

        // One row per known raw TCB.
        let all = s.cached_platforms_by_fmspc(&[]);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].qe_id, "QE");
        // Filtered by fmspc, case-insensitively.
        let hit = s.cached_platforms_by_fmspc(&["00906ea10000".to_string()]);
        assert_eq!(hit.len(), 2);
        assert!(s.cached_platforms_by_fmspc(&["FFFFFFFFFFFF".to_string()]).is_empty());
    }

    fn tcb_rec(version: u32, update: &str) -> TcbRecord {
        TcbRecord {
            prod_type: 0,
            fmspc: "00906EA10000".into(),
            version,
            update_type: update.into(),
            tcbinfo: serde_json::json!({"id": "SGX"}),
            raw_body: String::new(),
            issuer_chain: "chain".into(),
        }
    }

    #[test]
    fn tcb_identity_crl_round_trips_and_mismatches() {
        let (_dir, s) = temp_store();
        s.put_tcb(&tcb_rec(4, "STANDARD")).unwrap();
        assert!(s.get_tcb(0, "00906ea10000", 4, UpdateType::Standard).is_some());
        // Version / update / prod type are part of the identity of a record.
        assert!(s.get_tcb(0, "00906EA10000", 3, UpdateType::Standard).is_none());
        assert!(s.get_tcb(0, "00906EA10000", 4, UpdateType::Early).is_none());
        assert!(s.get_tcb(1, "00906EA10000", 4, UpdateType::Standard).is_none());
        assert_eq!(s.list_tcbs().len(), 1);
        // Tampered record under a foreign key is a miss.
        let key = keys::tcb("sgx", 4, "FFFFFFFFFFFF", "STANDARD");
        s.put_json(&key, &tcb_rec(4, "STANDARD")).unwrap();
        assert!(s.get_tcb(0, "FFFFFFFFFFFF", 4, UpdateType::Standard).is_none());

        let id = IdentityRecord {
            enclave_id: 1,
            version: 4,
            update_type: "STANDARD".into(),
            identity: serde_json::json!({"id": "QE"}),
            raw_body: String::new(),
            issuer_chain: "chain".into(),
        };
        s.put_identity(&id).unwrap();
        assert!(s.get_identity(1, 4, UpdateType::Standard).is_some());
        assert!(s.get_identity(2, 4, UpdateType::Standard).is_none());
        assert_eq!(s.list_identities().len(), 1);
        let key = keys::identity("qe", 3, "STANDARD");
        s.put_json(&key, &id).unwrap();
        assert!(s.get_identity(1, 3, UpdateType::Standard).is_none());

        let crl = PckCrlRecord {
            ca: "PROCESSOR".into(),
            pckcrl: vec![1, 2, 3],
            issuer_chain: "chain".into(),
        };
        s.put_pckcrl(&crl).unwrap();
        assert_eq!(s.get_pckcrl("processor").unwrap().pckcrl, vec![1, 2, 3]);
        assert!(s.get_pckcrl("PLATFORM").is_none());
        assert_eq!(s.list_pckcrls().len(), 1);
        let key = keys::pckcrl("PLATFORM");
        s.put_json(&key, &crl).unwrap();
        assert!(s.get_pckcrl("PLATFORM").is_none(), "ca mismatch reads as a miss");

        s.put_rootcacrl(&[9, 9]).unwrap();
        assert_eq!(s.get_rootcacrl().unwrap(), vec![9, 9]);

        s.put_crl("https://example/x.crl", &[7]).unwrap();
        assert_eq!(s.get_crl("https://example/x.crl").unwrap(), vec![7]);
        assert!(s.get_crl("https://example/other.crl").is_none());
        assert_eq!(s.list_crls().len(), 1);
    }

    fn reg(qe: &str, state: u8) -> RegisteredPlatform {
        RegisteredPlatform {
            qe_id: qe.into(),
            pce_id: "0001".into(),
            cpu_svn: "AA".into(),
            pce_svn: "BB".into(),
            enc_ppid: "PP".into(),
            platform_manifest: String::new(),
            state,
        }
    }

    #[test]
    fn registration_queue_normalises_takes_and_deletes() {
        let (_dir, s) = temp_store();
        s.register_platform(reg("qe-lowercase", 0)).unwrap();
        s.register_platform(reg("QE2", 1)).unwrap();

        // take_registered(state) returns only that state's rows, uppercased,
        // and removes them from the queue.
        let new = s.take_registered(0).unwrap();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].qe_id, "QE-LOWERCASE");
        assert!(s.take_registered(0).unwrap().is_empty());
        let na = s.take_registered(1).unwrap();
        assert_eq!(na.len(), 1);
        assert_eq!(na[0].qe_id, "QE2");

        // delete_registered removes exactly one row, case-insensitively.
        s.register_platform(reg("QE3", 0)).unwrap();
        s.register_platform(reg("QE4", 0)).unwrap();
        s.delete_registered(&reg("qe3", 0)).unwrap();
        let rest = s.take_registered(0).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].qe_id, "QE4");
    }

    #[test]
    fn appraisal_defaults_join_and_404_when_absent() {
        let (_dir, s) = temp_store();
        assert!(s.get_default_policies("ABCDABCDABCD").is_err());
        // No default policy for the fmspc is also a 404.
        s.upsert_appraisal_policy_raw("ABCDABCDABCD", "p.nondefault", false);
        assert!(s.get_default_policies("ABCDABCDABCD").is_err());

        s.upsert_appraisal_policy_raw("ABCDABCDABCD", "p.first", true);
        assert_eq!(s.get_default_policies("abcdabcdabcd").unwrap(), "p.first");
        // A second default clears the first.
        s.upsert_appraisal_policy_raw("ABCDABCDABCD", "p.second", true);
        assert_eq!(s.get_default_policies("ABCDABCDABCD").unwrap(), "p.second");
        // Re-upserting the same policy does not duplicate it.
        s.upsert_appraisal_policy_raw("ABCDABCDABCD", "p.second", true);
        let list: AppraisalList = s.get_json(&keys::appraisal("ABCDABCDABCD")).unwrap();
        assert_eq!(list.policies.len(), 3, "nondefault + first + second");
    }

    #[test]
    fn seed_value_loads_every_section() {
        let (_dir, s) = temp_store();
        s.load_seed_value(&serde_json::json!({
            "tcbinfo": [{
                "prod_type": "tdx", "fmspc": "00a067110000", "version": 4,
                "update_type": "early", "issuer_chain": "c",
                "tcbinfo": {"id": "TDX"}
            }],
            "identities": [{
                "enclave_id": 2, "version": 4, "update_type": "early",
                "issuer_chain": "c", "identity": {"id": "QVE"}
            }],
            "pckcrls": [{ "ca": "platform", "issuer_chain": "c", "pckcrl_hex": "0a0b" }],
            "rootcacrl_hex": "0c0d",
            "crls": [{ "uri": "https://example/x.crl", "crl_hex": "0e" }],
            "appraisal_policies": [
                { "fmspc": "abcdabcdabcd", "policy": "p.a", "is_default": true },
                { "fmspc": "", "policy": "p.skip" }
            ]
        }));
        assert!(s.get_tcb(1, "00A067110000", 4, UpdateType::Early).is_some());
        assert!(s.get_identity(2, 4, UpdateType::Early).is_some());
        assert_eq!(s.get_pckcrl("PLATFORM").unwrap().pckcrl, vec![0x0a, 0x0b]);
        assert_eq!(s.get_rootcacrl().unwrap(), vec![0x0c, 0x0d]);
        assert_eq!(s.get_crl("https://example/x.crl").unwrap(), vec![0x0e]);
        assert_eq!(s.get_default_policies("ABCDABCDABCD").unwrap(), "p.a");
    }

    #[test]
    fn seed_platform_merges_without_overwriting_cert_fields() {
        let (_dir, s) = temp_store();
        // A seeded cert establishes the pool first…
        s.load_seed_value(&serde_json::json!({
            "pckcerts": [{
                "qe_id": "QE", "pce_id": "0001",
                "cpusvn": "AB".repeat(16), "pcesvn": "00FF",
                "cert": "pem", "tcbm": "TM", "fmspc": "00906EA10000",
                "ca": "processor", "issuer_chain": "c", "enc_ppid": "PP"
            }]
        }));
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.enc_ppid, "PP");
        assert_eq!(pool.certs.len(), 1);
        assert_eq!(pool.raw_tcbs.len(), 1);

        // …and a later platforms[] row only fills blanks / adds raw levels.
        s.load_seed_value(&serde_json::json!({
            "platforms": [{
                "qe_id": "QE", "pce_id": "0001", "enc_ppid": "OTHER",
                "fmspc": "FFFFFFFFFFFF",
                "cpu_svn": "CD".repeat(16), "pce_svn": "00FE"
            }, {
                // Missing pce_id: skipped.
                "qe_id": "QE2"
            }]
        }));
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.enc_ppid, "PP", "cert-established fields win");
        assert_eq!(pool.fmspc, "00906EA10000");
        assert_eq!(pool.raw_tcbs.len(), 2);
        assert!(s.get_platform_pool("QE2", "").is_none());

        // Seeding the same cert twice does not duplicate pool entries.
        s.load_seed_value(&serde_json::json!({
            "pckcerts": [{
                "qeid": "QE", "pceid": "0001",
                "cpusvn": "AB".repeat(16), "pcesvn": "00FF",
                "cert": "pem", "tcbm": "TM", "fmspc": "00906EA10000"
            }]
        }));
        let pool = s.get_platform_pool("QE", "0001").unwrap();
        assert_eq!(pool.certs.len(), 1);
        // The alternate key spelling (qeid/pceid) is accepted.
        assert!(s.get_pckcert("QE", &"AB".repeat(16), "00FF", "0001").is_some());
    }

    /// A synthetic PCK certificate (Platform CA) matching the TCB below.
    const PCK_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIICPDCCAjOgAwIBAgIBATAKBggqhkjOPQQDAjAkMSIwIAYDVQQDDBlJbnRlbCBT\nR1ggUENLIFBsYXRmb3JtIENBMAAwJDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBD\nZXJ0aWZpY2F0ZTAAo4IByzCCAccwggHDBgkqhkiG+E0BDQEEggG0MIIBsDAeBgoq\nhkiG+E0BDQEBBBARERERERERERERERERERERMBAGCiqGSIb4TQENAQMEAkREMBQG\nCiqGSIb4TQENAQQEBhI0VniQqzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4\nTQENAQIBAgEiMBAGCyqGSIb4TQENAQICAgEiMBAGCyqGSIb4TQENAQIDAgEiMBAG\nCyqGSIb4TQENAQIEAgEiMBAGCyqGSIb4TQENAQIFAgEiMBAGCyqGSIb4TQENAQIG\nAgEiMBAGCyqGSIb4TQENAQIHAgEiMBAGCyqGSIb4TQENAQIIAgEiMBAGCyqGSIb4\nTQENAQIJAgEiMBAGCyqGSIb4TQENAQIKAgEiMBAGCyqGSIb4TQENAQILAgEiMBAG\nCyqGSIb4TQENAQIMAgEiMBAGCyqGSIb4TQENAQINAgEiMBAGCyqGSIb4TQENAQIO\nAgEiMBAGCyqGSIb4TQENAQIPAgEiMBAGCyqGSIb4TQENAQIQAgEiMBEGCyqGSIb4\nTQENAQIRAgIzMzAfBgsqhkiG+E0BDQECEgQQIiIiIiIiIiIiIiIiIiIiIjAAAwEA\n-----END CERTIFICATE-----\n";
    const CPUSVN: &str = "22222222222222222222222222222222";
    const PCESVN: &str = "3333";
    const PCEID: &str = "4444";
    const FMSPC: &str = "1234567890AB";

    fn tcb_info_json() -> serde_json::Value {
        let comps: Vec<serde_json::Value> =
            (0..16).map(|_| serde_json::json!({ "svn": 0x22 })).collect();
        serde_json::json!({
            "id": "SGX", "fmspc": FMSPC, "pceId": PCEID, "tcbType": 0,
            "tcbLevels": [{
                "tcb": { "sgxtcbcomponents": comps, "pcesvn": 0x3333 },
                "tcbStatus": "UpToDate"
            }]
        })
    }

    #[test]
    fn put_platform_collateral_v3_stores_every_collateral_kind() {
        let (_dir, s) = temp_store();
        let qeid = "33333333333333333333333333333333";
        let body = serde_json::json!({
            "platforms": [{
                "qe_id": qeid, "pce_id": PCEID,
                "cpu_svn": CPUSVN, "pce_svn": PCESVN, "enc_ppid": "E".repeat(768)
            }],
            "collaterals": {
                "pck_certs": [{
                    "qe_id": qeid, "pce_id": PCEID, "enc_ppid": "E".repeat(768),
                    "certs": [{
                        "tcb": { "pcesvn": 0x3333 },
                        "tcbm": format!("{CPUSVN}{PCESVN}"),
                        "cert": PCK_PEM
                    }]
                }],
                "tcbinfos": [{
                    "fmspc": FMSPC,
                    "tcbinfo": { "tcbInfo": tcb_info_json(), "signature": "v3-std" },
                    "tcbinfo_early": { "tcbInfo": tcb_info_json(), "signature": "v3-early" }
                }],
                "qeidentity": "{\"enclaveIdentity\":{\"id\":\"QE\"}}",
                "qveidentity": { "enclaveIdentity": { "id": "QVE" } },
                "pckcacrl": { "processorCrl": "0a0b", "platformCrl": "0c" },
                "rootcacrl": "0d0e",
                "rootcacrl_cdp": "https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl",
                "certificates": {
                    "SGX-PCK-Certificate-Issuer-Chain": { "PLATFORM": "pck-chain" },
                    "SGX-TCB-Info-Issuer-Chain": "tcb-chain",
                    "SGX-Enclave-Identity-Issuer-Chain": "id-chain"
                }
            }
        });
        s.put_platform_collateral(&body, 3).unwrap();

        // v3 TCB field names land as STANDARD / EARLY v3 records.
        let rec = s.get_tcb(0, FMSPC, 3, UpdateType::Standard).unwrap();
        assert_eq!(rec.issuer_chain, "tcb-chain");
        assert!(rec.raw_body.contains("v3-std"));
        assert!(s.get_tcb(0, FMSPC, 3, UpdateType::Early).is_some());
        assert!(s.get_tcb(0, FMSPC, 4, UpdateType::Standard).is_none());

        // Identities: string form and object form both stored, v3.
        let qe = s.get_identity(1, 3, UpdateType::Standard).unwrap();
        assert_eq!(qe.identity["enclaveIdentity"]["id"], "QE");
        assert_eq!(qe.issuer_chain, "id-chain");
        assert!(s.get_identity(2, 3, UpdateType::Standard).is_some());

        // CRLs: per-CA chains, and the CDP copy of the root CA CRL.
        assert_eq!(s.get_pckcrl("PROCESSOR").unwrap().pckcrl, vec![0x0a, 0x0b]);
        let platform = s.get_pckcrl("PLATFORM").unwrap();
        assert_eq!(platform.pckcrl, vec![0x0c]);
        assert_eq!(platform.issuer_chain, "pck-chain");
        assert_eq!(s.get_rootcacrl().unwrap(), vec![0x0d, 0x0e]);
        assert_eq!(
            s.get_crl("https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl").unwrap(),
            vec![0x0d, 0x0e]
        );

        // The cert was selected for the platform's raw TCB.
        let rec = s.get_pckcert(qeid, CPUSVN, PCESVN, PCEID).unwrap();
        assert_eq!(rec.ca, "PLATFORM");
        assert_eq!(rec.issuer_chain, "pck-chain");
        let pool = s.get_platform_pool(qeid, PCEID).unwrap();
        assert_eq!(pool.raw_tcbs.len(), 1);
        assert_eq!(pool.enc_ppid, "E".repeat(768));
    }

    #[test]
    fn put_platform_collateral_rejects_broken_inputs() {
        let (_dir, s) = temp_store();
        let base = serde_json::json!({
            "platforms": [{
                "qe_id": "QE", "pce_id": PCEID,
                "cpu_svn": CPUSVN, "pce_svn": PCESVN, "enc_ppid": "E".repeat(768)
            }],
            "collaterals": {
                "version": 4,
                "pck_certs": [{
                    "qe_id": "QE", "pce_id": PCEID, "enc_ppid": "E".repeat(768),
                    "certs": [{
                        "tcb": { "pcesvn": 0x3333 },
                        "tcbm": format!("{CPUSVN}{PCESVN}"),
                        "cert": PCK_PEM
                    }]
                }],
                "tcbinfos": [{
                    "fmspc": FMSPC,
                    "sgx_tcbinfo": { "tcbInfo": tcb_info_json(), "signature": "s" }
                }],
                "certificates": {
                    "SGX-PCK-Certificate-Issuer-Chain": { "PLATFORM": "c" }
                }
            }
        });

        // An empty certs array passes the schema but is rejected here.
        let mut bad = base.clone();
        bad["collaterals"]["pck_certs"][0]["certs"] = serde_json::json!([]);
        assert!(s.put_platform_collateral(&bad, 4).is_err());

        // An unparsable certificate is a 400, never a field fallback.
        let mut bad = base.clone();
        bad["collaterals"]["pck_certs"][0]["certs"][0]["cert"] =
            serde_json::json!("not a certificate");
        assert!(s.put_platform_collateral(&bad, 4).is_err());

        // No TCB info for the cert's fmspc.
        let mut bad = base.clone();
        bad["collaterals"]["tcbinfos"][0]["fmspc"] = serde_json::json!("FFFFFFFFFFFF");
        assert!(s.put_platform_collateral(&bad, 4).is_err());

        // A raw TCB below every cert fails selection.
        let mut bad = base.clone();
        bad["platforms"][0]["cpu_svn"] = serde_json::json!("11".repeat(16));
        bad["platforms"][0]["pce_svn"] = serde_json::json!("1100");
        assert!(s.put_platform_collateral(&bad, 4).is_err());

        // The happy path stores the pool.
        s.put_platform_collateral(&base, 4).unwrap();
        assert!(s.has_platform("QE", PCEID));
    }

    #[test]
    fn sha384_hex_matches_known_vector() {
        assert_eq!(
            sha384_hex(""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(sha384_hex("abc").len(), 96);
    }

    #[test]
    fn first_str_supports_dotted_pointers() {
        let v = serde_json::json!({
            "flat": "f",
            "nested": { "inner": "n" }
        });
        assert_eq!(first_str(&v, &["flat"]).as_deref(), Some("f"));
        assert_eq!(first_str(&v, &["nested.inner"]).as_deref(), Some("n"));
        assert_eq!(first_str(&v, &["missing", "flat"]).as_deref(), Some("f"));
        assert_eq!(first_str(&v, &["missing"]), None);
    }

    #[test]
    fn find_seed_path_never_discovers_a_fallback() {
        assert_eq!(find_seed_path(None), None);
        let missing = std::path::Path::new("/definitely/not/here.json");
        assert_eq!(find_seed_path(Some(missing)), Some(missing.to_path_buf()));
    }
}
