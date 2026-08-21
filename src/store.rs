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
    pub issuer_chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub enclave_id: u8,
    pub version: u32,
    pub update_type: String,
    pub identity: Value,
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
pub struct PlatformRecord {
    pub qe_id: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub pce_svn: String,
    pub enc_ppid: String,
    pub platform_manifest: String,
    #[serde(default)]
    pub fmspc: String,
    #[serde(default)]
    pub ca: String,
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
        let db = DB::open(&opts, path).map_err(|e| format!("rocksdb open {}: {e}", path.display()))?;
        Ok(Self {
            db,
            cache_mode,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            upstream_fetches: AtomicU64::new(0),
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
        let v = self.db.get(key.as_bytes()).ok().flatten()?;
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

    pub fn get_pckcert(
        &self,
        qeid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
    ) -> Option<PckCertRecord> {
        self.get_json(&keys::pckcert(qeid, pceid, cpusvn, pcesvn))
    }

    pub fn put_pckcert(&self, rec: &PckCertRecord) -> Result<(), PccsError> {
        self.put_json(
            &keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn),
            rec,
        )
    }

    pub fn has_platform(&self, qeid: &str, pceid: &str) -> bool {
        let q = qeid.to_ascii_uppercase();
        let p = pceid.to_ascii_uppercase();
        self.list_pckcerts()
            .into_iter()
            .any(|r| r.qeid == q && r.pceid == p)
    }

    pub fn list_pckcerts(&self) -> Vec<PckCertRecord> {
        self.scan_prefix(keys::PCKCERT)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn cached_platforms_by_fmspc(&self, fmspcs: &[String]) -> Vec<PlatformRecord> {
        self.list_pckcerts()
            .into_iter()
            .filter(|r| fmspcs.is_empty() || fmspcs.iter().any(|f| f == &r.fmspc))
            .map(|r| PlatformRecord {
                qe_id: r.qeid,
                pce_id: r.pceid,
                cpu_svn: r.cpusvn,
                pce_svn: r.pcesvn,
                enc_ppid: r.encrypted_ppid.unwrap_or_default(),
                platform_manifest: r.platform_manifest,
                fmspc: r.fmspc,
                ca: r.ca,
            })
            .collect()
    }

    // ---------- tcb / identity / crl ----------

    pub fn get_tcb(
        &self,
        prod_type: u8,
        fmspc: &str,
        version: u32,
        update: UpdateType,
    ) -> Option<TcbRecord> {
        self.get_json(&keys::tcb(
            keys::prod_name(prod_type),
            version,
            fmspc,
            update.as_str(),
        ))
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
        self.get_json(&keys::identity(
            keys::identity_name(enclave_id),
            version,
            update.as_str(),
        ))
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
        self.get_json(&keys::pckcrl(ca))
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

    pub fn register_platform(&self, mut p: RegisteredPlatform) {
        p.qe_id = p.qe_id.to_ascii_uppercase();
        p.pce_id = p.pce_id.to_ascii_uppercase();
        p.cpu_svn = p.cpu_svn.to_ascii_uppercase();
        p.pce_svn = p.pce_svn.to_ascii_uppercase();
        p.enc_ppid = p.enc_ppid.to_ascii_uppercase();
        let key = keys::preg(&p.qe_id, &p.pce_id, &p.cpu_svn, &p.pce_svn);
        let _ = self.put_json(&key, &p);
    }

    pub fn take_registered(&self, state: u8) -> Vec<RegisteredPlatform> {
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
        let _ = self.write_batch(batch);
        take
    }

    // ---------- appraisal ----------

    pub fn put_appraisal_policy(&self, body: &Value) -> Result<String, PccsError> {
        let is_default = body.get("is_default").and_then(|x| x.as_bool());
        let fmspc = body.get("fmspc").and_then(|x| x.as_str());
        let policy = body.get("policy").and_then(|x| x.as_str());
        let (Some(is_default), Some(fmspc), Some(policy)) = (is_default, fmspc, policy) else {
            return Err(error::INVALID_REQ);
        };
        let fmspc = crate::validate::fmspc(Some(fmspc))?;
        if policy.is_empty() {
            return Err(error::INVALID_REQ);
        }
        let id = sha384_hex(policy);
        let key = keys::appraisal(&fmspc);
        let mut list: AppraisalList = self.get_json(&key).unwrap_or_default();
        list.policies.push(AppraisalPolicy {
            id: id.clone(),
            fmspc,
            is_default,
            policy: policy.to_string(),
        });
        self.put_json(&key, &list)?;
        Ok(id)
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
                let hexv = item.get("pckcrl_hex").and_then(|x| x.as_str()).unwrap_or("");
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
                    let _ = self.put_appraisal_policy(&serde_json::json!({
                        "is_default": is_default,
                        "fmspc": fmspc,
                        "policy": policy
                    }));
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
            ca: item
                .get("ca")
                .and_then(|x| x.as_str())
                .unwrap_or("processor")
                .to_string(),
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
        let _ = self.put_pckcert(&rec);
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
            identity: item.get("identity").cloned().unwrap_or(Value::Null),
        };
        let _ = self.put_identity(&rec);
    }

    /// PUT /platformcollateral — write GET-shaped records directly.
    pub fn put_platform_collateral(&self, body: &Value, version: u32) -> Result<(), PccsError> {
        let Some(platforms) = body.get("platforms").and_then(|x| x.as_array()) else {
            return Err(error::INVALID_REQ);
        };
        if platforms.is_empty() {
            return Err(error::INVALID_REQ);
        }
        let collaterals = body.get("collaterals").cloned().unwrap_or(Value::Null);
        let mut batch_recs: Vec<PckCertRecord> = Vec::new();

        if let Some(tcbs) = collaterals.get("tcbinfos").and_then(|x| x.as_array()) {
            for t in tcbs {
                let fmspc = upper(t, "fmspc");
                if fmspc.is_empty() {
                    continue;
                }
                let issuer = first_str(
                    &collaterals,
                    &[
                        "certificates.TCB-Info-Issuer-Chain",
                        "tcb_issuer_chain",
                        "issuer_chain",
                    ],
                )
                .unwrap_or_default();
                for (field, prod, early) in [
                    ("sgx_tcbinfo", 0u8, false),
                    ("sgx_tcbinfo_early", 0, true),
                    ("tdx_tcbinfo", 1, false),
                    ("tdx_tcbinfo_early", 1, true),
                    ("tcbinfo", 0, false),
                    ("tcbinfo_early", 0, true),
                ] {
                    if let Some(info) = t.get(field) {
                        let update = if early { "EARLY" } else { "STANDARD" };
                        let _ = self.put_tcb(&TcbRecord {
                            prod_type: prod,
                            fmspc: fmspc.clone(),
                            version,
                            update_type: update.into(),
                            tcbinfo: info.clone(),
                            issuer_chain: issuer.clone(),
                        });
                    }
                }
            }
        }

        for (field, id, early) in [
            ("qeidentity", 1u8, false),
            ("qeidentity_early", 1, true),
            ("qveidentity", 2, false),
            ("qveidentity_early", 2, true),
            ("tdqeidentity", 3, false),
            ("tdqeidentity_early", 3, true),
        ] {
            if let Some(ident) = collaterals.get(field) {
                let update = if early { "EARLY" } else { "STANDARD" };
                let issuer = collaterals
                    .pointer("/certificates/SGX-Enclave-Identity-Issuer-Chain")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let identity = if ident.is_string() {
                    serde_json::from_str(ident.as_str().unwrap()).unwrap_or(ident.clone())
                } else {
                    ident.clone()
                };
                let _ = self.put_identity(&IdentityRecord {
                    enclave_id: id,
                    version,
                    update_type: update.into(),
                    identity,
                    issuer_chain: issuer,
                });
            }
        }

        if let Some(crl) = collaterals.get("pckcacrl") {
            if let Some(hexv) = crl.get("processorCrl").and_then(|x| x.as_str()) {
                if let Ok(bytes) = hex::decode(hexv) {
                    let issuer = collaterals
                        .pointer("/certificates/SGX-PCK-Certificate-Issuer-Chain/PROCESSOR")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let _ = self.put_pckcrl(&PckCrlRecord {
                        ca: "PROCESSOR".into(),
                        pckcrl: bytes,
                        issuer_chain: issuer,
                    });
                }
            }
            if let Some(hexv) = crl.get("platformCrl").and_then(|x| x.as_str()) {
                if let Ok(bytes) = hex::decode(hexv) {
                    let issuer = collaterals
                        .pointer("/certificates/SGX-PCK-Certificate-Issuer-Chain/PLATFORM")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let _ = self.put_pckcrl(&PckCrlRecord {
                        ca: "PLATFORM".into(),
                        pckcrl: bytes,
                        issuer_chain: issuer,
                    });
                }
            }
        }

        if let Some(hexv) = collaterals.get("rootcacrl").and_then(|x| x.as_str()) {
            if let Ok(bytes) = hex::decode(hexv) {
                let _ = self.put_rootcacrl(&bytes);
            }
        }

        let default_issuer = collaterals
            .pointer("/certificates/SGX-PCK-Certificate-Issuer-Chain/PROCESSOR")
            .and_then(|x| x.as_str())
            .or_else(|| {
                collaterals
                    .pointer("/certificates/SGX-PCK-Certificate-Issuer-Chain/PLATFORM")
                    .and_then(|x| x.as_str())
            })
            .unwrap_or("")
            .to_string();

        let mut certs_by_id: std::collections::HashMap<(String, String), Vec<(String, String)>> =
            std::collections::HashMap::new();
        if let Some(arr) = collaterals.get("pck_certs").and_then(|x| x.as_array()) {
            for pc in arr {
                let qe = first_upper(pc, &["qe_id", "qeid"]);
                let pce = first_upper(pc, &["pce_id", "pceid"]);
                if let Some(certs) = pc.get("certs").and_then(|x| x.as_array()) {
                    for c in certs {
                        let tcbm = upper(c, "tcbm");
                        let mut cert = c
                            .get("cert")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        if cert.contains('%') {
                            cert = percent_decode(&cert);
                        }
                        certs_by_id
                            .entry((qe.clone(), pce.clone()))
                            .or_default()
                            .push((tcbm, cert));
                    }
                }
            }
        }

        for p in platforms {
            let qe_id = first_upper(p, &["qe_id", "qeid"]);
            let pce_id = first_upper(p, &["pce_id", "pceid"]);
            if qe_id.is_empty() || pce_id.is_empty() {
                return Err(error::INVALID_REQ);
            }
            let cpu_svn = first_upper(p, &["cpu_svn", "cpusvn"]);
            let pce_svn = first_upper(p, &["pce_svn", "pcesvn"]);
            let enc_ppid = first_upper(p, &["enc_ppid", "encrypted_ppid"]);
            let fmspc = upper(p, "fmspc");
            let ca = p
                .get("ca")
                .and_then(|x| x.as_str())
                .unwrap_or("processor")
                .to_string();
            let issuer = p
                .get("issuer_chain")
                .and_then(|x| x.as_str())
                .unwrap_or(default_issuer.as_str())
                .to_string();
            let manifest = p
                .get("platform_manifest")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(list) = certs_by_id.get(&(qe_id.clone(), pce_id.clone())) {
                let selected = crate::selection::select_for_raw_tcb(&cpu_svn, &pce_svn, list);
                if let Some((tcbm, cert)) = selected {
                    batch_recs.push(PckCertRecord {
                        qeid: qe_id.clone(),
                        pceid: pce_id.clone(),
                        cpusvn: cpu_svn.clone(),
                        pcesvn: pce_svn.clone(),
                        cert,
                        tcbm,
                        fmspc: fmspc.clone(),
                        ca: ca.clone(),
                        issuer_chain: issuer.clone(),
                        encrypted_ppid: if enc_ppid.is_empty() {
                            None
                        } else {
                            Some(enc_ppid.clone())
                        },
                        platform_manifest: manifest.clone(),
                    });
                }
            }
            if let Some(cert) = p.get("cert").and_then(|x| x.as_str()) {
                if !cpu_svn.is_empty() && !pce_svn.is_empty() {
                    batch_recs.push(PckCertRecord {
                        qeid: qe_id,
                        pceid: pce_id,
                        cpusvn: cpu_svn,
                        pcesvn: pce_svn,
                        cert: cert.to_string(),
                        tcbm: first_upper(p, &["tcbm"]),
                        fmspc,
                        ca,
                        issuer_chain: issuer,
                        encrypted_ppid: if enc_ppid.is_empty() {
                            None
                        } else {
                            Some(enc_ppid)
                        },
                        platform_manifest: manifest,
                    });
                }
            }
        }

        let mut batch = WriteBatch::default();
        for rec in &batch_recs {
            let k = keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn);
            let bytes = serde_json::to_vec(rec).map_err(|_| error::INTERNAL_ERROR)?;
            batch.put(k.as_bytes(), bytes);
        }
        self.write_batch(batch)
    }
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
