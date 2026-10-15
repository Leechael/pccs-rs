//! Offline Intel PCCS db_version=5 snapshot restore. Never uses PCS or startup seeds.
//! Validate first, write/verify a private fresh store, then publish without overwriting.
use crate::config::RocksDbOpts;
use crate::keys;
use crate::store::{
    apply_rocksdb_opts, sha384_hex, AppraisalPolicy, CrlRecord, IdentityRecord, PckCertRecord,
    PckCrlRecord, PlatformCert, PlatformPool, RawTcb, RegisteredPlatform, TcbRecord,
};
use rocksdb::{IteratorMode, Options, WriteBatch, WriteOptions, DB};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;
const TABLES: &[&str] = &[
    "pcs_version",
    "platforms",
    "pck_cert",
    "platform_tcbs",
    "pcs_certificates",
    "pck_certchain",
    "fmspc_tcbs",
    "enclave_identities",
    "pck_crl",
    "crl_cache",
    "platforms_registered",
    "appraisal_policies",
];

#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub source_sha256: String,
    pub db_version: i64,
    pub api_version: i64,
    pub source_rows: BTreeMap<String, usize>,
    pub destination_records: usize,
}

struct Row {
    table: String,
    fields: BTreeMap<String, SqlValue>,
}
impl Row {
    fn value(&self, column: &str) -> Result<&SqlValue> {
        self.fields.get(column).ok_or_else(|| format!("{}.{}: missing column", self.table, column))
    }
    fn text(&self, column: &str) -> Result<String> {
        match self.value(column)? {
            SqlValue::Text(s) => Ok(s.clone()),
            SqlValue::Blob(b) => String::from_utf8(b.clone())
                .map_err(|_| format!("{}.{}: invalid UTF-8", self.table, column)),
            _ => Err(format!("{}.{}: expected text/UTF-8 BLOB", self.table, column)),
        }
    }
    fn nullable_text(&self, column: &str) -> Result<String> {
        if matches!(self.value(column)?, SqlValue::Null) {
            Ok(String::new())
        } else {
            self.text(column)
        }
    }
    fn blob(&self, column: &str) -> Result<Vec<u8>> {
        match self.value(column)? {
            SqlValue::Null => Ok(Vec::new()),
            SqlValue::Blob(b) => Ok(b.clone()),
            SqlValue::Text(s) if s.is_empty() => Ok(Vec::new()),
            _ => Err(format!("{}.{}: expected binary BLOB or NULL", self.table, column)),
        }
    }
    fn int(&self, column: &str) -> Result<i64> {
        match self.value(column)? {
            SqlValue::Integer(i) => Ok(*i),
            _ => Err(format!("{}.{}: expected integer", self.table, column)),
        }
    }
}

struct Snapshot {
    rows: BTreeMap<String, Vec<Row>>,
    entries: BTreeMap<String, Vec<u8>>,
    report: ImportReport,
}
impl Snapshot {
    fn add(&mut self, key: String, record: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|e| format!("serialize record: {e}"))?;
        if self.entries.insert(key.clone(), bytes).is_some() {
            return Err(format!("duplicate canonical destination key: {key}"));
        }
        Ok(())
    }
}

/// Restore only a standalone snapshot into a nonexistent directory. The report
/// contains row counts/hashes, not platform credentials or collateral payloads.
pub fn import_intel(source: &Path, destination: &Path) -> Result<ImportReport> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err("destination already exists; use a fresh directory".into());
    }
    let metadata = fs::symlink_metadata(source).map_err(|e| format!("source metadata: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("source must be a regular standalone SQLite snapshot".into());
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = source.as_os_str().to_os_string();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err("source has SQLite sidecars; use VACUUM INTO, not a live database".into());
        }
    }
    let source_hash = hash_file(source)?;
    let conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open read-only SQLite: {e}"))?;
    conn.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;")
        .map_err(|e| format!("read transaction: {e}"))?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| format!("SQLite integrity check: {e}"))?;
    if integrity != "ok" {
        return Err("SQLite integrity check failed".into());
    }
    let mut snapshot = read_snapshot(&conn, source_hash)?;
    convert(&mut snapshot)?;
    drop(conn);
    if hash_file(source)? != snapshot.report.source_sha256 {
        return Err("source changed during import; obtain a stable snapshot".into());
    }
    snapshot.report.destination_records = snapshot.entries.len();
    publish(&snapshot, destination)?;
    Ok(snapshot.report)
}

fn read_snapshot(conn: &Connection, source_hash: String) -> Result<Snapshot> {
    let mut statement = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .map_err(|e| format!("read schema: {e}"))?;
    let tables = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| format!("read tables: {e}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("read table names: {e}"))?;
    for table in TABLES {
        if !tables.iter().any(|t| t == table) {
            return Err(format!("missing required db_version=5 table: {table}"));
        }
    }
    let mut rows = BTreeMap::new();
    let mut source_rows = BTreeMap::new();
    for table in tables {
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {quoted}"))
            .map_err(|e| format!("read table {table}: {e}"))?;
        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        for required in required_columns(&table) {
            if !columns.iter().any(|c| c == required) {
                return Err(format!("{table}.{required}: missing required column"));
            }
        }
        if TABLES.contains(&table.as_str()) {
            for column in &columns {
                if !required_columns(&table).contains(&column.as_str())
                    && !matches!(column.as_str(), "created_time" | "updated_time")
                {
                    return Err(format!("{table}.{column}: unsupported column"));
                }
            }
        }
        let records = stmt
            .query_map([], |row| {
                let mut fields = BTreeMap::new();
                for (i, name) in columns.iter().enumerate() {
                    fields.insert(name.clone(), row.get::<_, SqlValue>(i)?);
                }
                Ok(Row { table: table.clone(), fields })
            })
            .map_err(|e| format!("query {table}: {e}"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("rows {table}: {e}"))?;
        source_rows.insert(table.clone(), records.len());
        if !TABLES.contains(&table.as_str()) && table != "umzug" && !records.is_empty() {
            return Err(format!("unsupported nonempty table: {table}"));
        }
        rows.insert(table, records);
    }
    let versions = &rows["pcs_version"];
    if versions.len() != 1 || versions[0].int("id")? != 1 {
        return Err("pcs_version must contain exactly the id=1 row".into());
    }
    let db_version = versions[0].int("db_version")?;
    let api_version = versions[0].int("api_version")?;
    if db_version != 5 || api_version != 4 {
        return Err("only Intel db_version=5/api_version=4 snapshots are supported".into());
    }
    Ok(Snapshot {
        rows,
        entries: BTreeMap::new(),
        report: ImportReport {
            source_sha256: source_hash,
            db_version,
            api_version,
            source_rows,
            destination_records: 0,
        },
    })
}

fn required_columns(table: &str) -> &'static [&'static str] {
    match table {
        "pcs_version" => &["id", "api_version", "db_version", "server_addr"],
        "platforms" => &["qe_id", "pce_id", "platform_manifest", "enc_ppid", "fmspc", "ca"],
        "pck_cert" => &["qe_id", "pce_id", "tcbm", "pck_cert"],
        "platform_tcbs" => &["qe_id", "pce_id", "cpu_svn", "pce_svn", "tcbm"],
        "pcs_certificates" => &["id", "cert", "crl"],
        "pck_certchain" => &["ca", "root_cert_id", "intmd_cert_id"],
        "fmspc_tcbs" => &[
            "fmspc",
            "type",
            "version",
            "update_type",
            "tcbinfo",
            "root_cert_id",
            "signing_cert_id",
        ],
        "enclave_identities" => {
            &["id", "version", "update_type", "identity", "root_cert_id", "signing_cert_id"]
        }
        "pck_crl" => &["ca", "pck_crl", "root_cert_id", "intmd_cert_id"],
        "crl_cache" => &["cdp_url", "crl"],
        "platforms_registered" => {
            &["qe_id", "pce_id", "cpu_svn", "pce_svn", "enc_ppid", "platform_manifest", "state"]
        }
        "appraisal_policies" => &["id", "type", "policy", "is_default", "fmspc"],
        _ => &[],
    }
}

fn chain(certificates: &BTreeMap<i64, String>, row: &Row, issuer: &str) -> Result<String> {
    if row.int("root_cert_id")? != 1 {
        return Err(format!("{}.root_cert_id: expected Intel root id=1", row.table));
    }
    let expected_issuer = if issuer == "signing_cert_id" {
        3
    } else if ca(row)? == "PROCESSOR" {
        2
    } else {
        4
    };
    if row.int(issuer)? != expected_issuer {
        return Err(format!("{}.{issuer}: inconsistent issuer pointer", row.table));
    }
    let root = certificates
        .get(&row.int("root_cert_id")?)
        .ok_or_else(|| format!("{}: missing root certificate join", row.table))?;
    let signing = certificates
        .get(&row.int(issuer)?)
        .ok_or_else(|| format!("{}: missing issuer certificate join", row.table))?;
    Ok(format!("{signing}{root}"))
}
fn hex_field(row: &Row, field: &str, length: usize) -> Result<String> {
    let text = row.text(field)?;
    if text.len() != length || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}.{}: invalid hex identifier", row.table, field));
    }
    Ok(text.to_ascii_uppercase())
}
fn version(row: &Row) -> Result<u32> {
    match row.int("version")? {
        n @ (3 | 4) => Ok(n as u32),
        _ => Err(format!("{}: unsupported API version", row.table)),
    }
}
fn update(row: &Row) -> Result<String> {
    match row.text("update_type")?.as_str() {
        "STANDARD" => Ok("STANDARD".into()),
        "EARLY" => Ok("EARLY".into()),
        _ => Err(format!("{}: unsupported update_type", row.table)),
    }
}

fn convert(snapshot: &mut Snapshot) -> Result<()> {
    let mut certificates = BTreeMap::new();
    for row in &snapshot.rows["pcs_certificates"] {
        let id = row.int("id")?;
        if !(1..=4).contains(&id) {
            return Err("unsupported pcs_certificates id".into());
        }
        let cert = row.text("cert")?;
        if cert.is_empty()
            || cert.contains(['\r', '\n'])
            || !cert.starts_with("-----BEGIN%20CERTIFICATE-----")
            || !cert.contains("-----END%20CERTIFICATE-----")
        {
            return Err("pcs_certificates.cert: expected URL-encoded PEM".into());
        }
        if certificates.insert(id, cert).is_some() {
            return Err("pcs_certificates: duplicate id".into());
        }
    }
    for row in snapshot.rows.remove("fmspc_tcbs").unwrap() {
        let raw_body = row.text("tcbinfo")?;
        let tcbinfo = signed_document(&raw_body, "fmspc_tcbs.tcbinfo")?;
        let prod_type = match row.int("type")? {
            0 => 0,
            1 => 1,
            _ => return Err("fmspc_tcbs: unsupported type".into()),
        };
        let fmspc = hex_field(&row, "fmspc", 12)?;
        let version = version(&row)?;
        let info = tcbinfo.get("tcbInfo").ok_or("fmspc_tcbs: missing tcbInfo")?;
        let expected_id = if prod_type == 0 { "SGX" } else { "TDX" };
        // PCS v3 SGX documents predate the v4 product discriminator. Their
        // migration keeps the signed body unchanged; do not insert an `id`.
        let valid_id = info.get("id").and_then(|v| v.as_str()) == Some(expected_id)
            || (version == 3 && prod_type == 0 && info.get("id").is_none());
        if info.get("fmspc").and_then(|v| v.as_str()).map(str::to_ascii_uppercase).as_ref()
            != Some(&fmspc)
            || !valid_id
        {
            return Err("fmspc_tcbs: document identity does not match row".into());
        }
        let rec = TcbRecord {
            prod_type,
            fmspc,
            version,
            update_type: update(&row)?,
            tcbinfo,
            raw_body,
            issuer_chain: chain(&certificates, &row, "signing_cert_id")?,
        };
        snapshot.add(
            keys::tcb(keys::prod_name(rec.prod_type), rec.version, &rec.fmspc, &rec.update_type),
            &rec,
        )?;
    }
    convert_platforms(snapshot, &certificates)?;
    convert_collateral(snapshot, &certificates)?;
    convert_queue_and_policies(snapshot)?;
    Ok(())
}

fn qeid(row: &Row) -> Result<String> {
    let id = row.text("qe_id")?;
    if id.is_empty() || id.len() > 260 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}.qe_id: invalid hex identifier", row.table));
    }
    Ok(id.to_ascii_uppercase())
}
fn platform_key(row: &Row) -> Result<(String, String)> {
    Ok((qeid(row)?, hex_field(row, "pce_id", 4)?))
}
fn ca(row: &Row) -> Result<String> {
    let ca = row.text("ca")?.to_ascii_uppercase();
    if ca != "PLATFORM" && ca != "PROCESSOR" {
        return Err(format!("{}.ca: unsupported CA", row.table));
    }
    Ok(ca)
}
fn credentials(row: &Row) -> Result<(String, String)> {
    let ppid = row.blob("enc_ppid")?;
    if !ppid.is_empty() && ppid.len() != 384 {
        return Err(format!("{}.enc_ppid: expected 384-byte encrypted PPID", row.table));
    }
    Ok((hex::encode_upper(ppid), hex::encode_upper(row.blob("platform_manifest")?)))
}
fn convert_platforms(snapshot: &mut Snapshot, certificates: &BTreeMap<i64, String>) -> Result<()> {
    let mut chains = BTreeMap::new();
    for row in snapshot.rows.remove("pck_certchain").unwrap() {
        let ca = ca(&row)?;
        if chains.insert(ca, chain(certificates, &row, "intmd_cert_id")?).is_some() {
            return Err("pck_certchain: duplicate canonical CA".into());
        }
    }
    let mut pools = BTreeMap::new();
    for row in snapshot.rows.remove("platforms").unwrap() {
        let (qe_id, pce_id) = platform_key(&row)?;
        let (enc_ppid, platform_manifest) = credentials(&row)?;
        let fmspc = row.nullable_text("fmspc")?.to_ascii_uppercase();
        if !fmspc.is_empty() && (fmspc.len() != 12 || !fmspc.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("platforms.fmspc: invalid hex identifier".into());
        }
        let ca = if row.nullable_text("ca")?.is_empty() { String::new() } else { ca(&row)? };
        let pool = PlatformPool {
            qe_id: qe_id.clone(),
            pce_id: pce_id.clone(),
            enc_ppid,
            platform_manifest,
            fmspc,
            issuer_chain: chains.get(&ca).cloned().unwrap_or_default(),
            ca,
            certs: Vec::new(),
            raw_tcbs: Vec::new(),
        };
        if pools.insert((qe_id, pce_id), pool).is_some() {
            return Err("platforms: duplicate canonical platform".into());
        }
    }
    let mut ppids = BTreeMap::new();
    for row in snapshot.rows.remove("pck_cert").unwrap() {
        let key = platform_key(&row)?;
        let pool = pools.get_mut(&key).ok_or("pck_cert: missing platform join")?;
        let tcbm = hex_field(&row, "tcbm", 36)?;
        let cert = row.text("pck_cert")?;
        let parsed = crate::selection::parse_pck_cert(&cert)
            .map_err(|_| "pck_cert: invalid SGX PCK certificate")?;
        // PCS v4 defines TCBm using this certificate's CPUSVN + PCESVN, not
        // the request's raw SVN: api.portal.trustedservices.intel.com/content/documentation.html
        if parsed.version != 3
            || parsed.pce_id != pool.pce_id
            || parsed.fmspc != pool.fmspc
            || parsed.ca != pool.ca
            || parsed.cpusvn != tcbm[..32]
            || parsed.pcesvn
                != crate::selection::little_endian_hex_to_int(&tcbm[32..])
                    .ok_or("pck_cert: invalid TCBm")?
        {
            return Err("pck_cert: certificate metadata/TCBm does not match platform row".into());
        }
        if pool.issuer_chain.is_empty() {
            return Err("pck_cert: missing issuer chain join".into());
        }
        if let Some(previous) = ppids.insert(key, parsed.ppid.clone()) {
            if previous != parsed.ppid {
                return Err("pck_cert: mixed PPIDs in a platform pool".into());
            }
        }
        if pool.certs.iter().any(|c| c.tcbm == tcbm) {
            return Err("pck_cert: duplicate canonical TCBm".into());
        }
        pool.certs.push(PlatformCert { tcbm, cert });
    }
    for row in snapshot.rows.remove("platform_tcbs").unwrap() {
        let key = platform_key(&row)?;
        let pool = pools.get_mut(&key).ok_or("platform_tcbs: missing platform join")?;
        let cpu_svn = hex_field(&row, "cpu_svn", 32)?;
        let pce_svn = hex_field(&row, "pce_svn", 4)?;
        let tcbm = hex_field(&row, "tcbm", 36)?;
        let cert = pool
            .certs
            .iter()
            .find(|c| c.tcbm == tcbm)
            .ok_or("platform_tcbs: missing PCK certificate join")?;
        if pool.raw_tcbs.iter().any(|r| r.cpu_svn == cpu_svn && r.pce_svn == pce_svn) {
            return Err("platform_tcbs: duplicate canonical raw TCB".into());
        }
        let rec = PckCertRecord {
            qeid: pool.qe_id.clone(),
            pceid: pool.pce_id.clone(),
            cpusvn: cpu_svn.clone(),
            pcesvn: pce_svn.clone(),
            cert: cert.cert.clone(),
            tcbm: tcbm.clone(),
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
        snapshot.add(keys::pckcert(&rec.qeid, &rec.pceid, &rec.cpusvn, &rec.pcesvn), &rec)?;
        pool.raw_tcbs.push(RawTcb { cpu_svn, pce_svn, tcbm });
    }
    for pool in pools.into_values() {
        snapshot.add(keys::platform(&pool.qe_id, &pool.pce_id), &pool)?;
    }
    Ok(())
}

fn signed_document(raw_body: &str, field: &str) -> Result<serde_json::Value> {
    let document: serde_json::Value =
        serde_json::from_str(raw_body).map_err(|_| format!("{field}: invalid JSON"))?;
    if document.get("signature").and_then(|v| v.as_str()).is_none_or(str::is_empty) {
        return Err(format!("{field}: missing signature"));
    }
    // Presence/shape only: cryptographic authenticity is verified by attestation
    // consumers against Intel trust anchors, not by a lossy parse/re-serialization.
    Ok(document)
}

fn der_crl(bytes: Vec<u8>, table: &str) -> Result<Vec<u8>> {
    use x509_cert::der::Decode;
    // from_der parses the complete CertificateList and rejects trailing input.
    // Validate syntax only; retain the original signed bytes, never reserialize.
    x509_cert::crl::CertificateList::from_der(&bytes)
        .map_err(|_| format!("{table}: invalid DER CRL"))?;
    Ok(bytes)
}
fn convert_collateral(snapshot: &mut Snapshot, certificates: &BTreeMap<i64, String>) -> Result<()> {
    for row in snapshot.rows.remove("enclave_identities").unwrap() {
        let enclave_id = match row.int("id")? {
            n @ (1..=3) => n as u8,
            _ => return Err("enclave_identities: unsupported id".into()),
        };
        let raw_body = row.text("identity")?;
        let identity = signed_document(&raw_body, "enclave_identities.identity")?;
        let expected = match enclave_id {
            1 => "QE",
            2 => "QVE",
            _ => "TD_QE",
        };
        if identity.pointer("/enclaveIdentity/id").and_then(|v| v.as_str()) != Some(expected) {
            return Err("enclave_identities: document identity does not match row".into());
        }
        let rec = IdentityRecord {
            enclave_id,
            version: version(&row)?,
            update_type: update(&row)?,
            identity,
            raw_body,
            issuer_chain: chain(certificates, &row, "signing_cert_id")?,
        };
        snapshot.add(
            keys::identity(keys::identity_name(rec.enclave_id), rec.version, &rec.update_type),
            &rec,
        )?;
    }
    for row in &snapshot.rows["pcs_certificates"] {
        let crl = row.blob("crl")?;
        if !crl.is_empty() {
            if row.int("id")? != 1 {
                return Err("pcs_certificates: unsupported non-root CRL".into());
            }
            let crl = der_crl(crl, "pcs_certificates.crl")?;
            // Root CA CRL is stored as a JSON byte array by the normal Store API.
            if snapshot
                .entries
                .insert(keys::rootcacrl(), serde_json::to_vec(&crl).map_err(|e| e.to_string())?)
                .is_some()
            {
                return Err("duplicate root CA CRL".into());
            }
        }
    }
    for row in snapshot.rows.remove("pck_crl").unwrap() {
        let rec = PckCrlRecord {
            ca: ca(&row)?,
            pckcrl: der_crl(row.blob("pck_crl")?, "pck_crl")?,
            issuer_chain: chain(certificates, &row, "intmd_cert_id")?,
        };
        snapshot.add(keys::pckcrl(&rec.ca), &rec)?;
    }
    for row in snapshot.rows.remove("crl_cache").unwrap() {
        let uri = row.text("cdp_url")?;
        if !crate::validate::is_valid_crl_uri(&uri) {
            return Err("crl_cache: unsupported CDP URI".into());
        }
        let rec = CrlRecord { uri, crl: der_crl(row.blob("crl")?, "crl_cache")? };
        snapshot.add(keys::crl(&rec.uri), &rec)?;
    }
    Ok(())
}
fn convert_queue_and_policies(snapshot: &mut Snapshot) -> Result<()> {
    for row in snapshot.rows.remove("platforms_registered").unwrap() {
        let (qe_id, pce_id) = platform_key(&row)?;
        let (enc_ppid, platform_manifest) = credentials(&row)?;
        let state = match row.int("state")? {
            n @ (0 | 1 | 9) => n as u8,
            _ => return Err("platforms_registered: unsupported state".into()),
        };
        let cpu_svn = row.text("cpu_svn")?.to_ascii_uppercase();
        let pce_svn = row.text("pce_svn")?.to_ascii_uppercase();
        if !cpu_svn.is_empty()
            && (cpu_svn.len() != 32 || !cpu_svn.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("platforms_registered.cpu_svn: invalid raw SVN".into());
        }
        // Intel's NOT_AVAILABLE rows use decimal PCESVN. Draining changes
        // only the state to DELETED, not the decimal key. Preserve both forms.
        let hex_svn = pce_svn.len() == 4 && pce_svn.bytes().all(|b| b.is_ascii_hexdigit());
        let decimal_svn = matches!(state, 1 | 9)
            && pce_svn.bytes().all(|b| b.is_ascii_digit())
            && pce_svn.parse::<u16>().is_ok();
        if !(pce_svn.is_empty() || hex_svn || decimal_svn) {
            return Err("platforms_registered.pce_svn: invalid raw SVN".into());
        }
        let rec = RegisteredPlatform {
            qe_id,
            pce_id,
            cpu_svn,
            pce_svn,
            enc_ppid,
            platform_manifest,
            state,
        };
        snapshot.add(keys::preg(&rec.qe_id, &rec.pce_id, &rec.cpu_svn, &rec.pce_svn), &rec)?;
    }
    let mut policies: BTreeMap<String, Vec<AppraisalPolicy>> = BTreeMap::new();
    for row in snapshot.rows.remove("appraisal_policies").unwrap() {
        let policy = row.text("policy")?;
        let id = hex_field(&row, "id", 96)?.to_ascii_lowercase();
        if policy.is_empty() || id != sha384_hex(&policy) {
            return Err("appraisal_policies: policy hash mismatch".into());
        }
        let policy_type = match row.int("type")? {
            n @ (0..=2) => n as u8,
            _ => return Err("appraisal_policies: unsupported type".into()),
        };
        let is_default = match row.int("is_default")? {
            0 => false,
            1 => true,
            _ => return Err("appraisal_policies: unsupported is_default".into()),
        };
        let fmspc = hex_field(&row, "fmspc", 12)?;
        let entries = policies.entry(fmspc.clone()).or_default();
        if entries.iter().any(|p| p.id == id) {
            return Err("appraisal_policies: duplicate canonical policy".into());
        }
        entries.push(AppraisalPolicy { id, policy_type, policy, is_default, fmspc });
    }
    for (fmspc, policies) in policies {
        snapshot.add(keys::appraisal(&fmspc), &serde_json::json!({"policies":policies}))?;
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| format!("hash source: {e}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer).map_err(|e| format!("hash source: {e}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}
fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| format!("create private destination: {e}"))
}
fn publish_directory(staging: &Path, destination: &Path) -> Result<()> {
    // One kernel operation: never reserve/check then rename, and never remove
    // destination on error. NOREPLACE maps to RENAME_EXCL on macOS.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::fs::{renameat_with, RenameFlags, CWD};
        renameat_with(CWD, staging, CWD, destination, RenameFlags::NOREPLACE)
            .map_err(|e| format!("publish destination: {e}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (staging, destination);
        Err("publish destination: atomic no-replace publication requires Linux or macOS".into())
    }
}

fn publish(snapshot: &Snapshot, destination: &Path) -> Result<()> {
    publish_with(snapshot, destination, |_, _| {})
}

// Filesystem boundary seam for deterministic competing-publisher tests.
fn publish_with(
    snapshot: &Snapshot,
    destination: &Path,
    before_rename: impl FnOnce(&Path, &Path),
) -> Result<()> {
    let parent =
        destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let staging = parent.join(format!(".pccs-import-{}", uuid::Uuid::new_v4()));
    private_directory(&staging)?;
    let result = (|| {
        let mut options = Options::default();
        options.create_if_missing(true);
        apply_rocksdb_opts(&mut options, &RocksDbOpts::default());
        let db = DB::open(&options, &staging).map_err(|e| format!("open staging RocksDB: {e}"))?;
        let mut batch = WriteBatch::default();
        for (key, value) in &snapshot.entries {
            batch.put(key.as_bytes(), value);
        }
        let mut write_options = WriteOptions::default();
        write_options.set_sync(true);
        db.write_opt(batch, &write_options).map_err(|e| format!("write staging RocksDB: {e}"))?;
        db.flush().map_err(|e| format!("flush staging RocksDB: {e}"))?;
        drop(db);
        let db = DB::open_for_read_only(&options, &staging, false)
            .map_err(|e| format!("reopen staging: {e}"))?;
        let mut count = 0;
        for item in db.iterator(IteratorMode::Start) {
            let (key, value) = item.map_err(|e| format!("readback staging: {e}"))?;
            let key = std::str::from_utf8(&key).map_err(|_| "invalid staging key")?;
            if snapshot.entries.get(key).map(Vec::as_slice) != Some(value.as_ref()) {
                return Err("staging record failed byte-exact verification".into());
            }
            count += 1;
        }
        if count != snapshot.entries.len() {
            return Err("staging record count mismatch".into());
        }
        drop(db);
        let report_path = staging.join("intel-import-report.json");
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&snapshot.report).map_err(|e| format!("report: {e}"))?,
        )
        .map_err(|e| format!("write report: {e}"))?;
        fs::File::open(&report_path)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("sync report: {e}"))?;
        #[cfg(unix)]
        fs::File::open(&staging)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("sync staging directory: {e}"))?;
        before_rename(&staging, destination);
        publish_directory(&staging, destination)?;
        #[cfg(unix)]
        fs::File::open(parent).and_then(|f| f.sync_all()).map_err(|e| {
            format!(
                "destination published but parent directory sync failed; inspect before retry: {e}"
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};

    /// Intent: regression/migration safety. A competing path created at the
    /// publication boundary is never replaced or removed, even on rename error.
    #[test]
    fn competing_destination_survives_publication() {
        for kind in ["empty", "nonempty", "symlink", "rename-error"] {
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("rocks");
            let foreign = temp.path().join("foreign");
            fs::create_dir(&foreign).unwrap();
            let snapshot = Snapshot {
                rows: BTreeMap::new(),
                entries: BTreeMap::new(),
                report: ImportReport {
                    source_sha256: "synthetic".into(),
                    db_version: 5,
                    api_version: 4,
                    source_rows: BTreeMap::new(),
                    destination_records: 0,
                },
            };
            let mut foreign_inode = 0;
            let result = publish_with(&snapshot, &destination, |staging, destination| {
                // Model another process replacing the old reservation, if any.
                if destination.exists() {
                    fs::remove_dir(destination).unwrap();
                }
                if kind == "symlink" {
                    symlink(&foreign, destination).unwrap();
                } else {
                    fs::create_dir(destination).unwrap();
                    if kind == "nonempty" {
                        fs::write(destination.join("marker"), b"foreign data").unwrap();
                    }
                }
                foreign_inode = fs::symlink_metadata(destination).unwrap().ino();
                if kind == "rename-error" {
                    fs::remove_dir_all(staging).unwrap();
                }
            });
            assert!(result.is_err(), "competing {kind} destination was overwritten");
            assert!(result.unwrap_err().contains("publish destination"));
            assert_eq!(fs::symlink_metadata(&destination).unwrap().ino(), foreign_inode);
            if kind == "nonempty" {
                assert_eq!(fs::read(destination.join("marker")).unwrap(), b"foreign data");
            } else if kind == "symlink" {
                assert_eq!(fs::read_link(&destination).unwrap(), foreign);
            } else {
                assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
            }
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2, "staging leaked");
        }
    }
}
