//! Migration-safety tests use synthetic SQLite rows, not production collateral.
//! The CLI, real SQLite/RocksDB and public HTTP responses are the test seams.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use pccs_rs::config::{CacheMode, Config};
use pccs_rs::{create_app_from_config, headers};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use tower::ServiceExt;

const FMSPC: &str = "1234567890AB";
const RAW_TCB: &str = "{\n  \"tcbInfo\": { \"id\": \"SGX\", \"fmspc\": \"1234567890AB\", \"tcbType\": 0, \"tcbLevels\": [] },\n  \"signature\": \"synthetic-not-cryptographically-valid\"\n}\n";
const PCK: &str = include_str!("fixtures/pck-synthetic.pem");
// Hand-encoded X.509 v2 CertificateList: synthetic issuer/dates/signature;
// no private key or production collateral. Signature is deliberately not authentic.
const CRL: &[u8] = include_bytes!("fixtures/crl-synthetic.der");
const ROOT: &str = "-----BEGIN%20CERTIFICATE-----%0AMAA=%0A-----END%20CERTIFICATE-----%0A";
const SIGNING: &str = "-----BEGIN%20CERTIFICATE-----%0AMAE=%0A-----END%20CERTIFICATE-----%0A";

fn snapshot(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch(include_str!("fixtures/intel-v5.sql")).unwrap();
    db
}

fn pool_snapshot(path: &Path) -> (Connection, Vec<u8>, String) {
    use base64::Engine;
    let db = snapshot(path);
    let manifest: Vec<u8> = (0..17950).map(|i| (i % 256) as u8).collect();
    let qeid = "AA".repeat(16);
    db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (4,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (3,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    db.execute("INSERT INTO pck_certchain VALUES ('PLATFORM',1,4)", []).unwrap();
    db.execute(
        "INSERT INTO platforms VALUES (?1,'4444',?2,NULL,?3,'PLATFORM')",
        params![qeid, manifest, FMSPC],
    )
    .unwrap();
    let high = format!("{}3333", "22".repeat(16));
    let low = format!("{}3333", "21".repeat(16));
    // Derive a second *synthetic* X.509 fixture at a lower component SVN.
    let encoded: String = PCK.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut der = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
    for i in 0..der.len() - 2 {
        if der[i..i + 3] == [2, 1, 0x22] {
            der[i + 2] = 0x21;
        }
    }
    let octets = [vec![4, 16], vec![0x22; 16]].concat();
    let start = der.windows(18).position(|w| w == octets).unwrap();
    der[start + 2..start + 18].fill(0x21);
    let low_cert = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    db.execute(
        "INSERT INTO pck_cert VALUES (?1,'4444',?2,?3)",
        params![qeid, high, PCK.as_bytes()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO pck_cert VALUES (?1,'4444',?2,?3)",
        params![qeid, low, low_cert.as_bytes()],
    )
    .unwrap();
    // Actual raw request values intentionally differ from the chosen certificate TCB.
    db.execute(
        "INSERT INTO platform_tcbs VALUES (?1,'4444',?2,'3433',?3)",
        params![qeid, "33".repeat(16), high],
    )
    .unwrap();
    let levels: Vec<Value> = [0x22,0x21].into_iter().map(|svn| serde_json::json!({
        "tcb": {"sgxtcbcomponents": (0..16).map(|_| serde_json::json!({"svn":svn})).collect::<Vec<_>>(), "pcesvn": 0x3333},
        "tcbStatus": "UpToDate"
    })).collect();
    let tcb = serde_json::json!({"tcbInfo":{"id":"SGX","fmspc":FMSPC,"pceId":"4444","tcbType":0,"tcbLevels":levels},"signature":"synthetic"}).to_string();
    db.execute(
        "INSERT INTO fmspc_tcbs VALUES (?1,0,4,'STANDARD',?2,1,3)",
        params![FMSPC, tcb.as_bytes()],
    )
    .unwrap();
    (db, manifest, low_cert)
}

fn import(source: &Path, destination: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pccs-rs"))
        .args(["db", "import-intel"])
        .arg(source)
        .arg("--db-path")
        .arg(destination)
        .output()
        .unwrap()
}

fn offline(destination: &Path) -> axum::Router {
    let mut cfg = Config::test_default();
    cfg.db_path = destination.to_path_buf();
    cfg.cache_mode = CacheMode::Offline;
    cfg.no_seed = true;
    create_app_from_config(cfg)
}

async fn get(router: axum::Router, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response =
        router.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

/// Intent: migration safety. Raw signed bytes and chain survive CLI import/reopen.
#[tokio::test]
async fn imported_signed_tcb_is_byte_exact_and_source_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let db = snapshot(&source);
    db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (3,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    db.execute(
        "INSERT INTO fmspc_tcbs VALUES (?1,0,4,'STANDARD',?2,1,3)",
        params![FMSPC, RAW_TCB.as_bytes()],
    )
    .unwrap();
    drop(db);
    let original = std::fs::read(&source).unwrap();
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_rows"]["fmspc_tcbs"], 1);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let chain = format!("{SIGNING}{ROOT}");
    // Reconstruct the app twice: database persistence, not an in-memory seed.
    for _ in 0..2 {
        let (status, response_headers, body) =
            get(offline(&destination), "/sgx/certification/v4/tcb?fmspc=1234567890ab").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, RAW_TCB.as_bytes());
        assert_eq!(response_headers[headers::TCB_INFO_ISSUER_CHAIN], chain);
    }
}

/// Intent: migration safety. Preserve indirect credentials, actual raw mappings,
/// and an unselected lower certificate needed by a future PPID-less request.
#[tokio::test]
async fn indirect_platform_keeps_full_pool_and_actual_raw_tcb_mappings() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let (db, manifest, low_cert) = pool_snapshot(&source);
    drop(db);
    let original = std::fs::read(&source).unwrap();
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_rows"]["platforms"], 1);
    assert_eq!(report["source_rows"]["pck_cert"], 2);
    assert_eq!(report["source_rows"]["platform_tcbs"], 1);
    let qeid = "AA".repeat(16);
    let raw_path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&pceid=4444&cpusvn={}&pcesvn=3433",
        "33".repeat(16)
    );
    let (status, response_headers, body) = get(offline(&destination), &raw_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PCK.as_bytes());
    assert_eq!(response_headers[headers::SGX_TCBM], format!("{}3333", "22".repeat(16)));
    assert_eq!(response_headers[headers::SGX_FMSPC], FMSPC);
    assert_eq!(response_headers[headers::SGX_PCK_CERTIFICATE_CA_TYPE], "PLATFORM");
    assert_eq!(
        response_headers[headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN],
        format!("{SIGNING}{ROOT}")
    );
    let raw_list = format!("/sgx/certification/v4/platforms?source=[{FMSPC}]");
    let router = offline(&destination);
    let response = router
        .oneshot(
            Request::builder()
                .uri(raw_list)
                .header(headers::ADMIN_TOKEN, "admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let platforms: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(platforms[0]["platform_manifest"], hex::encode_upper(&manifest));
    assert_eq!(platforms[0]["enc_ppid"], "");
    assert_eq!(platforms[0]["cpu_svn"], "33".repeat(16));
    assert_eq!(platforms[0]["pce_svn"], "3433");
    let low_path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&pceid=4444&cpusvn={}&pcesvn=3333",
        "21".repeat(16)
    );
    let (status, response_headers, body) = get(offline(&destination), &low_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, low_cert.as_bytes());
    assert_eq!(response_headers[headers::SGX_TCBM], format!("{}3333", "21".repeat(16)));
    assert_eq!(std::fs::read(&source).unwrap(), original);
}

/// Intent: migration safety. Cold collateral, queue states and policy metadata
/// remain distinct; public draining GETs have the same one-time semantics.
#[tokio::test]
async fn restores_identity_crls_queue_states_and_policy_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let db = snapshot(&source);
    db.execute("INSERT INTO pcs_certificates VALUES (1,?1,?2)", params![ROOT.as_bytes(), CRL])
        .unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (3,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (4,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    let identity = "{\n \"enclaveIdentity\": {\"id\":\"TD_QE\"}, \"signature\":\"synthetic\"\n}\n";
    db.execute("INSERT INTO enclave_identities VALUES (3,4,'EARLY',?1,1,3)", [identity.as_bytes()])
        .unwrap();
    db.execute("INSERT INTO pck_crl VALUES ('PLATFORM',?1,1,4)", [CRL]).unwrap();
    db.execute("INSERT INTO crl_cache VALUES ('https://certificates.trustedservices.intel.com/IntelSGXRootCA.der',?1)", [CRL]).unwrap();
    for (id, state, pce) in [("01", 0, "0001"), ("02", 1, "13107"), ("03", 9, "13107")] {
        db.execute(
            "INSERT INTO platforms_registered VALUES (?1,'0000',?2,?3,?4,NULL,?5)",
            params![id, "11".repeat(16), pce, vec![0xABu8; 384], state],
        )
        .unwrap();
    }
    let policy = "synthetic-policy";
    let policy_id = pccs_rs::store::sha384_hex(policy);
    db.execute(
        "INSERT INTO appraisal_policies VALUES (?1,2,?2,1,?3)",
        params![policy_id, policy, FMSPC],
    )
    .unwrap();
    let nondefault = "synthetic-nondefault-policy";
    let nondefault_id = pccs_rs::store::sha384_hex(nondefault);
    db.execute(
        "INSERT INTO appraisal_policies VALUES (?1,1,?2,0,?3)",
        params![nondefault_id, nondefault, FMSPC],
    )
    .unwrap();
    drop(db);
    let original = std::fs::read(&source).unwrap();
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read(&source).unwrap(), original);
    // These metadata fields deliberately have no HTTP getter. Inspect the
    // CLI's documented RocksDB output artifact, using public keys/record types,
    // before testing public queue drains; counts alone cannot prove retention.
    let restored =
        rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), &destination, false).unwrap();
    let deleted: pccs_rs::store::RegisteredPlatform = serde_json::from_slice(
        &restored
            .get(pccs_rs::keys::preg("03", "0000", &"11".repeat(16), "13107"))
            .unwrap()
            .expect("DELETED row retained"),
    )
    .unwrap();
    assert_eq!(deleted.state, 9);
    assert_eq!(deleted.pce_svn, "13107");
    assert_eq!(deleted.enc_ppid, "AB".repeat(384));
    let restored_policies: Value =
        serde_json::from_slice(&restored.get(pccs_rs::keys::appraisal(FMSPC)).unwrap().unwrap())
            .unwrap();
    let policies = restored_policies["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    let default = policies.iter().find(|p| p["id"] == policy_id).unwrap();
    assert_eq!(default["policy_type"], 2);
    assert_eq!(default["is_default"], true);
    assert_eq!(default["policy"], policy);
    let inactive = policies.iter().find(|p| p["id"] == nondefault_id).unwrap();
    assert_eq!(inactive["policy_type"], 1);
    assert_eq!(inactive["is_default"], false);
    assert_eq!(inactive["policy"], nondefault);
    drop(restored);
    let (status, response_headers, body) =
        get(offline(&destination), "/tdx/certification/v4/qe/identity?update=early").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, identity.as_bytes());
    assert_eq!(
        response_headers[headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN],
        format!("{SIGNING}{ROOT}")
    );
    let (status, _, body) =
        get(offline(&destination), "/sgx/certification/v4/pckcrl?ca=platform&encoding=der").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, CRL);
    let (status, _, body) = get(offline(&destination), "/sgx/certification/v4/rootcacrl").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, hex::encode(CRL).as_bytes());
    let (status,_,body) = get(offline(&destination), "/sgx/certification/v4/crl?uri=https://certificates.trustedservices.intel.com/IntelSGXRootCA.der").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, CRL);
    let (status, _, body) =
        get(offline(&destination), "/sgx/certification/v4/appraisalpolicy?fmspc=1234567890ab")
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, policy.as_bytes());
    for (source, id, pce) in [("reg", "01", "0001"), ("reg_na", "02", "13107")] {
        let response = offline(&destination)
            .oneshot(
                Request::builder()
                    .uri(format!("/sgx/certification/v4/platforms?source={source}"))
                    .header(headers::ADMIN_TOKEN, "admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["qe_id"], id);
        assert_eq!(rows[0]["pce_svn"], pce);
        assert_eq!(rows[0]["enc_ppid"], "AB".repeat(384));
        let response = offline(&destination)
            .oneshot(
                Request::builder()
                    .uri(format!("/sgx/certification/v4/platforms?source={source}"))
                    .header(headers::ADMIN_TOKEN, "admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), serde_json::json!([]));
    }
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_rows"]["platforms_registered"], 3);
    assert_eq!(report["source_rows"]["appraisal_policies"], 2);
}

/// Intent: migration safety. Nonuniform CPU bytes and a nonsymmetric PCE SVN
/// detect component reordering/byte swapping; a direct encrypted PPID is retained.
#[tokio::test]
async fn preserves_nonuniform_tcbm_little_endian_pce_svn_and_direct_credentials() {
    use base64::Engine;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let db = snapshot(&source);
    let encoded: String = PCK.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut der = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
    let old_cpu = [vec![4, 16], vec![0x22; 16]].concat();
    let cpu_start = der.windows(18).position(|w| w == old_cpu).unwrap();
    for (i, byte) in der[cpu_start + 2..cpu_start + 18].iter_mut().enumerate() {
        *byte = (i + 1) as u8;
    }
    let pce_start = der.windows(4).position(|w| w == [2, 2, 0x33, 0x33]).unwrap();
    der[pce_start + 2..pce_start + 4].copy_from_slice(&[0x12, 0x34]);
    let id_start = der.windows(4).position(|w| w == [4, 2, 0x44, 0x44]).unwrap();
    der[id_start + 2..id_start + 4].copy_from_slice(&[0x12, 0x34]);
    let cert = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    let tcbm = "0102030405060708090A0B0C0D0E0F103412";
    let ppid: Vec<u8> = (0..384).map(|i| (i % 251) as u8).collect();
    db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (4,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    db.execute("INSERT INTO pck_certchain VALUES ('PLATFORM',1,4)", []).unwrap();
    db.execute(
        "INSERT INTO platforms VALUES ('BB','1234',NULL,?1,?2,'PLATFORM')",
        params![ppid, FMSPC],
    )
    .unwrap();
    db.execute("INSERT INTO pck_cert VALUES ('BB','1234',?1,?2)", params![tcbm, cert.as_bytes()])
        .unwrap();
    db.execute(
        "INSERT INTO platform_tcbs VALUES ('BB','1234',?1,'FFFF',?2)",
        params!["FF".repeat(16), tcbm],
    )
    .unwrap();
    drop(db);
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let (status, response_headers, body) = get(
        offline(&destination),
        &format!(
            "/sgx/certification/v4/pckcert?qeid=BB&pceid=1234&cpusvn={}&pcesvn=FFFF",
            "FF".repeat(16)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_headers[headers::SGX_TCBM], tcbm);
    assert_eq!(body, cert.as_bytes());
    let response = offline(&destination)
        .oneshot(
            Request::builder()
                .uri(format!("/sgx/certification/v4/platforms?source=[{FMSPC}]"))
                .header(headers::ADMIN_TOKEN, "admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let rows: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(rows[0]["enc_ppid"], hex::encode_upper(ppid));
    assert_eq!(rows[0]["platform_manifest"], "");
    assert_eq!(rows[0]["pce_svn"], "FFFF");
}

/// Intent: invariant. Invalid snapshots are rejected before any destination
/// appears; checks include an empty table whose required column was lost.
#[test]
fn rejects_invalid_snapshot_without_publishing_or_mutating_source() {
    for (mutation,reason) in [
        ("ALTER TABLE pck_cert DROP COLUMN pck_cert", "pck_cert.pck_cert"),
        ("UPDATE pcs_version SET db_version=4", "db_version=5/api_version=4"),
        ("DROP TABLE enclave_identities", "missing required"),
        ("CREATE TABLE unexpected (data BLOB); INSERT INTO unexpected VALUES (x'1234')", "unsupported nonempty table"),
        ("INSERT INTO fmspc_tcbs VALUES ('1234567890AB',NULL,4,'STANDARD',CAST('{\"signature\":\"synthetic\"}' AS BLOB),1,3)", "expected integer"),
        ("INSERT INTO platform_tcbs VALUES ('AA','0000','00000000000000000000000000000000','0000','000000000000000000000000000000000000')", "missing platform join"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("snapshot.db");
        let destination = temp.path().join("rocks");
        let db = snapshot(&source);
        db.execute_batch(mutation).unwrap();
        drop(db);
        let original = std::fs::read(&source).unwrap();
        let output = import(&source,&destination);
        assert!(!output.status.success(), "invalid input was accepted: {mutation}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(),original);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(),1,"staging artifact leaked");
    }
}

/// Intent: regression/migration safety. Complete CRL syntax and full DER
/// consumption are required in every CRL source; rejection is read-only.
#[test]
fn rejects_malformed_crls_without_publishing_or_mutating_source() {
    let mut inner_trailing = CRL.to_vec();
    inner_trailing[1] += 1;
    inner_trailing.push(0);
    let mut trailing = CRL.to_vec();
    trailing.push(0);
    for payload in [vec![0x30, 1, 0], inner_trailing, trailing] {
        for table in ["pcs_certificates", "pck_crl", "crl_cache"] {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("snapshot.db");
            let destination = temp.path().join("rocks");
            let db = snapshot(&source);
            db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()])
                .unwrap();
            db.execute("INSERT INTO pcs_certificates VALUES (4,?1,NULL)", [SIGNING.as_bytes()])
                .unwrap();
            match table {
                "pcs_certificates" => db.execute("UPDATE pcs_certificates SET crl=?1 WHERE id=1", [&payload]),
                "pck_crl" => db.execute("INSERT INTO pck_crl VALUES ('PLATFORM',?1,1,4)", [&payload]),
                _ => db.execute("INSERT INTO crl_cache VALUES ('https://certificates.trustedservices.intel.com/IntelSGXRootCA.der',?1)", [&payload]),
            }.unwrap();
            drop(db);
            let original = std::fs::read(&source).unwrap();
            let output = import(&source, &destination);
            assert!(!output.status.success(), "malformed {table} CRL accepted: {payload:02x?}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains(table) && error.contains("DER"), "{error}");
            assert!(!destination.exists());
            assert_eq!(std::fs::read(&source).unwrap(), original);
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
    }
}

/// Intent: regression/migration safety. Certificate joins cannot silently choose
/// the last duplicate ID when a drifted source schema has lost its primary key.
#[test]
fn rejects_duplicate_certificate_ids_without_primary_key() {
    for second_cert in [ROOT, SIGNING] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("snapshot.db");
        let destination = temp.path().join("rocks");
        let db = snapshot(&source);
        db.execute_batch("DROP TABLE pcs_certificates; CREATE TABLE pcs_certificates (id INTEGER, cert BLOB, crl BLOB);").unwrap();
        for cert in [ROOT, second_cert] {
            db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [cert.as_bytes()])
                .unwrap();
        }
        drop(db);
        let original = std::fs::read(&source).unwrap();
        let output = import(&source, &destination);
        assert!(!output.status.success(), "duplicate certificate ID was accepted");
        assert!(String::from_utf8_lossy(&output.stderr).contains("pcs_certificates: duplicate id"));
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

/// Intent: invariant. A structurally incomplete signed envelope or wrong root
/// pointer cannot be migrated as a successful collateral response.
#[test]
fn rejects_unsigned_collateral_and_inconsistent_root_pointer() {
    for (body, root, reason) in [
        ("{\"tcbInfo\":{\"id\":\"SGX\",\"fmspc\":\"1234567890AB\"}}", 1, "signature"),
        (RAW_TCB, 3, "root_cert_id"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("snapshot.db");
        let destination = temp.path().join("rocks");
        let db = snapshot(&source);
        db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()]).unwrap();
        db.execute("INSERT INTO pcs_certificates VALUES (3,?1,NULL)", [SIGNING.as_bytes()])
            .unwrap();
        db.execute(
            "INSERT INTO fmspc_tcbs VALUES (?1,0,4,'STANDARD',?2,?3,3)",
            params![FMSPC, body.as_bytes(), root],
        )
        .unwrap();
        drop(db);
        let original = std::fs::read(&source).unwrap();
        let output = import(&source, &destination);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(reason),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }
}

/// Intent: migration safety. Public SGX v3/v4 and TDX v4 signed collateral
/// variants must not collapse into one product/version/update key.
#[tokio::test]
async fn retains_sgx_tdx_api_versions_and_update_variants() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let db = snapshot(&source);
    db.execute("INSERT INTO pcs_certificates VALUES (1,?1,NULL)", [ROOT.as_bytes()]).unwrap();
    db.execute("INSERT INTO pcs_certificates VALUES (3,?1,NULL)", [SIGNING.as_bytes()]).unwrap();
    let mut cases = Vec::new();
    for (prod, version) in [(0, 3), (0, 4), (1, 4)] {
        for update in ["STANDARD", "EARLY"] {
            let kind = if prod == 0 { "SGX" } else { "TDX" };
            // Actual PCS v3 SGX documents predate the v4 `id` discriminator.
            let id_field = if version == 3 { String::new() } else { format!("\"id\":\"{kind}\",") };
            let body = format!("{{\n \"tcbInfo\": {{{id_field}\"fmspc\":\"{FMSPC}\",\"tcbType\":0,\"tcbLevels\":[]}}, \"signature\":\"synthetic-{version}-{update}\"\n}}\n");
            db.execute(
                "INSERT INTO fmspc_tcbs VALUES (?1,?2,?3,?4,?5,1,3)",
                params![FMSPC, prod, version, update, body.as_bytes()],
            )
            .unwrap();
            let path = format!(
                "/{}/certification/v{version}/tcb?fmspc={FMSPC}&update={}",
                kind.to_ascii_lowercase(),
                update.to_ascii_lowercase()
            );
            cases.push((path, body, version));
        }
    }
    drop(db);
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    for (path, body, version) in cases {
        let (status, response_headers, response_body) = get(offline(&destination), &path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(response_body, body.as_bytes(), "{path}");
        assert_eq!(
            response_headers[headers::tcb_issuer_chain_name(version)],
            format!("{SIGNING}{ROOT}")
        );
    }
}

/// Intent: regression/migration safety. Known tables cannot carry silently lost
/// data columns, even when empty; only the documented audit columns are ignored.
#[test]
fn rejects_unrecognized_columns_in_known_tables() {
    for table in [
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
    ] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("snapshot.db");
        let destination = temp.path().join("rocks");
        let db = snapshot(&source);
        db.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN future_payload BLOB")).unwrap();
        drop(db);
        let original = std::fs::read(&source).unwrap();
        let output = import(&source, &destination);
        assert!(!output.status.success(), "unknown column in {table} was accepted");
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains(&format!("{table}.future_payload: unsupported column")));
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

/// Intent: migration safety (schema evidence only). Exact live DDL with real
/// NOT NULL timestamps/column order is accepted; payloads remain synthetic.
#[test]
fn accepts_live_v5_schema_with_timestamp_columns_and_bookkeeping() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    let db = Connection::open(&source).unwrap();
    db.execute_batch(include_str!("fixtures/intel-v5-live-schema.sql")).unwrap();
    db.execute("INSERT INTO pcs_version (id,api_version,server_addr,db_version,created_time,updated_time) VALUES (1,4,'api.trustedservices.intel.com',5,'synthetic-time','synthetic-time')",[]).unwrap();
    db.execute("INSERT INTO umzug VALUES ('05_db_version_5.js')", []).unwrap();
    drop(db);
    let original = std::fs::read(&source).unwrap();
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_rows"].as_object().unwrap().len(), 13);
    assert_eq!(report["source_rows"]["pcs_version"], 1);
    assert_eq!(report["source_rows"]["umzug"], 1);
    assert_eq!(report["destination_records"], 0);
    assert_eq!(std::fs::read(&source).unwrap(), original);
}

/// Intent: migration safety. Any existing destination, including an empty
/// directory or dangling symlink, is foreign and must remain unchanged.
#[cfg(unix)]
#[test]
fn refuses_preexisting_empty_nonempty_and_symlink_destinations() {
    use std::os::unix::fs::{symlink, MetadataExt};
    for kind in ["empty", "nonempty", "symlink", "dangling-symlink"] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("snapshot.db");
        let destination = temp.path().join("rocks");
        drop(snapshot(&source));
        let original = std::fs::read(&source).unwrap();
        let target = temp.path().join("foreign");
        if kind == "symlink" || kind == "dangling-symlink" {
            if kind == "symlink" {
                std::fs::create_dir(&target).unwrap();
            }
            symlink(&target, &destination).unwrap();
        } else {
            std::fs::create_dir(&destination).unwrap();
            if kind == "nonempty" {
                std::fs::write(destination.join("marker"), b"foreign data").unwrap();
            }
        }
        let inode = std::fs::symlink_metadata(&destination).unwrap().ino();
        let output = import(&source, &destination);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("destination already exists"));
        assert_eq!(std::fs::symlink_metadata(&destination).unwrap().ino(), inode);
        match kind {
            "nonempty" => {
                assert_eq!(std::fs::read(destination.join("marker")).unwrap(), b"foreign data")
            }
            "empty" => assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0),
            _ => assert_eq!(std::fs::read_link(&destination).unwrap(), target),
        }
        assert_eq!(std::fs::read(&source).unwrap(), original);
        let expected_paths = if kind == "symlink" { 3 } else { 2 };
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), expected_paths);
    }
}

/// Intent: invariant. A completed import is not a merge target; failed repeats
/// and missing/live sources leave both existing data and filesystem unchanged.
#[test]
fn refuses_existing_destination_missing_source_and_live_sidecars() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("snapshot.db");
    let destination = temp.path().join("rocks");
    drop(snapshot(&source));
    let output = import(&source, &destination);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let original_report = std::fs::read(destination.join("intel-import-report.json")).unwrap();
    let output = import(&source, &destination);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("destination already exists"));
    assert_eq!(
        std::fs::read(destination.join("intel-import-report.json")).unwrap(),
        original_report
    );
    let new_destination = temp.path().join("new-rocks");
    let missing = temp.path().join("missing.db");
    let output = import(&missing, &new_destination);
    assert!(!output.status.success());
    assert!(!missing.exists());
    assert!(!new_destination.exists());
    std::fs::write(temp.path().join("snapshot.db-wal"), b"not-a-standalone-snapshot").unwrap();
    let output = import(&source, &new_destination);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SQLite sidecars"));
    assert!(!new_destination.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o700);
    }
}
