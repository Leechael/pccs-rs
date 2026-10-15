-- Synthetic db_version=5 fixture, shaped from Intel DCAP_1.24 DAO/migrations.
-- No production platform credentials or signed collateral are included.
CREATE TABLE pcs_version (id INTEGER PRIMARY KEY, api_version INTEGER, server_addr TEXT, db_version INTEGER);
CREATE TABLE platforms (qe_id TEXT, pce_id TEXT, platform_manifest BLOB, enc_ppid BLOB, fmspc TEXT, ca TEXT, PRIMARY KEY(qe_id,pce_id));
CREATE TABLE pck_cert (qe_id TEXT, pce_id TEXT, tcbm TEXT, pck_cert BLOB, PRIMARY KEY(qe_id,pce_id,tcbm));
CREATE TABLE platform_tcbs (qe_id TEXT, pce_id TEXT, cpu_svn TEXT, pce_svn TEXT, tcbm TEXT, PRIMARY KEY(qe_id,pce_id,cpu_svn,pce_svn));
CREATE TABLE pcs_certificates (id INTEGER PRIMARY KEY, cert BLOB, crl BLOB);
CREATE TABLE pck_certchain (ca TEXT PRIMARY KEY, root_cert_id INTEGER, intmd_cert_id INTEGER);
CREATE TABLE fmspc_tcbs (fmspc TEXT, type INTEGER, version INTEGER, update_type TEXT, tcbinfo BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, PRIMARY KEY(fmspc,type,version,update_type));
CREATE TABLE enclave_identities (id INTEGER, version INTEGER, update_type TEXT, identity BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, PRIMARY KEY(id,version,update_type));
CREATE TABLE pck_crl (ca TEXT PRIMARY KEY, pck_crl BLOB, root_cert_id INTEGER, intmd_cert_id INTEGER);
CREATE TABLE crl_cache (cdp_url TEXT PRIMARY KEY, crl BLOB);
CREATE TABLE platforms_registered (qe_id TEXT, pce_id TEXT, cpu_svn TEXT, pce_svn TEXT, enc_ppid BLOB, platform_manifest BLOB, state INTEGER, PRIMARY KEY(qe_id,pce_id,cpu_svn,pce_svn));
CREATE TABLE appraisal_policies (id TEXT PRIMARY KEY, type INTEGER, policy TEXT, is_default INTEGER, fmspc TEXT);
CREATE TABLE umzug (name TEXT PRIMARY KEY);
INSERT INTO pcs_version VALUES (1,4,'api.trustedservices.intel.com',5);
