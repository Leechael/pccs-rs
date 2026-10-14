-- Schema-only evidence from Intel PCCS 1.24 live sqlite_master, 2026-10-14 UTC.
-- DDL contains no production rows, credentials, BLOB contents or host addresses.
-- Kept separately from synthetic payload fixtures to catch source schema drift.
CREATE TABLE appraisal_policies (id VARCHAR(255) PRIMARY KEY, type INTEGER NOT NULL, policy TEXT NOT NULL, is_default INTEGER NOT NULL, fmspc VARCHAR(255) NOT NULL, created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL);
CREATE TABLE crl_cache (cdp_url VARCHAR(255) PRIMARY KEY, crl BLOB, created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL);
CREATE TABLE "enclave_identities" (id INTEGER NOT NULL, version INTEGER NOT NULL, update_type VARCHAR(255) NOT NULL, identity BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL, PRIMARY KEY(id, version, update_type));
CREATE TABLE "fmspc_tcbs" (fmspc VARCHAR(255) NOT NULL, type INTEGER NOT NULL, version INTEGER NOT NULL, update_type VARCHAR(255) NOT NULL, tcbinfo BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL, PRIMARY KEY(fmspc, type, version, update_type));
CREATE TABLE `pck_cert` (`qe_id` VARCHAR(255) NOT NULL, `pce_id` VARCHAR(255) NOT NULL, `tcbm` VARCHAR(255) NOT NULL, `pck_cert` BLOB, `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL, PRIMARY KEY (`qe_id`, `pce_id`, `tcbm`));
CREATE TABLE `pck_certchain` (`ca` VARCHAR(255) PRIMARY KEY, `root_cert_id` INTEGER, `intmd_cert_id` INTEGER, `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL);
CREATE TABLE `pck_crl` (`ca` VARCHAR(255) PRIMARY KEY, `pck_crl` BLOB, `root_cert_id` INTEGER, `intmd_cert_id` INTEGER, `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL);
CREATE TABLE `pcs_certificates` (`id` INTEGER PRIMARY KEY, `cert` BLOB, `crl` BLOB, `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL);
CREATE TABLE `pcs_version` (`id` INTEGER PRIMARY KEY, `api_version` INTEGER, `server_addr` VARCHAR(255), `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL, db_version INT DEFAULT 1);
CREATE TABLE `platform_tcbs` (`qe_id` VARCHAR(255) NOT NULL, `pce_id` VARCHAR(255) NOT NULL, `cpu_svn` VARCHAR(255) NOT NULL, `pce_svn` VARCHAR(255) NOT NULL, `tcbm` VARCHAR(255), `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL, PRIMARY KEY (`qe_id`, `pce_id`, `cpu_svn`, `pce_svn`));
CREATE TABLE `platforms` (`qe_id` VARCHAR(255) NOT NULL, `pce_id` VARCHAR(255) NOT NULL, `platform_manifest` BLOB, `enc_ppid` BLOB, `fmspc` VARCHAR(255), `ca` VARCHAR(255), `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL, PRIMARY KEY (`qe_id`, `pce_id`));
CREATE TABLE `platforms_registered` (`qe_id` VARCHAR(255) NOT NULL, `pce_id` VARCHAR(255) NOT NULL, `cpu_svn` VARCHAR(255) NOT NULL, `pce_svn` VARCHAR(255) NOT NULL, `enc_ppid` BLOB, `platform_manifest` BLOB, `state` INTEGER, `created_time` DATETIME NOT NULL, `updated_time` DATETIME NOT NULL, PRIMARY KEY (`qe_id`, `pce_id`, `cpu_svn`, `pce_svn`));
CREATE TABLE `umzug` (`name` VARCHAR(255) NOT NULL UNIQUE PRIMARY KEY);
