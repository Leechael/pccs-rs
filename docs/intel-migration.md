# Migrating an Intel PCCS SQLite snapshot

This is an offline restore, not a live-database upgrade. The importer never calls Intel, changes the source database, or starts an HTTP listener. It supports **Intel db_version 5 / PCS API version 4** snapshots. The SQL schema version is not the API route version; cached SGX v3 documents can coexist with v4 documents.

## Prepare a standalone snapshot

Use Intel SQLite's `VACUUM INTO` (or an equivalent consistent SQLite backup) on the running Intel instance, under its existing database user. Do not copy a live SQLite main file while omitting its journal/WAL. Do not restart or recreate the old container, alter its token hashes, run Sequelize sync/migrations, or use a draining registration-queue GET to collect data.

Keep the snapshot and backups in a protected directory. Platform Manifests and encrypted PPIDs are registration credentials; do not put snapshots in Git, public object storage, logs, or chat. Record the snapshot's SHA-256 and table counts. Obtain the live `sqlite_master` DDL as well. Validation covers required tables/columns, recognized columns and supported row values—not literal DDL, index or constraint equivalence. Recognized tables may include the known `created_time`/`updated_time` audit fields; other extra columns are rejected rather than silently discarded.

## Import into a fresh directory

Run the pinned new binary as the user that will own the new service's database:

```sh
pccs-rs db import-intel /protected/pccs-snapshot.db \
  --db-path /persistent/pccs-rs/cache
```

`/persistent/pccs-rs` must already exist and be writable by that user; `cache` must **not** exist, even as an empty directory or dangling symlink. Never point this command at the old live database or a running Rust store. Imports into existing destinations always fail; this is not an incremental merge command.

The command:

1. Opens a regular standalone source file read-only, rejects SQLite sidecars, checks database integrity and schema/version, and reads in one transaction.
2. Validates BLOB encodings, discriminators, issuer joins, PCK certificate metadata and raw-TCB references. Unknown nonempty tables, missing required columns, unrecognized columns in supported tables, duplicate certificate IDs, canonical-key collisions and unsupported values fail the import. Empty unknown tables and Intel's `umzug` bookkeeping are counted but have no runtime cache record.
3. Preserves every platform's full certificate pool, binary credentials as uppercase hex, and each SQL raw-TCB→certificate mapping. It does **not** infer raw SVN from `tcbm`, or reselect a different certificate during restore.
4. Preserves signed TCB/identity UTF-8 bodies byte-for-byte and encoded issuer chains in issuer-before-root order, including id-less legacy SGX v3 TCB envelopes. CRLs must parse as complete DER CRL structures and remain byte-exact binary DER; parsing is not signature verification. Queue states (including drained NOT_AVAILABLE decimal-PCE-SVN rows) and appraisal policy types/defaults are retained.
5. Writes one batch into a private sibling staging directory, closes and reopens RocksDB, verifies every key/value byte and record count, then atomically publishes the destination with a no-replace rename on Linux/macOS.

Success prints a JSON report and saves the same `intel-import-report.json` inside the destination. It contains the source SHA-256, source versions, all source table counts and destination record count—not credentials or signed payloads. Counts are not expected to match one-for-one: SQL chain/certificate rows are denormalized, pool certificates live inside platform records, and policies are grouped by FMSPC. SQL timestamps and migration bookkeeping are not runtime cache state; retain the original snapshot for those audit fields.

Failure before publication removes only this invocation's staging directory; it does not create, remove or replace the destination. A destination created by another process remains untouched. An interrupted/killed process can leave a private `.pccs-import-*` staging directory; inspect it before deleting or retrying. If publication succeeded but parent-directory syncing failed, the error explicitly says so: inspect the complete destination rather than blindly retrying. No existing destination is ever merged or replaced.

The importer validates data structure and joins, **not cryptographic authenticity, freshness, certificate revocation, or trust of arbitrary snapshots**. Legacy identity-envelope compatibility and PCK/TCBm metadata checks still require rehearsal against the real source snapshot; a rejected row must be investigated, not dropped or silently re-fetched. Attestation consumers must still verify the collateral against Intel trust anchors. Synthetic migration tests do not constitute a real production attestation test.

## Start alongside Intel PCCS

Use an explicitly persistent host directory/volume, a distinct port, the same Intel PCS API key, and direct Intel upstream:

```sh
pccs-rs serve --config /protected/staging.toml \
  --host 127.0.0.1 --port 18081 --http \
  --db-path /persistent/pccs-rs/cache --no-seed
```

Set `uri = "https://api.trustedservices.intel.com/sgx/certification/v4/"` and `cache_mode = "lazy"` in the new config. Never use either public PCCS hostname as the new upstream; that would recurse after cutover. Existing SHA-512 `UserTokenHash`/`AdminTokenHash` values are compatible. `config import` converts configuration only, not the SQLite database; explicitly override its old port and choose the new persistent database path.

Default startup no longer discovers development fixtures. Explicit `--seed` is a development fixture loader, not this restore command; a missing explicit file is fatal. `--no-seed` disables even an explicit seed. Packaged systemd and Docker commands pass `--no-seed` as a defense in depth.

Check database ownership with the actual runtime identity before starting. The packaged unit uses `DynamicUser` and `StateDirectory`; account for its managed state-directory ownership instead of making the cache world-readable. A Docker bind mount must be writable by uid 10001. The importer intentionally creates private 0700 directories.

The old Intel service stays on its original HTTPS port, untouched. Rust may use loopback HTTP behind Caddy. Do not reuse the old upstream's TLS settings for a plain-HTTP Rust upstream.

## Acceptance gates before cutover

- Compare source table counts and snapshot hash with the report; investigate every rejected or unexpected row.
- Replay **every recorded raw CPU/PCE SVN request**, checking status, PEM/certificate fingerprint, `SGX-TCBm`, FMSPC, CA type and issuer-chain fingerprints. Raw inputs come from `platform_tcbs`, not from splitting `tcbm`.
- For the indirect usc5 platform, verify a PPID-less GET and byte-exact recovery of its Manifest from the imported store. Keep it indirect; submitting the Manifest to Intel's registration service is unnecessary and irreversible.
- Compare SGX/TDX TCB and identity bytes, issuer chains, update/API variants, and CRL hashes. Check cryptographic verification and validity windows with the actual QCNL, dstack and dcap-qvl consumers.
- On a **clone of the new store**, test authenticated Manifest registration via POST `/platforms` and explicit PCK-pool refresh. As in Intel PCCS 1.24, a known-platform GET uses local selection only: it does not retry upstream with stored credentials if selection fails. Scheduled daily refresh is collateral-only, not a PCK-pool refresh. Never evict/alter the old production cache for a test.
- Restart **only the new service** and repeat probes to prove persistence, ownership and no fixture re-seeding.
- Take a final snapshot or reconcile source deltas. A newly registered indirect platform is a hard stop until its Manifest and collateral are migrated. Do not assume all between-snapshot rows can be refetched without client credentials.
- Confirm the exact release/commit, API key, proxy config, both public hostnames and owner-approved rollback procedure.

Only Leechael performs production changes. After all gates pass, Caddy can switch `/sgx*` and `/tdx*` for **both** `pccs.phala.network` and `pccs-de.phala.network` to the new loopback upstream using a validated reload, not an Intel PCCS restart. Keep the original container and its protected snapshot available.

## Rollback window

Switching Caddy back restores old-cache reads, but does not transfer registrations made on Rust after cutover. Hold registration/admin mutations during the rollback window, or arrange a protected registration journal/replay procedure—especially for indirect platforms. Do not destroy either store until reconciliation and the rollback window are explicitly complete.
