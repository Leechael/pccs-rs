# Intel PCCS store contract (RocksDB rewrite spec)

Source: read-only Node PCCS at `/workspace/confidential-computing.tee.dcap.pccs/service` (models, migrations 00–05, DAOs, services, `pcs_client`, `pckCertSelection`, `config/default.json`). Do not treat this as a 1:1 table dump into RocksDB. Intel uses Sequelize + joins; the rewrite stores **one key = one GET response**. The registration queue is the only extra collection.

Config that affects the store (`config/default.json`):

| Field | Default | Store impact |
|---|---|---|
| `uri` | `https://api.trustedservices.intel.com/sgx/certification/v4/` | PCS base URL; `global.PCS_VERSION` parsed from `/vN/` (3 or 4). Hostname stored in `pcs_version.server_addr`; DB is invalid if hostname changes. |
| `ApiKey` | `""` | Sent as `Ocp-Apim-Subscription-Key` on PCK-cert fetches (always) and on **all** PCS calls if URI is the early-access portal `https://validation.api.trustedservices.intel.com/`. |
| `CachingFillMode` | `LAZY` | `LAZY` / `REQ` / `OFFLINE` — see §8. |
| `RefreshSchedule` | `0 0 1 * * *` | 6-field cron (sec min hour dom month dow). Scheduled refresh = collateral-only (no PCK certs). |
| `DB_CONFIG` / `sqlite.options.storage` | `sqlite` / `pckcache.db` | Intel backend. Rewrite: RocksDB. |

All hex identifiers are **uppercased** on the write path (qe_id, pce_id, cpu_svn, pce_svn, tcbm, fmspc, ca, enc_ppid, platform_manifest). Lengths: `qe_id` 1–260 chars; `pce_id` 4 hex; `cpu_svn` 32 hex; `pce_svn` 4 hex (LE uint16); `tcbm` 36 hex (cpusvn‖pcesvn); `fmspc` 12 hex; `enc_ppid` 768 hex.

---

## 1. Intel Sequelize models (current persistence)

No secondary SQL indexes. Uniqueness = composite PK. Every table has `created_time` / `updated_time` (Sequelize timestamps). Current schema is migration 05 (`db_version=5`, `api_version=4`). Extra table `umzug` is Umzug migration bookkeeping only — drop it.

### `pck_cert`

- PK `(qe_id, pce_id, tcbm)` — one PEM per Intel TCB level, **not** per raw TCB.
- `pck_cert` BLOB = PEM (decoded URI from PCS `cert`).
- Looked up two ways: (a) join via `platform_tcbs.tcbm` for GET `/pckcert`; (b) `findAll({qe_id,pce_id})` for selection.

### `platform_tcbs`

- PK `(qe_id, pce_id, cpu_svn, pce_svn)` — raw TCB → selected `tcbm`.
- This is the Intel join that GET `/pckcert` uses. In RocksDB this join is gone: the GET key **is** the raw TCB.

### `platforms`

- PK `(qe_id, pce_id)`.
- `platform_manifest` / `enc_ppid` BLOB (API hex ↔ binary via getters/setters).
- `fmspc`, `ca` (`PROCESSOR` \| `PLATFORM`) from PCS headers or X.509 issuer CN (`*Platform*` / `*Processor*`) + SGX ext OID `1.2.840.113741.1.13.1.4`.
- Presence of this row = “platform collateral is cached”. GET `/pckcert` then selects locally instead of calling PCS.

### `platforms_registered`  ← **only extra collection in the KV store**

- PK `(qe_id, pce_id, cpu_svn, pce_svn)`.
- `enc_ppid`, `platform_manifest` BLOB; `state` INTEGER: `0 NEW`, `1 NOT_AVAILABLE`, `9 DELETED`.
- Soft-delete only (`UPDATE state=9`). GET `source=reg` / `reg_na` **drains** (read + mark DELETED) in one transaction.
- Manifest-only POST zeros `cpu_svn`/`pce_svn`/`enc_ppid` → PK becomes `(qe,pce,'','')`.
- REQ-mode “Not available” rows store `cpu_svn` as lowercase 32-hex built from `sgxtcbcompNNsvn` and `pce_svn` as a **decimal integer string** (PCS `tcb.pcesvn`), not 4-hex LE.

### `fmspc_tcbs`

- PK `(fmspc, type, version, update_type)`.
- `type`: `0 SGX`, `1 TDX`. `version`: PCS API 3 or 4. `update_type`: `STANDARD` \| `EARLY`.
- `tcbinfo` BLOB = raw PCS JSON body `{tcbInfo, signature}`.
- `root_cert_id=1`, `signing_cert_id=3`. GET returns null if either cert is missing.

### `enclave_identities`

- PK `(id, version, update_type)`.
- `id`: `1 QE`, `2 QVE`, `3 TDQE`. `identity` BLOB = raw PCS JSON.
- Same cert-id rule as TCB (1 + 3).

### `pck_crl`

- PK `ca` (`PROCESSOR` \| `PLATFORM`).
- `pck_crl` BLOB = DER. `root_cert_id=1`, `intmd_cert_id` = 2 (PROCESSOR) or 4 (PLATFORM).

### `pck_certchain`

- PK `ca`. Pointers only: `root_cert_id=1`, `intmd_cert_id` = 2 or 4.
- GET `/pckcert` concatenates `intmd_cert + root_cert` (URL-encoded PEMs) into `SGX-PCK-Certificate-Issuer-Chain`.

### `pcs_certificates`

- PK `id`: `1` Intel SGX Root CA + its CRL; `2` Processor intermediate; `3` Processor signing (TCB/identity); `4` Platform intermediate.
- `cert` BLOB = URL-encoded PEM (`-----BEGIN%20CERTIFICATE-----`). `crl` BLOB on id=1 = root CA CRL DER.
- Split helper: last `-----BEGIN%20CERTIFICATE-----` in a header chain → `[intermediate, root]`.

### `crl_cache`

- PK `cdp_url` (exact request `uri`). `crl` BLOB = DER.

### `appraisal_policies`

- PK `id` = SHA-384 hex of `policy` UTF-8.
- `type` 0/1/2 from JWT `class_id` (SGX / TDX 1.0 / TDX 1.5). `is_default` INTEGER. `fmspc`. `policy` TEXT (JWT).
- PUT that sets `is_default` first clears other defaults for that fmspc. GET returns comma-joined default policy strings.

### `pcs_version`

- Single row `id=1`: `api_version`, `server_addr` (PCS hostname), `db_version=5`.
- Intel refuses to start if `server_addr ≠ uri.hostname`. Optional meta key in RocksDB; not required for GET serving.

Issuer-chain header names: v3 `SGX-TCB-Info-Issuer-Chain`; v4 `TCB-Info-Issuer-Chain`. Identity always `SGX-Enclave-Identity-Issuer-Chain`. PCK CRL always `SGX-PCK-CRL-Issuer-Chain`.

---

## 2. How each GET looks up rows

Every public GET is cache-first. Miss behavior is mode-dependent (§8). Keys below are the **rewrite** keys (Intel SQL is noted in parentheses).

### `GET /sgx/certification/v{3,4}/pckcert`

Query (all uppercased): `qeid`, `cpusvn` (32 hex), `pcesvn` (4 hex), `pceid` (4 hex), optional `encrypted_ppid` (768 hex).

Intel path:

1. `platforms.findOne({qe_id, pce_id})`.
2. If platform exists: join `platform_tcbs` ⋈ `pck_cert` ⋈ `platforms` ⋈ `pck_certchain` ⋈ `pcs_certificates` on `(qe_id,pce_id,cpu_svn,pce_svn)` → `tcbm` → cert + issuer PEMs. Null if chain certs missing. >1 row → 500.
3. If join misses and platform exists: run PCK selection (§6) using `platform.fmspc` / `platform.ca`, persist new `platform_tcbs` row, return selected cert.
4. If platform is null: `cachingMode.getPckCertFromPCS(...)` (LAZY fetches; REQ/OFFLINE → 461).

**RocksDB:** `pckcert/{qeid}/{pceid}/{cpusvn}/{pcesvn}` → value is the full response:

```
cert                         PEM
SGX-TCBm                     selected tcbm (36 hex)
SGX-FMSPC                    fmspc
SGX-PCK-Certificate-CA-Type  PROCESSOR | PLATFORM
SGX-PCK-Certificate-Issuer-Chain   intmd + root (URL-encoded PEMs)
```

Controller: `Content-Type: application/x-pem-file`, body = `cert`.

If this key is missing but a **platform** is known (see `meta/platform/{qeid}/{pceid}` under the registration/collateral write path), the server must run selection and **write this key** before responding. If the platform is unknown, follow §8.

### `GET /sgx|tdx/certification/v{3,4}/tcb`

Query: `fmspc` (12 hex), `update` default `STANDARD` (`EARLY` allowed). `type` from router (SGX=0 / TDX=1). `version` from URL.

Intel: `fmspc_tcbs` exact PK + join signing/root certs. Miss → PCS (LAZY) or 404.

**RocksDB:** `tcb/{sgx|tdx}/{fmspc}/{version}/{STANDARD|EARLY}` → `{ tcbinfo: raw JSON bytes, issuer_chain }`.

Response header = `TCB-Info-Issuer-Chain` (v4) or `SGX-TCB-Info-Issuer-Chain` (v3). Body = raw `tcbinfo` JSON. v3 miss in LAZY is 410 (PCS v3 EOL), not a fetch.

### `GET .../qe/identity` | `/qve/identity` | TDX `/qe/identity`

Query: `update` default `STANDARD`. `id` from path (1/2/3). `version` from URL.

Intel: `enclave_identities` exact PK + cert join.

**RocksDB:** `identity/{qe|qve|tdqe}/{version}/{STANDARD|EARLY}` → `{ identity: raw JSON bytes, issuer_chain: SGX-Enclave-Identity-Issuer-Chain }`.

### `GET /pckcrl`

Query: `ca` (`processor`\|`platform`, stored upper), optional `encoding`.

Intel: `pck_crl` by `ca` + cert join.

**RocksDB:** `pckcrl/{PROCESSOR|PLATFORM}` → `{ pckcrl: DER bytes, issuer_chain }`.

If `encoding` is not `DER`, body is hex of the DER (`Content-Type: application/x-pem-file`); if `DER`, raw bytes (`application/pkix-crl`).

### `GET /rootcacrl`

Intel: `pcs_certificates.id=1`.crl. If missing, fetch QE identity STANDARD to populate root cert, parse CDP, download CRL, store on id=1.

**RocksDB:** `rootcacrl` → DER bytes. Response is **hex** of those bytes, `Content-Type: application/pkix-crl` (Intel backward-compat).

### `GET /crl?uri=`

`uri` max 2048, must match Intel allow-list (`isValidCrlUri`):

- `https://([a-zA-Z0-9-]*certificates.trustedservices.intel.com|certprx.adsdcsp.com)/IntelSGXRootCA...`
- `https://([a-zA-Z0-9-]*\.?api.trustedservices.intel.com|[a-zA-Z0-9-]+\.az.sgx(prod|np).adsdcsp.com)/sgx/certification/vN/pckcrl?...`

Intel: `crl_cache.findByPk(uri)`.

**RocksDB:** `crl/{uri}` → DER bytes. `Content-Type: application/pkix-crl`.

### `GET /appraisalpolicy?fmspc=`

Intel: `appraisal_policies WHERE is_default AND fmspc`. 404 if empty. Body = `policy` strings joined by `,`.

**RocksDB:** `appraisal/{fmspc}` → comma-joined default policy string(s). Individual policy id is only the PUT response, not a GET key.

### `GET /platforms`  (admin)

`source` query:

| `source` | Behavior |
|---|---|
| omitted or `reg` | **NEW drain:** read all `state=0`, then set those rows to `state=9`, return the snapshot. Transactional. Header `platform-count`. |
| `reg_na` | Same drain for `state=1` (NOT_AVAILABLE). |
| `[fmspc,fmspc,...]` (brackets required) | Cached platforms whose `fmspc` is in the list. Empty `[]` = **all** cached platforms. Each fmspc validated 12 hex. **Does not drain.** |

Returned fields: `qe_id, pce_id, cpu_svn, pce_svn, enc_ppid, platform_manifest`.

- Drain path: hex via JS `Buffer.toString('hex')` → **lowercase**.
- fmspc path (Intel SQL `hex()`): typically **uppercase**.

Intel fmspc listing is `platforms ⋈ platform_tcbs` (one row per raw TCB). Empty fmspc list skips the `IN` filter.

**RocksDB:** this is the only non-GET-response collection — see `reg/` in §9. For `source=[fmspc]` walk `meta/fmspc/{fmspc}/...` (written when a pckcert/platform is stored).

---

## 3. How `PUT /platformcollateral` writes

Admin. Version from URL. Body `{ platforms[], collaterals }` validated by AJV (`PLATFORM_COLLATERAL_SCHEMA_V3` if version<4, else V4). One Sequelize transaction. Integrity: every issuer-chain’s root PEM (after `split_chain`) must be byte-identical or 460.

Write effects mapped to **API keys** (do not recreate Intel tables):

1. **PCK certs** (`collaterals.pck_certs[]`): for each `(qe_id,pce_id)` flush that platform’s certs, decode URI certs, parse first cert for `fmspc`/`ca`. Pick TCB info for that fmspc — prefer `*_early` over standard; v3 fields `tcbinfo`/`tcbinfo_early`, v4 `sgx_tcbinfo`/`tdx_tcbinfo`/`sgx_tcbinfo_early`/`tdx_tcbinfo_early`. Merge request platforms that have `cpu_svn`+`pce_svn` with already-cached raw TCBs for that qe/pce. Run `selectBestPckCert` per raw TCB. **Write one `pckcert/{qe}/{pce}/{cpusvn}/{pcesvn}` per selected mapping.** Also write `meta/platform/{qe}/{pce}` = `{fmspc,ca,enc_ppid,platform_manifest}` and `meta/fmspc/{fmspc}/{qe}/{pce}`.
2. **TCB infos:** for each present type field, write `tcb/{sgx|tdx}/{fmspc}/{version}/{STANDARD|EARLY}` with `JSON.stringify(tcbinfo[type])` as body and the payload’s issuer chain.
3. **PCK CRLs:** `pckcacrl.processorCrl` / `platformCrl` are hex DER → `pckcrl/{PROCESSOR|PLATFORM}`.
4. **Identities:** `qeidentity`/`qeidentity_early`/`qveidentity`/`qveidentity_early`/`tdqeidentity`/`tdqeidentity_early` → `identity/{qe|qve|tdqe}/{version}/{STANDARD|EARLY}`.
5. **Issuer chains** in `collaterals.certificates`: denormalize into the tcb/identity/pckcert/pckcrl values (do not store a cert-id table). Required: `SGX-PCK-Certificate-Issuer-Chain.{PROCESSOR,PLATFORM}`. TCB chain name is version-dependent. Identity: `SGX-Enclave-Identity-Issuer-Chain`.
6. **Root CA CRL:** `rootcacrl` hex → `rootcacrl`. If `rootcacrl_cdp` present, also `crl/{cdp}`.

v4 `collaterals.version` must be 4. v3 schema uses `tcbinfo` (not `sgx_tcbinfo`). Empty `certs[]` → 400.

---

## 4. `POST /platforms` and `GET /platforms`

### POST (user token)

Query `update` = `STANDARD` (default) \| `EARLY` \| `ALL` (`canBeAll=true` only here). Body: `{qe_id, pce_id}` required; optional `cpu_svn`, `pce_svn`, `enc_ppid`, `platform_manifest` (`PLATFORM_REG_SCHEMA`).

Normalize:

- Uppercase `qe_id`, `pce_id`.
- If `platform_manifest` is non-empty: set `cpu_svn=pce_svn=enc_ppid=''`.
- Else: require `cpu_svn`, `pce_svn`, `enc_ppid`; set `platform_manifest=''`; uppercase the three.

Cache-hit test (`checkPCKCertCacheStatus`):

- No `platforms` row → not cached.
- Request has no manifest: copy cached manifest; cached iff `pckcert` join hits for this raw TCB.
- Request has manifest ≠ cached manifest → not cached.
- Else cached.

Then `cachingMode.registerPlatforms(isCached, reg, update)` — §8. Response is always `200 Operation successful.` (no body collateral).

### GET — NEW drain (detail)

```
BEGIN
  SELECT qe_id,pce_id,cpu_svn,pce_svn,platform_manifest,enc_ppid
    FROM platforms_registered WHERE state = 0;   -- NEW
  UPDATE platforms_registered SET state = 9 WHERE state = 0;
COMMIT
→ header platform-count = N, body = JSON array
```

`reg_na` is identical with `state=1`. Rows already `9` are never returned. This is how PCCS Admin Tool / OFFLINE air-gap export works.

`source=[fmspc,...]`: not a queue. List cached platforms (one JSON object per raw TCB that has a `pckcert/` key) filtered by fmspc.

---

## 5. Refresh

Refreshable only in LAZY and REQ (`isRefreshable()`). OFFLINE → 503.

### `GET|POST /refresh` (admin)

| Query | What it refetches |
|---|---|
| no `type` | **Not** PCK certs. If `PCS_VERSION>3`: all cached `pckcrl/*`, all cached `tcb/*` with `version>3`, identities QE/QVE/TDQE × v4 × {STANDARD,EARLY}. Always: `rootcacrl` (re-download via root cert CDP) and every `crl/*`. v3-only rows are skipped (warn). |
| `type=certs` + `fmspc` (required, single 12 hex) | For every cached platform whose fmspc matches: PCS `pckcerts` (manifest POST or enc_ppid GET), PCS SGX TCB **EARLY**, re-select every raw TCB, rewrite those `pckcert/{qe}/{pce}/{cpusvn}/{pcesvn}` keys and issuer chain. |

Identity refresh uses the first HTTP 200’s `SGX-Enclave-Identity-Issuer-Chain` for all. TCB refresh writes issuer chain from each response (`TCB-Info-Issuer-Chain` on v4). A non-200 on TCB/CRL refresh → 503. Missing identity is logged and skipped.

### Scheduled (`RefreshSchedule`)

Same as “no `type`”. Never refreshes PCK certs. Failures are logged, not returned.

Intel also deletes leftover `fmspc_tcbs` rows with `type IS NULL` before TCB refresh (migration leftover). Irrelevant if we never store that shape.

---

## 6. PCK cert selection

Implementation: `pckCertSelection/pckCertSelection.js` (`selectBestPckCert`). Pure function. Persist only the **result** (the GET `/pckcert` value).

### When it runs

1. GET `/pckcert` — platform cached, raw-TCB key missing.
2. `getPckCertFromPCS` (LAZY miss / POST register) — after PCS returns the cert array; also re-selects every already-known raw TCB for that platform.
3. PUT `/platformcollateral` — every raw TCB (request ∪ previously cached).
4. Refresh `type=certs` — every raw TCB of matching-fmspc platforms.

### Inputs

| Arg | Meaning |
|---|---|
| `rawCpusvn` | 32-hex raw CPUSVN |
| `rawPcesvn` | 4-hex LE; converted via byte-swap to integer |
| `pceid` | 4 hex; must equal TCB info `pceId` and every cert’s PCEID |
| `pckCertData` | `[{ tcbm, pck_cert }]` — PEM, not the PCS `tcb` object |
| `tcbInfo` | `tcbInfo` object (not the wrapper). **Always SGX**, never TDX. Prefer EARLY, else STANDARD. |

TCB info must have `tcbType===0`, non-empty `tcbLevels[]`, each with `sgxtcbcomponents[]` and integer `pcesvn≥0`. Every PCK cert: X.509 version 3, same PPID, FMSPC = tcbInfo.fmspc.

### Algorithm

1. Parse each PEM → `Tcb(cpusvn_from_sgx_ext, pcesvn_int)`.
2. One bucket per TCB-info level (`sgxtcbcomponents[i].svn` → 16-byte CPUSVN + `pcesvn`). Sort buckets descending (`Tcb.compare`). Non-comparable TCBs keep original order.
3. Place each cert into the first bucket where `cert.tcb >= bucket.tcb`. Inside a bucket, insert descending. Unmatched certs go to a trailing bucket.
4. Walk buckets then certs; first cert with `rawTCB >= cert.tcb` wins. Return the original `{tcbm, pck_cert}` record.

`Tcb.compare`: 17 components (16 CPUSVN bytes + PCESVN). All ≤ → -1; all ≥ → +1; mixed → `TcbNonComparableError` (skip). No match → throw → Intel maps to 404 / 400 (collateral PUT).

### Outputs written

`pckcert/{qeid}/{pceid}/{cpusvn}/{pcesvn}` = selected PEM + `tcbm` + platform `fmspc`/`ca` + issuer chain. Intel also upserts `platform_tcbs`; we do not keep that table.

LAZY + PCS response contains any `cert === "Not available"` (after `decodeURIComponent`): **do not** write the new raw-TCB key (`needUpdatePlatformTcbs(false)`). REQ always writes. Re-selection of already-known raw TCBs always writes.

---

## 7. PCS client

Module: `pcs_client/pcs_client.js`. `got` + optional `caw` proxy. Timeout 120s, retry limit 6, `throwHttpErrors=false`. Any `/v3/` URL → 410 EOL. Logs `request-id`, `warning`, URL (query values >50 chars truncated).

### URLs (base = `config.uri`, TDX = replace `/sgx/` → `/tdx/`)

| Call | Method | URL | Query / body | API key? |
|---|---|---|---|---|
| `getCerts` | GET | `{uri}pckcerts` | `encrypted_ppid`, `pceid` | **yes** |
| `getCertsWithManifest` | POST | `{uri}pckcerts` | JSON `{platformManifest, pceid}` | **yes** + `Content-Type: application/json` |
| `getPckCrl` | GET | `{uri}pckcrl` | `ca=processor\|platform` (lower), `encoding=der` | no (unless early-access host) |
| `getTcb` | GET | `{uri}tcb` or TDX | `fmspc`, `update=standard\|early` (lower) | no |
| `getEnclaveIdentity` | GET | `{uri}qe/identity` \| `{uri}qve/identity` \| TDX `qe/identity` | `update=standard\|early` | no |
| `getFileFromUrl` | GET | absolute CDP / CRL URI | — | no |

Early-access: if URL starts with `https://validation.api.trustedservices.intel.com/`, **every** request gets `Ocp-Apim-Subscription-Key: {ApiKey}`.

Commented-out single-cert `pckcert` GET is unused. Encrypted PPID of all zeros is rejected before the call.

### Response headers to keep (denormalize into the GET-response value)

| Header | Used for |
|---|---|
| `SGX-PCK-Certificate-Issuer-Chain` | pckcert + pckcrl issuer (URL-encoded PEM pair) |
| `SGX-FMSPC` | platform meta + pckcert header (uppercase) |
| `SGX-PCK-Certificate-CA-Type` | `PROCESSOR` \| `PLATFORM` |
| `TCB-Info-Issuer-Chain` (v4) / `SGX-TCB-Info-Issuer-Chain` (v3) | tcb value |
| `SGX-Enclave-Identity-Issuer-Chain` | identity value |
| `SGX-PCK-CRL-Issuer-Chain` | pckcrl value |
| `request-id`, `warning` | log only |
| `error-code`, `error-message` | log on HTTP 400 only |

PCK certs body: JSON array `{ tcb: {sgxtcbcomp01svn…16, pcesvn}, tcbm, cert }` where `cert` is URI-encoded PEM or `"Not available"`. Filter `"Not available"` before store; REQ also enqueues those TCB levels as `reg/` `NOT_AVAILABLE`.

Non-200 on a fetch that is supposed to fill cache → 404 `No cache data for this platform.` (except refresh TCB/CRL → 503). Network failure → 502.

---

## 8. Caching mode (reads / writes)

Set from `CachingFillMode` at process start.

| | LAZY | REQ | OFFLINE |
|---|---|---|---|
| GET miss (pckcert, no platform) | Fetch PCS, write GET keys, return | **461** Platform unknown (does **not** fetch) | **461** |
| GET miss (tcb / identity / pckcrl / crl / rootcacrl) | Fetch PCS, write that GET key | **404** (no fetch) | **404** |
| GET `/pckcert` platform known, raw TCB missing | Local selection; write `pckcert/...` | same | same |
| POST `/platforms` not cached | `getPckCertFromPCS` + QV fill (`checkQuoteVerificationCollateral`) | Insert `reg/` NEW, fetch PCS, mark that row DELETED, QV fill. Also `reg/` NOT_AVAILABLE for `"Not available"` certs | Insert `reg/` NEW only. No PCS |
| POST `/platforms` cached | QV fill only | QV fill only | no-op |
| QV fill (`update`) | If missing: both PCK CRLs; identities QE+QVE (+TDQE if v4) × requested update set (`STANDARD` / `EARLY` / both for `ALL`); rootcacrl | same | never |
| Refresh / scheduler | yes | yes | 503 / no-op |
| Write new raw-TCB key after PCS if any cert is `"Not available"` | **no** | **yes** | n/a |

v3 GET on a PCS-backed path: LAZY/REQ miss is 410 (EOL), not a network call.

`getPckCertFromPCS` write set (single transaction in Intel): `meta/platform`, delete+rewrite that platform’s `pckcert/*` raw-TCB keys (re-select existing raw TCBs), `tcb/sgx/{fmspc}/{ver}/{EARLY,STANDARD}` (STANDARD required; EARLY optional), v4 also `tcb/tdx/...` if PCS returns them, issuer chains folded into those values. If raw TCB was omitted (manifest-only register), it returns `{}` and does not write a new raw-TCB key.

---

## 9. RocksDB key layout (API-keyed, no joins)

One key = one GET response. Values are self-contained (body + response headers). No cert-id table, no `pck_certchain`, no `platform_tcbs`, no `fmspc_tcbs` as a separate relation. The **only** extra prefix is the registration queue (plus tiny write-side meta so PUT/POST/refresh/selection can find “all raw TCBs for this platform” and “all platforms for this fmspc”).

```
# ---- GET responses (serve these, do not join) ----
pckcert/{qeid}/{pceid}/{cpusvn}/{pcesvn}
    → { cert, tcbm, fmspc, ca, issuer_chain }

tcb/{sgx|tdx}/{fmspc}/{version}/{STANDARD|EARLY}
    → { tcbinfo, issuer_chain }

identity/{qe|qve|tdqe}/{version}/{STANDARD|EARLY}
    → { identity, issuer_chain }

pckcrl/{PROCESSOR|PLATFORM}
    → { pckcrl_der, issuer_chain }

rootcacrl
    → der

crl/{uri}
    → der

appraisal/{fmspc}
    → comma-joined default policy string

# ---- registration queue (GET /platforms drain) ----
reg/{NEW|NA}/{qeid}/{pceid}/{cpusvn}/{pcesvn}
    → { enc_ppid, platform_manifest, state }
# drain: prefix-scan reg/NEW/ or reg/NA/, return values, delete those keys
# (Intel soft-deletes to state=9; hard-delete is fine — DELETED is never read)

# ---- write-side meta only (not served as GET bodies) ----
meta/platform/{qeid}/{pceid}
    → { fmspc, ca, enc_ppid, platform_manifest }
    # "platform is cached"; selection + POST cache-hit test

meta/fmspc/{fmspc}/{qeid}/{pceid}
    → {}
    # GET /platforms?source=[fmspc]; refresh type=certs

meta/rawtcb/{qeid}/{pceid}/{cpusvn}/{pcesvn}
    → tcbm
    # iterate raw TCBs on collateral PUT / cert refresh / re-selection
    # (same coords as pckcert/; kept so a prefix scan is cheap)

meta/certs/{qeid}/{pceid}/{tcbm}
    → pem
    # the Intel cert *set* (one PEM per Intel TCB level). Needed to re-run
    # selectBestPckCert when a new raw TCB shows up. Not a GET key.

meta/appraisal/{fmspc}/{id}
    → { policy, is_default, type }
    # PUT bookkeeping so a new default can unset the previous one, then
    # rebuild appraisal/{fmspc}

meta/version
    → { api_version, server_addr, db_version }   # optional
```

### Scan / write rules

| Operation | Keys |
|---|---|
| GET `/pckcert` | `get pckcert/{qe}/{pce}/{cpu}/{pce_svn}`. Miss + `meta/platform` exists → select using `meta/certs/{qe}/{pce}/*` + `tcb/sgx/{fmspc}/{ver}/EARLY` else STANDARD → put the GET key + `meta/rawtcb`. Miss + no platform → §8. |
| GET `/tcb` `/qe|qve/identity` `/pckcrl` `/crl` `/rootcacrl` `/appraisalpolicy` | single get of that prefix |
| GET `/platforms?source=reg` | prefix `reg/NEW/`, collect, delete |
| GET `/platforms?source=reg_na` | prefix `reg/NA/`, collect, delete |
| GET `/platforms?source=[fmspc,...]` | for each fmspc, prefix `meta/fmspc/{fmspc}/`, then for each qe/pce prefix `meta/rawtcb/{qe}/{pce}/` + `meta/platform` to build the JSON rows. Empty list: prefix `meta/platform/` |
| PUT `/platformcollateral` | rewrite `meta/certs/{qe}/{pce}/*`, re-select every `meta/rawtcb` ∪ request raw TCBs, put each `pckcert/...`, put tcb/identity/pckcrl/rootcacrl/crl keys, put `meta/platform` + `meta/fmspc` |
| POST `/platforms` | maybe put `reg/NEW/...`; maybe PCS fill (same key set as GET miss) |
| Refresh no type | rewrite every `pckcrl/*`, `tcb/*` with version>3, all 6 identity keys, `rootcacrl`, every `crl/*` |
| Refresh `type=certs` | platforms under `meta/fmspc/{fmspc}/` → PCS pckcerts + SGX EARLY tcb → rewrite `meta/certs` + every `pckcert/{qe}/{pce}/*` |

All hex path segments uppercase. Values: JSON or length-prefixed blobs; PEM/JSON/DER as Intel stores them (cert chains stay URL-encoded). Writes that Intel wraps in `sequelize.transaction` must be a RocksDB `WriteBatch`.

This layout answers every GET without joins. `meta/certs` + `meta/rawtcb` exist only so selection/refresh/PUT can rebuild GET keys — they are not a Sequelize clone.
