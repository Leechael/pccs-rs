//! Request parameter validation matching Node `validatorService.js` + controllers.

use crate::error::{self, PccsError};
use serde_json::Value;
use std::collections::HashMap;

fn is_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hex_or_empty(value: &str, expected_len: usize) -> bool {
    value.is_empty() || is_hex(value, expected_len)
}

/// Percent-decoding over raw bytes (a `%XX` escape can land mid-UTF-8, so the
/// input must never be sliced as `&str`). Shared by the collateral loader and
/// the upstream client — Node uses `decodeURIComponent` in both places.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-decoding for a query component: `+` also means space.
fn query_decode(s: &str) -> String {
    percent_decode(&s.replace('+', " "))
}

/// Node `middleware/filterDuplicatedParams.js`: when a name repeats, the FIRST
/// occurrence wins (`Array.isArray(value) ? value[0] : value`).
pub fn query_params(query: Option<&str>) -> Result<HashMap<String, String>, PccsError> {
    let mut out: HashMap<String, String> = HashMap::new();
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return Ok(out);
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // An empty key (`?=x`) is not an error: Express parses the query with
        // `qs`, which happily produces a `''` key. Rejecting it would 400 a
        // request Node answers normally — and no PCCS parameter is ever read
        // under the empty name, so the entry is simply inert.
        let key = query_decode(raw_key);
        out.entry(key).or_insert_with(|| query_decode(raw_value));
    }
    Ok(out)
}

pub fn require_hex(
    value: Option<&str>,
    field: &str,
    expected_len: usize,
) -> Result<String, PccsError> {
    let Some(v) = value.filter(|s| !s.is_empty()) else {
        tracing::error!("{field} field is missing");
        return Err(error::INVALID_REQ);
    };
    if !is_hex(v, expected_len) {
        tracing::error!("{field} field is not valid hex string : {v}");
        return Err(error::INVALID_REQ);
    }
    Ok(v.to_ascii_uppercase())
}

pub fn fmspc(value: Option<&str>) -> Result<String, PccsError> {
    require_hex(value, "fmspc", 12)
}

pub fn cpusvn(value: Option<&str>) -> Result<String, PccsError> {
    require_hex(value, "cpusvn", 32)
}

pub fn pcesvn(value: Option<&str>) -> Result<String, PccsError> {
    require_hex(value, "pcesvn", 4)
}

pub fn pceid(value: Option<&str>) -> Result<String, PccsError> {
    require_hex(value, "pceid", 4)
}

/// `encrypted_ppid` may be omitted entirely (Node: `null`/`undefined` skips the
/// check). Present but empty is a validation failure — Node runs
/// `isHex('', 768)`, which is false.
pub fn encrypted_ppid(value: Option<&str>) -> Result<Option<String>, PccsError> {
    match value {
        None => Ok(None),
        Some(v) => require_hex(Some(v), "encrypted ppid", 768).map(Some),
    }
}

/// qeid: required, max 260 chars, uppercased (not required to be hex).
pub fn qeid(value: Option<&str>) -> Result<String, PccsError> {
    const QEID_MAX: usize = 260;
    let Some(v) = value.filter(|s| !s.is_empty()) else {
        tracing::error!("qeid field is missing");
        return Err(error::INVALID_REQ);
    };
    if v.len() > QEID_MAX {
        tracing::error!("qeid field is not valid length (max {QEID_MAX}) : {v}");
        return Err(error::INVALID_REQ);
    }
    Ok(v.to_ascii_uppercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    Standard,
    Early,
    All,
}

impl UpdateType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::Early => "EARLY",
            Self::All => "ALL",
        }
    }
}

pub fn update_type(value: Option<&str>, can_be_all: bool) -> Result<UpdateType, PccsError> {
    let raw = value.unwrap_or("STANDARD").to_ascii_uppercase();
    match raw.as_str() {
        "STANDARD" => Ok(UpdateType::Standard),
        "EARLY" => Ok(UpdateType::Early),
        "ALL" if can_be_all => Ok(UpdateType::All),
        other => {
            tracing::error!("Invalid update type : {other}");
            Err(error::INVALID_REQ)
        }
    }
}

pub fn pck_ca(value: Option<&str>) -> Result<String, PccsError> {
    let ca = value.unwrap_or("").to_ascii_uppercase();
    if ca != "PROCESSOR" && ca != "PLATFORM" {
        tracing::error!("ca is not valid : {ca}");
        return Err(error::INVALID_REQ);
    }
    Ok(ca)
}

/// Node `apputil.getApiVersionFromUrl`.
pub fn api_version_from_url(url: &str) -> Result<u32, PccsError> {
    // /v([1-9][0-9]*)/
    let bytes = url.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'/'
            && bytes[i + 1] == b'v'
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 2] != b'0'
        {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'/' {
                if let Ok(ver) = url[i + 2..j].parse::<u32>() {
                    if ver == 3 || ver == 4 {
                        return Ok(ver);
                    }
                }
            }
        }
        i += 1;
    }
    Err(error::INVALID_REQ)
}

/// Node `isValidCrlUri`.
pub fn is_valid_crl_uri(uri: &str) -> bool {
    const MAX: usize = 2048;
    if uri.is_empty() || uri.len() > MAX {
        return false;
    }
    is_root_crl_uri(uri) || is_intermediate_crl_uri(uri)
}

fn is_root_crl_uri(uri: &str) -> bool {
    // ^https://([a-zA-Z0-9-]*certificates\.trustedservices\.intel\.com|certprx\.adsdcsp\.com)/IntelSGXRootCA\..*$
    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path)) = rest.split_once('/') else {
        return false;
    };
    let host_ok = host == "certprx.adsdcsp.com"
        || (host.ends_with("certificates.trustedservices.intel.com")
            && host[..host
                .len()
                .saturating_sub("certificates.trustedservices.intel.com".len())]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    host_ok && path.starts_with("IntelSGXRootCA.") && path.len() > "IntelSGXRootCA.".len()
}

fn is_intermediate_crl_uri(uri: &str) -> bool {
    // ^https://(api host)/sgx/certification/v([1-9][0-9]*)/pckcrl\?.*$
    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path_q)) = rest.split_once('/') else {
        return false;
    };
    let host_ok = is_intermediate_host(host);
    if !host_ok {
        return false;
    }
    let Some((path, query)) = path_q.split_once('?') else {
        return false;
    };
    if query.is_empty() {
        return false;
    }
    // sgx/certification/vN/pckcrl  with N >= 1, no leading zero
    let Some(ver_and_rest) = path.strip_prefix("sgx/certification/v") else {
        return false;
    };
    let Some((ver, tail)) = ver_and_rest.split_once('/') else {
        return false;
    };
    if tail != "pckcrl" {
        return false;
    }
    !ver.is_empty() && ver.as_bytes()[0] != b'0' && ver.bytes().all(|b| b.is_ascii_digit())
}

fn is_intermediate_host(host: &str) -> bool {
    // [a-zA-Z0-9-]*\.?api\.trustedservices\.intel\.com
    // or [a-zA-Z0-9-]+\.az\.sgx(prod|np)\.adsdcsp\.com
    if host == "api.trustedservices.intel.com" || host.ends_with(".api.trustedservices.intel.com") {
        let prefix = host
            .strip_suffix("api.trustedservices.intel.com")
            .unwrap_or("");
        let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
        return prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    }
    if let Some(left) = host.strip_suffix(".az.sgxprod.adsdcsp.com") {
        return !left.is_empty() && left.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    }
    if let Some(left) = host.strip_suffix(".az.sgxnp.adsdcsp.com") {
        return !left.is_empty() && left.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    }
    false
}

/// Parse GET /platforms `source` query:
/// - missing / "reg" / "reg_na"
/// - "[fmspc,fmspc]" list
pub enum PlatformsSource {
    Reg,
    RegNa,
    Fmspc(Vec<String>),
}

pub fn platforms_source(source: Option<&str>) -> Result<PlatformsSource, PccsError> {
    match source {
        None | Some("") | Some("reg") => Ok(PlatformsSource::Reg),
        Some("reg_na") => Ok(PlatformsSource::RegNa),
        Some(fmspc_raw) => {
            if fmspc_raw.len() < 2 || !fmspc_raw.starts_with('[') || !fmspc_raw.ends_with(']') {
                tracing::error!("Invalid fmspc : {fmspc_raw}");
                return Err(error::INVALID_REQ);
            }
            let inner = fmspc_raw[1..fmspc_raw.len() - 1].trim();
            if inner.is_empty() {
                return Ok(PlatformsSource::Fmspc(vec![]));
            }
            let mut out = Vec::new();
            for part in inner.split(',') {
                out.push(fmspc(Some(part.trim()))?);
            }
            Ok(PlatformsSource::Fmspc(out))
        }
    }
}

// --------------------------------------------------------------------------
// Body schemas — hand-written equivalents of Node `services/pccs_schemas.js`
// --------------------------------------------------------------------------

fn reject(what: &str) -> PccsError {
    tracing::error!("{what}");
    error::INVALID_REQ
}

/// `type: 'string'` plus an optional pattern. `None` when the key is absent.
fn opt_str<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>, PccsError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(reject(&format!("{key} must be a string"))),
    }
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, PccsError> {
    opt_str(v, key)?.ok_or_else(|| reject(&format!("{key} is required")))
}

/// Node `PLATFORM_REG_SCHEMA` (ajv). The body must be an **object**; an array
/// fails `type: 'object'`.
pub struct PlatformReg {
    pub qe_id: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub pce_svn: String,
    pub enc_ppid: String,
    pub platform_manifest: String,
}

pub fn platform_reg(body: &Value) -> Result<PlatformReg, PccsError> {
    if !body.is_object() {
        return Err(reject("Failed to validate the registration data."));
    }
    let qe_id = req_str(body, "qe_id")?;
    if qe_id.is_empty() || qe_id.len() > 260 {
        return Err(reject("qe_id length out of range"));
    }
    let pce_id = req_str(body, "pce_id")?;
    if !is_hex(pce_id, 4) {
        return Err(reject("pce_id is not a valid hex string"));
    }
    // ajv checks every present property against its pattern, whether or not
    // platform_manifest is set.
    let cpu_svn = opt_str(body, "cpu_svn")?.unwrap_or("");
    let pce_svn = opt_str(body, "pce_svn")?.unwrap_or("");
    let enc_ppid = opt_str(body, "enc_ppid")?.unwrap_or("");
    if body.get("cpu_svn").is_some() && !is_hex(cpu_svn, 32) {
        return Err(reject("cpu_svn is not a valid hex string"));
    }
    if body.get("pce_svn").is_some() && !is_hex(pce_svn, 4) {
        return Err(reject("pce_svn is not a valid hex string"));
    }
    if body.get("enc_ppid").is_some() && !is_hex(enc_ppid, 768) {
        return Err(reject("enc_ppid is not a valid hex string"));
    }
    let manifest = opt_str(body, "platform_manifest")?.unwrap_or("");

    // Node `normalizeRegData`
    if manifest.is_empty() {
        if cpu_svn.is_empty() || pce_svn.is_empty() || enc_ppid.is_empty() {
            return Err(reject("cpu_svn / pce_svn / enc_ppid are required"));
        }
        Ok(PlatformReg {
            qe_id: qe_id.to_ascii_uppercase(),
            pce_id: pce_id.to_ascii_uppercase(),
            cpu_svn: cpu_svn.to_ascii_uppercase(),
            pce_svn: pce_svn.to_ascii_uppercase(),
            enc_ppid: enc_ppid.to_ascii_uppercase(),
            platform_manifest: String::new(),
        })
    } else {
        Ok(PlatformReg {
            qe_id: qe_id.to_ascii_uppercase(),
            pce_id: pce_id.to_ascii_uppercase(),
            cpu_svn: String::new(),
            pce_svn: String::new(),
            enc_ppid: String::new(),
            platform_manifest: manifest.to_string(),
        })
    }
}

/// Node `PLATFORM_COLLATERAL_SCHEMA_V3` / `_V4`.
pub fn platform_collateral(body: &Value, version: u32) -> Result<(), PccsError> {
    if !body.is_object() {
        return Err(reject("collateral body must be an object"));
    }
    let platforms = body
        .get("platforms")
        .and_then(|v| v.as_array())
        .ok_or_else(|| reject("platforms is required"))?;
    for p in platforms {
        if !p.is_object() {
            return Err(reject("platforms[] entry must be an object"));
        }
        let qe_id = req_str(p, "qe_id")?;
        if qe_id.is_empty() || qe_id.len() > 260 {
            return Err(reject("platforms[].qe_id length out of range"));
        }
        if !is_hex(req_str(p, "pce_id")?, 4) {
            return Err(reject("platforms[].pce_id is not valid hex"));
        }
        for (key, len) in [("cpu_svn", 32), ("pce_svn", 4), ("enc_ppid", 768)] {
            if let Some(v) = opt_str(p, key)? {
                if !is_hex_or_empty(v, len) {
                    return Err(reject(&format!("platforms[].{key} is not valid hex")));
                }
            }
        }
        opt_str(p, "platform_manifest")?;
    }

    let collaterals = body
        .get("collaterals")
        .filter(|v| v.is_object())
        .ok_or_else(|| reject("collaterals is required"))?;

    if version >= 4 {
        match collaterals.get("version").and_then(|v| v.as_u64()) {
            Some(4) => {}
            _ => return Err(reject("collaterals.version must be 4")),
        }
    }

    let pck_certs = collaterals
        .get("pck_certs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| reject("collaterals.pck_certs is required"))?;
    for pc in pck_certs {
        if !pc.is_object() {
            return Err(reject("pck_certs[] entry must be an object"));
        }
        let qe_id = req_str(pc, "qe_id")?;
        if qe_id.is_empty() || qe_id.len() > 260 {
            return Err(reject("pck_certs[].qe_id length out of range"));
        }
        if !is_hex(req_str(pc, "pce_id")?, 4) {
            return Err(reject("pck_certs[].pce_id is not valid hex"));
        }
        if !is_hex_or_empty(req_str(pc, "enc_ppid")?, 768) {
            return Err(reject("pck_certs[].enc_ppid is not valid hex"));
        }
        opt_str(pc, "platform_manifest")?;
        // Node's schema has no `minItems`, so an empty `certs` array passes
        // validation. It is rejected later, by `put_platform_collateral`,
        // exactly as Node rejects it in `addPlatformCollateral`.
        let certs = pc
            .get("certs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| reject("pck_certs[].certs is required"))?;
        for c in certs {
            if !c.is_object() {
                return Err(reject("certs[] entry must be an object"));
            }
            if !c.get("tcb").map(|t| t.is_object()).unwrap_or(false) {
                return Err(reject("certs[].tcb is required"));
            }
            if !is_hex(req_str(c, "tcbm")?, 36) {
                return Err(reject("certs[].tcbm must be 36 hex characters"));
            }
            if req_str(c, "cert")?.is_empty() {
                return Err(reject("certs[].cert must not be empty"));
            }
        }
    }

    let tcbinfos = collaterals
        .get("tcbinfos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| reject("collaterals.tcbinfos is required"))?;
    // Only the keys Node's schema actually defines. The `*_early` variants are
    // absent from `PLATFORM_COLLATERAL_SCHEMA_V3/V4`, and ajv runs without
    // `additionalProperties: false`, so Node ignores them at the schema step
    // (and still stores them afterwards). Validating them here would 400 a body
    // Node accepts.
    let tcb_fields: &[&str] = if version < 4 {
        &["tcbinfo"]
    } else {
        &["sgx_tcbinfo", "tdx_tcbinfo"]
    };
    for t in tcbinfos {
        if !t.is_object() {
            return Err(reject("tcbinfos[] entry must be an object"));
        }
        // Node's schema is a bare `{'type': 'string'}` — no hex pattern. The
        // 12-hex requirement only exists on the *inner* `tcbInfo.fmspc`.
        // Downstream (`put_platform_collateral`) uppercases it and uses it as a
        // key, like Node does.
        req_str(t, "fmspc")?;
        for field in tcb_fields {
            let Some(info) = t.get(*field) else { continue };
            if !info.is_object() {
                return Err(reject(&format!("tcbinfos[].{field} must be an object")));
            }
            if !info.get("tcbInfo").map(|v| v.is_object()).unwrap_or(false) {
                return Err(reject(&format!("tcbinfos[].{field}.tcbInfo is required")));
            }
            req_str(info, "signature")?;
        }
    }

    if let Some(crl) = collaterals.get("pckcacrl") {
        if !crl.is_object() {
            return Err(reject("pckcacrl must be an object"));
        }
        // Plain strings in Node's schema. A value that will not hex-decode is
        // dropped downstream, not answered with a 400 here.
        for key in ["processorCrl", "platformCrl"] {
            opt_str(crl, key)?;
        }
    }
    opt_str(collaterals, "rootcacrl")?;
    opt_str(collaterals, "rootcacrl_cdp")?;

    let certificates = collaterals
        .get("certificates")
        .filter(|v| v.is_object())
        .ok_or_else(|| reject("collaterals.certificates is required"))?;
    let issuer_chains = certificates
        .get("SGX-PCK-Certificate-Issuer-Chain")
        .filter(|v| v.is_object())
        .ok_or_else(|| reject("SGX-PCK-Certificate-Issuer-Chain is required"))?;
    for ca in ["PROCESSOR", "PLATFORM"] {
        opt_str(issuer_chains, ca)?;
    }
    for key in [
        "SGX-TCB-Info-Issuer-Chain",
        "TCB-Info-Issuer-Chain",
        "SGX-Enclave-Identity-Issuer-Chain",
    ] {
        opt_str(certificates, key)?;
    }
    Ok(())
}

/// Node `APPRAISAL_POLICY_REG_SCHEMA` + `appraisalPolicyService.putAppraisalPolicy`.
pub struct AppraisalPolicyReg {
    pub is_default: bool,
    pub fmspc: String,
    pub policy: String,
    /// Node `getPolicyTypeByClassId`: 0 = SGX, 1 = TDX 1.0, 2 = TDX 1.5.
    pub policy_type: u8,
}

const CLASS_ID_SGX: &str = "3123ec35-8d38-4ea5-87a5-d6c48b567570";
const CLASS_ID_TDX_10: &str = "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f";
const CLASS_ID_TDX_15: &str = "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3";
const CLASS_ID_TDQE: &str = "3769258c-75e6-4bc7-8d72-d2b0e224cad2";

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

pub fn appraisal_policy(body: &Value) -> Result<AppraisalPolicyReg, PccsError> {
    if !body.is_object() {
        return Err(reject("Failed to validate the appraisal policy file."));
    }
    let is_default = body
        .get("is_default")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| reject("is_default is required"))?;
    let fmspc_raw = req_str(body, "fmspc")?;
    if !is_hex(fmspc_raw, 12) {
        return Err(reject("fmspc must be 12 hex characters"));
    }
    let policy = req_str(body, "policy")?;
    if policy.is_empty() {
        return Err(reject("policy must not be empty"));
    }
    // Node: policy must be JWS-like — the payload is segment[1], base64url.
    if !policy.contains('.') {
        return Err(reject("Failed to validate the policy field."));
    }
    let segment = policy.split('.').nth(1).unwrap_or("");
    let decoded = base64url_decode(segment).ok_or_else(|| reject("Invalid policy payload."))?;
    let payload: Value =
        serde_json::from_slice(&decoded).map_err(|_| reject("Invalid policy payload."))?;
    let policy_type = policy_type_by_class_id(&payload)?;

    Ok(AppraisalPolicyReg {
        is_default,
        fmspc: fmspc_raw.to_ascii_uppercase(),
        policy: policy.to_string(),
        policy_type,
    })
}

/// Node `getPolicyTypeByClassId`.
fn policy_type_by_class_id(payload: &Value) -> Result<u8, PccsError> {
    let raw = payload
        .get("policy_payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| reject("Invalid policy data."))?;
    let policy_payload: Value = serde_json::from_str(raw)
        .map_err(|_| reject("Failed to parse appraisal policy payload"))?;
    let array = policy_payload
        .get("policy_array")
        .and_then(|v| v.as_array())
        .ok_or_else(|| reject("Policy array not found."))?;
    for policy in array {
        let class_id = policy
            .get("environment")
            .and_then(|e| e.get("class_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| reject("Invalid policy data."))?
            .to_ascii_lowercase();
        match class_id.as_str() {
            CLASS_ID_SGX => return Ok(0),
            CLASS_ID_TDX_10 => return Ok(1),
            CLASS_ID_TDX_15 => return Ok(2),
            CLASS_ID_TDQE => continue,
            _ => return Err(reject("Unknown policy class_id.")),
        }
    }
    Err(reject("Failed to get a valid policy type."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duplicated_query_params_keep_the_first_value() {
        let q = query_params(Some("fmspc=AAAA&fmspc=BBBB&update=early")).unwrap();
        assert_eq!(q.get("fmspc").unwrap(), "AAAA");
        assert_eq!(q.get("update").unwrap(), "early");
    }

    #[test]
    fn query_params_decode_percent_and_plus() {
        let q = query_params(Some("source=%5BABCD%5D&x=a+b")).unwrap();
        assert_eq!(q.get("source").unwrap(), "[ABCD]");
        assert_eq!(q.get("x").unwrap(), "a b");
        assert_eq!(query_params(Some("flag")).unwrap().get("flag").unwrap(), "");
        // `qs` keeps an empty key rather than rejecting the query string.
        let empty_key = query_params(Some("=novalue")).unwrap();
        assert_eq!(empty_key.get("").unwrap(), "novalue");
        // …and it must not disturb a real parameter alongside it.
        let mixed = query_params(Some("=x&fmspc=ABCDABCDABCD")).unwrap();
        assert_eq!(mixed.get("fmspc").unwrap(), "ABCDABCDABCD");
    }

    #[test]
    fn percent_decode_survives_multibyte_boundaries() {
        // '%' immediately followed by a multi-byte character must not panic.
        assert_eq!(percent_decode("%é"), "%é");
        assert_eq!(percent_decode("a%2Bb"), "a+b");
        assert_eq!(percent_decode("%2"), "%2");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(
            percent_decode("-----BEGIN%20CERTIFICATE-----%0A"),
            "-----BEGIN CERTIFICATE-----\n"
        );
    }

    #[test]
    fn encrypted_ppid_present_but_empty_is_rejected() {
        assert!(encrypted_ppid(None).unwrap().is_none());
        assert!(encrypted_ppid(Some("")).is_err());
        assert!(encrypted_ppid(Some(&"A".repeat(768))).unwrap().is_some());
    }

    #[test]
    fn platform_reg_rejects_arrays_and_bad_hex() {
        assert!(platform_reg(&json!([{ "qe_id": "AA", "pce_id": "0000" }])).is_err());
        assert!(platform_reg(&json!("string")).is_err());
        assert!(platform_reg(&json!({ "qe_id": "AA", "pce_id": "zzzz" })).is_err());
        // present-but-invalid cpu_svn is rejected even with a platform_manifest
        assert!(platform_reg(&json!({
            "qe_id": "AA", "pce_id": "0000",
            "platform_manifest": "DEAD", "cpu_svn": "nothex"
        }))
        .is_err());
        let ok = platform_reg(&json!({
            "qe_id": "aa", "pce_id": "00ff",
            "cpu_svn": "0".repeat(32), "pce_svn": "0001",
            "enc_ppid": "a".repeat(768)
        }))
        .unwrap();
        assert_eq!(ok.qe_id, "AA");
        assert_eq!(ok.pce_id, "00FF");
        assert_eq!(ok.enc_ppid, "A".repeat(768));
    }

    #[test]
    fn appraisal_policy_requires_a_jws_like_payload() {
        assert!(appraisal_policy(&json!({
            "is_default": true, "fmspc": "ABCDABCDABCD", "policy": "nodots"
        }))
        .is_err());

        let payload = json!({
            "policy_payload": json!({
                "policy_array": [{ "environment": { "class_id": CLASS_ID_TDX_15 } }]
            })
            .to_string()
        });
        use base64::Engine;
        let seg =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let jws = format!("aGVhZGVy.{seg}.c2ln");
        let parsed = appraisal_policy(&json!({
            "is_default": true, "fmspc": "abcdabcdabcd", "policy": jws
        }))
        .unwrap();
        assert_eq!(parsed.fmspc, "ABCDABCDABCD");
        assert_eq!(parsed.policy_type, 2);
    }

    #[test]
    fn collateral_schema_checks_required_keys() {
        let good = json!({
            "platforms": [{ "qe_id": "AA", "pce_id": "0000" }],
            "collaterals": {
                "version": 4,
                "pck_certs": [{
                    "qe_id": "AA", "pce_id": "0000", "enc_ppid": "",
                    "certs": [{ "tcb": {}, "tcbm": "0".repeat(36), "cert": "x" }]
                }],
                "tcbinfos": [{ "fmspc": "ABCDABCDABCD" }],
                "certificates": { "SGX-PCK-Certificate-Issuer-Chain": { "PROCESSOR": "c" } }
            }
        });
        assert!(platform_collateral(&good, 4).is_ok());

        let mut bad = good.clone();
        bad["collaterals"]["pck_certs"][0]["certs"][0]["tcbm"] = json!("short");
        assert!(platform_collateral(&bad, 4).is_err());

        let mut bad = good.clone();
        bad["collaterals"]
            .as_object_mut()
            .unwrap()
            .remove("certificates");
        assert!(platform_collateral(&bad, 4).is_err());

        let mut bad = good.clone();
        bad["collaterals"]["version"] = json!(3);
        assert!(platform_collateral(&bad, 4).is_err());
    }

    #[test]
    fn crl_uri_root_ok() {
        assert!(is_valid_crl_uri(
            "https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
        ));
    }

    #[test]
    fn crl_uri_intermediate_ok() {
        assert!(is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor"
        ));
    }

    #[test]
    fn crl_uri_rejects_http_and_evil() {
        assert!(!is_valid_crl_uri(
            "http://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
        ));
        assert!(!is_valid_crl_uri(
            "https://nonexistent.url/doEvil?url=https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
        ));
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v0/pckcrl?ca=processor"
        ));
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v04/pckcrl?ca=processor"
        ));
    }

    #[test]
    fn version_from_url() {
        assert_eq!(
            api_version_from_url("/sgx/certification/v4/tcb").unwrap(),
            4
        );
        assert_eq!(
            api_version_from_url("/sgx/certification/v3/pckcert").unwrap(),
            3
        );
    }

    #[test]
    fn version_from_url_rejects_unknown_and_malformed() {
        // Only v3 and v4 exist; v10 parses but is not a PCS API version.
        assert!(api_version_from_url("/sgx/certification/v10/tcb").is_err());
        // v0 is not a valid version token (no leading zero).
        assert!(api_version_from_url("/sgx/certification/v0/tcb").is_err());
        assert!(api_version_from_url("/sgx/certification/v04/tcb").is_err());
        assert!(api_version_from_url("/sgx/certification/").is_err());
        assert!(api_version_from_url("").is_err());
        // The version segment must be followed by '/'.
        assert!(api_version_from_url("/v4").is_err());
    }

    #[test]
    fn update_type_parsing() {
        assert_eq!(update_type(None, false).unwrap(), UpdateType::Standard);
        assert_eq!(
            update_type(Some("standard"), false).unwrap(),
            UpdateType::Standard
        );
        assert_eq!(update_type(Some("early"), false).unwrap(), UpdateType::Early);
        // ALL is only accepted where Node allows it (POST /platforms).
        assert_eq!(update_type(Some("all"), true).unwrap(), UpdateType::All);
        assert!(update_type(Some("all"), false).is_err());
        assert!(update_type(Some("bogus"), true).is_err());
        assert_eq!(UpdateType::Standard.as_str(), "STANDARD");
        assert_eq!(UpdateType::Early.as_str(), "EARLY");
        assert_eq!(UpdateType::All.as_str(), "ALL");
    }

    #[test]
    fn qeid_rules() {
        assert!(qeid(None).is_err());
        assert!(qeid(Some("")).is_err());
        assert!(qeid(Some(&"A".repeat(261))).is_err());
        // Not required to be hex; uppercased like Node.
        assert_eq!(qeid(Some("qeid-1")).unwrap(), "QEID-1");
        assert_eq!(qeid(Some(&"a".repeat(260))).unwrap(), "A".repeat(260));
    }

    #[test]
    fn hex_validators_require_presence_and_length() {
        assert!(fmspc(None).is_err());
        assert!(fmspc(Some("ABCD")).is_err());
        assert_eq!(fmspc(Some("abcdabcdabcd")).unwrap(), "ABCDABCDABCD");
        assert!(cpusvn(Some(&"0".repeat(31))).is_err());
        assert_eq!(cpusvn(Some(&"a".repeat(32))).unwrap(), "A".repeat(32));
        assert!(pcesvn(Some("12345")).is_err());
        assert_eq!(pcesvn(Some("abcd")).unwrap(), "ABCD");
        assert!(pceid(Some("zzzz")).is_err());
        assert_eq!(pceid(Some("00ff")).unwrap(), "00FF");
    }

    #[test]
    fn pck_ca_is_case_insensitive_processor_or_platform() {
        assert_eq!(pck_ca(Some("processor")).unwrap(), "PROCESSOR");
        assert_eq!(pck_ca(Some("Platform")).unwrap(), "PLATFORM");
        assert!(pck_ca(Some("root")).is_err());
        assert!(pck_ca(None).is_err());
    }

    #[test]
    fn platforms_source_variants() {
        assert!(matches!(platforms_source(None).unwrap(), PlatformsSource::Reg));
        assert!(matches!(
            platforms_source(Some("")).unwrap(),
            PlatformsSource::Reg
        ));
        assert!(matches!(
            platforms_source(Some("reg")).unwrap(),
            PlatformsSource::Reg
        ));
        assert!(matches!(
            platforms_source(Some("reg_na")).unwrap(),
            PlatformsSource::RegNa
        ));
        // Empty list is allowed and matches nothing downstream.
        match platforms_source(Some("[]")).unwrap() {
            PlatformsSource::Fmspc(v) => assert!(v.is_empty()),
            _ => panic!("[] must be an fmspc list"),
        }
        match platforms_source(Some("[abcdabcdabcd, 00906EA10000]")).unwrap() {
            PlatformsSource::Fmspc(v) => {
                assert_eq!(v, vec!["ABCDABCDABCD", "00906EA10000"])
            }
            _ => panic!("expected fmspc list"),
        }
        assert!(platforms_source(Some("ABCDABCDABCD")).is_err());
        assert!(platforms_source(Some("[nothex]")).is_err());
    }

    #[test]
    fn platform_reg_manifest_branch_and_length_limits() {
        // With a platform manifest the raw-TCB fields are dropped, not required.
        let reg = platform_reg(&json!({
            "qe_id": "aa", "pce_id": "0000", "platform_manifest": "AB"
        }))
        .unwrap();
        assert_eq!(reg.platform_manifest, "AB");
        assert!(reg.cpu_svn.is_empty());
        assert!(reg.enc_ppid.is_empty());

        // Without one, cpu_svn / pce_svn / enc_ppid are all mandatory.
        assert!(platform_reg(&json!({ "qe_id": "AA", "pce_id": "0000" })).is_err());
        assert!(platform_reg(&json!({ "pce_id": "0000" })).is_err());
        assert!(platform_reg(&json!({ "qe_id": "A".repeat(261), "pce_id": "0000" })).is_err());
        assert!(platform_reg(&json!({
            "qe_id": "AA", "pce_id": "0000",
            "cpu_svn": "0".repeat(32), "pce_svn": "zzzz", "enc_ppid": "a".repeat(768)
        }))
        .is_err());
    }

    #[test]
    fn platform_collateral_v3_and_field_edge_cases() {
        // v3 has no `collaterals.version` check and uses the v3 field names.
        let v3 = json!({
            "platforms": [{ "qe_id": "AA", "pce_id": "0000" }],
            "collaterals": {
                "pck_certs": [{
                    "qe_id": "AA", "pce_id": "0000", "enc_ppid": "",
                    "certs": [{ "tcb": {}, "tcbm": "0".repeat(36), "cert": "x" }]
                }],
                "tcbinfos": [{ "fmspc": "ABCDABCDABCD", "tcbinfo": { "tcbInfo": {}, "signature": "s" } }],
                "certificates": { "SGX-PCK-Certificate-Issuer-Chain": { "PROCESSOR": "c" } }
            }
        });
        assert!(platform_collateral(&v3, 3).is_ok());
        // The same body fails v4: `collaterals.version` must be 4.
        assert!(platform_collateral(&v3, 4).is_err());

        let mut bad = v3.clone();
        bad["platforms"] = json!(["not-an-object"]);
        assert!(platform_collateral(&bad, 3).is_err());

        let mut bad = v3.clone();
        bad["collaterals"]["pck_certs"] = json!(["not-an-object"]);
        assert!(platform_collateral(&bad, 3).is_err());

        let mut bad = v3.clone();
        bad["collaterals"]["pck_certs"][0]["certs"] = json!([{ "tcbm": "0".repeat(36), "cert": "x" }]);
        assert!(platform_collateral(&bad, 3).is_err());

        // tcbinfos[].tcbinfo must be an object carrying tcbInfo + signature.
        let mut bad = v3.clone();
        bad["collaterals"]["tcbinfos"][0]["tcbinfo"] = json!("not-an-object");
        assert!(platform_collateral(&bad, 3).is_err());
        let mut bad = v3.clone();
        bad["collaterals"]["tcbinfos"][0]["tcbinfo"] = json!({ "signature": "s" });
        assert!(platform_collateral(&bad, 3).is_err());

        // pckcacrl, when present, must be an object of strings.
        let mut bad = v3.clone();
        bad["collaterals"]["pckcacrl"] = json!("nope");
        assert!(platform_collateral(&bad, 3).is_err());
        let mut bad = v3.clone();
        bad["collaterals"]["pckcacrl"] = json!({ "processorCrl": 42 });
        assert!(platform_collateral(&bad, 3).is_err());

        // rootcacrl is a plain string when present.
        let mut bad = v3.clone();
        bad["collaterals"]["rootcacrl"] = json!(42);
        assert!(platform_collateral(&bad, 3).is_err());

        // A non-object body is rejected before any key is read.
        assert!(platform_collateral(&json!([]), 4).is_err());
    }

    #[test]
    fn appraisal_policy_payload_branches() {
        let jws = |inner: serde_json::Value| {
            use base64::Engine;
            let seg = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(inner.to_string().as_bytes());
            format!("aGVhZGVy.{seg}.c2ln")
        };
        let put = |policy: String| {
            appraisal_policy(&json!({
                "is_default": true, "fmspc": "ABCDABCDABCD", "policy": policy
            }))
        };

        // Payload segment that is not JSON.
        assert!(put(jws(json!("not an object"))).is_err());
        // policy_payload must be a string containing JSON.
        assert!(put(jws(json!({ "policy_payload": 42 }))).is_err());
        assert!(put(jws(json!({ "policy_payload": "not json" }))).is_err());
        // policy_array missing / entries without a class_id.
        assert!(put(jws(json!({
            "policy_payload": json!({ "nope": [] }).to_string()
        })))
        .is_err());
        assert!(put(jws(json!({
            "policy_payload": json!({ "policy_array": [{ "environment": {} }] }).to_string()
        })))
        .is_err());
        // A TDQE entry alone never determines a policy type.
        assert!(put(jws(json!({
            "policy_payload": json!({
                "policy_array": [{ "environment": { "class_id": CLASS_ID_TDQE } }]
            }).to_string()
        })))
        .is_err());
        // TDX 1.0 → 1, SGX → 0; a TDQE entry before a real one is skipped.
        let tdx10 = put(jws(json!({
            "policy_payload": json!({
                "policy_array": [
                    { "environment": { "class_id": CLASS_ID_TDQE } },
                    { "environment": { "class_id": CLASS_ID_TDX_10 } }
                ]
            }).to_string()
        })))
        .unwrap();
        assert_eq!(tdx10.policy_type, 1);
        let sgx = put(jws(json!({
            "policy_payload": json!({
                "policy_array": [{ "environment": { "class_id": CLASS_ID_SGX } }]
            }).to_string()
        })))
        .unwrap();
        assert_eq!(sgx.policy_type, 0);

        // is_default must be a bool; policy must be a non-empty string.
        assert!(appraisal_policy(&json!({
            "is_default": "yes", "fmspc": "ABCDABCDABCD", "policy": "a.b.c"
        }))
        .is_err());
        assert!(appraisal_policy(&json!({
            "is_default": true, "fmspc": "ABCDABCDABCD", "policy": ""
        }))
        .is_err());
        assert!(appraisal_policy(&json!([])).is_err());
    }

    #[test]
    fn crl_uri_more_variants() {
        // Empty / oversized URIs are rejected up front.
        assert!(!is_valid_crl_uri(""));
        assert!(!is_valid_crl_uri(&format!(
            "https://certificates.trustedservices.intel.com/IntelSGXRootCA.{}",
            "a".repeat(2048)
        )));
        // Node's prefix class is `[a-zA-Z0-9-]*` — no dot, so only a direct
        // alphanumeric prefix of the certificates host matches, never a
        // subdomain or a lookalike.
        assert!(is_valid_crl_uri(
            "https://sbcertificates.trustedservices.intel.com/IntelSGXRootCA.der.crl"
        ));
        assert!(!is_valid_crl_uri(
            "https://sb.certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
        ));
        assert!(!is_valid_crl_uri(
            "https://evil_certificates.trustedservices.intel.com/IntelSGXRootCA.crl"
        ));
        // The alternate root-CRL host from Node's regex.
        assert!(is_valid_crl_uri(
            "https://certprx.adsdcsp.com/IntelSGXRootCA.crl"
        ));
        // Root CA path must have something after `IntelSGXRootCA.`.
        assert!(!is_valid_crl_uri(
            "https://certificates.trustedservices.intel.com/IntelSGXRootCA."
        ));
        // Intermediate: the az.sgxprod / az.sgxnp hosts from Node's regex.
        assert!(is_valid_crl_uri(
            "https://uswest.az.sgxprod.adsdcsp.com/sgx/certification/v4/pckcrl?ca=processor"
        ));
        assert!(is_valid_crl_uri(
            "https://uswest.az.sgxnp.adsdcsp.com/sgx/certification/v3/pckcrl?ca=platform"
        ));
        assert!(!is_valid_crl_uri(
            "https://.az.sgxprod.adsdcsp.com/sgx/certification/v4/pckcrl?ca=processor"
        ));
        // A query string is mandatory, and the path must end at pckcrl.
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl"
        ));
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?"
        ));
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrlx?ca=processor"
        ));
        assert!(!is_valid_crl_uri(
            "https://api.trustedservices.intel.com/sgx/certification/vX/pckcrl?ca=processor"
        ));
    }
}
