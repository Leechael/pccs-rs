//! Request parameter validation matching Node `validatorService.js` + controllers.

use crate::error::{self, PccsError};

fn is_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn require_hex(value: Option<&str>, field: &str, expected_len: usize) -> Result<String, PccsError> {
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

/// `encrypted_ppid` may be omitted (Node: null/undefined allowed).
pub fn encrypted_ppid(value: Option<&str>) -> Result<Option<String>, PccsError> {
    match value {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
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
        if bytes[i] == b'/' && bytes[i + 1] == b'v' && bytes[i + 2].is_ascii_digit() && bytes[i + 2] != b'0'
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
            && host[..host.len().saturating_sub("certificates.trustedservices.intel.com".len())]
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
    !ver.is_empty()
        && ver.as_bytes()[0] != b'0'
        && ver.bytes().all(|b| b.is_ascii_digit())
}

fn is_intermediate_host(host: &str) -> bool {
    // [a-zA-Z0-9-]*\.?api\.trustedservices\.intel\.com
    // or [a-zA-Z0-9-]+\.az\.sgx(prod|np)\.adsdcsp\.com
    if host == "api.trustedservices.intel.com" || host.ends_with(".api.trustedservices.intel.com") {
        let prefix = host.strip_suffix("api.trustedservices.intel.com").unwrap_or("");
        let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
        return prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
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
            if fmspc_raw.len() < 2
                || !fmspc_raw.starts_with('[')
                || !fmspc_raw.ends_with(']')
            {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
